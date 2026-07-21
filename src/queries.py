from typing import Any, Dict, List, Optional
from client import CPPMClient
import datetime as _dt
import json
import logging
import re

logger = logging.getLogger("CPPMQueries")

class ResourceNotFound(Exception):
    pass


class ReplaceScanAborted(Exception):
    """Raised by ``_remove_absent_tagged`` when the replace-scan refuses to
    delete — an empty batch, or a removal set exceeding the safety ratio — so
    the caller surfaces it as a sync ERROR instead of mass-deleting endpoints."""
    pass


def _nas_name(s: dict) -> str:
    """NAS device name for a ClearPass ``/api/session`` record.

    ClearPass's documented field is ``nas_name`` (with the underscore); older or
    variant deployments may expose ``nasname`` / ``nasidentifier``. Fall back to
    the NAS IP (``nasipaddress``) when no name is present so the Access Tracker
    still shows which network device the session terminated on."""
    return (s.get("nas_name") or s.get("nasname") or s.get("nasidentifier")
            or s.get("nas_identifier") or s.get("nas-identifier")
            or s.get("nasipaddress") or "")


def _nas_port(s: dict) -> str:
    """NAS port identifier for a ClearPass ``/api/session`` record.

    ClearPass carries the port in ``nasportid`` (e.g. "Ethernet1/0/12"); there
    is no ``nasport`` field. Returns '' when the session has no port info
    (e.g. a wireless controller session), so the UI can show '—'."""
    return (s.get("nasportid") or s.get("nas_port_id")
            or s.get("nasport") or s.get("nas_port") or "")


def _nas_port_type(s: dict) -> str:
    """NAS port type (e.g. 'Ethernet', 'Wireless - IEEE 802.11') if reported."""
    return s.get("nasporttype") or s.get("nas_port_type") or ""


def _nas_ip(s: dict) -> str:
    """NAS IP (the switch/controller the session terminated on) for a ClearPass
    ``/api/session`` record. Distinct from ``_nas_name`` — the name helper only
    falls back to ``nasipaddress`` when no name is present; this always pulls the
    IP so the realtime NAC→IPAM reverse sync can model the switch device in
    NetBox by its IP."""
    return (s.get("nasipaddress") or s.get("nas_ip_address")
            or s.get("nas_ip") or "")


def _iso_dt(dt) -> str:
    """CPPM datetime string → ISO 8601 (swaps the space separator for ``T``) so
    JS ``new Date()`` and our own parsers handle it reliably. ``''`` for absent.
    Module-level twin of the local ``_iso`` in get_access_tracker /
    get_device_sessions, lifted so get_recent_sessions can share it."""
    if not dt:
        return ""
    s = str(dt).strip()
    return s.replace(" ", "T") if " " in s else s


def _make_p12_handler(p12_bytes: bytes):
    """Build a one-shot ``http.server`` handler that serves ``p12_bytes`` at
    ``/bundle.p12`` (404 elsewhere). Used by :meth:`CPPMQueries.import_cert`
    to host the PKCS#12 bundle ClearPass fetches during the PUT — the server
    lives only for the duration of that PUT call. The handler silences its
    own request logging (the spoke log already records the install step)."""
    import http.server

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler API)
            if self.path.split("?", 1)[0] == "/bundle.p12":
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pkcs12")
                self.send_header("Content-Length", str(len(p12_bytes)))
                self.end_headers()
                self.wfile.write(p12_bytes)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):  # silence per-request stderr noise
            pass

    return _Handler


def _detect_local_ipv4() -> str:
    """Best-effort primary outbound IPv4 of this host, for ClearPass to fetch
    the PKCS12 bundle when ``LM_CPPM_P12_HOST`` is unset. Uses the UDP-connect
    trick (no packets sent) to find the source IP of the default route — the
    address ClearPass most likely reaches when the spoke shares its routed
    network. Returns ``""`` on failure; the caller still requires a non-empty
    host so a failed detection surfaces the actionable ERROR (set the env)."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("223.255.255.1", 1))  # RFC 5737 — never routed
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        finally:
            s.close()
    except Exception:
        pass
    return ""


def _split_pem_certs(pem_text: str) -> list:
    """Split a PEM bundle into its individual ``BEGIN/END CERTIFICATE`` blocks,
    preserving the delimiters. Tolerant of CRLF and surrounding text (keys,
    comments). Used to separate the leaf from its issuing CAs."""
    blocks = []
    if not pem_text or "BEGIN CERTIFICATE" not in pem_text:
        return blocks
    for part in pem_text.replace("\r", "").split("-----END CERTIFICATE-----"):
        i = part.find("-----BEGIN CERTIFICATE-----")
        if i < 0:
            continue
        body = part[i:]
        if not body.endswith("\n"):
            body += "\n"
        blocks.append(body + "-----END CERTIFICATE-----\n")
    return blocks


# Canonical Let's Encrypt root CAs (self-signed, stable, publicly anchored).
# certbot's ``chain.pem`` / ``fullchain.pem`` ship ONLY the leaf + intermediate(s)
# — NEVER the self-signed root — so a chain that stops at an R3/R10/R11 (→ ISRG
# Root X1) or E5/E6 (→ ISRG Root X2) intermediate is missing the very cert
# ClearPass demands in its Certificate Trust List. These are appended by
# ``_ca_certs_to_trust`` when the supplied chain isn't already rooted.
_ISRG_ROOT_X1_PEM = """-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
"""

_ISRG_ROOT_X2_PEM = """-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----
"""

# Missing-root Subject CN → canonical ISRG root PEM. The topmost cert in a
# certbot chain is an intermediate (issuer = the root); we map that issuer CN
# to the root PEM to append.
_LE_ROOT_BY_CN = {
    "ISRG Root X1": _ISRG_ROOT_X1_PEM,
    "ISRG Root X2": _ISRG_ROOT_X2_PEM,
}


def _missing_root_pem(ca_pems: list) -> Optional[str]:
    """Return the canonical ISRG root PEM to append when the supplied CA chain
    stops at a non-self-signed intermediate, else ``None``.

    certbot's ``chain.pem``/``fullchain.pem`` never include the self-signed
    root, so a chain ending at R3/R10/R11 (issuer ``ISRG Root X1``) or E5/E6
    (issuer ``ISRG Root X2``) is missing the root ClearPass requires in the
    CTL. We detect by inspecting the LAST cert: if it's self-signed
    (issuer == subject) the root is already present; otherwise the issuer CN
    names the missing root. Best-effort — a non-LE issuer (or a parse failure)
    returns ``None`` and the chain is left as-is (today's behavior)."""
    if not ca_pems:
        return None
    try:
        from cryptography import x509
        last = x509.load_pem_x509_certificate(ca_pems[-1].encode())
    except Exception:
        return None
    if last.issuer == last.subject:          # self-signed → root already present
        return None
    cn_attrs = last.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    cn = str(cn_attrs[0].value).strip() if cn_attrs else ""
    return _LE_ROOT_BY_CN.get(cn)


def _ca_certs_to_trust(fullchain: str, chain: str) -> list:
    """Return the CA certs (intermediates + root) to add to ClearPass's
    Certificate Trust List, as PEM strings. Prefers the explicit ``chain``
    (CA chain, no leaf); otherwise derives from ``fullchain`` by skipping the
    first cert (the leaf). ClearPass 422's a third-party-CA-signed server
    cert until the issuing root CA is imported AND enabled in the CTL —
    these are the CAs the leaf chains up to.

    certbot ships ONLY the leaf + intermediate(s) (never the self-signed
    root), so when the derived chain stops at a non-self-signed intermediate
    we append the canonical ISRG root its issuer names (``_missing_root_pem``)
    — that root is the cert ClearPass's 422 names."""
    if chain and "BEGIN CERTIFICATE" in chain:
        cas = _split_pem_certs(chain)
    else:
        blocks = _split_pem_certs(fullchain)
        cas = blocks[1:] if len(blocks) > 1 else []
    root = _missing_root_pem(cas)
    if root and root not in cas:
        cas.append(root)
    return cas


def _cert_subject_cn(pem: str) -> str:
    """Best-effort Common Name from a PEM cert, for idempotency matching +
    diagnostics. Returns ``""`` on any parse failure (the caller treats an
    empty CN as 'unknown' and still POSTs)."""
    try:
        from cryptography import x509
        certs = x509.load_pem_x509_certificates(pem.encode())
        if certs:
            attrs = certs[0].subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME)
            if attrs:
                return str(attrs[0].value)
    except Exception:
        pass
    return ""


class CPPMQueries:
    """
    High-level interface for querying ClearPass Policy Manager.
    """
    # Tenant tag stored as endpoint attributes — the SAME names the at-auth-time
    # Context Server Action (lm/clearpass/netbox-tenant-context-server-action.json)
    # populates as Authorization attributes, so an Enforcement Policy can match
    # the tenant whether it was resolved ahead-of-time (this sync, via MAC lookup)
    # or at auth time (the CSA, via the endpoint's IP).
    TENANT_ATTR_SLUG = "NetBox_Tenant_Slug"
    TENANT_ATTR_NAME = "NetBox_Tenant_Name"
    TENANT_ATTR_ID = "NetBox_Tenant_ID"
    # Human-readable tenant attributes (value pulled from NetBox via the hub
    # payload): the friendly name and the machine slug. These sit alongside the
    # NetBox_Tenant_* tags so ClearPass Device Inventory shows a plain "Tenant"
    # column and an enforcement policy can match on either a friendly label or
    # the CSA's slug.
    TENANT_ATTR_TENANT = "Tenant"
    TENANT_ATTR_TENANT_SLUG = "Tenant_Slug"

    # Upper bound on how many endpoints the substring search scans. ClearPass's
    # REST `filter` only supports exact-equality (no SQL-LIKE), so partial match
    # is done client-side over a bounded paged scan of the inventory. Active
    # sessions are naturally bounded so they scan fully. Tuned for the global
    # search dropdown's responsiveness; raise if a deployment needs deeper reach.
    SEARCH_SCAN_CAP = 5000

    # Larger cap for the scheduled endpoint sync's IP→MAC resolution scans —
    # correctness over latency (the sync runs on a schedule, not per keystroke).
    # A static-IP device whose endpoint sorts toward the tail of a large
    # inventory was missed under SEARCH_SCAN_CAP; this scans deep enough to find
    # it, and each scan logs scanned-vs-total so a cap hit (or a small inventory
    # where .62 genuinely isn't present) is visible.
    SYNC_SCAN_CAP = 200000

    # An endpoint's IP can live under varying attribute names depending on the
    # profiler / sync path (``IP Address``, ``Framed-IP-Address``, a vendor-
    # specific name, …). The REST ``filter`` only matches the first-class
    # ``ip_address`` field, so an IP-only NetBox record can't always be matched
    # by the filter alone. The fallback scan (_endpoint_ips) is therefore
    # name-agnostic: it checks the value of EVERY attribute for the wanted IP
    # rather than guessing names, so an endpoint carrying the IP under any name
    # is found and its MAC reused. See _build_ip_endpoint_map.

    def __init__(self, client: CPPMClient):
        self.client = client

    def _items(self, result: Any, key: str = "_embedded") -> List[Dict]:
        """Extracts item list from CPPM's HAL-style response."""
        if isinstance(result, dict):
            if "status" in result and result["status"] == "ERROR":
                return []
            embedded = result.get("_embedded", {})
            if embedded:
                for v in embedded.values():
                    if isinstance(v, list):
                        return v
            if "items" in result:
                return result["items"]
        elif isinstance(result, list):
            return result
        return []

    # --- Access Tracker ---

    def get_access_tracker(self, limit: int = 200, offset: int = 0) -> Dict[str, Any]:
        """Active sessions only from the ClearPass Access Tracker.

        ClearPass ``/api/session`` returns both active and closed sessions, so
        without a filter the list (and ``count``) grows forever as history
        accumulates. Active sessions have no ``acctstoptime`` — filtering on
        ``{"acctstoptime": {"$exists": false}}`` returns only sessions that have
        not closed out. (Filtering on ``state`` is known to 500 on ClearPass.)"""
        active_filter = json.dumps({"acctstoptime": {"$exists": False}}, separators=(",", ":"))
        result = self.client.query(
            "/api/session",
            params={
                "calculate_count": "true",
                "limit": limit,
                "offset": offset,
                "filter": active_filter,
            },
        )
        _items_preview = result.get('_embedded', {}).get('items', []) if isinstance(result, dict) else []
        logger.info(f"CPPM /api/session count={result.get('count') if isinstance(result, dict) else '?'} first_item={dict(list(_items_preview[0].items())[:20]) if _items_preview else '{}'}")
        if isinstance(result, dict) and result.get("status") == "ERROR":
            return result
        items = self._items(result)

        def _iso(dt):
            """Convert CPPM datetime string to ISO 8601 so JS new Date() parses it reliably."""
            if not dt:
                return ""
            return str(dt).strip().replace(" ", "T") if " " in str(dt) else str(dt)

        sessions = []
        for s in items:
            # Role: may be a list or a single string
            roles_raw = s.get("roles") or s.get("role") or ""
            role = roles_raw[0] if isinstance(roles_raw, list) and roles_raw else (roles_raw if isinstance(roles_raw, str) else "")
            # Service: may be service or servicename
            svc = s.get("service") or s.get("servicename") or s.get("service_name") or ""
            sessions.append({
                "id":               s.get("id", ""),
                "username":         s.get("username", ""),
                "mac":              s.get("callingstation", s.get("mac", "")),
                "ip":               s.get("framedipaddress", ""),
                "calling_station":  s.get("callingstation", ""),
                "nas_name":         _nas_name(s),
                "nas_port":         _nas_port(s),
                "nas_port_type":    _nas_port_type(s),
                "role":             role,
                "service":          svc,
                "start_time":       _iso(s.get("acctstarttime", "")),
                "state":            s.get("state", ""),
                "acct_session_time": s.get("acctsessiontime", 0),
            })
        total = result.get("count", len(sessions)) if isinstance(result, dict) else len(sessions)
        return {"status": "SUCCESS", "sessions": sessions, "total": total}

    def get_recent_sessions(self, lookback_minutes: int = 2) -> Dict[str, Any]:
        """Sessions that started within the last ``lookback_minutes`` (Access
        Tracker / accounting) — the pull side of the realtime NAC→IPAM reverse
        sync. The hub loop calls this every ~60s with a 2-minute window so newly
        authenticated devices flow into NetBox.

        Pages ``/api/session`` filtered by ``acctstarttime >= <now - lookback>``
        (ISO 8601 UTC; ClearPass accepts ISO strings in ``$gte``, the same shape
        ``get_auth_logs`` uses). Returns normalized rows ``{mac, ip, nas_ip,
        nas_name, nas_port, nas_port_type, username, start_time}`` — the fields
        the NetBox sink needs to create a missing endpoint device + its
        switch/port topology. Rows with no MAC are dropped (the sink is
        MAC-keyed). **Not cached** — time-sensitive; the spoke handler bypasses
        the cache for this command.
        """
        try:
            lookback = int(lookback_minutes)
        except (TypeError, ValueError):
            lookback = 2
        end = _dt.datetime.now(_dt.timezone.utc)
        start = end - _dt.timedelta(minutes=max(0, lookback))
        start_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        filt = json.dumps({"acctstarttime": {"$gte": start_iso}},
                          separators=(",", ":"))
        sessions: List[Dict[str, Any]] = []
        total: Any = None
        limit = 1000
        offset = 0
        while True:
            result = self.client.query("/api/session", params={
                "calculate_count": "true",
                "limit": limit, "offset": offset, "filter": filt,
            })
            if isinstance(result, dict) and result.get("status") == "ERROR":
                return result
            items = self._items(result)
            for s in items:
                mac = s.get("callingstation", s.get("mac", ""))
                if not mac:
                    continue  # MAC-keyed downstream; nothing to ingest without one
                sessions.append({
                    "mac":           mac,
                    "ip":            s.get("framedipaddress", ""),
                    "nas_ip":        _nas_ip(s),
                    "nas_name":      _nas_name(s),
                    "nas_port":      _nas_port(s),
                    "nas_port_type": _nas_port_type(s),
                    "username":      s.get("username", ""),
                    "start_time":    _iso_dt(s.get("acctstarttime", "")),
                })
            if total is None and isinstance(result, dict):
                total = result.get("count")
            if len(items) < limit:
                break
            offset += limit
            if isinstance(total, int) and offset >= total:
                break
        return {"status": "SUCCESS", "sessions": sessions,
                "total": len(sessions), "window_start": start_iso,
                "window_end": end_iso}

    # --- Device Database ---

    def get_device_database(self, limit: int = 200, offset: int = 0, status: Optional[str] = None) -> Dict[str, Any]:
        """Endpoint (device) database from ClearPass."""
        params: Dict[str, Any] = {
            "calculate_count": "true",
            "limit": limit,
            "offset": offset,
        }
        if status:
            params["filter"] = json.dumps({"status": status}, separators=(",", ":"))
        result = self.client.query("/api/endpoint", params=params)
        if isinstance(result, dict) and result.get("status") == "ERROR":
            return result
        items = self._items(result)
        devices = []
        for d in items:
            attrs = d.get("attributes", {}) or {}
            devices.append({
                "id": d.get("id", ""),
                "mac": d.get("mac_address", ""),
                "status": d.get("status", ""),
                "description": d.get("description", ""),
                "device_vendor": attrs.get("Device Vendor", ""),
                "device_os": attrs.get("Device OS", ""),
                "device_type": attrs.get("Device Type", ""),
                "hostname": attrs.get("Hostname", ""),
                "ip": attrs.get("ip_address", attrs.get("IP Address", "")),
                # Full attribute map (non-empty values) so the Device Database
                # list can show endpoint attributes inline. The detail modal
                # (GET_ENDPOINT_DETAIL) returns the same map for the click view.
                "attributes": {k: v for k, v in attrs.items() if v},
            })
        total = result.get("count", len(devices)) if isinstance(result, dict) else len(devices)
        return {"status": "SUCCESS", "devices": devices, "total": total}

    # --- NAC Status Summary ---

    def get_nac_status(self) -> Dict[str, Any]:
        """Aggregate NAC health: active session count + device counts by status.

        ``active_sessions`` counts only sessions that have not closed out (no
        ``acctstoptime``); without this filter ClearPass returns every session
        ever recorded and the count grows monotonically."""
        active_filter = json.dumps({"acctstoptime": {"$exists": False}}, separators=(",", ":"))
        # Four independent count queries, run SERIALLY. They share one
        # requests.Session whose token refresh (client._get_token) mutates
        # client state (_token / _token_expiry / session.auth); fanning them
        # across a thread pool raced that refresh — two threads could hit an
        # expired token at once and stampede /api/oauth, or read _token
        # mid-write. These are cheap limit=1 count GETs, so sequential latency
        # is negligible and correctness wins.
        sessions_result = self.client.query("/api/session",
            params={"calculate_count": "true", "limit": 1, "filter": active_filter})
        devices_result = self.client.query("/api/endpoint",
            params={"calculate_count": "true", "limit": 1})
        known_result = self.client.query("/api/endpoint",
            params={"calculate_count": "true", "limit": 1, "filter": '{"status":"Known"}'})
        unknown_result = self.client.query("/api/endpoint",
            params={"calculate_count": "true", "limit": 1, "filter": '{"status":"Unknown"}'})
        return {
            "status": "SUCCESS",
            "active_sessions": sessions_result.get("count", 0) if isinstance(sessions_result, dict) else 0,
            "total_devices": devices_result.get("count", 0) if isinstance(devices_result, dict) else 0,
            "known_devices": known_result.get("count", 0) if isinstance(known_result, dict) else 0,
            "unknown_devices": unknown_result.get("count", 0) if isinstance(unknown_result, dict) else 0,
        }

    # --- Existing queries ---

    def get_device_by_mac(self, mac: str) -> Optional[Dict[str, Any]]:
        result = self.client.query("/api/endpoint", params={"filter": json.dumps({"mac_address": mac}, separators=(",", ":"))})
        items = self._items(result)
        return items[0] if items else None

    def get_endpoint_detail(self, mac: str) -> Dict[str, Any]:
        """Full endpoint record from ClearPass including all attributes."""
        result = self.client.query("/api/endpoint", params={"filter": json.dumps({"mac_address": mac}, separators=(",", ":"))})
        if isinstance(result, dict) and result.get("status") == "ERROR":
            return result
        items = self._items(result)
        if not items:
            return {"status": "ERROR", "message": "Endpoint not found"}
        ep = items[0]
        attrs = ep.get("attributes", {}) or {}
        return {
            "status": "SUCCESS",
            "id": ep.get("id", ""),
            "mac": ep.get("mac_address", ""),
            "status_val": ep.get("status", ""),
            "description": ep.get("description", ""),
            "hostname": attrs.get("Hostname", attrs.get("hostname", "")),
            "ip": attrs.get("IP Address", attrs.get("ip_address", attrs.get("ip", ""))),
            "device_vendor": attrs.get("Device Vendor", attrs.get("device_vendor", "")),
            "device_os": attrs.get("Device OS", attrs.get("device_os", "")),
            "device_type": attrs.get("Device Type", attrs.get("device_type", "")),
            "attributes": {k: v for k, v in attrs.items() if v},
        }

    # --- NetBox → ClearPass endpoint sync (CPPM_SYNC_ENDPOINTS) ---
    # The hub owns the schedule and the batch; this spoke writes it into
    # ClearPass Device Inventory. See lm/docs/modules/cppm.md §4 for the
    # contract. The IPAM source is the source of truth: with replace=True the
    # spoke upserts the batch AND removes endpoints previously tagged with this
    # tenant that are absent from the batch. Best-effort — per-endpoint failures
    # are counted, never raised.

    @staticmethod
    def _norm_mac(mac: str) -> str:
        """Normalize a MAC to ClearPass's lowercase colon form (aa:bb:cc:dd:ee:ff)."""
        m = (mac or "").strip().lower()
        hexonly = re.sub(r"[^0-9a-f]", "", m)
        if len(hexonly) == 12:
            return ":".join(hexonly[i:i + 2] for i in range(0, 12, 2))
        return m

    @staticmethod
    def _coerce_attrs(attrs: Any) -> Dict[str, str]:
        """Coerce endpoint attribute values to strings, dropping nulls.

        ClearPass requires every endpoint attribute value to be a string; a
        non-string (number/bool/list) or null in a PUT/POST body makes the
        whole request fail with 422. The PUT-merge round-trips an existing
        endpoint's *entire* attribute map (including profiler-populated values
        that may not be strings), so coerce before sending so a profiler
        attribute can't break the merge.
        """
        if not isinstance(attrs, dict):
            return {}
        out: Dict[str, str] = {}
        for k, v in attrs.items():
            if v is None:
                continue
            out[k] = v if isinstance(v, str) else str(v)
        return out

    def _get_endpoint_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        result = self.client.query("/api/endpoint", params={"filter": json.dumps({"ip_address": ip}, separators=(",", ":"))})
        items = self._items(result)
        return items[0] if items else None

    @staticmethod
    def _endpoint_ips(ep: Dict[str, Any]) -> set:
        """Every IP address carried by a CPPM endpoint — the first-class
        ``ip_address`` field plus the value of ANY attribute. ClearPass stores
        the endpoint IP under varying attribute names depending on the profiler
        / sync path, so rather than guess names we scan every attribute value.
        Values are stripped of a trailing CIDR suffix so a ``/32`` form still
        matches a bare wanted IP. Non-IP attribute values are collected too
        (harmless: only values equal to a wanted IP ever match downstream in
        _build_ip_endpoint_map, and a junk string can't equal a real IP)."""
        ips: set = set()
        if not isinstance(ep, dict):
            return ips
        top = ep.get("ip_address")
        if isinstance(top, str) and top.strip():
            ips.add(top.strip().split("/")[0].strip())
        attrs = ep.get("attributes") or {}
        if isinstance(attrs, dict):
            for v in attrs.values():
                if isinstance(v, str) and v.strip():
                    ips.add(v.strip().split("/")[0].strip())
        return ips

    def _build_ip_endpoint_map(self, target_ips: set) -> Dict[str, Dict[str, Any]]:
        """Bounded paged scan of the endpoint inventory building IP → endpoint
        for the requested IPs. Used when a NetBox IP record has no MAC: the
        ClearPass ``ip_address`` filter (``_get_endpoint_by_ip``) only matches
        the first-class field, so an endpoint whose IP lives in an attribute
        (``IP Address`` etc.) is missed. This scan finds it so its MAC can be
        reused and the endpoint tagged for the tenant.

        Stops early once every requested IP is resolved or ``SYNC_SCAN_CAP`` is
        hit. Best-effort: a CPPM paging failure returns whatever resolved so far
        (the sync then skips the unresolved IPs as before). Logs scanned-vs-total
        so a cap hit (or a small inventory where the IP genuinely isn't present)
        is distinguishable from a real miss."""
        resolved: Dict[str, Dict[str, Any]] = {}
        wanted = {str(ip).strip() for ip in target_ips if str(ip).strip()}
        if not wanted:
            return resolved
        cap = self.SYNC_SCAN_CAP
        limit = 1000
        offset = 0
        scanned = 0
        total = 0
        while scanned < cap:
            ep_r = self.client.query("/api/endpoint", params={
                "limit": limit, "offset": offset, "calculate_count": "true"})
            if isinstance(ep_r, dict) and ep_r.get("status") == "ERROR":
                logger.warning("endpoint IP-map scan failed: %s", ep_r.get("message"))
                break
            items = self._items(ep_r)
            if not items:
                break
            for ep in items:
                for ip in self._endpoint_ips(ep):
                    if ip in wanted and ip not in resolved:
                        resolved[ip] = ep
            scanned += len(items)
            total = ep_r.get("count", total) if isinstance(ep_r, dict) else total
            offset += limit
            if len(items) < limit or offset >= total:
                break
            if all(ip in resolved for ip in wanted):
                break
        logger.info("endpoint IP-map scan: scanned %d of %d endpoints (cap %d, %s); "
                    "resolved %d of %d wanted IPs",
                    scanned, total, cap,
                    "CAPPED — raise SYNC_SCAN_CAP" if scanned >= cap else "complete",
                    len(resolved), len(wanted))
        return resolved

    def _build_mac_endpoint_map(self, target_macs: set) -> Dict[str, Dict[str, Any]]:
        """Bounded paged scan of the endpoint inventory building normalized
        MAC → endpoint for the requested MACs. Replaces the per-record
        ``get_device_by_mac`` GET that ``_upsert_endpoint`` used to issue for
        every MAC-bearing record (185 records ⇒ 185 extra round-trips ⇒ the
        hub's 180s "Timed out waiting for spoke response"). One bounded scan
        with early-stop once every wanted MAC is resolved (or ``SYNC_SCAN_CAP``
        is hit) cuts the per-batch ClearPass calls roughly in half.

        Best-effort: a CPPM paging failure, or a cap hit before all MACs are
        found, returns whatever resolved so far — ``_upsert_endpoint`` falls
        back to ``get_device_by_mac`` for any MAC still absent from the map, so
        correctness is preserved (just slower for the unresolved few). Logs
        scanned-vs-total so a cap hit is distinguishable from a real miss."""
        resolved: Dict[str, Dict[str, Any]] = {}
        wanted = {self._norm_mac(m) for m in target_macs if self._norm_mac(m)}
        if not wanted:
            return resolved
        cap = self.SYNC_SCAN_CAP
        limit = 1000
        offset = 0
        scanned = 0
        total = 0
        while scanned < cap:
            ep_r = self.client.query("/api/endpoint", params={
                "limit": limit, "offset": offset, "calculate_count": "true"})
            if isinstance(ep_r, dict) and ep_r.get("status") == "ERROR":
                logger.warning("endpoint MAC-map scan failed: %s", ep_r.get("message"))
                break
            items = self._items(ep_r)
            if not items:
                break
            for ep in items:
                m = self._norm_mac(ep.get("mac_address", ""))
                if m and m in wanted and m not in resolved:
                    resolved[m] = ep
            scanned += len(items)
            total = ep_r.get("count", total) if isinstance(ep_r, dict) else total
            offset += limit
            if len(items) < limit or offset >= total:
                break
            if all(m in resolved for m in wanted):
                break
        logger.info("endpoint MAC-map scan: scanned %d of %d endpoints (cap %d, %s); "
                    "resolved %d of %d wanted MACs",
                    scanned, total, cap,
                    "CAPPED — raise SYNC_SCAN_CAP" if scanned >= cap else "complete",
                    len(resolved), len(wanted))
        return resolved

    def _build_session_ip_mac_map(self, target_ips: set) -> Dict[str, str]:
        """Bounded paged scan of ClearPass sessions building IP → MAC for the
        requested IPs. Used when a NetBox IP record has no MAC AND no existing
        ClearPass endpoint carries its IP: a session (Access Tracker) whose
        ``framedipaddress`` matches the IP still exposes the device's MAC
        (``callingstationid``), so the sync can create a tenant-tagged endpoint
        for it instead of skipping.

        Returns IP → normalized MAC. Best-effort: a paging failure returns
        whatever resolved so far. Stops early once every requested IP is resolved
        or ``SYNC_SCAN_CAP`` is hit. Logs scanned-vs-total so a cap hit (or a
        small session set where the IP genuinely isn't present) is visible."""
        resolved: Dict[str, str] = {}
        wanted = {str(ip).strip() for ip in target_ips if str(ip).strip()}
        if not wanted:
            return resolved
        cap = self.SYNC_SCAN_CAP
        limit = 1000
        offset = 0
        scanned = 0
        total = 0
        while scanned < cap:
            s_r = self.client.query("/api/session", params={
                "limit": limit, "offset": offset, "calculate_count": "true"})
            if isinstance(s_r, dict) and s_r.get("status") == "ERROR":
                logger.warning("session IP→MAC scan failed: %s", s_r.get("message"))
                break
            items = self._items(s_r)
            if not items:
                break
            for s in items:
                ip = (s.get("framedipaddress") or "").strip()
                if not ip or ip not in wanted or ip in resolved:
                    continue
                # ``callingstationid`` is the confirmed /api/session field for
                # the caller (endpoint) MAC; some ClearPass versions / the older
                # access-tracker code use ``callingstation`` / a ``mac`` key, so
                # accept all three.
                mac_raw = s.get("callingstationid") or s.get("callingstation") or s.get("mac") or ""
                mac = self._norm_mac(mac_raw)
                if mac:
                    resolved[ip] = mac
            scanned += len(items)
            total = s_r.get("count", total) if isinstance(s_r, dict) else total
            offset += limit
            if len(items) < limit or offset >= total:
                break
            if all(ip in resolved for ip in wanted):
                break
        logger.info("session IP→MAC scan: scanned %d of %d sessions (cap %d, %s); "
                    "resolved %d of %d wanted IPs",
                    scanned, total, cap,
                    "CAPPED — raise SYNC_SCAN_CAP" if scanned >= cap else "complete",
                    len(resolved), len(wanted))
        return resolved

    def _upsert_endpoint(self, mac: str, ip: str, rec: Dict[str, Any],
                         tenant_id: str, tenant_slug: str, tenant_name: str,
                         source: str,
                         ip_map: Optional[Dict[str, Dict[str, Any]]] = None,
                         mac_map: Optional[Dict[str, Dict[str, Any]]] = None) -> str:
        """Upsert one endpoint. Returns 'pushed' | 'skipped' | 'error'.

        Keyed on MAC (authoritative); falls back to IP lookup when MAC is empty.
        Existing endpoints are PUT-merged (so profiler-derived attributes are
        preserved); new ones are POSTed. IP-only records with no existing
        endpoint can't be created (ClearPass endpoints are MAC-keyed) → skipped.

        ``mac_map`` (built once per batch by ``sync_endpoints``) is the primary
        MAC → existing-endpoint lookup so a batch doesn't issue a per-record
        ``get_device_by_mac`` GET; a MAC absent from the map (cap hit / scan
        failure) falls back to the per-record GET.

        ``ip_map`` is the analogous fallback for the IP lookup: the ClearPass
        ``ip_address`` filter only matches the first-class field, so an endpoint
        whose IP lives in an attribute (``IP Address`` etc.) is found here
        instead — letting the sync tag an existing endpoint whose MAC the
        NetBox IP record lacks.
        """
        hostname = (rec.get("hostname", "") or "").strip()
        tag_attrs = {
            self.TENANT_ATTR_SLUG: tenant_slug,
            self.TENANT_ATTR_NAME: tenant_name,
            self.TENANT_ATTR_ID: tenant_id,
            self.TENANT_ATTR_TENANT: tenant_name,
            self.TENANT_ATTR_TENANT_SLUG: tenant_slug,
        }
        if ip:
            tag_attrs["IP Address"] = ip
        if hostname:
            tag_attrs["Hostname"] = hostname
        description = f"Synced from {source} (tenant {tenant_slug})"

        existing = None
        if mac:
            # Prefer the batch-built MAC map (one scan for the whole batch);
            # fall back to a per-record GET only for MACs the map didn't
            # resolve (cap hit / scan failure).
            nmac = self._norm_mac(mac)
            existing = (mac_map or {}).get(nmac) if mac_map is not None else None
            if not existing:
                existing = self.get_device_by_mac(mac)
        elif ip:
            # Cheap exact-field filter first, then the batch IP→endpoint map
            # (attribute-based: ``IP Address`` etc.) so an existing endpoint
            # whose MAC the source record lacks is still found and tagged.
            existing = self._get_endpoint_by_ip(ip)
            if not existing and ip_map:
                existing = ip_map.get(ip)

        if existing:
            ep_id = existing.get("id")
            if not ep_id:
                return "error"
            cur_attrs = dict(existing.get("attributes") or {})
            cur_attrs.update(tag_attrs)
            cur_attrs = self._coerce_attrs(cur_attrs)
            body: Dict[str, Any] = {"id": ep_id, "attributes": cur_attrs, "description": description}
            # ClearPass requires `status` on PUT too (POST sets "Known" below);
            # omitting it 422s with "Endpoint status (Known / Unknown / Disabled)
            # must be specified". Preserve an existing status so a Disabled /
            # Unknown endpoint isn't silently flipped back to Known.
            body["status"] = existing.get("status") or "Known"
            # ClearPass also requires `name` on PUT — omitting it 422s with
            # validation_messages:["name"]. But a non-empty value alone isn't
            # enough: ClearPass also 422s on `name` when the preserved value is
            # whitespace-only OR exceeds its server-side length ceiling (the
            # response body just says ["name"] either way). Strip, fall through
            # to mac → ip → a synthetic label when blank, and cap at 255 so a
            # long profiler-derived name doesn't re-fail on PUT.
            name_val = (str(existing.get("name") or "").strip()
                        or str(mac or "").strip()
                        or str(ip or "").strip()
                        or f"endpoint-{ep_id}")
            body["name"] = name_val[:255].strip() or f"endpoint-{ep_id}"
            if mac:
                body["mac_address"] = mac
            res = self.client._request("PUT", f"/api/endpoint/{ep_id}", json=body)
            if isinstance(res, dict) and res.get("status") == "ERROR":
                # Include the name value + length we sent so a residual 422
                # (e.g. a format/char constraint, or a different max-length)
                # is diagnosable from the log instead of just "['name']".
                _nv = body.get("name", "")
                logger.warning("endpoint PUT %s failed: %s (sent name=%r len=%d mac=%r status=%r)",
                               ep_id, res.get("message"),
                               _nv[:80], len(str(_nv)), mac or "",
                               body.get("status", ""))
                return "error"
            return "pushed"

        if not mac:
            # No MAC and no existing endpoint to tag — nothing to attach to.
            logger.info(
                "endpoint sync SKIP: tenant=%s ip=%s hostname=%s mac=<empty> "
                "— NetBox IP record has no mac_address custom field and no "
                "existing ClearPass endpoint matched by ip_address; ClearPass "
                "endpoints are MAC-keyed so an IP-only record cannot be created. "
                "(If the device is already in ClearPass, ensure the NetBox IP "
                "carries its MAC so the sync can merge by MAC.)",
                tenant_slug, ip or "<empty>", hostname or "<empty>")
            return "skipped"

        body = {"mac_address": mac, "name": mac, "description": description,
                "attributes": self._coerce_attrs(tag_attrs), "status": "Known"}
        res = self.client._request("POST", "/api/endpoint", json=body)
        if isinstance(res, dict) and res.get("status") == "ERROR":
            logger.warning("endpoint POST %s failed: %s", mac, res.get("message"))
            return "error"
        return "pushed"

    def _remove_absent_tagged(self, tenant_slug: str, batch_keys: set) -> int:
        """Delete endpoints tagged with this tenant whose key is not in the batch.

        Pages through /api/endpoint and filters client-side by the tenant
        attribute (ClearPass's filter support for arbitrary attributes is
        inconsistent across versions, so a client-side scan is the reliable
        path). Returns the number deleted.

        SAFETY: this DELETEs every tenant-tagged endpoint whose key is absent
        from ``batch_keys``. An empty/truncated/failed batch would therefore
        wipe the tenant's entire ClearPass inventory. Two guards prevent that:
          1. An empty ``batch_keys`` aborts outright (nothing to reconcile
             against — every tagged endpoint would look "absent").
          2. A two-pass scan tallies the total tagged set first; if the
             removal set would exceed 50% of it, the scan aborts without
             deleting. Both raise ``ReplaceScanAborted`` so the sync surfaces
             an ERROR rather than silently mass-deleting.
        """
        # Guard 1: an empty batch means the upstream produced no endpoints
        # (empty/truncated/failed). Reconciling against nothing would delete
        # the whole tagged inventory — refuse.
        if not batch_keys:
            raise ReplaceScanAborted(
                f"empty batch for tenant '{tenant_slug}' — refusing to remove "
                "any tagged endpoints (would delete the entire tenant inventory)")

        # Pass 1: enumerate this tenant's tagged endpoints and which are absent
        # from the batch, tallying the total so a runaway removal can be caught
        # BEFORE any DELETE is issued.
        tagged_total = 0
        to_delete: List[str] = []  # endpoint ids
        limit = 1000
        offset = 0
        while True:
            res = self.client.query("/api/endpoint", params={
                "limit": limit, "offset": offset, "calculate_count": "true"})
            if isinstance(res, dict) and res.get("status") == "ERROR":
                logger.warning("replace-scan list failed: %s", res.get("message"))
                break
            items = self._items(res)
            if not items:
                break
            for ep in items:
                attrs = ep.get("attributes") or {}
                if attrs.get(self.TENANT_ATTR_SLUG) != tenant_slug:
                    continue
                tagged_total += 1
                mac = self._norm_mac(ep.get("mac_address", ""))
                ip_val = attrs.get("IP Address") or attrs.get("ip_address") or ep.get("ip_address") or ""
                ip = ip_val.strip() if isinstance(ip_val, str) else ""
                key = mac or f"ip:{ip}"
                if key in batch_keys:
                    continue
                ep_id = ep.get("id")
                if not ep_id:
                    continue
                to_delete.append(ep_id)
            count = res.get("count", 0) if isinstance(res, dict) else 0
            offset += limit
            if len(items) < limit or offset >= count:
                break

        # Guard 2: refuse a removal that would take out more than half of the
        # tenant's currently-tagged endpoints — the signature of a truncated or
        # partially-failed batch. Surface it loudly instead of deleting.
        if tagged_total and len(to_delete) > tagged_total * 0.5:
            raise ReplaceScanAborted(
                f"replace-scan for tenant '{tenant_slug}' would remove "
                f"{len(to_delete)} of {tagged_total} tagged endpoints (>50%) — "
                "likely a truncated/failed batch; refusing to mass-delete")

        removed = 0
        for ep_id in to_delete:
            d = self.client._request("DELETE", f"/api/endpoint/{ep_id}")
            if isinstance(d, dict) and d.get("status") != "ERROR":
                removed += 1
            else:
                logger.warning("endpoint DELETE %s failed: %s", ep_id,
                               d.get("message") if isinstance(d, dict) else d)
        return removed

    def sync_endpoints(self, tenant_id: str, tenant_slug: str, tenant_name: str,
                       source: str, endpoints: List[Dict[str, Any]],
                       replace: bool = True) -> Dict[str, Any]:
        """Sync a tenant's endpoint batch into ClearPass Device Inventory.

        Upserts each endpoint (keyed on MAC, falling back to IP) tagged with the
        tenant attributes so an Enforcement Policy can match the tenant the same
        way the at-auth-time Context Server Action does. When replace=True, the
        IPAM source is treated as the source of truth: endpoints previously
        tagged with this tenant that are absent from the batch are deleted.

        IP-only records (no MAC on the NetBox side) are resolved two ways before
        the upsert: (1) an existing ClearPass endpoint found by IP — its MAC is
        reused and the endpoint PUT-tagged; (2) if none, a MAC borrowed from a
        live ClearPass session whose framedipaddress matches — a new endpoint is
        created tagged for the tenant. Records left with no MAC after both are
        skipped (ClearPass endpoints are MAC-keyed).

        Returns {status, pushed, errors, skipped, removed, message}. The hub
        reads status/pushed/errors/message; skipped/removed are extra detail.
        """
        tenant_slug = (tenant_slug or "").strip()
        if not tenant_slug:
            return {"status": "ERROR", "message": "Missing tenant_slug",
                    "pushed": 0, "errors": 0, "skipped": 0, "removed": 0}
        source = source or "IPAM"

        batch: List[tuple] = []  # (key, mac, ip, rec)
        batch_keys: set = set()
        for rec in endpoints or []:
            if not isinstance(rec, dict):
                continue
            mac = self._norm_mac(rec.get("mac", ""))
            ip = (rec.get("ip", "") or "").strip()
            if not mac and not ip:
                continue
            key = mac or f"ip:{ip}"
            batch_keys.add(key)
            batch.append((key, mac, ip, rec))

        # MAC-bearing records: build a MAC → existing-endpoint map ONCE so
        # _upsert_endpoint doesn't issue a per-record get_device_by_mac GET
        # (185 records ⇒ 185 extra round-trips ⇒ the hub's 180s timeout). One
        # bounded scan replaces them; unresolved MACs fall back to the per-
        # record GET inside _upsert_endpoint.
        mac_map: Optional[Dict[str, Dict[str, Any]]] = None
        batch_macs = {mac for _, mac, ip, _ in batch if mac}
        if batch_macs:
            try:
                mac_map = self._build_mac_endpoint_map(batch_macs)
            except Exception as e:
                logger.warning("endpoint sync tenant=%s MAC-map build failed: %s "
                               "(falling back to per-record get_device_by_mac)",
                               tenant_slug, e)
                mac_map = None

        # IP-only records (no MAC on the NetBox side) need an existing
        # ClearPass endpoint found by IP so they can be tagged. The cheap
        # ``ip_address`` filter runs per-record inside _upsert_endpoint; this
        # batch-level map is the attribute-based fallback (``IP Address`` etc.)
        # built once so we don't re-scan the inventory per record.
        ip_map: Optional[Dict[str, Dict[str, Any]]] = None
        ip_only = {ip for _, mac, ip, _ in batch if not mac and ip}
        if ip_only:
            try:
                ip_map = self._build_ip_endpoint_map(ip_only)
                resolved_n = len({ip for ip in ip_only if ip in ip_map})
                if ip_only and resolved_n == 0:
                    logger.warning("endpoint sync tenant=%s: IP→endpoint map resolved "
                                   "0 of %d IP-only records — ClearPass has no endpoint "
                                   "carrying any of these IPs, so they will be skipped "
                                   "(no MAC to attach). If the devices are expected in "
                                   "ClearPass, verify the endpoint inventory. IPs: %s",
                                   tenant_slug, len(ip_only),
                                   ", ".join(sorted(ip_only)[:10]))
                else:
                    logger.info("endpoint sync tenant=%s IP→endpoint map: %d of %d "
                                "IP-only records resolved from ClearPass",
                                tenant_slug, resolved_n, len(ip_only))
            except Exception as e:
                logger.warning("endpoint sync tenant=%s IP-map build failed: %s "
                               "(falling back to exact ip_address filter only)",
                               tenant_slug, e)
                ip_map = None

        # Fallback MAC source for IP-only records the endpoint inventory did NOT
        # resolve: a live ClearPass session (Access Tracker) whose
        # ``framedipaddress`` matches. CPPM has the device's MAC in the session
        # even when no endpoint record carries the IP, so borrowing it lets the
        # sync create a tenant-tagged endpoint instead of skipping. Best-effort;
        # typical 802.1X+DHCP sessions don't carry framedipaddress, so this often
        # resolves 0 — logged so it's distinguishable from a silent skip.
        unresolved = ip_only - set(ip_map or {})
        if unresolved:
            try:
                session_mac_map = self._build_session_ip_mac_map(unresolved)
                sm_n = len(session_mac_map)
                if sm_n:
                    logger.info("endpoint sync tenant=%s session IP→MAC map: %d of %d "
                                "unresolved IP-only records borrowed a MAC from "
                                "ClearPass sessions", tenant_slug, sm_n, len(unresolved))
                else:
                    logger.info("endpoint sync tenant=%s session IP→MAC map: 0 of %d "
                                "unresolved IP-only records had a session with "
                                "framedipaddress — no MAC to borrow. IPs: %s",
                                tenant_slug, len(unresolved),
                                ", ".join(sorted(unresolved)[:10]))
                # Apply borrowed MACs to the batch in place so each record becomes
                # MAC-bearing for the upsert AND batch_keys carries the borrowed
                # MAC (the new endpoint's key) — otherwise the replace-scan would
                # delete the endpoint we just created in the same pass.
                for i, (key, mac, ip, rec) in enumerate(batch):
                    if not mac and ip and ip in session_mac_map:
                        borrowed = session_mac_map[ip]
                        batch[i] = (borrowed, borrowed, ip, rec)
                        batch_keys.discard(key)   # drop the old ip:{ip} key
                        batch_keys.add(borrowed)   # new key = borrowed MAC
            except Exception as e:
                logger.warning("endpoint sync tenant=%s session MAC-map build failed: "
                               "%s (skipping session fallback)", tenant_slug, e)

        pushed = errors = skipped = 0
        err_msgs: List[str] = []
        skipped_details: List[Dict[str, Any]] = []
        for key, mac, ip, rec in batch:
            try:
                outcome = self._upsert_endpoint(mac, ip, rec, tenant_id, tenant_slug,
                                                 tenant_name, source,
                                                 ip_map=ip_map, mac_map=mac_map)
                if outcome == "pushed":
                    pushed += 1
                elif outcome == "skipped":
                    skipped += 1
                    # _upsert_endpoint already logged the per-record reason; capture
                    # a concise detail so the hub can surface it in sync status.
                    reason = ("no MAC on source record and no existing ClearPass "
                              "endpoint matched by IP") if not mac else "skipped"
                    skipped_details.append({
                        "ip": ip or "", "mac": mac or "",
                        "hostname": (rec.get("hostname", "") or "").strip(),
                        "reason": reason,
                    })
                else:
                    errors += 1
            except Exception as e:
                errors += 1
                err_msgs.append(f"{key}: {e}")

        removed = 0
        if replace:
            try:
                removed = self._remove_absent_tagged(tenant_slug, batch_keys)
            except ReplaceScanAborted as e:
                # Deliberate safety abort (empty/runaway batch) — count it as an
                # error so the sync reports ERROR rather than a silent success
                # that skipped stale-removal. Nothing was deleted.
                errors += 1
                err_msgs.append(f"replace-scan aborted: {e}")
                logger.error("endpoint sync tenant=%s replace-scan aborted: %s",
                             tenant_slug, e)
            except Exception as e:
                err_msgs.append(f"replace-scan: {e}")

        if skipped_details:
            logger.info(
                "endpoint sync tenant=%s skipped %d record(s): %s",
                tenant_slug, skipped,
                "; ".join(f"ip={s['ip'] or '<empty>'} mac={s['mac'] or '<empty>'} "
                          f"hostname={s['hostname'] or '<empty>'}" for s in skipped_details))

        status = "SUCCESS" if errors == 0 else "ERROR"
        msg = f"synced {pushed} from {source}"
        if skipped:
            msg += f", skipped {skipped}"
            # Name the first couple of skipped IPs so the status card shows a hint
            # without bloating the message for large batches.
            names = [s["ip"] or s["hostname"] or "(no ip)" for s in skipped_details[:3]]
            if names:
                msg += " (" + ", ".join(names) + ")"
        if replace:
            msg += f", removed {removed} stale"
        if err_msgs:
            msg += " | errors: " + "; ".join(err_msgs[:8])
        return {"status": status, "pushed": pushed, "errors": errors,
                "skipped": skipped, "removed": removed, "message": msg,
                "skipped_details": skipped_details}

    def get_device_sessions(self, mac: str, limit: int = 20) -> Dict[str, Any]:
        """Accounting sessions for a specific device by calling station (MAC).

        ClearPass ``/api/session`` rejects ``callingstation`` as a filter key
        (HTTP 422 "cannot filter using 'callingstation'") — the filterable field
        is ``callingstationid``. Try that first (fast, server-filtered); if the
        deployed ClearPass still rejects it (or returns an error), fall back to
        a bounded unfiltered paged scan + client-side separator-insensitive MAC
        match — the same pattern the global-search substring scan uses — so the
        lookup always works and never emits a 422 error storm. On-demand only
        (device-detail), so the bounded scan cost is acceptable."""
        norm = self._norm_mac(mac)
        mac_hex = re.sub(r"[^0-9a-f]", "", norm.lower()) if norm else ""

        def _query_filtered(filter_key: str, value: str):
            return self.client.query(
                "/api/session",
                params={
                    "filter": json.dumps({filter_key: value}, separators=(",", ":")),
                    "limit": limit,
                    "calculate_count": "true",
                },
            )

        result = _query_filtered("callingstationid", norm) if norm else None
        used_fallback = False
        if isinstance(result, dict) and result.get("status") == "ERROR":
            # Server filter rejected (e.g. field not filterable on this ClearPass
            # build) → bounded client-side scan so we still return matches.
            used_fallback = True
            items: List[Dict[str, Any]] = []
            offset = 0
            page = 500
            while len(items) < limit:
                r = self.client.query("/api/session", params={
                    "limit": page, "offset": offset, "calculate_count": "true"})
                if isinstance(r, dict) and r.get("status") == "ERROR":
                    break
                page_items = self._items(r)
                if not page_items:
                    break
                for s in page_items:
                    s_hex = re.sub(r"[^0-9a-f]", "",
                                   (s.get("callingstationid")
                                    or s.get("callingstation") or "").lower())
                    if mac_hex and s_hex == mac_hex:
                        items.append(s)
                        if len(items) >= limit:
                            break
                if len(page_items) < page:
                    break
                offset += page
        else:
            items = self._items(result)
        def _iso(dt):
            if not dt: return ""
            return str(dt).strip().replace(" ", "T") if " " in str(dt) else str(dt)

        sessions = []
        for s in items:
            roles_raw = s.get("roles") or s.get("role") or ""
            role = roles_raw[0] if isinstance(roles_raw, list) and roles_raw else (roles_raw if isinstance(roles_raw, str) else "")
            svc = s.get("service") or s.get("servicename") or s.get("service_name") or ""
            sessions.append({
                "id":        s.get("id", ""),
                "username":  s.get("username", ""),
                "ip":        s.get("framedipaddress", ""),
                "nas_name":  _nas_name(s),
                "nas_port":  _nas_port(s),
                "nas_port_type": _nas_port_type(s),
                "role":      role,
                "service":   svc,
                "start_time": _iso(s.get("acctstarttime", "")),
                "state":     s.get("state", ""),
            })
        total = (result.get("count", len(sessions))
                 if isinstance(result, dict) and not used_fallback else len(sessions))
        return {"status": "SUCCESS", "sessions": sessions, "total": total}

    def get_user_sessions(self, username: str) -> List[Dict[str, Any]]:
        result = self.client.query("/api/session", params={"filter": json.dumps({"username": username}, separators=(",", ":"))})
        return self._items(result)

    def get_auth_logs(self, start_time: str, end_time: str) -> List[Dict[str, Any]]:
        result = self.client.query(
            "/api/session",
            params={"filter": json.dumps({"acctstarttime": {"$gte": start_time, "$lte": end_time}}, separators=(",", ":"))},
        )
        return self._items(result)

    def _endpoint_search_result(self, ep: Dict[str, Any]) -> Dict[str, Any]:
        """Normalise a ClearPass endpoint into a global-search result."""
        attrs = ep.get("attributes") or {}
        # Prefer the Hostname attribute (populated by sync / profiler) for the
        # display name; fall back to MAC so the row is never blank.
        name = attrs.get("Hostname") or ep.get("mac_address", "")
        return {
            "source":  "cppm",
            "type":    "endpoint",
            "name":    name,
            "ip":      ep.get("ip_address", ""),
            "mac":     ep.get("mac_address", ""),
            "status":  ep.get("status", ""),
            "vendor":  ep.get("vendor_name", ""),
            "id":      ep.get("id", ""),
        }

    @staticmethod
    def _endpoint_matches(ep: Dict[str, Any], q: str) -> bool:
        """True if `q` is a case-insensitive substring of any endpoint text
        field — MAC, IP, status, vendor, or any attribute value (Hostname,
        Tenant, etc.). Any part of any string matches. MACs are also compared
        separator-stripped so a partial MAC typed without colons/dashes
        ("445566") matches "11:22:33:44:55:66"."""
        if not q:
            return False
        haystacks = [
            ep.get("mac_address", ""),
            ep.get("ip_address", ""),
            ep.get("status", ""),
            ep.get("vendor_name", ""),
        ]
        attrs = ep.get("attributes") or {}
        if isinstance(attrs, dict):
            for v in attrs.values():
                if isinstance(v, str):
                    haystacks.append(v)
        if any(q in str(h).lower() for h in haystacks):
            return True
        # Separator-insensitive MAC match: strip everything but hex from both
        # the query and the MAC, then substring-test.
        q_hex = re.sub(r"[^0-9a-f]", "", q)
        if q_hex:
            mac_hex = re.sub(r"[^0-9a-f]", "", (ep.get("mac_address") or "").lower())
            if q_hex in mac_hex:
                return True
        return False

    def search(self, query: str) -> Dict[str, Any]:
        """
        Search CPPM endpoints (Device Inventory) and active sessions by
        substring across MAC / IP / hostname / vendor / username / NAS.

        ClearPass's REST `filter` only supports exact-equality (no SQL-LIKE),
        so partial matching is done client-side: exact MAC/IP filters run first
        (precise + cheap), then a bounded paged scan of the endpoint inventory
        and the active-session list matches `q` as a case-insensitive substring
        of any text field. Returns normalised results tagged source="cppm".
        """
        q = query.strip().lower()
        if not q:
            return {"status": "SUCCESS", "results": [], "count": 0}
        results = []
        seen_ids: set = set()
        try:
            # --- Exact endpoint lookup (MAC / IP) — precise & cheap ----------
            for filter_def in [{"mac_address": q}, {"ip_address": q}]:
                ep_r = self.client.query("/api/endpoint", params={"filter": json.dumps(filter_def, separators=(",", ":")), "limit": 10})
                for ep in self._items(ep_r):
                    if ep.get("id") and ep["id"] not in seen_ids:
                        seen_ids.add(ep["id"])
                        results.append(self._endpoint_search_result(ep))

            # --- Endpoint substring scan (bounded) --------------------------
            limit = 1000
            offset = 0
            scanned = 0
            while scanned < self.SEARCH_SCAN_CAP:
                ep_r = self.client.query("/api/endpoint", params={
                    "limit": limit, "offset": offset, "calculate_count": "true"})
                if isinstance(ep_r, dict) and ep_r.get("status") == "ERROR":
                    logger.warning("endpoint substring scan failed: %s", ep_r.get("message"))
                    break
                items = self._items(ep_r)
                if not items:
                    break
                for ep in items:
                    if not self._endpoint_matches(ep, q):
                        continue
                    if ep.get("id") and ep["id"] in seen_ids:
                        continue
                    if ep.get("id"):
                        seen_ids.add(ep["id"])
                    results.append(self._endpoint_search_result(ep))
                scanned += len(items)
                count = ep_r.get("count", 0) if isinstance(ep_r, dict) else 0
                offset += limit
                if len(items) < limit or offset >= count:
                    break

            # --- Active sessions (bounded) — substring by IP/MAC/user/NAS ---
            limit = 1000
            offset = 0
            while True:
                session_r = self.client.query("/api/session", params={
                    "limit": limit, "offset": offset, "calculate_count": "true"})
                if isinstance(session_r, dict) and session_r.get("status") == "ERROR":
                    logger.warning("session substring scan failed: %s", session_r.get("message"))
                    break
                items = self._items(session_r)
                if not items:
                    break
                for s in items:
                    fields = [
                        s.get("username", ""),
                        s.get("framedipaddress", ""),
                        s.get("callingstation", ""),
                        _nas_name(s),
                    ]
                    roles = s.get("roles")
                    if isinstance(roles, list):
                        fields.extend(str(r) for r in roles)
                    matched = any(q in str(f).lower() for f in fields)
                    if not matched:
                        # Separator-insensitive MAC match for callingstation.
                        q_hex = re.sub(r"[^0-9a-f]", "", q)
                        if q_hex:
                            mac_hex = re.sub(r"[^0-9a-f]", "", (s.get("callingstation") or "").lower())
                            matched = q_hex in mac_hex
                    if not matched:
                        continue
                    results.append({
                        "source":   "cppm",
                        "type":     "session",
                        "name":     s.get("username", ""),
                        "ip":       s.get("framedipaddress", ""),
                        "mac":      s.get("callingstation", ""),
                        "nas":      _nas_name(s),
                        "role":     (roles or [""])[0] if isinstance(roles, list) else s.get("role", ""),
                        "id":       s.get("id", ""),
                    })
                count = session_r.get("count", 0) if isinstance(session_r, dict) else 0
                offset += limit
                if len(items) < limit or offset >= count:
                    break
        except Exception as e:
            logger.error(f"CPPM search failed: {e}")
            return {"status": "ERROR", "message": str(e), "results": []}

        # Deduplicate by id
        seen: set = set()
        unique = []
        for r in results:
            key = f"{r['source']}/{r['type']}/{r.get('id', r.get('mac', ''))}"
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return {"status": "SUCCESS", "results": unique, "count": len(unique)}

    def list_roles(self) -> List[Dict[str, Any]]:
        result = self.client.query("/api/role")
        return self._items(result)

    def get_system_health(self) -> Dict[str, Any]:
        result = self.client.query("/api/server/version")
        if isinstance(result, dict) and result.get("status") != "ERROR":
            return {"status": "SUCCESS", "version": result.get("app_major_version", ""), "details": result}
        return {"status": "ERROR", "message": result.get("message", "Unreachable")}

    # ── Cert install (INSTALL_CERT) ──────────────────────────────────────────
    # ClearPass's server-cert API does NOT accept inline PEM — it fetches a
    # PKCS#12 bundle from a URL we hand it, so import_cert converts PEM→p12,
    # stands up a short-lived HTTP server on a ClearPass-reachable address
    # serving the p12, discovers the cluster server UUID, then PUTs the p12 URL
    # + passphrase to /api/server-cert/name/{uuid}/{service}. The HTTP server
    # is torn down the moment the PUT returns. No restart is needed for HTTPS
    # services. The spoke's INSTALL_CERT handler runs this in an executor
    # (CPPMQueries is synchronous requests-based).

    @staticmethod
    def _build_pkcs12(fullchain_pem: str, privkey_pem: str, passphrase: str) -> bytes:
        """Modern PKCS#12 (AES-256-CBC + SHA-256 HMAC) via ``cryptography``.

        Preferred bundle shape — readable by current ClearPass builds. Raises
        if ``cryptography`` isn't installed or the PEM is invalid; the caller
        falls back to :meth:`_build_pkcs12_legacy` on any failure (older
        ClearPass builds that can't read modern p12)."""
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import (
            pkcs12, BestAvailableEncryption, load_pem_private_key,
        )
        key = load_pem_private_key(privkey_pem.encode(), password=None)
        certs = x509.load_pem_x509_certificates(fullchain_pem.encode())
        if not certs:
            raise ValueError("no certificates parsed from fullchain PEM")
        return pkcs12.serialize_key_and_certificates(
            name=(f"lm-le-cert").encode(),
            key=key,
            cert=certs[0],
            cas=certs[1:] if len(certs) > 1 else None,
            encryption_algorithm=BestAvailableEncryption(passphrase.encode()),
        )

    @staticmethod
    def _build_pkcs12_legacy(fullchain_pem: str, privkey_pem: str,
                             passphrase: str) -> bytes:
        """Legacy PKCS#12 (RC2-40 + SHA-1) via the ``openssl`` CLI ``-legacy``
        flag — the bundle shape older ClearPass builds expect. Used when the
        modern bundle is rejected. ``-legacy`` is OpenSSL 3.x only; on older
        OpenSSL (1.x, where legacy is the default and the flag is unknown) we
        retry without it. Raises ``RuntimeError`` on openssl absence/failure."""
        import os
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            certf = os.path.join(td, "fullchain.pem")
            keyf = os.path.join(td, "privkey.pem")
            p12f = os.path.join(td, "bundle.p12")
            with open(certf, "w") as f:
                f.write(fullchain_pem)
            with open(keyf, "w") as f:
                f.write(privkey_pem)

            def _run(extra):
                return subprocess.run(
                    ["openssl", "pkcs12", "-export"] + extra +
                    ["-in", certf, "-inkey", keyf, "-out", p12f,
                     "-passout", f"pass:{passphrase}"],
                    check=False, capture_output=True, timeout=30,
                )
            try:
                cp = _run(["-legacy"])
            except FileNotFoundError:
                raise RuntimeError(
                    "openssl CLI not found — needed for legacy PKCS#12 build")
            stderr = cp.stderr or b""
            if cp.returncode != 0 and (b"Invalid option" in stderr
                                       or b"unknown option" in stderr
                                       or b"unrecognized option" in stderr):
                # Older OpenSSL: legacy algorithms are the default and -legacy
                # isn't recognized — retry without it.
                cp = _run([])
            if cp.returncode != 0:
                raise RuntimeError(
                    "openssl pkcs12 failed: " + stderr.decode(errors="replace")[:300])
            with open(p12f, "rb") as f:
                return f.read()

    def _cluster_server_uuid(self) -> str:
        """Discover the ClearPass cluster server UUID via
        ``GET /api/cluster/server``. ClearPass items use ``server_uuid``
        (NOT ``uuid``/``id`` — those keys don't exist, which surfaced as
        "cluster server has no uuid/id"). Prefer the publisher
        (``is_publisher``, or ``is_master`` on pre-6.11 builds) so the cert
        lands on the cluster publisher and replicates; fall back to the first
        server. Raises ``RuntimeError`` with the API detail on failure."""
        srv = self.client.query("/api/cluster/server")
        if isinstance(srv, dict) and srv.get("status") == "ERROR":
            raise RuntimeError(f"GET /api/cluster/server failed: {srv.get('message')}")
        items = self._items(srv)
        if not items:
            raise RuntimeError("no cluster servers returned by /api/cluster/server")

        def _uuid_of(it: Dict[str, Any]) -> str:
            return (it.get("server_uuid") or it.get("uuid")
                    or it.get("id") or "")
        for it in items:
            if it.get("is_publisher") or it.get("is_master"):
                uid = _uuid_of(it)
                if uid:
                    return uid
        return _uuid_of(items[0])

    def _ensure_trust_list_cas(self, fullchain: str, chain: str) -> list:
        """Import+enable the leaf's issuing CAs into ClearPass's Certificate
        Trust List so ClearPass accepts a third-party-CA-signed server cert.

        ClearPass 422's ``server-cert/name/.../HTTPS(RSA)`` with
        ``Certificate CA "CN=ISRG Root X1,..." ... must be added and enabled
        in Certificate Trust List`` until the issuing root CA (and ideally the
        intermediate) is imported AND enabled in the CTL. This is run BEFORE
        the server-cert PUT so the PUT can succeed first time.

        Best-effort and NON-BLOCKING: each CA is added independently, and a
        CTL failure never aborts the server-cert PUT — if the CTL shape is off
        the PUT still runs and surfaces the real 422 (the diagnostic), so this
        can't become a new blocker. Idempotent by subject CN: GET the list
        once, skip CAs already present (PATCH-enable them), POST the rest.
        Returns a per-CA result list for the caller's envelope/log."""
        cas = _ca_certs_to_trust(fullchain, chain)
        if not cas:
            return []

        # One GET to index existing CTL entries by subject CN (best-effort —
        # the list item's CN field name isn't documented, so try several).
        existing: Dict[str, Any] = {}
        try:
            lst = self.client.query("/api/cert-trust-list")
            for it in self._items(lst):
                if not isinstance(it, dict):
                    continue
                cn = (it.get("subject_common_name") or it.get("subject_cn")
                      or it.get("cn") or it.get("name") or "")
                cn = str(cn).strip() if cn else ""
                if cn:
                    existing[cn] = it.get("id")
        except Exception as e:
            logger.warning("trust-list GET failed (%s) — proceeding with blind "
                           "POST (no idempotency index)", e)

        results = []
        for pem in cas:
            cn = _cert_subject_cn(pem) or "<unknown>"
            if cn in existing:
                # Already trusted — ensure it's enabled (PATCH), don't re-POST.
                tid = existing.get(cn)
                enabled = True
                if tid is not None:
                    try:
                        self.client._request(
                            "PATCH", f"/api/cert-trust-list/{tid}",
                            json={"enabled": True})
                    except Exception as e:
                        enabled = False
                        logger.warning("trust-list PATCH-enable %s failed: %s", cn, e)
                results.append({"ca": cn, "action": "already-trusted",
                                "enabled": enabled})
                continue
            try:
                r = self.client._request(
                    "POST", "/api/cert-trust-list",
                    json={"cert_file": pem, "cert_usage": ["Others"],
                          "enabled": True})
            except Exception as e:
                logger.warning("trust-list POST %s failed: %s", cn, e)
                results.append({"ca": cn, "action": "error",
                                "message": str(e)[:160]})
                continue
            st = (r or {}).get("status", "ERROR") if isinstance(r, dict) else "ERROR"
            msg = str((r or {}).get("message", "") or "") if isinstance(r, dict) else ""
            # A duplicate/conflict (CA already trusted under a usage we didn't
            # match) is fine — the CA is present, which is all the PUT requires.
            low = msg.lower()
            if st == "ERROR" and any(k in low for k in
                                     ("exist", "duplicate", "already")):
                results.append({"ca": cn, "action": "already-trusted"})
            else:
                results.append({"ca": cn, "action": "added", "status": st,
                                "message": msg[:160]})
        return results

    def import_cert(self, fullchain: str, privkey: str, domain: str = "",
                    service_name: str = "HTTPS(RSA)",
                    chain: str = "") -> Dict[str, Any]:
        """Install a CA-signed cert (LE fullchain + key) into ClearPass as the
        named service's server cert — default the admin WebUI ``HTTPS(RSA)``
        cert. See the class-level notes above for the host-and-fetch flow.

        ``LM_CPPM_P12_HOST`` (required) is THIS spoke's address as ClearPass
        sees it — the p12 URL ClearPass fetches is built from it, so it must be
        reachable from the ClearPass node. ``LM_CPPM_P12_PORT`` (default 0 =
        ephemeral) fixes the port if your firewall mandates one.

        PEM→p12 prefers the modern bundle via ``cryptography``; if ClearPass
        rejects it (older builds), we regenerate with ``openssl -legacy`` and
        retry the PUT once. Returns the ``CPPMClient._request`` shape
        (``{status, message}``)."""
        fullchain = fullchain or ""
        privkey = privkey or ""
        if not fullchain or "BEGIN CERTIFICATE" not in fullchain:
            return {"status": "ERROR",
                    "message": "invalid or empty fullchain PEM for cert install"}
        if not privkey or "PRIVATE KEY" not in privkey:
            return {"status": "ERROR",
                    "message": "invalid or empty privkey PEM for cert install"}

        import os
        import secrets
        url_host = os.getenv("LM_CPPM_P12_HOST", "").strip()
        if not url_host:
            # Auto-detect the host's primary outbound IPv4 so cert distribution
            # works without manual env config on a routed shared network. The
            # explicit env stays authoritative when the spoke is multi-homed on
            # a segment ClearPass can't reach via the default route.
            url_host = _detect_local_ipv4()
            if url_host:
                logger.info("LM_CPPM_P12_HOST unset — auto-detected %s "
                            "(override via LM_CPPM_P12_HOST if ClearPass can't "
                            "reach it)", url_host)
        if not url_host:
            return {"status": "ERROR",
                    "message": "LM_CPPM_P12_HOST not set and could not auto-detect "
                               "this spoke's IP — set it to the address ClearPass "
                               "sees so ClearPass can fetch the PKCS12 bundle"}
        try:
            bind_port = int(os.getenv("LM_CPPM_P12_PORT", "0") or 0)
        except ValueError:
            bind_port = 0
        passphrase = secrets.token_urlsafe(18)
        service_name = service_name or "HTTPS(RSA)"

        # Build modern p12; fall back to legacy immediately if the modern
        # builder is unavailable (no cryptography / bad PEM).
        used_legacy = False
        try:
            p12 = self._build_pkcs12(fullchain, privkey, passphrase)
        except Exception as e:
            logger.warning("modern PKCS12 build failed (%s) — using openssl -legacy", e)
            try:
                p12 = self._build_pkcs12_legacy(fullchain, privkey, passphrase)
                used_legacy = True
            except Exception as e2:
                return {"status": "ERROR",
                        "message": f"PKCS12 build failed: {e2}"}

        try:
            server_uuid = self._cluster_server_uuid()
        except RuntimeError as e:
            return {"status": "ERROR", "message": str(e)}
        if not server_uuid:
            return {"status": "ERROR",
                    "message": "cluster server has no uuid/id (cannot address PUT)"}

        # Import+enable the issuing CAs in ClearPass's Certificate Trust List
        # BEFORE the server-cert PUT — ClearPass 422's the PUT until the root
        # CA is trusted. Best-effort + non-blocking: a CTL failure surfaces as
        # a logged result + the same PUT 422 (diagnostic), never a new blocker.
        try:
            trust_results = self._ensure_trust_list_cas(fullchain, chain)
            if trust_results:
                logger.info("ClearPass CTL: %s", trust_results)
        except Exception as e:
            trust_results = [{"ca": "<ctl>", "action": "error",
                              "message": str(e)[:160]}]
            logger.warning("ClearPass CTL pre-step failed (%s) — PUT still "
                           "attempted", e)

        import http.server
        import threading

        def _put_with(bundle: bytes) -> Dict[str, Any]:
            handler = _make_p12_handler(bundle)
            srv = http.server.ThreadingHTTPServer(("0.0.0.0", bind_port), handler)
            port = srv.server_address[1]
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://{url_host}:{port}/bundle.p12"
                return self.client._request(
                    "PUT",
                    f"/api/server-cert/name/{server_uuid}/{service_name}",
                    json={"pkcs12_file_url": url, "pkcs12_passphrase": passphrase},
                )
            finally:
                try:
                    srv.shutdown()
                    srv.server_close()
                except Exception:
                    pass
                thread.join(timeout=5)

        res = _put_with(p12)
        # If ClearPass couldn't read the modern p12, retry once with the legacy
        # bundle (old builds need RC2/SHA-1). Match ONLY on p12-parse/read
        # markers — a "URL not trusted" / "could not fetch" 422 is a URL-reach
        # problem (retrying with a different bundle won't help) so it surfaces
        # as a plain ERROR without burning the legacy retry.
        if (isinstance(res, dict) and res.get("status") == "ERROR"
                and not used_legacy):
            body_txt = str(res.get("message", "")).lower()
            if any(k in body_txt for k in
                   ("pkcs12", "p12", "parse", "empty", "mac", "decrypt",
                    "unsupported")):
                logger.warning("modern p12 rejected by ClearPass (%s) — retrying "
                               "with openssl -legacy", res.get("message"))
                try:
                    p12_leg = self._build_pkcs12_legacy(fullchain, privkey, passphrase)
                    res = _put_with(p12_leg)
                except Exception as e:
                    logger.warning("legacy p12 build failed: %s", e)

        if isinstance(res, dict) and res.get("status") == "ERROR":
            res["trust_list"] = trust_results
            return res
        return {"status": "SUCCESS",
                "message": f"cert '{domain or 'lm-le'}' installed as {service_name} "
                           f"on ClearPass server {server_uuid}",
                "trust_list": trust_results}
