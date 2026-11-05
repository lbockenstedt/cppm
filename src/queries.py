"""High-level ClearPass Policy Manager (CPPM) queries and write operations.

Wraps the low-level CPPMClient with helpers for the Access Tracker, sessions,
endpoint inventory search, tenant tagging/sync, and certificate installation,
normalising ClearPass's varied field names into stable dictionaries.
"""
# Type hints only; they document the shapes of values passed around.
from typing import Any, Dict, List, Optional
# Low-level authenticated REST client for ClearPass.
from client import CPPMClient
# datetime for timestamps, json for payloads, logging for diagnostics, re for parsing.
import datetime as _dt
import json
import logging
import re
# quote URL-encodes values embedded in API paths (e.g. MAC addresses, names).
from urllib.parse import quote

# One named logger so all CPPM query messages can be filtered together.
logger = logging.getLogger("CPPMQueries")

class ResourceNotFound(Exception):
    """Raised when a requested ClearPass object does not exist."""
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
    # Try each known field spelling in turn; fall back to the NAS IP, then empty string.
    return (s.get("nas_name") or s.get("nasname") or s.get("nasidentifier")
            or s.get("nas_identifier") or s.get("nas-identifier")
            or s.get("nasipaddress") or "")


def _nas_port(s: dict) -> str:
    """NAS port identifier for a ClearPass ``/api/session`` record.

    ClearPass carries the port in ``nasportid`` (e.g. "Ethernet1/0/12"); there
    is no ``nasport`` field. Returns '' when the session has no port info
    (e.g. a wireless controller session), so the UI can show '—'."""
    # Try each known port field spelling; empty string when none is present.
    return (s.get("nasportid") or s.get("nas_port_id")
            or s.get("nasport") or s.get("nas_port") or "")


def _nas_port_type(s: dict) -> str:
    """NAS port type (e.g. 'Ethernet', 'Wireless - IEEE 802.11') if reported."""
    # Try both known spellings; empty string when absent.
    return s.get("nasporttype") or s.get("nas_port_type") or ""


def _nas_ip(s: dict) -> str:
    """NAS IP (the switch/controller the session terminated on) for a ClearPass
    ``/api/session`` record. Distinct from ``_nas_name`` — the name helper only
    falls back to ``nasipaddress`` when no name is present; this always pulls the
    IP so the realtime NAC→IPAM reverse sync can model the switch device in
    NetBox by its IP."""
    # Try each known IP field spelling; empty string when absent.
    return (s.get("nasipaddress") or s.get("nas_ip_address")
            or s.get("nas_ip") or "")


def _iso_dt(dt) -> str:
    """CPPM datetime string → ISO 8601 (swaps the space separator for ``T``) so
    JS ``new Date()`` and our own parsers handle it reliably. ``''`` for absent.
    Module-level twin of the local ``_iso`` in get_access_tracker /
    get_device_sessions, lifted so get_recent_sessions can share it."""
    # Missing timestamps become an empty string.
    if not dt:
        return ""
    # Swap the space separator for "T" so the value is valid ISO 8601.
    s = str(dt).strip()
    return s.replace(" ", "T") if " " in s else s


def _make_p12_handler(p12_bytes: bytes):
    """Build a one-shot ``http.server`` handler that serves ``p12_bytes`` at
    ``/bundle.p12`` (404 elsewhere). Used by :meth:`CPPMQueries.import_cert`
    to host the PKCS#12 bundle ClearPass fetches during the PUT — the server
    lives only for the duration of that PUT call. The handler silences its
    own request logging (the spoke log already records the install step)."""
    # Imported lazily: only certificate installation needs an HTTP server.
    import http.server

    # Handler class closes over p12_bytes so each install serves its own bundle.
    class _Handler(http.server.BaseHTTPRequestHandler):
        """Minimal request handler that only knows how to serve the bundle."""

        def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler API)
            """Serve the PKCS#12 bundle at /bundle.p12 and 404 everything else."""
            # Ignore any query string when matching the path.
            if self.path.split("?", 1)[0] == "/bundle.p12":
                # Send the bundle with the PKCS#12 content type and exact length.
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pkcs12")
                self.send_header("Content-Length", str(len(p12_bytes)))
                self.end_headers()
                self.wfile.write(p12_bytes)
            else:
                # Any other path is not served.
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):  # silence per-request stderr noise
            """Suppress the default per-request logging to stderr."""
            pass

    # Return the class (not an instance); http.server instantiates it per request.
    return _Handler


def _detect_local_ipv4() -> str:
    """Best-effort primary outbound IPv4 of this host, for ClearPass to fetch
    the PKCS12 bundle when ``LM_CPPM_P12_HOST`` is unset. Uses the UDP-connect
    trick (no packets sent) to find the source IP of the default route — the
    address ClearPass most likely reaches when the spoke shares its routed
    network. Returns ``""`` on failure; the caller still requires a non-empty
    host so a failed detection surfaces the actionable ERROR (set the env)."""
    # Imported lazily: only needed for this one-off address detection.
    import socket
    # A UDP "connect" sends no packets but makes the OS choose a source address.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # The socket's local address is the host's outbound IP; ignore loopback results.
            s.connect(("223.255.255.1", 1))  # RFC 5737 — never routed
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        # Always release the socket.
        finally:
            s.close()
    # Any socket error simply means "could not detect".
    except Exception:
        pass
    # Empty string signals detection failure to the caller.
    return ""


def _split_pem_certs(pem_text: str) -> list:
    """Split a PEM bundle into its individual ``BEGIN/END CERTIFICATE`` blocks,
    preserving the delimiters. Tolerant of CRLF and surrounding text (keys,
    comments). Used to separate the leaf from its issuing CAs."""
    # Collected certificate blocks; nothing to do if the text holds no certificate.
    blocks = []
    if not pem_text or "BEGIN CERTIFICATE" not in pem_text:
        return blocks
    # Split on END markers (after removing CR characters) so each piece holds one cert.
    for part in pem_text.replace("\r", "").split("-----END CERTIFICATE-----"):
        # Locate the BEGIN marker; pieces without one are leftover text, not certs.
        i = part.find("-----BEGIN CERTIFICATE-----")
        if i < 0:
            continue
        # Keep text from BEGIN onwards, make sure it ends with a newline, re-add END.
        body = part[i:]
        if not body.endswith("\n"):
            body += "\n"
        blocks.append(body + "-----END CERTIFICATE-----\n")
    # Return the list of individual PEM certificates.
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

# ISRG Root X2: the ECDSA Let's Encrypt root, needed for E5/E6 intermediates.
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
    # An empty chain has no last cert to inspect.
    if not ca_pems:
        return None
    # Parse the last cert of the chain; imported lazily as cryptography is optional.
    try:
        from cryptography import x509
        last = x509.load_pem_x509_certificate(ca_pems[-1].encode())
    # Unparseable cert or missing library: leave the chain unchanged.
    except Exception:
        return None
    if last.issuer == last.subject:          # self-signed → root already present
        return None
    # Read the issuer's Common Name to find which root is missing.
    cn_attrs = last.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    cn = str(cn_attrs[0].value).strip() if cn_attrs else ""
    # Return the matching root PEM, or None for a non-Let's-Encrypt issuer.
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
    # An explicit CA chain is used as-is.
    if chain and "BEGIN CERTIFICATE" in chain:
        cas = _split_pem_certs(chain)
    else:
        # Otherwise take fullchain minus its first cert (the leaf).
        blocks = _split_pem_certs(fullchain)
        cas = blocks[1:] if len(blocks) > 1 else []
    # Append the missing self-signed root when the chain does not already contain it.
    root = _missing_root_pem(cas)
    if root and root not in cas:
        cas.append(root)
    # Return the CA certificates to trust.
    return cas


def _cert_subject_cn(pem: str) -> str:
    """Best-effort Common Name from a PEM cert, for idempotency matching +
    diagnostics. Returns ``""`` on any parse failure (the caller treats an
    empty CN as 'unknown' and still POSTs)."""
    # Parse the PEM (lazy import; cryptography is optional) and read the first cert's CN.
    try:
        from cryptography import x509
        certs = x509.load_pem_x509_certificates(pem.encode())
        if certs:
            attrs = certs[0].subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME)
            if attrs:
                return str(attrs[0].value)
    # Any parse error: fall through to the empty "unknown" result.
    except Exception:
        pass
    # Empty string means the CN could not be determined.
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
        """Wrap an already-configured CPPMClient."""
        # All API calls go through this client.
        self.client = client

    def _items(self, result: Any, key: str = "_embedded") -> List[Dict]:
        """Extracts item list from CPPM's HAL-style response."""
        # Dict responses: an error result has no items.
        if isinstance(result, dict):
            if "status" in result and result["status"] == "ERROR":
                return []
            # HAL responses keep the list under _embedded.<resource>; return the first list found.
            embedded = result.get("_embedded", {})
            if embedded:
                for v in embedded.values():
                    if isinstance(v, list):
                        return v
            # Some endpoints use a plain "items" key instead.
            if "items" in result:
                return result["items"]
        # Already a list: return it unchanged.
        elif isinstance(result, list):
            return result
        # Anything else carries no items.
        return []

    # --- Access Tracker ---

    def get_access_tracker(self, limit: int = 200, offset: int = 0) -> Dict[str, Any]:
        """Active sessions only from the ClearPass Access Tracker.

        ClearPass ``/api/session`` returns both active and closed sessions, so
        without a filter the list (and ``count``) grows forever as history
        accumulates. Active sessions have no ``acctstoptime`` — filtering on
        ``{"acctstoptime": {"$exists": false}}`` returns only sessions that have
        not closed out. (Filtering on ``state`` is known to 500 on ClearPass.)"""
        # Compact JSON filter selecting only sessions that have not stopped yet.
        active_filter = json.dumps({"acctstoptime": {"$exists": False}}, separators=(",", ":"))
        # Ask ClearPass for one page of active sessions plus the total count.
        result = self.client.query(
            "/api/session",
            params={
                "calculate_count": "true",
                "limit": limit,
                "offset": offset,
                "filter": active_filter,
            },
        )
        # Log the count and the first record's fields to help map ClearPass field names.
        _items_preview = result.get('_embedded', {}).get('items', []) if isinstance(result, dict) else []
        logger.info(f"CPPM /api/session count={result.get('count') if isinstance(result, dict) else '?'} first_item={dict(list(_items_preview[0].items())[:20]) if _items_preview else '{}'}")
        # Pass API errors straight back to the caller.
        if isinstance(result, dict) and result.get("status") == "ERROR":
            return result
        # Extract the list of session records from the HAL response.
        items = self._items(result)

        def _iso(dt):
            """Convert CPPM datetime string to ISO 8601 so JS new Date() parses it reliably."""
            # Missing timestamps become an empty string.
            if not dt:
                return ""
            # Swap the space separator for "T" to make an ISO 8601 string.
            return str(dt).strip().replace(" ", "T") if " " in str(dt) else str(dt)

        # Normalise each raw session into the stable shape the WebUI expects.
        sessions = []
        for s in items:
            # Role: may be a list or a single string
            roles_raw = s.get("roles") or s.get("role") or ""
            # Use the first role from a list, the string itself, or empty string.
            role = roles_raw[0] if isinstance(roles_raw, list) and roles_raw else (roles_raw if isinstance(roles_raw, str) else "")
            # Service: may be service or servicename
            svc = s.get("service") or s.get("servicename") or s.get("service_name") or ""
            # Build the normalised session row.
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
        # Prefer the server's total count; fall back to the page length.
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
        # Accept strings/ints for the window; fall back to 2 minutes on bad input.
        try:
            lookback = int(lookback_minutes)
        except (TypeError, ValueError):
            lookback = 2
        # Compute the UTC time window [now - lookback, now] as ISO 8601 strings.
        end = _dt.datetime.now(_dt.timezone.utc)
        start = end - _dt.timedelta(minutes=max(0, lookback))
        start_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        # Filter for sessions whose accounting start is inside the window.
        filt = json.dumps({"acctstarttime": {"$gte": start_iso}},
                          separators=(",", ":"))
        # Accumulated rows, the server-reported total, and the paging position.
        sessions: List[Dict[str, Any]] = []
        total: Any = None
        limit = 1000
        offset = 0
        # Page through the results 1000 at a time.
        while True:
            # Fetch one page of sessions in the window.
            result = self.client.query("/api/session", params={
                "calculate_count": "true",
                "limit": limit, "offset": offset, "filter": filt,
            })
            # Pass API errors straight back to the caller.
            if isinstance(result, dict) and result.get("status") == "ERROR":
                return result
            # Normalise each session that has a MAC address.
            items = self._items(result)
            for s in items:
                mac = s.get("callingstation", s.get("mac", ""))
                if not mac:
                    continue  # MAC-keyed downstream; nothing to ingest without one
                # Keep only the fields the NetBox sink needs.
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
            # Remember the server's total from the first page.
            if total is None and isinstance(result, dict):
                total = result.get("count")
            # A short page means there are no more results.
            if len(items) < limit:
                break
            # Move to the next page; stop early once the known total is reached.
            offset += limit
            if isinstance(total, int) and offset >= total:
                break
        # Return the rows together with the window that was queried.
        return {"status": "SUCCESS", "sessions": sessions,
                "total": len(sessions), "window_start": start_iso,
                "window_end": end_iso}

    # --- Device Database ---

    def get_device_database(self, limit: int = 200, offset: int = 0, status: Optional[str] = None) -> Dict[str, Any]:
        """Endpoint (device) database from ClearPass."""
        # Ask for one page with the total count included.
        params: Dict[str, Any] = {
            "calculate_count": "true",
            "limit": limit,
            "offset": offset,
        }
        # Optionally restrict to one endpoint status (e.g. Known/Unknown).
        if status:
            params["filter"] = json.dumps({"status": status}, separators=(",", ":"))
        # Fetch the page; pass API errors straight back.
        result = self.client.query("/api/endpoint", params=params)
        if isinstance(result, dict) and result.get("status") == "ERROR":
            return result
        # Normalise each endpoint into the shape the Device Database view expects.
        items = self._items(result)
        devices = []
        for d in items:
            # Endpoint attributes may be missing or null; treat both as an empty dict.
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
        # Prefer the server's total count; fall back to the page length.
        total = result.get("count", len(devices)) if isinstance(result, dict) else len(devices)
        return {"status": "SUCCESS", "devices": devices, "total": total}

    def get_all_endpoints(self, page_size: int = 1000) -> Dict[str, Any]:
        """Every endpoint in the device database, paged. One page (200) used to
        hide the rest from LM's Device Database, scans and NetBox matching."""
        # A non-positive page size would loop forever.
        if page_size <= 0:
            return {"status": "ERROR", "message": "page_size must be positive"}
        # Accumulated endpoints and the latest server total.
        devices: List[Dict[str, Any]] = []
        last_total = 0
        # Keep fetching pages, using the number already collected as the offset.
        while True:
            page = self.get_device_database(limit=page_size, offset=len(devices))
            # Stop and report on the first API error.
            if page.get("status") == "ERROR":
                return page
            # Add this page and remember the server's total.
            rows = page["devices"]
            devices.extend(rows)
            last_total = page.get("total", 0) or 0
            # A short/empty page ends the scan. The server total is only trusted
            # when it exceeds this page's size (count may be absent, in which
            # case total falls back to the page length).
            if len(rows) < page_size:
                break
            if last_total > len(rows) and len(devices) >= last_total:
                break
        # Report the larger of rows collected and server total.
        return {"status": "SUCCESS", "devices": devices,
                "total": max(len(devices), last_total)}

    # --- NAC Status Summary ---

    def get_nac_status(self) -> Dict[str, Any]:
        """Aggregate NAC health: active session count + device counts by status.

        ``active_sessions`` counts only sessions that have not closed out (no
        ``acctstoptime``); without this filter ClearPass returns every session
        ever recorded and the count grows monotonically."""
        # Compact JSON filter selecting only sessions that have not stopped yet.
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
        # Pull the count from each result, using 0 when a query failed.
        return {
            "status": "SUCCESS",
            "active_sessions": sessions_result.get("count", 0) if isinstance(sessions_result, dict) else 0,
            "total_devices": devices_result.get("count", 0) if isinstance(devices_result, dict) else 0,
            "known_devices": known_result.get("count", 0) if isinstance(known_result, dict) else 0,
            "unknown_devices": unknown_result.get("count", 0) if isinstance(unknown_result, dict) else 0,
        }

    # --- Existing queries ---

    def get_device_by_mac(self, mac: str) -> Optional[Dict[str, Any]]:
        """Look up an endpoint record in ClearPass by its MAC address."""
        # Query endpoints filtered by exact MAC address.
        result = self.client.query("/api/endpoint", params={"filter": json.dumps({"mac_address": mac}, separators=(",", ":"))})
        # Return the first match, or None when no endpoint has that MAC.
        items = self._items(result)
        return items[0] if items else None

    def get_endpoint_detail(self, mac: str) -> Dict[str, Any]:
        """Full endpoint record from ClearPass including all attributes."""
        # Query endpoints filtered by exact MAC address; pass API errors straight back.
        result = self.client.query("/api/endpoint", params={"filter": json.dumps({"mac_address": mac}, separators=(",", ":"))})
        if isinstance(result, dict) and result.get("status") == "ERROR":
            return result
        # No match means the endpoint does not exist.
        items = self._items(result)
        if not items:
            return {"status": "ERROR", "message": "Endpoint not found"}
        # Take the single matching endpoint and its attribute map.
        ep = items[0]
        attrs = ep.get("attributes", {}) or {}
        # Return the identity fields plus the full attribute map.
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

    # --- Policy Manager local users (hub JIT 802.1X accounts) ---
    # The hub's dot1x_jit broker creates one local user per simulated 802.1X
    # identity, owns the random password (vault), rotates it and deletes the
    # user when the sim engine releases it. Every user it creates carries the
    # LOCAL_USER_MARKER attribute; create refuses to take over an existing
    # local user without it so a hand-made account is never overwritten.
    # Attribute name/value stamped on every local user the hub creates, proving LM owns it.
    LOCAL_USER_MARKER = "LM_Managed"
    LOCAL_USER_MARKER_VALUE = "dot1x_jit"

    @staticmethod
    def _local_user_path(user_id: str) -> str:
        """Build the URL-encoded API path for one local user."""
        return f"/api/local-user/user-id/{quote(str(user_id), safe='')}"

    def get_local_user(self, user_id: str) -> Dict[str, Any]:
        """Fetch a Policy Manager local user. Returns {status, found, user}."""
        # Normalise the id; an empty id cannot be looked up.
        user_id = (user_id or "").strip()
        if not user_id:
            return {"status": "ERROR", "message": "Missing user_id"}
        # Fetch the user; a 404 is a normal "not found", other errors pass through.
        res = self.client._request("GET", self._local_user_path(user_id))
        if isinstance(res, dict) and res.get("status") == "ERROR":
            if res.get("code") == 404:
                return {"status": "SUCCESS", "found": False}
            return res
        # Copy the record and drop the password so it never leaves the spoke.
        user = dict(res or {})
        user.pop("password", None)
        return {"status": "SUCCESS", "found": True, "user": user}

    def create_local_user(self, user_id: str, password: str,
                          role_name: str = "[Employee]", tenant_slug: str = "",
                          attributes: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create (or re-key, when already LM-managed) a local user."""
        # Normalise the id; both id and password are mandatory.
        user_id = (user_id or "").strip()
        if not user_id or not password:
            return {"status": "ERROR", "message": "user_id and password are required"}
        # Check whether the user already exists (errors pass straight back).
        existing = self.get_local_user(user_id)
        if existing.get("status") == "ERROR":
            return existing
        # Stringify caller attributes (dropping empty ones), then add the LM marker and tenant.
        attrs = {k: str(v) for k, v in (attributes or {}).items() if v not in (None, "")}
        attrs[self.LOCAL_USER_MARKER] = self.LOCAL_USER_MARKER_VALUE
        if tenant_slug:
            attrs["Tenant_Slug"] = tenant_slug
        # Existing user: only take it over when it already carries the LM marker.
        if existing.get("found"):
            cur = (existing.get("user") or {}).get("attributes") or {}
            if cur.get(self.LOCAL_USER_MARKER) != self.LOCAL_USER_MARKER_VALUE:
                return {"status": "ERROR", "code": 409,
                        "message": f"local user {user_id!r} exists and is not LM-managed"}
            # Re-key the LM-managed user: new password/role, merged attributes, enabled.
            res = self.client._request("PATCH", self._local_user_path(user_id), json={
                "password": password, "role_name": role_name, "enabled": True,
                "attributes": {**cur, **attrs}})
            if isinstance(res, dict) and res.get("status") == "ERROR":
                return res
            return {"status": "SUCCESS", "user_id": user_id, "created": False}
        # New user: create it with the marker attributes and no forced password change.
        res = self.client._request("POST", "/api/local-user", json={
            "user_id": user_id, "username": user_id, "password": password,
            "role_name": role_name, "enabled": True,
            "change_pwd_next_login": False, "attributes": attrs})
        # Pass API errors back; otherwise report that a new user was created.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        return {"status": "SUCCESS", "user_id": user_id, "created": True}

    def set_local_user_password(self, user_id: str, password: str) -> Dict[str, Any]:
        """Replace a local user's password."""
        # Normalise the id; both id and password are mandatory.
        user_id = (user_id or "").strip()
        if not user_id or not password:
            return {"status": "ERROR", "message": "user_id and password are required"}
        # PATCH only the password field.
        res = self.client._request("PATCH", self._local_user_path(user_id),
                                   json={"password": password})
        # Pass API errors back; otherwise report success.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            return res
        return {"status": "SUCCESS", "user_id": user_id}

    def delete_local_user(self, user_id: str) -> Dict[str, Any]:
        """Delete a local user. Already-absent counts as success."""
        # Normalise the id; an empty id cannot be deleted.
        user_id = (user_id or "").strip()
        if not user_id:
            return {"status": "ERROR", "message": "Missing user_id"}
        # Delete the user; a 404 means it was already gone, which counts as success.
        res = self.client._request("DELETE", self._local_user_path(user_id))
        if isinstance(res, dict) and res.get("status") == "ERROR":
            if res.get("code") == 404:
                return {"status": "SUCCESS", "user_id": user_id, "deleted": False}
            return res
        # Report that the user was actually removed.
        return {"status": "SUCCESS", "user_id": user_id, "deleted": True}

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
        # Lower-case, then keep only hex digits so any separator style is accepted.
        m = (mac or "").strip().lower()
        hexonly = re.sub(r"[^0-9a-f]", "", m)
        # Twelve hex digits form a real MAC: re-insert colons every two characters.
        if len(hexonly) == 12:
            return ":".join(hexonly[i:i + 2] for i in range(0, 12, 2))
        # Anything else is returned as-is (lower-cased) rather than guessed at.
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
        # Non-dict input carries no usable attributes.
        if not isinstance(attrs, dict):
            return {}
        # Copy every non-null attribute, converting non-strings to strings.
        out: Dict[str, str] = {}
        for k, v in attrs.items():
            if v is None:
                continue
            out[k] = v if isinstance(v, str) else str(v)
        return out

    def _get_endpoint_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Look up an endpoint by its first-class ip_address field; None when absent."""
        # Query endpoints filtered by exact IP and return the first match.
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
        # Collected IPs; non-dict input has none.
        ips: set = set()
        if not isinstance(ep, dict):
            return ips
        # The first-class ip_address field, minus any CIDR suffix.
        top = ep.get("ip_address")
        if isinstance(top, str) and top.strip():
            ips.add(top.strip().split("/")[0].strip())
        # Every non-empty string attribute value, minus any CIDR suffix.
        attrs = ep.get("attributes") or {}
        if isinstance(attrs, dict):
            for v in attrs.values():
                if isinstance(v, str) and v.strip():
                    ips.add(v.strip().split("/")[0].strip())
        # Return all candidate IP values.
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
        # Result map and the set of non-empty IPs still being looked for.
        resolved: Dict[str, Dict[str, Any]] = {}
        wanted = {str(ip).strip() for ip in target_ips if str(ip).strip()}
        if not wanted:
            return resolved
        # Paging state: scan cap, page size, offset, rows scanned and server total.
        cap = self.SYNC_SCAN_CAP
        limit = 1000
        offset = 0
        scanned = 0
        total = 0
        # Page through the inventory until the cap is reached.
        while scanned < cap:
            # Fetch one page of endpoints with the total count.
            ep_r = self.client.query("/api/endpoint", params={
                "limit": limit, "offset": offset, "calculate_count": "true"})
            # Paging failure: log and return what has been resolved so far.
            if isinstance(ep_r, dict) and ep_r.get("status") == "ERROR":
                logger.warning("endpoint IP-map scan failed: %s", ep_r.get("message"))
                break
            # An empty page means the inventory is exhausted.
            items = self._items(ep_r)
            if not items:
                break
            # Record the first endpoint seen for each wanted IP.
            for ep in items:
                for ip in self._endpoint_ips(ep):
                    if ip in wanted and ip not in resolved:
                        resolved[ip] = ep
            # Advance the counters and remember the server total.
            scanned += len(items)
            total = ep_r.get("count", total) if isinstance(ep_r, dict) else total
            offset += limit
            # Stop at the last page or once every wanted IP is resolved.
            if len(items) < limit or offset >= total:
                break
            if all(ip in resolved for ip in wanted):
                break
        # Log coverage so a cap hit can be told apart from a genuine miss.
        logger.info("endpoint IP-map scan: scanned %d of %d endpoints (cap %d, %s); "
                    "resolved %d of %d wanted IPs",
                    scanned, total, cap,
                    "CAPPED — raise SYNC_SCAN_CAP" if scanned >= cap else "complete",
                    len(resolved), len(wanted))
        # Return the IP-to-endpoint map.
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
        # Result map and the set of normalised MACs still being looked for.
        resolved: Dict[str, Dict[str, Any]] = {}
        wanted = {self._norm_mac(m) for m in target_macs if self._norm_mac(m)}
        if not wanted:
            return resolved
        # Paging state: scan cap, page size, offset, rows scanned and server total.
        cap = self.SYNC_SCAN_CAP
        limit = 1000
        offset = 0
        scanned = 0
        total = 0
        # Page through the inventory until the cap is reached.
        while scanned < cap:
            # Fetch one page of endpoints with the total count.
            ep_r = self.client.query("/api/endpoint", params={
                "limit": limit, "offset": offset, "calculate_count": "true"})
            # Paging failure: log and return what has been resolved so far.
            if isinstance(ep_r, dict) and ep_r.get("status") == "ERROR":
                logger.warning("endpoint MAC-map scan failed: %s", ep_r.get("message"))
                break
            # An empty page means the inventory is exhausted.
            items = self._items(ep_r)
            if not items:
                break
            # Record the first endpoint seen for each wanted (normalised) MAC.
            for ep in items:
                m = self._norm_mac(ep.get("mac_address", ""))
                if m and m in wanted and m not in resolved:
                    resolved[m] = ep
            # Advance the counters and remember the server total.
            scanned += len(items)
            total = ep_r.get("count", total) if isinstance(ep_r, dict) else total
            offset += limit
            # Stop at the last page or once every wanted MAC is resolved.
            if len(items) < limit or offset >= total:
                break
            if all(m in resolved for m in wanted):
                break
        # Log coverage so a cap hit can be told apart from a genuine miss.
        logger.info("endpoint MAC-map scan: scanned %d of %d endpoints (cap %d, %s); "
                    "resolved %d of %d wanted MACs",
                    scanned, total, cap,
                    "CAPPED — raise SYNC_SCAN_CAP" if scanned >= cap else "complete",
                    len(resolved), len(wanted))
        # Return the MAC-to-endpoint map.
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
        # Result map and the set of non-empty IPs still being looked for.
        resolved: Dict[str, str] = {}
        wanted = {str(ip).strip() for ip in target_ips if str(ip).strip()}
        if not wanted:
            return resolved
        # Paging state: scan cap, page size, offset, rows scanned and server total.
        cap = self.SYNC_SCAN_CAP
        limit = 1000
        offset = 0
        scanned = 0
        total = 0
        # Page through all sessions until the cap is reached.
        while scanned < cap:
            # Fetch one page of sessions with the total count.
            s_r = self.client.query("/api/session", params={
                "limit": limit, "offset": offset, "calculate_count": "true"})
            # Paging failure: log and return what has been resolved so far.
            if isinstance(s_r, dict) and s_r.get("status") == "ERROR":
                logger.warning("session IP→MAC scan failed: %s", s_r.get("message"))
                break
            # An empty page means there are no more sessions.
            items = self._items(s_r)
            if not items:
                break
            # Only sessions whose IP is wanted and not yet resolved are interesting.
            for s in items:
                ip = (s.get("framedipaddress") or "").strip()
                if not ip or ip not in wanted or ip in resolved:
                    continue
                # ``callingstationid`` is the confirmed /api/session field for
                # the caller (endpoint) MAC; some ClearPass versions / the older
                # access-tracker code use ``callingstation`` / a ``mac`` key, so
                # accept all three.
                mac_raw = s.get("callingstationid") or s.get("callingstation") or s.get("mac") or ""
                # Keep the normalised MAC for this IP when the session carried one.
                mac = self._norm_mac(mac_raw)
                if mac:
                    resolved[ip] = mac
            # Advance the counters and remember the server total.
            scanned += len(items)
            total = s_r.get("count", total) if isinstance(s_r, dict) else total
            offset += limit
            # Stop at the last page or once every wanted IP is resolved.
            if len(items) < limit or offset >= total:
                break
            if all(ip in resolved for ip in wanted):
                break
        # Log coverage so a cap hit can be told apart from a genuine miss.
        logger.info("session IP→MAC scan: scanned %d of %d sessions (cap %d, %s); "
                    "resolved %d of %d wanted IPs",
                    scanned, total, cap,
                    "CAPPED — raise SYNC_SCAN_CAP" if scanned >= cap else "complete",
                    len(resolved), len(wanted))
        # Return the IP-to-MAC map.
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
        # Hostname from the source record, and the tenant tags written on every endpoint.
        hostname = (rec.get("hostname", "") or "").strip()
        tag_attrs = {
            self.TENANT_ATTR_SLUG: tenant_slug,
            self.TENANT_ATTR_NAME: tenant_name,
            self.TENANT_ATTR_ID: tenant_id,
            self.TENANT_ATTR_TENANT: tenant_name,
            self.TENANT_ATTR_TENANT_SLUG: tenant_slug,
        }
        # Add the IP and hostname attributes only when known.
        if ip:
            tag_attrs["IP Address"] = ip
        if hostname:
            tag_attrs["Hostname"] = hostname
        # Description that records where and for which tenant this endpoint was synced.
        description = f"Synced from {source} (tenant {tenant_slug})"

        # Find any existing endpoint for this record.
        existing = None
        if mac:
            # Prefer the batch-built MAC map (one scan for the whole batch);
            # fall back to a per-record GET only for MACs the map didn't
            # resolve (cap hit / scan failure).
            nmac = self._norm_mac(mac)
            existing = (mac_map or {}).get(nmac) if mac_map is not None else None
            if not existing:
                existing = self.get_device_by_mac(mac)
        # No MAC: look the endpoint up by IP instead.
        elif ip:
            # Cheap exact-field filter first, then the batch IP→endpoint map
            # (attribute-based: ``IP Address`` etc.) so an existing endpoint
            # whose MAC the source record lacks is still found and tagged.
            existing = self._get_endpoint_by_ip(ip)
            if not existing and ip_map:
                existing = ip_map.get(ip)

        # Existing endpoint: merge our tags into its attributes and PUT it back.
        if existing:
            # Without an id the endpoint cannot be updated.
            ep_id = existing.get("id")
            if not ep_id:
                return "error"
            # Merge tenant tags over the current attributes and make every value a string.
            cur_attrs = dict(existing.get("attributes") or {})
            cur_attrs.update(tag_attrs)
            cur_attrs = self._coerce_attrs(cur_attrs)
            # Base PUT body: id, merged attributes and the sync description.
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
            # Include the MAC when the record supplied one.
            if mac:
                body["mac_address"] = mac
            # Send the update; a failure is logged with the values that were sent.
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
            # Update succeeded.
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

        # New endpoint: create it keyed on MAC, named by MAC and marked Known.
        body = {"mac_address": mac, "name": mac, "description": description,
                "attributes": self._coerce_attrs(tag_attrs), "status": "Known"}
        # Send the create; a failure is logged and counted as an error.
        res = self.client._request("POST", "/api/endpoint", json=body)
        if isinstance(res, dict) and res.get("status") == "ERROR":
            logger.warning("endpoint POST %s failed: %s", mac, res.get("message"))
            return "error"
        # Create succeeded.
        return "pushed"

    def _remove_absent_tagged(self, tenant_slug: str, batch_keys: set,
                              allow_mass_remove: bool = False) -> int:
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

        ``allow_mass_remove`` skips guard 2 only, for a one-off sync an operator
        has confirmed (the tenant's IPAM data really did shrink). Guard 1 always
        applies.
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
        # Tally of tenant-tagged endpoints, ids to delete, and paging state.
        tagged_total = 0
        to_delete: List[str] = []  # endpoint ids
        limit = 1000
        offset = 0
        # Page through the whole endpoint inventory.
        while True:
            # Fetch one page of endpoints with the total count.
            res = self.client.query("/api/endpoint", params={
                "limit": limit, "offset": offset, "calculate_count": "true"})
            # Paging failure: log and stop scanning (deletions are then based on what was seen).
            if isinstance(res, dict) and res.get("status") == "ERROR":
                logger.warning("replace-scan list failed: %s", res.get("message"))
                break
            # An empty page means the inventory is exhausted.
            items = self._items(res)
            if not items:
                break
            # Only endpoints tagged with this tenant are candidates for removal.
            for ep in items:
                attrs = ep.get("attributes") or {}
                if attrs.get(self.TENANT_ATTR_SLUG) != tenant_slug:
                    continue
                # Count it as tagged and work out its key (MAC, or IP when no MAC).
                tagged_total += 1
                mac = self._norm_mac(ep.get("mac_address", ""))
                ip_val = attrs.get("IP Address") or attrs.get("ip_address") or ep.get("ip_address") or ""
                ip = ip_val.strip() if isinstance(ip_val, str) else ""
                key = mac or f"ip:{ip}"
                # Endpoints still present in the batch are kept.
                if key in batch_keys:
                    continue
                # Endpoints without an id cannot be deleted; otherwise queue it for removal.
                ep_id = ep.get("id")
                if not ep_id:
                    continue
                to_delete.append(ep_id)
            # Advance to the next page; stop at the last page.
            count = res.get("count", 0) if isinstance(res, dict) else 0
            offset += limit
            if len(items) < limit or offset >= count:
                break

        # Guard 2: refuse a removal that would take out more than half of the
        # tenant's currently-tagged endpoints — the signature of a truncated or
        # partially-failed batch. Surface it loudly instead of deleting.
        if (not allow_mass_remove and tagged_total
                and len(to_delete) > tagged_total * 0.5):
            raise ReplaceScanAborted(
                f"replace-scan for tenant '{tenant_slug}' would remove "
                f"{len(to_delete)} of {tagged_total} tagged endpoints (>50%) — "
                "likely a truncated/failed batch; refusing to mass-delete")

        # Pass 2: delete each queued endpoint, counting successes and logging failures.
        removed = 0
        for ep_id in to_delete:
            d = self.client._request("DELETE", f"/api/endpoint/{ep_id}")
            if isinstance(d, dict) and d.get("status") != "ERROR":
                removed += 1
            else:
                logger.warning("endpoint DELETE %s failed: %s", ep_id,
                               d.get("message") if isinstance(d, dict) else d)
        # Number of endpoints actually removed.
        return removed

    def sync_endpoints(self, tenant_id: str, tenant_slug: str, tenant_name: str,
                       source: str, endpoints: List[Dict[str, Any]],
                       replace: bool = True,
                       allow_mass_remove: bool = False) -> Dict[str, Any]:
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
        # A tenant slug is required because it is the tag that scopes the whole sync.
        tenant_slug = (tenant_slug or "").strip()
        if not tenant_slug:
            return {"status": "ERROR", "message": "Missing tenant_slug",
                    "pushed": 0, "errors": 0, "skipped": 0, "removed": 0}
        # Default the source label used in endpoint descriptions.
        source = source or "IPAM"

        # Normalised batch entries and the set of their keys (used by the replace-scan).
        batch: List[tuple] = []  # (key, mac, ip, rec)
        batch_keys: set = set()
        # Normalise every record; skip non-dicts and records with neither MAC nor IP.
        for rec in endpoints or []:
            if not isinstance(rec, dict):
                continue
            mac = self._norm_mac(rec.get("mac", ""))
            ip = (rec.get("ip", "") or "").strip()
            if not mac and not ip:
                continue
            # Key on MAC when present, otherwise on "ip:<address>".
            key = mac or f"ip:{ip}"
            batch_keys.add(key)
            batch.append((key, mac, ip, rec))

        # MAC-bearing records: build a MAC → existing-endpoint map ONCE so
        # _upsert_endpoint doesn't issue a per-record get_device_by_mac GET
        # (185 records ⇒ 185 extra round-trips ⇒ the hub's 180s timeout). One
        # bounded scan replaces them; unresolved MACs fall back to the per-
        # record GET inside _upsert_endpoint.
        # Build the MAC map; a failure just means per-record lookups are used instead.
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
        # Build the IP map; a failure means only the exact ip_address filter is used.
        ip_map: Optional[Dict[str, Dict[str, Any]]] = None
        ip_only = {ip for _, mac, ip, _ in batch if not mac and ip}
        if ip_only:
            try:
                ip_map = self._build_ip_endpoint_map(ip_only)
                # Count how many IP-only records were resolved and log a warning when none were.
                resolved_n = len({ip for ip in ip_only if ip in ip_map})
                if ip_only and resolved_n == 0:
                    logger.warning("endpoint sync tenant=%s: IP→endpoint map resolved "
                                   "0 of %d IP-only records — ClearPass has no endpoint "
                                   "carrying any of these IPs, so they will be skipped "
                                   "(no MAC to attach). If the devices are expected in "
                                   "ClearPass, verify the endpoint inventory. IPs: %s",
                                   tenant_slug, len(ip_only),
                                   ", ".join(sorted(ip_only)[:10]))
                # Some were resolved: log the coverage.
                else:
                    logger.info("endpoint sync tenant=%s IP→endpoint map: %d of %d "
                                "IP-only records resolved from ClearPass",
                                tenant_slug, resolved_n, len(ip_only))
            # Map build failed: log and continue without it.
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
        # IPs still without an endpoint; try borrowing a MAC from live sessions.
        unresolved = ip_only - set(ip_map or {})
        if unresolved:
            try:
                # Build the session map and log how many MACs were borrowed.
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
            # Session fallback failed: log and continue without it.
            except Exception as e:
                logger.warning("endpoint sync tenant=%s session MAC-map build failed: "
                               "%s (skipping session fallback)", tenant_slug, e)

        # Per-outcome counters, error messages and details of skipped records.
        pushed = errors = skipped = 0
        err_msgs: List[str] = []
        skipped_details: List[Dict[str, Any]] = []
        # Upsert every batch record; one failure must not stop the rest.
        for key, mac, ip, rec in batch:
            try:
                outcome = self._upsert_endpoint(mac, ip, rec, tenant_id, tenant_slug,
                                                 tenant_name, source,
                                                 ip_map=ip_map, mac_map=mac_map)
                # Tally the outcome reported by the upsert.
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
                # Anything else ("error") counts as a failure.
                else:
                    errors += 1
            # Unexpected exception: count it and keep its message for the summary.
            except Exception as e:
                errors += 1
                err_msgs.append(f"{key}: {e}")

        # Replace mode: remove tenant-tagged endpoints that are no longer in the batch.
        removed = 0
        if replace:
            try:
                removed = self._remove_absent_tagged(
                    tenant_slug, batch_keys, allow_mass_remove=allow_mass_remove)
            except ReplaceScanAborted as e:
                # Deliberate safety abort (empty/runaway batch) — count it as an
                # error so the sync reports ERROR rather than a silent success
                # that skipped stale-removal. Nothing was deleted.
                errors += 1
                err_msgs.append(f"replace-scan aborted: {e}")
                logger.error("endpoint sync tenant=%s replace-scan aborted: %s",
                             tenant_slug, e)
            # Other replace-scan failures are reported but do not mark the sync as failed.
            except Exception as e:
                err_msgs.append(f"replace-scan: {e}")

        # Log a one-line summary of every skipped record.
        if skipped_details:
            logger.info(
                "endpoint sync tenant=%s skipped %d record(s): %s",
                tenant_slug, skipped,
                "; ".join(f"ip={s['ip'] or '<empty>'} mac={s['mac'] or '<empty>'} "
                          f"hostname={s['hostname'] or '<empty>'}" for s in skipped_details))

        # Overall status plus a human-readable summary message for the hub.
        status = "SUCCESS" if errors == 0 else "ERROR"
        msg = f"synced {pushed} from {source}"
        # Mention skipped records in the message.
        if skipped:
            msg += f", skipped {skipped}"
            # Name the first couple of skipped IPs so the status card shows a hint
            # without bloating the message for large batches.
            names = [s["ip"] or s["hostname"] or "(no ip)" for s in skipped_details[:3]]
            if names:
                msg += " (" + ", ".join(names) + ")"
        # Mention stale removals and up to eight error messages.
        if replace:
            msg += f", removed {removed} stale"
        if err_msgs:
            msg += " | errors: " + "; ".join(err_msgs[:8])
        # Return counts, message and skip details to the hub.
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
        # Normalised MAC and its bare hex form (for separator-insensitive matching).
        norm = self._norm_mac(mac)
        mac_hex = re.sub(r"[^0-9a-f]", "", norm.lower()) if norm else ""

        def _query_filtered(filter_key: str, value: str):
            """Query /api/session filtered by one exact key/value pair."""
            return self.client.query(
                "/api/session",
                params={
                    "filter": json.dumps({filter_key: value}, separators=(",", ":")),
                    "limit": limit,
                    "calculate_count": "true",
                },
            )

        # Try the server-side callingstationid filter first.
        result = _query_filtered("callingstationid", norm) if norm else None
        used_fallback = False
        if isinstance(result, dict) and result.get("status") == "ERROR":
            # Server filter rejected (e.g. field not filterable on this ClearPass
            # build) → bounded client-side scan so we still return matches.
            used_fallback = True
            # Collected matches and paging state for the fallback scan.
            items: List[Dict[str, Any]] = []
            offset = 0
            page = 500
            # Keep paging until enough matching sessions are found.
            while len(items) < limit:
                # Fetch one page of sessions.
                r = self.client.query("/api/session", params={
                    "limit": page, "offset": offset, "calculate_count": "true"})
                # Stop on API error or an empty page.
                if isinstance(r, dict) and r.get("status") == "ERROR":
                    break
                page_items = self._items(r)
                if not page_items:
                    break
                # Compare each session's MAC (hex only) with the requested one.
                for s in page_items:
                    s_hex = re.sub(r"[^0-9a-f]", "",
                                   (s.get("callingstationid")
                                    or s.get("callingstation") or "").lower())
                    if mac_hex and s_hex == mac_hex:
                        items.append(s)
                        if len(items) >= limit:
                            break
                # A short page means there are no more sessions; otherwise move on.
                if len(page_items) < page:
                    break
                offset += page
        else:
            # Server filter worked: use its result directly.
            items = self._items(result)
        def _iso(dt):
            """Convert a CPPM datetime string to ISO 8601 (space becomes "T"); "" when missing."""
            if not dt: return ""
            return str(dt).strip().replace(" ", "T") if " " in str(dt) else str(dt)

        # Normalise each raw session into the shape the device-detail view expects.
        sessions = []
        for s in items:
            # First role from a list, the string itself, or empty; service under any spelling.
            roles_raw = s.get("roles") or s.get("role") or ""
            role = roles_raw[0] if isinstance(roles_raw, list) and roles_raw else (roles_raw if isinstance(roles_raw, str) else "")
            svc = s.get("service") or s.get("servicename") or s.get("service_name") or ""
            # Build the normalised session row.
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
        # Trust the server's count only when the server filter was used.
        total = (result.get("count", len(sessions))
                 if isinstance(result, dict) and not used_fallback else len(sessions))
        return {"status": "SUCCESS", "sessions": sessions, "total": total}

    def get_user_sessions(self, username: str) -> List[Dict[str, Any]]:
        """Query active and historical sessions associated with a specific username."""
        # Filter sessions by exact username and return the raw records.
        result = self.client.query("/api/session", params={"filter": json.dumps({"username": username}, separators=(",", ":"))})
        return self._items(result)

    def get_auth_logs(self, start_time: str, end_time: str) -> List[Dict[str, Any]]:
        """Retrieve authentication session logs within an ISO timestamp window."""
        # Filter sessions whose accounting start is between the two timestamps.
        result = self.client.query(
            "/api/session",
            params={"filter": json.dumps({"acctstarttime": {"$gte": start_time, "$lte": end_time}}, separators=(",", ":"))},
        )
        # Return the raw session records.
        return self._items(result)

    def _endpoint_search_result(self, ep: Dict[str, Any]) -> Dict[str, Any]:
        """Normalise a ClearPass endpoint into a global-search result."""
        # Endpoint attributes may be missing or null.
        attrs = ep.get("attributes") or {}
        # Prefer the Hostname attribute (populated by sync / profiler) for the
        # display name; fall back to MAC so the row is never blank.
        name = attrs.get("Hostname") or ep.get("mac_address", "")
        # Tenant slug stamped by the IPAM→CPPM sync (or the at-auth-time CSA).
        # Empty when the endpoint has no NetBox tenant tag (e.g. profiler-only).
        tenant_slug = (attrs.get(self.TENANT_ATTR_SLUG) or "").strip()
        # Build the normalised search-result row.
        return {
            "source":  "cppm",
            "type":    "endpoint",
            "name":    name,
            "ip":      ep.get("ip_address", ""),
            "mac":     ep.get("mac_address", ""),
            "status":  ep.get("status", ""),
            "vendor":  ep.get("vendor_name", ""),
            "tenant":  tenant_slug,
            "id":      ep.get("id", ""),
        }

    @staticmethod
    def _endpoint_matches(ep: Dict[str, Any], q: str) -> bool:
        """True if `q` is a case-insensitive substring of any endpoint text
        field — MAC, IP, status, vendor, or any attribute value (Hostname,
        Tenant, etc.). Any part of any string matches. MACs are also compared
        separator-stripped so a partial MAC typed without colons/dashes
        ("445566") matches "11:22:33:44:55:66"."""
        # An empty query never matches.
        if not q:
            return False
        # Text fields to search: MAC, IP, status, vendor, plus every string attribute.
        haystacks = [
            ep.get("mac_address", ""),
            ep.get("ip_address", ""),
            ep.get("status", ""),
            ep.get("vendor_name", ""),
        ]
        # Add every string attribute value to the search fields.
        attrs = ep.get("attributes") or {}
        if isinstance(attrs, dict):
            for v in attrs.values():
                if isinstance(v, str):
                    haystacks.append(v)
        # Plain case-insensitive substring match on any field.
        if any(q in str(h).lower() for h in haystacks):
            return True
        # Separator-insensitive MAC match: strip everything but hex from both
        # the query and the MAC, then substring-test.
        q_hex = re.sub(r"[^0-9a-f]", "", q)
        if q_hex:
            mac_hex = re.sub(r"[^0-9a-f]", "", (ep.get("mac_address") or "").lower())
            if q_hex in mac_hex:
                return True
        # Nothing matched.
        return False

    def search(self, query: str, tenant: str = "",
               is_admin: bool = False) -> Dict[str, Any]:
        """
        Search CPPM endpoints (Device Inventory) and active sessions by
        substring across MAC / IP / hostname / vendor / username / NAS.

        ClearPass's REST `filter` only supports exact-equality (no SQL-LIKE),
        so partial matching is done client-side: exact MAC/IP filters run first
        (precise + cheap), then a bounded paged scan of the endpoint inventory
        and the active-session list matches `q` as a case-insensitive substring
        of any text field. Returns normalised results tagged source="cppm".

        Tenant scoping (enforced spoke-side per the hub payload contract):
          - `tenant` slug set → only emit results whose NetBox_Tenant_Slug
            matches. Sessions don't carry a tenant attribute directly, so each
            session is joined to its endpoint by MAC to resolve the slug; a
            session whose MAC has no endpoint (or a non-matching one) is
            dropped.
          - `tenant` absent + `is_admin` True → unscoped (all results).
          - `tenant` absent + `is_admin` False → empty (never leak another
            tenant's sessions/endpoints).

        Each sub-search (endpoints, sessions) is wrapped in its own try/except
        so a failure in one doesn't drop the other.
        """
        # Normalise the query; an empty query returns no results.
        q = query.strip().lower()
        if not q:
            return {"status": "SUCCESS", "results": [], "count": 0}

        # Results are tenant-scoped whenever a tenant slug is supplied.
        scoped = bool(tenant)
        if not scoped and not is_admin:
            # No scope + non-admin → return nothing rather than risk leaking
            # another tenant's sessions/endpoints.
            return {"status": "SUCCESS", "results": [], "count": 0}

        # Collected results and ids already emitted (to avoid duplicates).
        results = []
        seen_ids: set = set()
        # MAC → NetBox_Tenant_Slug map, populated from the endpoint scan so
        # sessions can be joined to a tenant (sessions carry no tenant attr).
        mac_to_tenant: Dict[str, str] = {}

        def _ep_tenant_slug(ep: Dict[str, Any]) -> str:
            """Return the NetBox tenant slug tagged on an endpoint, or "" when untagged."""
            attrs = ep.get("attributes") or {}
            return (attrs.get(self.TENANT_ATTR_SLUG) or "").strip()

        # --- Endpoints (exact + bounded substring scan) ---------------------
        try:
            # Exact endpoint lookup (MAC / IP) — precise & cheap.
            for filter_def in [{"mac_address": q}, {"ip_address": q}]:
                ep_r = self.client.query("/api/endpoint", params={"filter": json.dumps(filter_def, separators=(",", ":")), "limit": 10})
                # Record each match's tenant, apply tenant scoping and de-duplicate by id.
                for ep in self._items(ep_r):
                    mac = self._norm_mac(ep.get("mac_address", ""))
                    tslug = _ep_tenant_slug(ep)
                    if mac:
                        mac_to_tenant[mac] = tslug
                    if scoped and tslug != tenant:
                        continue
                    if ep.get("id") and ep["id"] not in seen_ids:
                        seen_ids.add(ep["id"])
                        results.append(self._endpoint_search_result(ep))

            # Endpoint substring scan (bounded).
            # Paging state for the bounded scan.
            limit = 1000
            offset = 0
            scanned = 0
            # Page through the inventory until the search scan cap is reached.
            while scanned < self.SEARCH_SCAN_CAP:
                # Fetch one page of endpoints.
                ep_r = self.client.query("/api/endpoint", params={
                    "limit": limit, "offset": offset, "calculate_count": "true"})
                # Paging failure: log and stop the endpoint scan.
                if isinstance(ep_r, dict) and ep_r.get("status") == "ERROR":
                    logger.warning("endpoint substring scan failed: %s", ep_r.get("message"))
                    break
                # An empty page means the inventory is exhausted.
                items = self._items(ep_r)
                if not items:
                    break
                # Remember each endpoint's tenant (for the session join) before filtering.
                for ep in items:
                    mac = self._norm_mac(ep.get("mac_address", ""))
                    tslug = _ep_tenant_slug(ep)
                    if mac:
                        mac_to_tenant[mac] = tslug
                    # Skip non-matches, other tenants' endpoints and duplicates.
                    if not self._endpoint_matches(ep, q):
                        continue
                    if scoped and tslug != tenant:
                        continue
                    if ep.get("id") and ep["id"] in seen_ids:
                        continue
                    # Record the id and emit the result.
                    if ep.get("id"):
                        seen_ids.add(ep["id"])
                    results.append(self._endpoint_search_result(ep))
                # Advance counters; stop at the last page.
                scanned += len(items)
                count = ep_r.get("count", 0) if isinstance(ep_r, dict) else 0
                offset += limit
                if len(items) < limit or offset >= count:
                    break
        # Endpoint search failure is logged so the session search still runs.
        except Exception as e:
            logger.error(f"CPPM endpoint search failed: {e}")

        # --- Active sessions (bounded) — substring by IP/MAC/user/NAS ------
        try:
            # Paging state for the session scan.
            limit = 1000
            offset = 0
            # Page through every session (session lists are naturally bounded).
            while True:
                # Fetch one page of sessions.
                session_r = self.client.query("/api/session", params={
                    "limit": limit, "offset": offset, "calculate_count": "true"})
                # Paging failure: log and stop the session scan.
                if isinstance(session_r, dict) and session_r.get("status") == "ERROR":
                    logger.warning("session substring scan failed: %s", session_r.get("message"))
                    break
                # An empty page means there are no more sessions.
                items = self._items(session_r)
                if not items:
                    break
                # Text fields to search: username, IP, MAC and NAS name.
                for s in items:
                    fields = [
                        s.get("username", ""),
                        s.get("framedipaddress", ""),
                        s.get("callingstation", ""),
                        _nas_name(s),
                    ]
                    # Role names are searchable too.
                    roles = s.get("roles")
                    if isinstance(roles, list):
                        fields.extend(str(r) for r in roles)
                    # Plain case-insensitive substring match on any field.
                    matched = any(q in str(f).lower() for f in fields)
                    if not matched:
                        # Separator-insensitive MAC match for callingstation.
                        q_hex = re.sub(r"[^0-9a-f]", "", q)
                        if q_hex:
                            mac_hex = re.sub(r"[^0-9a-f]", "", (s.get("callingstation") or "").lower())
                            matched = q_hex in mac_hex
                    # Skip sessions that matched nothing.
                    if not matched:
                        continue
                    # Resolve the session's tenant by joining to its endpoint
                    # (sessions carry no tenant attribute of their own).
                    smac = self._norm_mac(s.get("callingstation", ""))
                    stenant = mac_to_tenant.get(smac, "")
                    if scoped and stenant != tenant:
                        # No endpoint, or endpoint's tenant doesn't match → drop
                        # for scoped callers (never leak across tenants).
                        continue
                    # Emit the session as a normalised search result.
                    results.append({
                        "source":   "cppm",
                        "type":     "session",
                        "name":     s.get("username", ""),
                        "ip":       s.get("framedipaddress", ""),
                        "mac":      s.get("callingstation", ""),
                        "nas":      _nas_name(s),
                        "role":     (roles or [""])[0] if isinstance(roles, list) else s.get("role", ""),
                        "tenant":   stenant,
                        "id":       s.get("id", ""),
                    })
                # Advance to the next page; stop at the last page.
                count = session_r.get("count", 0) if isinstance(session_r, dict) else 0
                offset += limit
                if len(items) < limit or offset >= count:
                    break
        # Session search failure is logged so endpoint results are still returned.
        except Exception as e:
            logger.error(f"CPPM session search failed: {e}")

        # Deduplicate by id
        # Unique results and the keys already seen.
        seen: set = set()
        unique = []
        # Key on source/type/id (or MAC) and keep only the first occurrence.
        for r in results:
            key = f"{r['source']}/{r['type']}/{r.get('id', r.get('mac', ''))}"
            if key not in seen:
                seen.add(key)
                unique.append(r)
        # Return the de-duplicated results and their count.
        return {"status": "SUCCESS", "results": unique, "count": len(unique)}

    def list_roles(self) -> List[Dict[str, Any]]:
        """Fetch all configured user and device roles defined in ClearPass."""
        # Fetch every role and return the raw records.
        result = self.client.query("/api/role")
        return self._items(result)

    def get_system_health(self) -> Dict[str, Any]:
        """Query ClearPass server version and health status."""
        # Ask ClearPass for its version information.
        result = self.client.query("/api/server/version")
        # Success: report the major version plus the full details.
        if isinstance(result, dict) and result.get("status") != "ERROR":
            return {"status": "SUCCESS", "version": result.get("app_major_version", ""), "details": result}
        # Failure: report the API error message.
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
        # Imported lazily: cryptography is only needed for certificate installs.
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import (
            pkcs12, BestAvailableEncryption, load_pem_private_key,
        )
        # Load the unencrypted private key and every certificate in the chain.
        key = load_pem_private_key(privkey_pem.encode(), password=None)
        certs = x509.load_pem_x509_certificates(fullchain_pem.encode())
        # A chain with no certificates cannot be bundled.
        if not certs:
            raise ValueError("no certificates parsed from fullchain PEM")
        # Bundle key + leaf cert + CA certs, encrypted with the supplied passphrase.
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
        # Standard-library helpers to run openssl on temporary files.
        import os
        import subprocess
        import tempfile
        # Work in a temp directory that is deleted (with the private key) afterwards.
        with tempfile.TemporaryDirectory() as td:
            # Paths for the input PEMs and the output bundle.
            certf = os.path.join(td, "fullchain.pem")
            keyf = os.path.join(td, "privkey.pem")
            p12f = os.path.join(td, "bundle.p12")
            # Write the certificate chain and private key for openssl to read.
            with open(certf, "w") as f:
                f.write(fullchain_pem)
            with open(keyf, "w") as f:
                f.write(privkey_pem)

            def _run(extra):
                """Run "openssl pkcs12 -export" with extra flags; returns the CompletedProcess."""
                return subprocess.run(
                    ["openssl", "pkcs12", "-export"] + extra +
                    ["-in", certf, "-inkey", keyf, "-out", p12f,
                     "-passout", f"pass:{passphrase}"],
                    check=False, capture_output=True, timeout=30,
                )
            # First try with -legacy (OpenSSL 3.x).
            try:
                cp = _run(["-legacy"])
            # openssl is not installed: nothing to fall back to.
            except FileNotFoundError:
                raise RuntimeError(
                    "openssl CLI not found — needed for legacy PKCS#12 build")
            # Error text used to recognise an "unknown -legacy option" failure.
            stderr = cp.stderr or b""
            if cp.returncode != 0 and (b"Invalid option" in stderr
                                       or b"unknown option" in stderr
                                       or b"unrecognized option" in stderr):
                # Older OpenSSL: legacy algorithms are the default and -legacy
                # isn't recognized — retry without it.
                cp = _run([])
            # Any remaining failure is fatal; include part of openssl's error text.
            if cp.returncode != 0:
                raise RuntimeError(
                    "openssl pkcs12 failed: " + stderr.decode(errors="replace")[:300])
            # Return the bytes of the generated bundle.
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
        # List cluster servers; API errors become a RuntimeError with the detail.
        srv = self.client.query("/api/cluster/server")
        if isinstance(srv, dict) and srv.get("status") == "ERROR":
            raise RuntimeError(f"GET /api/cluster/server failed: {srv.get('message')}")
        # An empty cluster list means there is nowhere to install the cert.
        items = self._items(srv)
        if not items:
            raise RuntimeError("no cluster servers returned by /api/cluster/server")

        def _uuid_of(it: Dict[str, Any]) -> str:
            """Return a server's UUID, trying each known field name; "" if none."""
            return (it.get("server_uuid") or it.get("uuid")
                    or it.get("id") or "")
        # Prefer the publisher (master) so the cert replicates across the cluster.
        for it in items:
            if it.get("is_publisher") or it.get("is_master"):
                uid = _uuid_of(it)
                if uid:
                    return uid
        # No publisher flagged: use the first server.
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
        # Work out which CA certs must be trusted; none means nothing to do.
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
        # Process each CA independently so one failure does not block the others.
        for pem in cas:
            # Identify the CA by its subject CN for idempotency checks.
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
            # Not yet trusted: POST it to the trust list as enabled.
            try:
                r = self.client._request(
                    "POST", "/api/cert-trust-list",
                    json={"cert_file": pem, "cert_usage": ["Others"],
                          "enabled": True})
            # Request failure: record the error and continue with the next CA.
            except Exception as e:
                logger.warning("trust-list POST %s failed: %s", cn, e)
                results.append({"ca": cn, "action": "error",
                                "message": str(e)[:160]})
                continue
            # Pull status and message out of the response.
            st = (r or {}).get("status", "ERROR") if isinstance(r, dict) else "ERROR"
            msg = str((r or {}).get("message", "") or "") if isinstance(r, dict) else ""
            # A duplicate/conflict (CA already trusted under a usage we didn't
            # match) is fine — the CA is present, which is all the PUT requires.
            low = msg.lower()
            if st == "ERROR" and any(k in low for k in
                                     ("exist", "duplicate", "already")):
                results.append({"ca": cn, "action": "already-trusted"})
            else:
                # Any other response is recorded as "added" with its status and message.
                results.append({"ca": cn, "action": "added", "status": st,
                                "message": msg[:160]})
        # Per-CA outcomes for the caller's log/response.
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
        # Treat None as empty, then reject inputs that are clearly not PEM certificate/key text.
        fullchain = fullchain or ""
        privkey = privkey or ""
        if not fullchain or "BEGIN CERTIFICATE" not in fullchain:
            return {"status": "ERROR",
                    "message": "invalid or empty fullchain PEM for cert install"}
        if not privkey or "PRIVATE KEY" not in privkey:
            return {"status": "ERROR",
                    "message": "invalid or empty privkey PEM for cert install"}

        # os reads the host/port settings; secrets generates a random bundle passphrase.
        import os
        import secrets
        # Address ClearPass will use to fetch the bundle; auto-detect when not configured.
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
        # Without a reachable address ClearPass cannot fetch the bundle.
        if not url_host:
            return {"status": "ERROR",
                    "message": "LM_CPPM_P12_HOST not set and could not auto-detect "
                               "this spoke's IP — set it to the address ClearPass "
                               "sees so ClearPass can fetch the PKCS12 bundle"}
        # Optional fixed port for the bundle server; 0 lets the OS pick a free one.
        try:
            bind_port = int(os.getenv("LM_CPPM_P12_PORT", "0") or 0)
        except ValueError:
            bind_port = 0
        # One-off random passphrase protecting the bundle while it is served.
        passphrase = secrets.token_urlsafe(18)
        # Default to the admin WebUI HTTPS certificate slot.
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

        # Find which cluster server to install on; failures become an error result.
        try:
            server_uuid = self._cluster_server_uuid()
        except RuntimeError as e:
            return {"status": "ERROR", "message": str(e)}
        # A server without a UUID cannot be addressed in the PUT URL.
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

        # http.server serves the bundle; threading runs it alongside the PUT call.
        import http.server
        import threading

        def _put_with(bundle: bytes) -> Dict[str, Any]:
            """Serve the bundle on a temporary HTTP server and PUT its URL to ClearPass."""
            # Start a threaded HTTP server for this bundle on the chosen (or ephemeral) port.
            handler = _make_p12_handler(bundle)
            srv = http.server.ThreadingHTTPServer(("0.0.0.0", bind_port), handler)
            # Find the actual port and serve requests on a background daemon thread.
            port = srv.server_address[1]
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            # Tell ClearPass where to fetch the bundle and the passphrase to open it.
            try:
                url = f"http://{url_host}:{port}/bundle.p12"
                return self.client._request(
                    "PUT",
                    f"/api/server-cert/name/{server_uuid}/{service_name}",
                    json={"pkcs12_file_url": url, "pkcs12_passphrase": passphrase},
                )
            # Always stop the temporary server once the PUT returns, even on error.
            finally:
                try:
                    srv.shutdown()
                    srv.server_close()
                # Shutdown errors are irrelevant; the server is being discarded anyway.
                except Exception:
                    pass
                # Give the server thread a moment to exit.
                thread.join(timeout=5)

        # Try the install with the bundle built above.
        res = _put_with(p12)
        # If ClearPass couldn't read the modern p12, retry once with the legacy
        # bundle (old builds need RC2/SHA-1). Match ONLY on p12-parse/read
        # markers — a "URL not trusted" / "could not fetch" 422 is a URL-reach
        # problem (retrying with a different bundle won't help) so it surfaces
        # as a plain ERROR without burning the legacy retry.
        if (isinstance(res, dict) and res.get("status") == "ERROR"
                and not used_legacy):
            # Only retry when the error text points at a bundle-format problem.
            body_txt = str(res.get("message", "")).lower()
            if any(k in body_txt for k in
                   ("pkcs12", "p12", "parse", "empty", "mac", "decrypt",
                    "unsupported")):
                logger.warning("modern p12 rejected by ClearPass (%s) — retrying "
                               "with openssl -legacy", res.get("message"))
                # Rebuild as a legacy bundle and retry the PUT once.
                try:
                    p12_leg = self._build_pkcs12_legacy(fullchain, privkey, passphrase)
                    res = _put_with(p12_leg)
                # Legacy build failed: keep the original error result.
                except Exception as e:
                    logger.warning("legacy p12 build failed: %s", e)

        # Failure: attach the trust-list results to the error for diagnosis.
        if isinstance(res, dict) and res.get("status") == "ERROR":
            res["trust_list"] = trust_results
            return res
        # Success: describe what was installed where.
        return {"status": "SUCCESS",
                "message": f"cert '{domain or 'lm-le'}' installed as {service_name} "
                           f"on ClearPass server {server_uuid}",
                "trust_list": trust_results}

    # --- Network Devices (RADIUS/TACACS clients) per tenant subnet ---
    # The hub sends each tenant's subnets plus the shared secrets from the
    # tenant's "radius" vault secret. LM owns only the devices whose
    # description carries NAD_MARKER for that tenant; anything else is left alone.

    # Prefix written into a device description to mark it as LM-owned for one tenant.
    NAD_MARKER = "LM-managed tenant="

    def _list_network_devices(self) -> List[Dict[str, Any]]:
        """List every ClearPass network device, paging 1000 at a time.

        Raises:
            RuntimeError: when the API returns an error.
        """
        # Accumulated devices and the current paging offset.
        out: List[Dict[str, Any]] = []
        offset = 0
        # Page through the device list.
        while True:
            # Fetch one page of network devices; API errors abort the listing.
            res = self.client._request("GET", "/api/network-device",
                                       params={"limit": 1000, "offset": offset})
            if isinstance(res, dict) and res.get("status") == "ERROR":
                raise RuntimeError(res.get("message") or "network-device list failed")
            # Add this page; a short page means the list is complete.
            page = self._items(res)
            out.extend(page)
            if len(page) < 1000:
                return out
            # Move on to the next page.
            offset += 1000

    def sync_network_devices(self, tenant_id: str, tenant_name: str, subnets: List[str],
                             radius_secret: str = "", tacacs_secret: str = "") -> Dict[str, Any]:
        """Make the tenant's LM-managed Network Devices match ``subnets``:
        create or update one device per subnet (name ``LM-<tenant>-<subnet>``)
        with the shared secrets, and delete the tenant's LM-managed devices
        whose subnet is gone. Returns {status, created, updated, removed,
        errors, error_details}."""
        # The tenant id, at least one subnet and at least one shared secret are required.
        tenant_id = (tenant_id or "").strip()
        if not tenant_id or not subnets or not (radius_secret or tacacs_secret):
            return {"status": "ERROR",
                    "message": "tenant_id, subnets and a RADIUS or TACACS secret are required"}
        # Marker identifying this tenant's LM-managed devices.
        marker = f"{self.NAD_MARKER}{tenant_id}"
        # Index this tenant's LM-managed devices by name (marker is before the first ";").
        try:
            existing = {d.get("name"): d for d in self._list_network_devices()
                        if marker == str(d.get("description") or "").split(";")[0]}
        # Listing failed: report the error without changing anything.
        except RuntimeError as e:
            return {"status": "ERROR", "message": str(e)}
        # Outcome counters and the names of devices that should exist.
        result = {"created": 0, "updated": 0, "removed": 0, "errors": 0, "error_details": []}
        wanted = set()
        # Create or update one network device per subnet.
        for subnet in subnets:
            # Device name derived from tenant and subnet ("/" is not allowed in names).
            name = f"LM-{tenant_id}-{subnet.replace('/', '_')}"
            wanted.add(name)
            # Device body: subnet as address range and a description carrying the marker.
            body = {"name": name, "ip_address": subnet,
                    "description": f"{marker}; {tenant_name or tenant_id} subnet (managed by LM)"}
            # Include whichever shared secrets were supplied.
            if radius_secret:
                body["radius_secret"] = radius_secret
            if tacacs_secret:
                body["tacacs_secret"] = tacacs_secret
            # Existing device: PATCH it in place.
            if name in existing:
                res = self.client._request("PATCH", f"/api/network-device/{existing[name]['id']}",
                                           json=body)
                key = "updated"
            # New device: POST it (vendor is required on create).
            else:
                res = self.client._request("POST", "/api/network-device",
                                           json={**body, "vendor_name": "Aruba"})
                key = "created"
            # Record the error, or count the create/update.
            if isinstance(res, dict) and res.get("status") == "ERROR":
                result["errors"] += 1
                result["error_details"].append(f"{subnet}: {res.get('message')}")
            else:
                result[key] += 1
        # Delete this tenant's LM-managed devices whose subnet is no longer wanted.
        for name, dev in existing.items():
            if name in wanted:
                continue
            # Delete the stale device and record the outcome.
            res = self.client._request("DELETE", f"/api/network-device/{dev['id']}")
            if isinstance(res, dict) and res.get("status") == "ERROR":
                result["errors"] += 1
                result["error_details"].append(f"remove {name}: {res.get('message')}")
            else:
                result["removed"] += 1
        # SUCCESS when everything worked, PARTIAL when any step failed.
        result["status"] = "SUCCESS" if not result["errors"] else "PARTIAL"
        return result
