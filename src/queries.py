from typing import Any, Dict, List, Optional
from client import CPPMClient
import json
import logging
import re

logger = logging.getLogger("CPPMQueries")

class ResourceNotFound(Exception):
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
        sessions_result = self.client.query("/api/session", params={"calculate_count": "true", "limit": 1, "filter": active_filter})
        devices_result = self.client.query("/api/endpoint", params={"calculate_count": "true", "limit": 1})
        known_result = self.client.query(
            "/api/endpoint",
            params={"calculate_count": "true", "limit": 1, "filter": '{"status":"Known"}'},
        )
        unknown_result = self.client.query(
            "/api/endpoint",
            params={"calculate_count": "true", "limit": 1, "filter": '{"status":"Unknown"}'},
        )
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
                         ip_map: Optional[Dict[str, Dict[str, Any]]] = None) -> str:
        """Upsert one endpoint. Returns 'pushed' | 'skipped' | 'error'.

        Keyed on MAC (authoritative); falls back to IP lookup when MAC is empty.
        Existing endpoints are PUT-merged (so profiler-derived attributes are
        preserved); new ones are POSTed. IP-only records with no existing
        endpoint can't be created (ClearPass endpoints are MAC-keyed) → skipped.

        ``ip_map`` (built once per batch by ``sync_endpoints``) is a fallback
        for the IP lookup: the ClearPass ``ip_address`` filter only matches the
        first-class field, so an endpoint whose IP lives in an attribute
        (``IP Address`` etc.) is found here instead — letting the sync tag an
        existing endpoint whose MAC the NetBox IP record lacks.
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
            # validation_messages:["name"]. Preserve the endpoint's existing
            # name; fall back to mac, then ip, then a synthetic label so the
            # field is never empty (an IP-only upsert of an existing endpoint
            # has no mac to name it by).
            body["name"] = existing.get("name") or mac or ip or f"endpoint-{ep_id}"
            if mac:
                body["mac_address"] = mac
            res = self.client._request("PUT", f"/api/endpoint/{ep_id}", json=body)
            if isinstance(res, dict) and res.get("status") == "ERROR":
                logger.warning("endpoint PUT %s failed: %s", ep_id, res.get("message"))
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
        """
        removed = 0
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
                mac = self._norm_mac(ep.get("mac_address", ""))
                ip_val = attrs.get("IP Address") or attrs.get("ip_address") or ep.get("ip_address") or ""
                ip = ip_val.strip() if isinstance(ip_val, str) else ""
                key = mac or f"ip:{ip}"
                if key in batch_keys:
                    continue
                ep_id = ep.get("id")
                if not ep_id:
                    continue
                d = self.client._request("DELETE", f"/api/endpoint/{ep_id}")
                if isinstance(d, dict) and d.get("status") != "ERROR":
                    removed += 1
                else:
                    logger.warning("endpoint DELETE %s failed: %s", ep_id,
                                   d.get("message") if isinstance(d, dict) else d)
            count = res.get("count", 0) if isinstance(res, dict) else 0
            offset += limit
            if len(items) < limit or offset >= count:
                break
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
                                                 tenant_name, source, ip_map=ip_map)
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
        """Accounting sessions for a specific device by calling station (MAC address)."""
        result = self.client.query(
            "/api/session",
            params={
                "filter": json.dumps({"callingstation": mac}, separators=(",", ":")),
                "limit": limit,
                "calculate_count": "true",
            },
        )
        if isinstance(result, dict) and result.get("status") == "ERROR":
            return result
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
        total = result.get("count", len(sessions)) if isinstance(result, dict) else len(sessions)
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
