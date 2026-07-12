import asyncio
from typing import Any, Dict
from queries import CPPMQueries
from client import CPPMClient
import os
import logging
import time

logger = logging.getLogger("CPPMSpoke")

SENSITIVE_KEYS = {'password', 'secret', 'token', 'pass', 'auth_key', 'client_secret'}

def _mask(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: (_mask(v) if isinstance(v, (dict, list)) else ('********' if k.lower() in SENSITIVE_KEYS else v))
                for k, v in data.items()}
    elif isinstance(data, list):
        return [_mask(item) for item in data]
    return data

class CPPMSpoke:
    """
    Handles command execution for the CPPM spoke.
    Maps Hub commands to CPPM API queries.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        self.spoke_id = spoke_id
        self.config = config
        self.client = CPPMClient()
        self.queries = CPPMQueries(self.client)
        self._cache: Dict[str, Any] = {}
        # Per-command refresh timestamps so the cache can expire. Without a
        # TTL, _cache was populated only by an explicit CPPM_REFRESH_CACHE and
        # served indefinitely; a 60s TTL bounds staleness so a stale default
        # page can't be handed back indefinitely between refreshes.
        self._cache_ts: Dict[str, float] = {}
        self._cache_ttl = 60.0

    def get_version(self) -> str:
        try:
            version_path = os.path.join(os.path.dirname(__file__), "../VERSION")
            if os.path.exists(version_path):
                with open(version_path) as f:
                    return f.read().strip()
        except Exception:
            pass
        return "unknown"

    def _sync_call(self, fn, *args, **kwargs):
        """Runs a synchronous requests-based method in a thread to avoid blocking the event loop."""
        return asyncio.get_event_loop().run_in_executor(None, lambda: fn(*args, **kwargs))

    async def refresh_cache(self) -> Dict[str, Any]:
        refresh_map = {
            "CPPM_GET_ACCESS_TRACKER": self.queries.get_access_tracker,
            "CPPM_GET_DEVICE_DATABASE": self.queries.get_device_database,
            "CPPM_GET_NAC_STATUS": self.queries.get_nac_status,
        }
        results = {}
        for cmd, method in refresh_map.items():
            try:
                res = await asyncio.get_event_loop().run_in_executor(None, method)
                if isinstance(res, dict) and res.get("status") == "SUCCESS":
                    self._cache[cmd] = res
                    self._cache_ts[cmd] = time.time()
                    results[cmd] = "OK"
                else:
                    results[cmd] = f"Error: {res.get('message') if isinstance(res, dict) else res}"
            except Exception as e:
                logger.error(f"Cache refresh failed for {cmd}: {e}")
                results[cmd] = f"Exception: {str(e)}"
        return {"status": "SUCCESS", "refreshed": results}

    async def handle_command(self, cmd_type: str, data: Dict[str, Any]) -> Any:
        normalized = cmd_type.upper()
        logger.info(f"CPPM command: {normalized} | data: {_mask(data)}")

        if normalized == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if normalized == "CPPM_REFRESH_CACHE":
            return await self.refresh_cache()

        if normalized == "UPDATE_CONFIG":
            host = data.get("host", "")
            if not host:
                return {"status": "ERROR", "message": "Missing 'host'"}
            self.config = data
            self.client.update_config(
                host=host,
                user=data.get("user", ""),
                password=data.get("password", ""),
                client_id=data.get("client_id", ""),
                client_secret=data.get("client_secret", ""),
            )
            return {"status": "SUCCESS", "message": f"Config updated for host {host}"}

        if normalized == "TEST_AUTH":
            results = []
            client = self.client
            base = client._base_url()
            # Reuse the client's long-lived keep-alive Session instead of
            # building a fresh requests.Session (new TCP pool) per TEST_AUTH —
            # the client session already has verify=False and an OAuth token
            # path configured; the probe posts grant-specific bodies below.
            session = client.session
            candidates = []
            if client.client_id and client.client_secret:
                candidates.append({"grant_type": "client_credentials",
                                    "client_id": client.client_id,
                                    "client_secret": client.client_secret})
            if client.user and client.password:
                for cid in ([client.client_id] if client.client_id else []) + ["ClearPass"]:
                    body = {"grant_type": "password", "username": client.user, "password": client.password, "client_id": cid}
                    if client.client_secret:
                        body["client_secret"] = client.client_secret
                    candidates.append(body)
                candidates.append({"grant_type": "password", "username": client.user, "password": client.password})
            if not candidates:
                return {"status": "ERROR", "message": "No credentials configured"}
            for body in candidates:
                label = f"grant={body.get('grant_type')} client_id={body.get('client_id', '<none>')}"
                try:
                    resp = session.post(f"{base}/api/oauth", json=body, timeout=10)
                    if resp.ok:
                        token = resp.json().get("access_token")
                        results.append({"attempt": label, "result": "SUCCESS" if token else "OK_BUT_NO_TOKEN",
                                        "detail": resp.json()})
                    else:
                        results.append({"attempt": label, "result": f"HTTP {resp.status_code}",
                                        "detail": resp.text[:300]})
                except Exception as e:
                    results.append({"attempt": label, "result": "EXCEPTION", "detail": str(e)})
            return {"status": "SUCCESS", "auth_attempts": results}

        if normalized == "PROBE_API":
            path = data.get("path")
            method = data.get("method", "GET").upper()
            payload = data.get("payload", {})
            if not path:
                return {"status": "ERROR", "message": "Missing path for PROBE_API"}
            try:
                res = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self.client._request(method, path, json=payload or None)
                )
                return res
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        # Cached commands
        CACHED = {"CPPM_GET_ACCESS_TRACKER", "CPPM_GET_DEVICE_DATABASE", "CPPM_GET_NAC_STATUS"}
        # Serve from cache ONLY for a default query. The cache is keyed by command
        # NAME (refresh_cache primes it with defaults), so returning it for a
        # paged/filtered request (limit/offset/status) would hand back the cached
        # default page/filter — a request for page 2 or status="Unknown" must go live.
        _default_query = not any(k in data for k in ("limit", "offset", "status"))
        if (normalized in CACHED and _default_query and normalized in self._cache
                and (time.time() - self._cache_ts.get(normalized, 0)) < self._cache_ttl):
            return self._cache[normalized]

        if normalized == "CPPM_GET_ACCESS_TRACKER":
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.get_access_tracker(
                    limit=data.get("limit", 200), offset=data.get("offset", 0)
                )
            )

        if normalized == "CPPM_GET_RECENT_SESSIONS":
            # Realtime NAC→IPAM reverse sync pull: sessions started in the last
            # ``lookback_minutes`` (default 2). NOT in CACHED — time-sensitive,
            # the hub loop calls this every ~60s. See lm core/src/realtime_ipam_nac_sync.py.
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.get_recent_sessions(
                    lookback_minutes=int(data.get("lookback_minutes", 2))
                )
            )

        if normalized == "CPPM_GET_DEVICE_DATABASE":
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.get_device_database(
                    limit=data.get("limit", 200),
                    offset=data.get("offset", 0),
                    status=data.get("status"),
                )
            )

        if normalized == "CPPM_GET_NAC_STATUS":
            return await asyncio.get_event_loop().run_in_executor(None, self.queries.get_nac_status)

        if normalized == "CPPM_GET_SYSTEM_HEALTH":
            return await asyncio.get_event_loop().run_in_executor(None, self.queries.get_system_health)

        if normalized == "GET_DEVICE":
            mac = data.get("mac")
            if not mac:
                return {"status": "ERROR", "message": "Missing 'mac'"}
            res = await asyncio.get_event_loop().run_in_executor(None, lambda: self.queries.get_device_by_mac(mac))
            return {"status": "SUCCESS", "device": res} if res else {"status": "ERROR", "message": "Device not found"}

        if normalized == "LIST_ENDPOINTS":
            return await asyncio.get_event_loop().run_in_executor(None, self.queries.get_device_database)

        if normalized == "GET_ENDPOINT_DETAIL":
            mac = data.get("mac")
            if not mac:
                return {"status": "ERROR", "message": "Missing 'mac'"}
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.get_endpoint_detail(mac)
            )

        if normalized == "GET_DEVICE_SESSIONS":
            mac = data.get("mac")
            if not mac:
                return {"status": "ERROR", "message": "Missing 'mac'"}
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.get_device_sessions(mac)
            )

        if normalized == "GET_USER_SESSIONS":
            username = data.get("username")
            if not username:
                return {"status": "ERROR", "message": "Missing 'username'"}
            sessions = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.get_user_sessions(username)
            )
            return {"status": "SUCCESS", "sessions": sessions}

        if normalized == "GET_LOGS":
            start = data.get("start")
            end = data.get("end")
            if not start or not end:
                return {"status": "ERROR", "message": "Missing 'start' or 'end'"}
            logs = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.get_auth_logs(start, end)
            )
            return {"status": "SUCCESS", "logs": logs}

        if normalized == "LIST_ROLES":
            roles = await asyncio.get_event_loop().run_in_executor(None, self.queries.list_roles)
            return {"status": "SUCCESS", "roles": roles}

        if normalized == "SEARCH_SESSIONS":
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.search(data.get("q", ""))
            )

        if normalized == "CPPM_SYNC_ENDPOINTS":
            # Hub-orchestrated IPAM → ClearPass endpoint sync. The hub owns the
            # schedule + batch; this writes it into Device Inventory tagged with
            # the tenant attributes. replace=True (IPAM is source of truth) also
            # deletes endpoints previously tagged with this tenant absent from
            # the batch. See lm/docs/modules/cppm.md §4. Runs in an executor
            # because CPPMQueries uses synchronous requests.
            return await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.queries.sync_endpoints(
                    tenant_id=data.get("tenant_id", ""),
                    tenant_slug=data.get("tenant_slug", ""),
                    tenant_name=data.get("tenant_name", ""),
                    source=data.get("source", ""),
                    endpoints=data.get("endpoints", []) or [],
                    replace=bool(data.get("replace", True)),
                ),
            )

        if normalized == "INSTALL_CERT":
            # Hub-brokered cert distribution: install the delivered LE cert as
            # a ClearPass server cert. Default service is HTTPS(RSA) (the admin
            # WebUI cert); the caller may target RADIUS/RadSec/HTTPS(ECC) via
            # ``service_name``. Runs in an executor because import_cert uses
            # synchronous requests + a short-lived HTTP server to host the
            # PKCS12 bundle ClearPass fetches. See CPPMQueries.import_cert.
            fullchain = (data.get("fullchain") or "")
            privkey = (data.get("privkey") or "")
            chain = (data.get("chain") or "")
            domain = (data.get("domain") or "")
            service = (data.get("service_name") or data.get("service")
                       or "HTTPS(RSA)")
            if not fullchain or not privkey:
                return {"status": "ERROR",
                        "message": "INSTALL_CERT requires fullchain + privkey"}
            return await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.queries.import_cert(
                    fullchain=fullchain, privkey=privkey, domain=domain,
                    service_name=service, chain=chain),
            )

        logger.warning(f"Unknown CPPM command: {cmd_type}")
        return {"status": "ERROR", "message": f"Unknown command: {cmd_type}"}
