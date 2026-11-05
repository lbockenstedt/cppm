"""Command handler for the CPPM (ClearPass) spoke.

Translates commands sent by the Lab Manager hub into ClearPass REST calls via
CPPMQueries, runs the blocking HTTP work in a thread pool so the WebSocket
event loop stays responsive, and keeps a short-lived cache for dashboard views.
"""
# asyncio runs blocking ClearPass calls in a thread pool executor.
import asyncio
# Type hints only.
from typing import Any, Dict
# High-level ClearPass queries and the low-level REST client they use.
from queries import CPPMQueries
from client import CPPMClient
# os locates the VERSION file; logging records commands; time drives cache expiry.
import os
import logging
import time

# One named logger for this spoke.
logger = logging.getLogger("CPPMSpoke")

# Keys whose values are replaced with asterisks before command data is logged.
SENSITIVE_KEYS = {'password', 'secret', 'token', 'pass', 'auth_key', 'client_secret',
                  'radius_secret', 'tacacs_secret'}

def _mask(data: Any) -> Any:
    """Mask sensitive keys such as passwords and secret tokens in logged data."""
    # Dicts: recurse into nested containers and mask values of sensitive keys.
    if isinstance(data, dict):
        return {k: (_mask(v) if isinstance(v, (dict, list)) else ('********' if k.lower() in SENSITIVE_KEYS else v))
                for k, v in data.items()}
    # Lists: mask each element.
    elif isinstance(data, list):
        return [_mask(item) for item in data]
    # Plain values are returned unchanged.
    return data

class CPPMSpoke:
    """Handles command execution for the CPPM spoke.

    Maps Lab Manager Hub commands to ClearPass REST API queries, maintains
    short-lived memory caches for dashboard views, and orchestrates certificate installs.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        """Initialize the CPPM spoke instance with client and query handlers."""
        # Spoke identity, its instance config, the ClearPass client and query helper.
        self.spoke_id = spoke_id
        self.config = config
        self.client = CPPMClient()
        self.queries = CPPMQueries(self.client)
        # Cached results of the dashboard commands, keyed by command name.
        self._cache: Dict[str, Any] = {}
        # Per-command refresh timestamps so the cache can expire. Without a
        # TTL, _cache was populated only by an explicit CPPM_REFRESH_CACHE and
        # served indefinitely; a 60s TTL bounds staleness so a stale default
        # page can't be handed back indefinitely between refreshes.
        self._cache_ts: Dict[str, float] = {}
        self._cache_ttl = 60.0

    def get_version(self) -> str:
        """Read and return semantic version string from local VERSION file."""
        # VERSION sits one directory above this file; read it if present.
        try:
            version_path = os.path.join(os.path.dirname(__file__), "../VERSION")
            if os.path.exists(version_path):
                with open(version_path) as f:
                    return f.read().strip()
        # Unreadable file: fall through to "unknown".
        except Exception:
            pass
        # Version could not be determined.
        return "unknown"

    def _sync_call(self, fn, *args, **kwargs):
        """Runs a synchronous requests-based method in a thread to avoid blocking the event loop."""
        # Wrap the call in a lambda so positional and keyword arguments are preserved.
        return asyncio.get_event_loop().run_in_executor(None, lambda: fn(*args, **kwargs))

    async def refresh_cache(self) -> Dict[str, Any]:
        """Fetch fresh data for cached endpoints (Access Tracker, Device DB, NAC Status)."""
        # Dashboard commands that are cached, mapped to the query method that refreshes each.
        refresh_map = {
            "CPPM_GET_ACCESS_TRACKER": self.queries.get_access_tracker,
            "CPPM_GET_DEVICE_DATABASE": self.queries.get_device_database,
            "CPPM_GET_NAC_STATUS": self.queries.get_nac_status,
        }
        # Per-command outcome reported back to the caller.
        results = {}
        # Refresh each command independently so one failure does not block the others.
        for cmd, method in refresh_map.items():
            try:
                # Run the blocking query in a worker thread.
                res = await asyncio.get_event_loop().run_in_executor(None, method)
                # Cache successful results with the time they were fetched.
                if isinstance(res, dict) and res.get("status") == "SUCCESS":
                    self._cache[cmd] = res
                    self._cache_ts[cmd] = time.time()
                    results[cmd] = "OK"
                # Unsuccessful result: report its message without caching it.
                else:
                    results[cmd] = f"Error: {res.get('message') if isinstance(res, dict) else res}"
            # Unexpected exception: log it and report it for this command.
            except Exception as e:
                logger.error(f"Cache refresh failed for {cmd}: {e}")
                results[cmd] = f"Exception: {str(e)}"
        # Summary of what was refreshed.
        return {"status": "SUCCESS", "refreshed": results}

    async def handle_command(self, cmd_type: str, data: Dict[str, Any]) -> Any:
        """Dispatch incoming hub command to the corresponding CPPM client or query method."""
        # Commands are matched case-insensitively; log each one with secrets masked.
        normalized = cmd_type.upper()
        logger.info(f"CPPM command: {normalized} | data: {_mask(data)}")

        # GET_VERSION: report this spoke's version.
        if normalized == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        # CPPM_REFRESH_CACHE: re-prime the dashboard cache.
        if normalized == "CPPM_REFRESH_CACHE":
            return await self.refresh_cache()

        # UPDATE_CONFIG: point the client at a (new) ClearPass host with new credentials.
        if normalized == "UPDATE_CONFIG":
            host = data.get("host", "")
            # A host is mandatory.
            if not host:
                return {"status": "ERROR", "message": "Missing 'host'"}
            # Store the new config and reconfigure the client in place.
            self.config = data
            self.client.update_config(
                host=host,
                user=data.get("user", ""),
                password=data.get("password", ""),
                client_id=data.get("client_id", ""),
                client_secret=data.get("client_secret", ""),
                verify_ssl=data.get("verify_ssl"),
            )
            # Confirm the reconfiguration.
            return {"status": "SUCCESS", "message": f"Config updated for host {host}"}

        # TEST_AUTH: try every OAuth grant combination and report each outcome (diagnostics).
        if normalized == "TEST_AUTH":
            # Per-attempt results and the client whose settings are being tested.
            results = []
            client = self.client
            base = client._base_url()
            # Reuse the client's long-lived keep-alive Session instead of
            # building a fresh requests.Session (new TCP pool) per TEST_AUTH —
            # the client session already has verify=False and an OAuth token
            # path configured; the probe posts grant-specific bodies below.
            session = client.session
            # Build the same candidate grants the client would use, client_credentials first.
            candidates = []
            if client.client_id and client.client_secret:
                candidates.append({"grant_type": "client_credentials",
                                    "client_id": client.client_id,
                                    "client_secret": client.client_secret})
            # Password grant with each client id, then without a client id.
            if client.user and client.password:
                for cid in ([client.client_id] if client.client_id else []) + ["ClearPass"]:
                    body = {"grant_type": "password", "username": client.user, "password": client.password, "client_id": cid}
                    if client.client_secret:
                        body["client_secret"] = client.client_secret
                    candidates.append(body)
                candidates.append({"grant_type": "password", "username": client.user, "password": client.password})
            # Nothing to test without credentials.
            if not candidates:
                return {"status": "ERROR", "message": "No credentials configured"}
            # Attempt each grant and record the HTTP outcome.
            for body in candidates:
                label = f"grant={body.get('grant_type')} client_id={body.get('client_id', '<none>')}"
                try:
                    # Request a token for this grant.
                    resp = session.post(f"{base}/api/oauth", json=body, timeout=10)
                    # Record whether a token came back, plus the full response for inspection.
                    if resp.ok:
                        token = resp.json().get("access_token")
                        results.append({"attempt": label, "result": "SUCCESS" if token else "OK_BUT_NO_TOKEN",
                                        "detail": resp.json()})
                    # Record the HTTP status and a short body excerpt.
                    else:
                        results.append({"attempt": label, "result": f"HTTP {resp.status_code}",
                                        "detail": resp.text[:300]})
                # Record network/TLS exceptions.
                except Exception as e:
                    results.append({"attempt": label, "result": "EXCEPTION", "detail": str(e)})
            # Return every attempt's result.
            return {"status": "SUCCESS", "auth_attempts": results}

        # PROBE_API: send an arbitrary request to ClearPass (debugging aid).
        if normalized == "PROBE_API":
            # Read the path, HTTP method and optional JSON payload.
            path = data.get("path")
            method = data.get("method", "GET").upper()
            payload = data.get("payload", {})
            # A path is mandatory.
            if not path:
                return {"status": "ERROR", "message": "Missing path for PROBE_API"}
            # Run the request in a worker thread and return the raw result.
            try:
                res = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self.client._request(method, path, json=payload or None)
                )
                return res
            # Report any exception as an error result.
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

        # CPPM_GET_ACCESS_TRACKER: live active sessions page.
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

        # CPPM_GET_DEVICE_DATABASE: live endpoint page, optionally filtered by status.
        if normalized == "CPPM_GET_DEVICE_DATABASE":
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.get_device_database(
                    limit=data.get("limit", 200),
                    offset=data.get("offset", 0),
                    status=data.get("status"),
                )
            )

        # CPPM_GET_NAC_STATUS: live summary counts.
        if normalized == "CPPM_GET_NAC_STATUS":
            return await asyncio.get_event_loop().run_in_executor(None, self.queries.get_nac_status)

        # CPPM_GET_SYSTEM_HEALTH: ClearPass version / reachability.
        if normalized == "CPPM_GET_SYSTEM_HEALTH":
            return await asyncio.get_event_loop().run_in_executor(None, self.queries.get_system_health)

        # GET_DEVICE: one endpoint looked up by MAC.
        if normalized == "GET_DEVICE":
            mac = data.get("mac")
            # A MAC is mandatory.
            if not mac:
                return {"status": "ERROR", "message": "Missing 'mac'"}
            # Look it up in a worker thread and report found / not found.
            res = await asyncio.get_event_loop().run_in_executor(None, lambda: self.queries.get_device_by_mac(mac))
            return {"status": "SUCCESS", "device": res} if res else {"status": "ERROR", "message": "Device not found"}

        # LIST_ENDPOINTS: every endpoint in the inventory, paged.
        if normalized == "LIST_ENDPOINTS":
            return await asyncio.get_event_loop().run_in_executor(None, self.queries.get_all_endpoints)

        # GET_ENDPOINT_DETAIL: full attribute map for one endpoint (MAC required).
        if normalized == "GET_ENDPOINT_DETAIL":
            mac = data.get("mac")
            if not mac:
                return {"status": "ERROR", "message": "Missing 'mac'"}
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.get_endpoint_detail(mac)
            )

        # GET_DEVICE_SESSIONS: sessions for one device (MAC required).
        if normalized == "GET_DEVICE_SESSIONS":
            mac = data.get("mac")
            if not mac:
                return {"status": "ERROR", "message": "Missing 'mac'"}
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.get_device_sessions(mac)
            )

        # GET_USER_SESSIONS: sessions for one username (username required).
        if normalized == "GET_USER_SESSIONS":
            username = data.get("username")
            if not username:
                return {"status": "ERROR", "message": "Missing 'username'"}
            sessions = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.get_user_sessions(username)
            )
            return {"status": "SUCCESS", "sessions": sessions}

        # GET_LOGS: authentication sessions within a time window (start and end required).
        if normalized == "GET_LOGS":
            start = data.get("start")
            end = data.get("end")
            if not start or not end:
                return {"status": "ERROR", "message": "Missing 'start' or 'end'"}
            logs = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.get_auth_logs(start, end)
            )
            return {"status": "SUCCESS", "logs": logs}

        # LIST_ROLES: every role defined in ClearPass.
        if normalized == "LIST_ROLES":
            roles = await asyncio.get_event_loop().run_in_executor(None, self.queries.list_roles)
            return {"status": "SUCCESS", "roles": roles}

        # SEARCH_SESSIONS: global substring search, tenant-scoped.
        if normalized == "SEARCH_SESSIONS":
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.search(
                    data.get("q", ""),
                    tenant=data.get("tenant", ""),
                    is_admin=bool(data.get("is_admin", False)),
                )
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
                    # Operator-confirmed one-off: lets a sync remove more than
                    # half of the tenant's tagged endpoints (hub admin-ops).
                    allow_mass_remove=data.get("allow_mass_remove") is True,
                ),
            )

        if normalized == "CPPM_SYNC_NADS":
            # Hub-orchestrated: one Network Device per tenant subnet carrying the
            # tenant's RADIUS/TACACS shared secrets (see sync_network_devices).
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.queries.sync_network_devices(
                    data.get("tenant_id") or "", data.get("tenant_name") or "",
                    list(data.get("subnets") or []),
                    data.get("radius_secret") or "", data.get("tacacs_secret") or ""))

        if normalized in ("CPPM_CREATE_LOCAL_USER", "CPPM_SET_LOCAL_USER_PASSWORD",
                          "CPPM_DELETE_LOCAL_USER", "CPPM_GET_LOCAL_USER"):
            # Hub dot1x_jit broker: Policy Manager local users backing
            # simulated 802.1X identities. See CPPMQueries local-user section.
            uid = data.get("user_id") or data.get("username") or ""
            if normalized == "CPPM_CREATE_LOCAL_USER":
                # Bind the matching query method into a no-argument callable.
                fn = lambda: self.queries.create_local_user(
                    uid, data.get("password") or "",
                    role_name=data.get("role_name") or "[Employee]",
                    tenant_slug=data.get("tenant_slug") or "",
                    attributes=data.get("attributes") or None)
            elif normalized == "CPPM_SET_LOCAL_USER_PASSWORD":
                fn = lambda: self.queries.set_local_user_password(uid, data.get("password") or "")
            elif normalized == "CPPM_DELETE_LOCAL_USER":
                fn = lambda: self.queries.delete_local_user(uid)
            else:
                fn = lambda: self.queries.get_local_user(uid)
            # Run the chosen operation in a worker thread.
            return await asyncio.get_event_loop().run_in_executor(None, fn)

        if normalized == "INSTALL_CERT":
            # Hub-brokered cert distribution: install the delivered LE cert as
            # a ClearPass server cert. Default service is HTTPS(RSA) (the admin
            # WebUI cert); the caller may target RADIUS/RadSec/HTTPS(ECC) via
            # ``service_name``. Runs in an executor because import_cert uses
            # synchronous requests + a short-lived HTTP server to host the
            # PKCS12 bundle ClearPass fetches. See CPPMQueries.import_cert.
            # Pull the certificate parts and target service out of the command data.
            fullchain = (data.get("fullchain") or "")
            privkey = (data.get("privkey") or "")
            chain = (data.get("chain") or "")
            domain = (data.get("domain") or "")
            service = (data.get("service_name") or data.get("service")
                       or "HTTPS(RSA)")
            # The certificate and its private key are mandatory.
            if not fullchain or not privkey:
                return {"status": "ERROR",
                        "message": "INSTALL_CERT requires fullchain + privkey"}
            # Install in a worker thread (it blocks on HTTP and a temporary server).
            return await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.queries.import_cert(
                    fullchain=fullchain, privkey=privkey, domain=domain,
                    service_name=service, chain=chain),
            )

        # Anything else is an unknown command: log it and report an error.
        logger.warning(f"Unknown CPPM command: {cmd_type}")
        return {"status": "ERROR", "message": f"Unknown command: {cmd_type}"}
