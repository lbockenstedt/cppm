# cppm — ClearPass NAC

Aruba ClearPass Policy Manager spoke. Repo: `cppm`. `module_type = "nac"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

NAC spoke — endpoint auditing, session/access-tracker monitoring, and a hub-orchestrated IPAM→ClearPass endpoint sync. Source for the realtime NAC→IPAM reverse sync (`CPPM_GET_RECENT_SESSIONS` → `NETBOX_SYNC_ACCESS_TRACKER` on the netbox spoke).

## Entrypoints

`python3 -m src.control_plane` (`CPPMControlPlane`); spoke `CPPMSpoke` (**no base class** — not `BaseSpoke`); falls back to `run_standalone_mode()` (FastAPI `0.0.0.0:8000`, `/status`) if `--hub` omitted. systemd `lm-cppm.service`. Installer `install.sh` (clones to `/opt/lm/cppm`, venv, `.env`, unit; `PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/cppm/src`). `src/main.py` is a standalone demo script, not the entrypoint.

## Ports / backends

Talks to ClearPass REST (`CPPMClient`, `src/client.py`, `requests.Session`, TLS verify off). Auth: OAuth2 (`POST /api/oauth`) with **password grant preferred over client_credentials** when user creds are available (inherits the user's operator profile vs the API client's restricted profile); falls back to basic auth. Token cached with expiry (`expires_in`, 30s skew). Endpoints: `/api/session` (access tracker / recent sessions / user sessions / NAC status), `/api/endpoint` (device DB, by-MAC, by-IP, upsert/sync), `/api/role`. Standalone mode serves :8000.

## Environment variables

`.env.example` (loaded by `client.py`'s hand-rolled `load_dotenv()`): `CPPM_HOST`, `CPPM_CLIENT_ID`, `CPPM_CLIENT_SECRET`, `CPPM_USER`, `CPPM_PASS`; plus `SPOKE_ID`, `SPOKE_SECRET`, `HUB_URL`. Connection config also pushable via `UPDATE_CONFIG`.

## Install flags

`install.sh`: `--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs` (no-op). Keeps default PSK `lm-secret` for zero-touch.

## Key commands / handlers (`spoke.handle_command`, via `run_in_executor` — `CPPMQueries` is sync `requests`)

`GET_VERSION`, `CPPM_REFRESH_CACHE`, `UPDATE_CONFIG`, `TEST_AUTH` (tries every OAuth candidate, reports per-attempt), `PROBE_API` (raw `_request`). Cached: `CPPM_GET_ACCESS_TRACKER`, `CPPM_GET_DEVICE_DATABASE`, `CPPM_GET_NAC_STATUS`. Live: `CPPM_GET_RECENT_SESSIONS` (last `lookback_minutes` default 2 — **not cached**, time-sensitive, called ~60s by the hub realtime NAC→IPAM loop), `CPPM_GET_SYSTEM_HEALTH`, `GET_DEVICE` (by MAC), `LIST_ENDPOINTS`, `GET_ENDPOINT_DETAIL`, `GET_DEVICE_SESSIONS`, `GET_USER_SESSIONS`, `GET_LOGS` (auth logs by start/end), `LIST_ROLES`, `SEARCH_SESSIONS`, `CPPM_SYNC_ENDPOINTS` (hub-orchestrated IPAM→ClearPass: upserts a tenant's endpoint batch tagged `NetBox_Tenant_Slug`/`_Name`/`_ID` + `Tenant`/`Tenant_Slug` + `IP Address`/`Hostname`/`status:Known`; `replace=True` deletes endpoints previously tagged with this tenant absent from the batch; MAC-keyed upsert with IP fallback; IP-only records with no existing endpoint skipped; per-endpoint failures counted, never raised).

## Key files

`src/control_plane.py` (+ standalone FastAPI), `src/spoke.py` (~251 lines — `CPPMSpoke` non-BaseSpoke, dispatch, cache, `SENSITIVE_KEYS` masking), `src/client.py` (~178 lines — `CPPMClient`: `load_dotenv`, OAuth `_get_token`/`_try_oauth`, `_request`/`query`, `update_config`, 204-tolerant empty-body), `src/queries.py` (~1153 lines — `CPPMQueries`: all the get_* + `sync_endpoints` + helpers `_nas_*`, `_iso_dt`, `_norm_mac`, `_coerce_attrs`, `_endpoint_ips`, `_build_ip/mac_endpoint_map`, `_get_endpoint_by_ip`, `_upsert_endpoint`), `src/main.py` (demo), `install.sh`, `API_SPEC.md`, `requirements.txt`, `VERSION`.

## Notable behaviors & gotchas

- **`CPPMSpoke` is non-BaseSpoke** — `class CPPMSpoke:` (no `BaseSpoke` base). Implements `spoke_id`/`config`/`get_version`/`handle_command` itself; registered into the control plane's `modules` dict. The control plane also locally overrides `register_module` (same pattern as ldap). On the hub side, the agent-spoke role loader wraps it with `_RoleAdapter`.
- **Endpoint IP fallback scan** — ClearPass's `ip_address` filter only matches the first-class field; `_endpoint_ips` collects IPs from arbitrary attribute names and `_build_ip/mac_endpoint_map` do bounded paged scans (`ENDPOINT_SCAN_CAP` / a larger sync cap) so static-IP devices whose IP lives under a profiler-populated attribute are still matched and their MAC reused.
- **In-memory cache** for `CPPM_GET_ACCESS_TRACKER`/`CPPM_GET_DEVICE_DATABASE`/`CPPM_GET_NAC_STATUS` only; `CPPM_GET_RECENT_SESSIONS` deliberately uncached (realtime loop).
- **Token strategy** — password grant with `client_id` (configured, then `ClearPass`), then password grant with no `client_id`, then `client_credentials` (user operator profile > API client profile). Tolerates empty 204 bodies on DELETE.
- **`CPPM_SYNC_ENDPOINTS` tenant tagging** uses the same attribute names the at-auth-time Context Server Action uses (`NetBox_Tenant_Slug` etc.) so an Enforcement Policy matches the tenant whether the endpoint was synced in advance or tagged at auth time.

## Related pages

[architecture-topology.md](architecture-topology.md), [netbox.md](netbox.md) (NAC→IPAM reverse sync), [lm-hub.md](lm-hub.md), [install-flags.md](install-flags.md).