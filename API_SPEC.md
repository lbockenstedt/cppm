# CPPM Spoke API Specification

The CPPM Spoke integrates Lab Manager with Aruba ClearPass Policy Manager (CPPM) for endpoint auditing and session monitoring.

## Command Set

### System
- **`get_version`**
  - **Purpose**: Retrieves the version of the CPPM spoke.
  - **Payload**: `{}`
  - **Response**: `{"version": "string"}`
- **`UPDATE_CONFIG`**
  - **Purpose**: Updates the connection credentials for the CPPM server.
  - **Payload**: `{"host": "string", "user": "string", "password": "string"}`
  - **Response**: `{"status": "success", "message": "..."}`
- **`TEST_AUTH`**
  - **Purpose**: Tries every OAuth grant the configured credentials allow
    against `POST /api/oauth` and reports each outcome (diagnostics).
  - **Payload**: `{}`
  - **Response**: `{"status": "SUCCESS", "auth_attempts": [{"attempt", "result", "detail"}, ...]}`.
    `result` is `SUCCESS`, `OK_BUT_NO_TOKEN`, `HTTP <code>` or `EXCEPTION`.
    A failed `HTTP <code>` attempt whose reply names a known cause also has
    `hint`, saying what to do: for "Replication: Writes on …" (the node
    refuses database writes, so it cannot issue a token; likely a
    subscriber, or cut off from its publisher), point LM at the cluster's
    publisher. With no credentials:
    `{"status": "ERROR", "message": "No credentials configured"}`.

### Auditing & Querying
- **`CPPM_GET_ACCESS_TRACKER`**
  - **Purpose**: Lists active sessions for dashboard counts, or active and
    completed authentications started in a recent window for the Access Tracker.
  - **Payload**: `{"limit": 200, "offset": 0, "lookback_hours": 24, "window_end": "2026-07-02T10:00:00Z"}`.
    `lookback_hours` is optional; when omitted, only active sessions are
    returned. The recent-history window is bounded to 1–168 hours and sorts
    newest session IDs first. Optional `window_end` fixes the inclusive upper
    timestamp bound across offset pages; without it, the spoke starts a new
    snapshot at the current UTC time. The hub pages with ClearPass's 1,000-row
    limit and reuses the first page's window end.
  - **Response**: `{"status": "SUCCESS", "sessions": [...], "total": n}`.
    Recent-history responses also include `window_start`, `window_end`,
    `lookback_hours`, and `has_more`; API failures return an `ERROR` response.
- **`CPPM_GET_NAC_STATUS`**
  - **Purpose**: The NAC landing page totals: sessions that have not ended,
    and all, Known and Unknown endpoints.
  - **Payload**: `{}`
  - **Response**: `{"status": "SUCCESS", "active_sessions", "total_devices", "known_devices", "unknown_devices"}`.
    Each count is an integer, or `null` when its query failed or returned no
    count (the WebUI shows "—", never 0). When every count query fails it
    returns the first query's `ERROR` reply unchanged (its `message` carries
    ClearPass's reason), or `{"status": "ERROR", "message": "ClearPass returned no counts"}` when
    none returned an error or a count. The spoke caches only `SUCCESS`.
- **`get_device`**
  - **Purpose**: Retrieves detailed information for a specific device by its MAC address.
  - **Payload**: `{"mac": "XX:XX:XX:XX:XX:XX"}`
  - **Response**: Device object containing endpoint details or an error.
- **`list_endpoints`**
  - **Purpose**: Lists endpoints matching specific criteria.
  - **Payload**: `{"filters": { "os": "Windows", "vendor": "Apple" }}`
  - **Response**: A list of endpoint objects.
- **`get_user_sessions`**
  - **Purpose**: Retrieves all active network sessions for a specific user.
  - **Payload**: `{"username": "string"}`
  - **Response**: A list of session objects.
- **`get_logs`**
  - **Purpose**: Retrieves authentication logs within a defined time window.
  - **Payload**: `{"start": "ISO-timestamp", "end": "ISO-timestamp"}`
  - **Response**: A list of log entries.

### Endpoint Sync
- **`CPPM_SYNC_ENDPOINTS`**
  - **Purpose**: Hub-orchestrated IPAM → ClearPass sync. Writes a tenant's
    endpoint batch (pulled from the configured IPAM source, e.g. NetBox) into
    ClearPass Device Inventory, tagged with the tenant so an Enforcement Policy
    can match the tenant the same way the at-auth-time Context Server Action
    (`NetBox_Tenant_Name`) does. When `replace: true`, the IPAM source is the
    source of truth — endpoints previously tagged with this tenant that are
    absent from the batch are deleted. Best-effort: per-endpoint failures are
    counted, never raised.
  - **Payload**: `{"tenant_id": "lrb", "tenant_name": "LRB", "source": "NetBox", "replace": true, "endpoints": [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "ws-01"}]}`
  - **Upsert key**: MAC (normalized to `aa:bb:cc:dd:ee:ff`), falling back to IP
    lookup when MAC is empty. Existing endpoints are PUT-merged (profiler
    attributes preserved) + tagged with `NetBox_Tenant_Name`/`_ID` and
    the human-readable `Tenant` (name), plus `IP Address`, `Hostname`, and
    `status: Known`; new ones are POSTed. Tenant ownership (for `replace` and
    search scoping) is `NetBox_Tenant_ID` = the LM `tenant_id`. Slug attributes
    left by older versions (`NetBox_Tenant_Slug`, `Tenant_Slug`) are removed on
    the next PUT. IP-only records with no existing endpoint
    are skipped (ClearPass endpoints are MAC-keyed). Records with neither MAC
    nor IP are dropped by the hub.
  - **Response**: `{"status": "SUCCESS"|"ERROR", "pushed": <int>, "errors": <int>, "skipped": <int>, "removed": <int>, "message": "..."}`

### Local Users (JIT 802.1X)
Used by the hub's `dot1x_jit` broker to create Policy Manager local users for
simulated 802.1X clients. Every user it creates carries the attribute
`LM_Managed: dot1x_jit`; create refuses to take over an
existing local user without that marker.
- **`CPPM_SYNC_NADS`** — `{"tenant_id": "dxp", "tenant_name": "DXP", "subnets": ["10.0.0.0/8"], "radius_secret": "...", "tacacs_secret": "..."}` →
  `{"status": "SUCCESS"|"PARTIAL"|"ERROR", "created", "updated", "removed", "errors", "error_details"}`. One Network Device per subnet (`LM-<tenant>-<subnet>`, vendor Aruba, description `LM-managed tenant=<tenant>; …`); the tenant's LM-managed devices whose subnet is gone are deleted. Devices without the marker are never touched. At least one secret is required.
- **`CPPM_CREATE_LOCAL_USER`** — `{"user_id": "jsmith", "password": "...", "role_name": "[Employee]"}` →
  `{"status", "user_id", "created": bool}`. An existing LM-managed user is re-keyed (PATCH); a non-managed one returns `ERROR` with `code: 409`.
- **`CPPM_SET_LOCAL_USER_PASSWORD`** — `{"user_id", "password"}` → `{"status", "user_id"}`.
- **`CPPM_DELETE_LOCAL_USER`** — `{"user_id"}` → `{"status", "user_id", "deleted": bool}` (absent = success, `deleted: false`).
- **`CPPM_GET_LOCAL_USER`** — `{"user_id"}` → `{"status", "found": bool, "user"}` (password never returned).

## Integration Flow
1. **Command Trigger**: The Hub sends a signed WebSocket message (e.g., `get_device`).
2. **Execution**: `CPPMSpoke` routes the command to `CPPMQueries`.
3. **API Call**: `CPPMQueries` uses `CPPMClient` to perform an authenticated REST request to the CPPM API.
4. **Response**: The results (endpoint, session, or log data) are returned to the Hub as a signed response.
