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

### Auditing & Querying
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
    (`NetBox_Tenant_Slug`) does. When `replace: true`, the IPAM source is the
    source of truth — endpoints previously tagged with this tenant that are
    absent from the batch are deleted. Best-effort: per-endpoint failures are
    counted, never raised.
  - **Payload**: `{"tenant_id": "lrb", "tenant_slug": "lrb", "tenant_name": "LRB", "source": "NetBox", "replace": true, "endpoints": [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "ws-01"}]}`
  - **Upsert key**: MAC (normalized to `aa:bb:cc:dd:ee:ff`), falling back to IP
    lookup when MAC is empty. Existing endpoints are PUT-merged (profiler
    attributes preserved) + tagged with `NetBox_Tenant_Slug`/`_Name`/`_ID` and
    the human-readable `Tenant` (name) / `Tenant_Slug` (slug), plus `IP Address`,
    `Hostname`, and `status: Known`; new ones are POSTed. The `Tenant`/
    `Tenant_Slug` values are pulled from NetBox via the hub payload
    (`tenant_name` / `tenant_slug`). IP-only records with no existing endpoint
    are skipped (ClearPass endpoints are MAC-keyed). Records with neither MAC
    nor IP are dropped by the hub.
  - **Response**: `{"status": "SUCCESS"|"ERROR", "pushed": <int>, "errors": <int>, "skipped": <int>, "removed": <int>, "message": "..."}`

## Integration Flow
1. **Command Trigger**: The Hub sends a signed WebSocket message (e.g., `get_device`).
2. **Execution**: `CPPMSpoke` routes the command to `CPPMQueries`.
3. **API Call**: `CPPMQueries` uses `CPPMClient` to perform an authenticated REST request to the CPPM API.
4. **Response**: The results (endpoint, session, or log data) are returned to the Hub as a signed response.
