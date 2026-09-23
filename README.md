# cppm — ClearPass Policy Manager Spoke (Lab Manager Module)

Aruba ClearPass Policy Manager network access control (NAC) spoke for Lab Manager. Manages live session monitoring, endpoint auditing, device profiling, hub-brokered certificate installation, and bidirectional NAC/IPAM synchronization.

---

## Architecture & Overview

The `cppm` spoke integrates Aruba ClearPass Policy Manager with Lab Manager's hub-and-spoke infrastructure over an outbound WebSocket connection (port 443).

```
 +-------------------------------------------------------+
 |                     Lab Manager Hub                   |
 +-------------------------------------------------------+
           | (Outbound WebSocket over TLS, port 443)
           v
 +-------------------------------------------------------+
 |                 CPPMControlPlane                      |
 |  (Registers module "cppm", dispatches WebSocket cmds) |
 +-------------------------------------------------------+
           |
           v
 +-------------------------------------------------------+
 |             ClearPassSpoke (CPPMSpoke)                |
 |  - Spoke coordinator & command router                 |
 |  - In-memory cache & background refresher             |
 |  - Realtime NAC->IPAM sync pull                       |
 |  - TLS certificate import coordinator                 |
 +-------------------------------------------------------+
      |                                    |
      v                                    v
+-----------------------+        +-----------------------+
|      CPPMClient       |        |      CPPMQueries      |
| - OAuth2 token engine |        | - Access Tracker      |
| - Session management  |        | - Device DB & sync    |
| - TLS verify toggle   |        | - Certificate bundle  |
+-----------------------+        +-----------------------+
           \                                /
            v                              v
   +-----------------------------------------------+
   |      Aruba ClearPass Policy Manager REST      |
   |              https://<host>/api/              |
   +-----------------------------------------------+
```

- **Spoke Coordinator (`ClearPassSpoke` / `CPPMSpoke`):** Implements message dispatching, input validation, sensitive credential masking, and in-memory TTL caching.
- **REST Client (`ClearPassClient` / `CPPMClient`):** Handles HTTP communication with ClearPass REST endpoints, automated OAuth2 token generation and renewal with graceful fallback grants, and granular TLS certificate verification.
- **Background Cache Refresher:** Provides responsive responses for high-volume dashboard views (`CPPM_GET_ACCESS_TRACKER`, `CPPM_GET_DEVICE_DATABASE`, `CPPM_GET_NAC_STATUS`) backed by a 60-second TTL cache.
- **Realtime NAC→IPAM Sync (`CPPM_GET_RECENT_SESSIONS`):** Serves uncached, time-windowed session queries called by the hub every ~60 seconds to push newly connected MACs, IPs, switch ports, and NAS identifiers into NetBox.
- **TLS Certificate Distribution Target (`INSTALL_CERT`):** Imports Let's Encrypt / ACME TLS certificates issued by the `le` spoke into ClearPass's server certificates (HTTPS/RADIUS/RadSec) and updates the Certificate Trust List (CTL).

---

## Features

- **Access Tracker Live Session Inspection:** Real-time query of active authentication sessions, authorization status, client IP/MAC mappings, SSID/NAS port details, and RADIUS accounting records.
- **Endpoint & Device Database Management:** Device inventory scanning, manual and automated endpoint upserting, vendor MAC profiling, and tenant-tag synchronization (`NetBox_Tenant_Slug`, `NetBox_Tenant_Name`, `NetBox_Tenant_ID`).
- **Device Profiling & MAC Queries:** Detailed device lookups by MAC address or IP address with deep fallback scans across vendor attributes.
- **System Health Monitoring:** Cluster node status, service operational state, RADIUS/TACACS+ process health, and system resource metrics.
- **Robust OAuth2 Authentication:** Automated authentication negotiation prioritizing user password grants (for full operator privileges) with fallback to client credentials and HTTP basic auth.
- **SSL Verification Toggles:** Configurable TLS certificate verification (`verify_ssl` in `UPDATE_CONFIG` and `LM_CPPM_VERIFY_TLS` environment variable) supporting self-signed certificates in lab environments.

---

## Spoke Commands Reference

The following commands are supported by `CPPMSpoke`:

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `GET_VERSION` | *None* | Returns the spoke's semantic version from the `VERSION` file. |
| `UPDATE_CONFIG` | `host`, `user`, `password`, `client_id`, `client_secret`, `verify_ssl` | Reconfigures ClearPass target host, API credentials, and SSL verification mode dynamically. |
| `CPPM_REFRESH_CACHE` | *None* | Primes in-memory caches for Access Tracker, Device Database, and NAC Status. |
| `TEST_AUTH` | *None* | Probes configured credentials against `/api/oauth` across grant types and returns per-attempt diagnostics. |
| `PROBE_API` | `path`, `method`, `payload` | Executes an arbitrary raw REST request against the ClearPass API for troubleshooting. |
| `CPPM_GET_ACCESS_TRACKER` | `limit` (default 200), `offset` (default 0) | Fetches recent access authentication sessions from `/api/session` (cached for default query). |
| `CPPM_GET_RECENT_SESSIONS` | `lookback_minutes` (default 2) | Live, uncached session query for the hub's realtime NAC→IPAM reverse sync loop. |
| `CPPM_GET_DEVICE_DATABASE` | `limit` (default 200), `offset` (default 0), `status` | Lists registered endpoints from the ClearPass device inventory with optional status filter. |
| `CPPM_GET_NAC_STATUS` | *None* | Summarizes overall NAC operational health and cluster node states. |
| `CPPM_GET_SYSTEM_HEALTH` | *None* | Inspects server hardware metrics, disk, memory, CPU, and running daemon status. |
| `GET_DEVICE` | `mac` | Queries endpoint attributes and status for a specific MAC address. |
| `LIST_ENDPOINTS` | *None* | Returns endpoint listings from the device database. |
| `GET_ENDPOINT_DETAIL` | `mac` | Retrieves extended profiling data, attribute tags, and authorization history for an endpoint. |
| `INSTALL_CERT` | `fullchain`, `privkey`, `domain`, `service_name`, `chain` | Imports and binds an ACME TLS certificate into ClearPass HTTPS/RADIUS services and Certificate Trust List. |

---

<!-- INSTALLERS:START -->
## Installation

Every installer in this repo, with every flag and environment variable it accepts.
Installers are idempotent — re-running one updates code and preserves credentials.

### ClearPass (NAC) spoke — `install.sh`

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/cppm/main/install.sh \
  | sudo bash -s -- --hub lm-hub.lrbtechnologies.com
```

| Flag | Purpose |
| :--- | :--- |
| `--hub URL` | Hub WebSocket URL. A bare host is fine — `lm-hub.example.com` becomes `wss://lm-hub.example.com:443`, `host:port` gets a `wss://` prefix, and an explicit `ws://`/`wss://` is left alone. Omit it to auto-discover the hub (DNS `lm-hub.<suffix>`, then mDNS `_lm-hub._tcp.local.`). |
| `--id`, `--name` | Pin the spoke id. Omitted, the id derives from the hostname, so a renamed clone reconnects under its new name. |
| `--secret` | Pre-shared spoke secret. |
| `--hub-secret` | Hub PSK for auto-approval. Without it the spoke lands in *pending approval* in the WebUI. |
| `--all-prereqs` | Accepted and ignored — kept so the hub's install-module call doesn't abort. |

**Environment overrides:** `HUB_URL` (same normalization as `--hub`), `SPOKE_ID`.
<!-- INSTALLERS:END -->
