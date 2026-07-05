import json
import pytest
from unittest.mock import MagicMock
from src.client import CPPMClient
from src.queries import CPPMQueries

@pytest.fixture
def mock_client():
    return MagicMock(spec=CPPMClient)

@pytest.fixture
def queries(mock_client):
    return CPPMQueries(mock_client)

def test_get_device_by_mac_success(queries, mock_client):
    # Bare-list HAL response — _items() returns it as-is; queries filters by
    # a JSON `mac_address` filter on /api/endpoint.
    mock_client.query.return_value = [
        {"mac_address": "00:11:22:33:44:55", "attributes": {"Hostname": "test-device"}}
    ]

    result = queries.get_device_by_mac("00:11:22:33:44:55")

    assert result is not None
    assert result["mac_address"] == "00:11:22:33:44:55"
    mock_client.query.assert_called_once_with(
        "/api/endpoint",
        params={"filter": json.dumps({"mac_address": "00:11:22:33:44:55"}, separators=(",", ":"))})

def test_get_device_by_mac_dict_response(queries, mock_client):
    # HAL _embedded shape — _items() returns the first embedded list.
    mock_client.query.return_value = {
        "_embedded": {"items": [{"mac_address": "00:11:22:33:44:55", "attributes": {}}]}
    }

    result = queries.get_device_by_mac("00:11:22:33:44:55")

    assert result is not None
    assert result["mac_address"] == "00:11:22:33:44:55"

def test_get_device_by_mac_not_found(queries, mock_client):
    # Mock an empty list
    mock_client.query.return_value = []

    result = queries.get_device_by_mac("00:11:22:33:44:55")

    assert result is None

def test_get_user_sessions_success(queries, mock_client):
    mock_client.query.return_value = [
        {"session_id": "123", "user": "testuser", "status": "active"},
        {"session_id": "456", "user": "testuser", "status": "active"}
    ]

    result = queries.get_user_sessions("testuser")

    assert len(result) == 2
    assert result[0]["session_id"] == "123"
    mock_client.query.assert_called_once_with(
        "/api/session",
        params={"filter": json.dumps({"username": "testuser"}, separators=(",", ":"))})

# (test_list_endpoints_success removed — CPPMQueries has no list_endpoints; the
#  method was dropped and the dead main.py reference is a separate cleanup.)

def test_get_auth_logs_success(queries, mock_client):
    mock_client.query.return_value = [
        {"timestamp": "2026-06-07T10:00:00Z", "event": "auth_success"},
        {"timestamp": "2026-06-07T10:05:00Z", "event": "auth_failure"}
    ]

    result = queries.get_auth_logs("2026-06-07T00:00:00Z", "2026-06-07T23:59:59Z")

    assert len(result) == 2
    assert result[0]["event"] == "auth_success"
    mock_client.query.assert_called_once_with(
        "/api/session",
        params={"filter": json.dumps(
            {"acctstarttime": {"$gte": "2026-06-07T00:00:00Z", "$lte": "2026-06-07T23:59:59Z"}},
            separators=(",", ":"))})


# ── _upsert_endpoint PUT must include status (422 fix) ──────────────────────

def test_upsert_endpoint_put_preserves_existing_status(queries, mock_client):
    """ClearPass requires `status` on PUT (POST sets "Known"). The PUT body must
    carry it and preserve an existing non-default status (Disabled/Unknown)
    instead of flipping it back to Known."""
    queries.get_device_by_mac = MagicMock(return_value={
        "id": 3018, "status": "Disabled", "attributes": {"OS": "Win"}})
    mock_client._request.return_value = {"status": "SUCCESS"}

    res = queries._upsert_endpoint("aa:bb:cc:dd:ee:ff", "10.0.0.5",
                                   {"hostname": "ws"}, "t1", "lrb", "LRB", "NetBox")

    assert res == "pushed"
    call = mock_client._request.call_args
    assert call.args[0] == "PUT"
    body = call.kwargs["json"]
    assert body["id"] == 3018
    assert body["status"] == "Disabled"   # preserved, not reset to Known
    assert body["mac_address"] == "aa:bb:cc:dd:ee:ff"


def test_upsert_endpoint_put_defaults_status_known_when_missing(queries, mock_client):
    """An existing endpoint with no status field → PUT body defaults to Known
    (parity with the POST path) so ClearPass accepts the upsert."""
    queries.get_device_by_mac = MagicMock(return_value={
        "id": 3019, "attributes": {}})
    mock_client._request.return_value = {"status": "SUCCESS"}

    res = queries._upsert_endpoint("aa:bb:cc:dd:ee:ff", "10.0.0.5",
                                   {"hostname": "ws"}, "t1", "lrb", "LRB", "NetBox")

    assert res == "pushed"
    body = mock_client._request.call_args.kwargs["json"]
    assert body["status"] == "Known"


# ── get_recent_sessions (realtime NAC→IPAM reverse-sync pull) ───────────────

def test_get_recent_sessions_filters_by_acctstarttime_and_normalizes(queries, mock_client):
    """The realtime reverse sync pulls sessions started in the last N minutes.
    The /api/session filter is acctstarttime $gte <ISO start ~ now-lookback>;
    rows normalize to {mac, ip, nas_ip, nas_port, ...} and MAC-less rows drop."""
    import json as _json
    import datetime as _dt
    mock_client.query.return_value = {
        "count": 2,
        "_embedded": {"items": [
            {"id": 1, "username": "alice", "callingstation": "AA:BB:CC:DD:EE:01",
             "framedipaddress": "10.0.0.5", "nasipaddress": "10.0.0.254",
             "nas_name": "sw-core", "nasportid": "Ethernet1/0/12",
             "nasporttype": "Ethernet", "acctstarttime": "2026-06-30 10:00:00"},
            {"id": 2, "username": "", "callingstation": "",  # no MAC → dropped
             "framedipaddress": "10.0.0.6", "acctstarttime": "2026-06-30 10:00:30"},
        ]},
    }

    res = queries.get_recent_sessions(lookback_minutes=2)

    assert res["status"] == "SUCCESS"
    assert len(res["sessions"]) == 1            # MAC-less row dropped
    s = res["sessions"][0]
    assert s["mac"] == "AA:BB:CC:DD:EE:01"
    assert s["ip"] == "10.0.0.5"
    assert s["nas_ip"] == "10.0.0.254"
    assert s["nas_name"] == "sw-core"
    assert s["nas_port"] == "Ethernet1/0/12"
    assert s["nas_port_type"] == "Ethernet"
    assert s["username"] == "alice"
    assert s["start_time"] == "2026-06-30T10:00:00"   # space → T
    # Filter is acctstarttime $gte an ISO start ~ now-2min (UTC).
    params = mock_client.query.call_args.kwargs["params"]
    filt = _json.loads(params["filter"])
    assert "acctstarttime" in filt and "$gte" in filt["acctstarttime"]
    parsed = _dt.datetime.strptime(filt["acctstarttime"]["$gte"], "%Y-%m-%dT%H:%M:%SZ")
    age = (_dt.datetime.utcnow() - parsed).total_seconds()
    assert 90 <= age <= 150                       # ~2 minutes lookback
    assert res["window_start"] == filt["acctstarttime"]["$gte"]
    assert res["window_end"]


def test_get_recent_sessions_propagates_api_error(queries, mock_client):
    mock_client.query.return_value = {"status": "ERROR", "message": "boom"}
    res = queries.get_recent_sessions(lookback_minutes=2)
    assert res["status"] == "ERROR"


def test_get_device_sessions_filters_by_callingstationid(queries, mock_client):
    """ClearPass /api/session 422s on filter key ``callingstation`` ("cannot
    filter using 'callingstation'"); the filterable field is ``callingstationid``.
    Lock the corrected key + ClearPass lowercase-colon MAC normalization."""
    import json as _json
    mock_client.query.return_value = [
        {"id": 1, "username": "u", "framedipaddress": "10.0.0.5",
         "callingstationid": "aa:bb:cc:dd:ee:01",
         "acctstarttime": "2026-07-01 12:00:00", "state": "active"}]
    res = queries.get_device_sessions("AA-BB-CC-DD-EE-01")
    assert res["status"] == "SUCCESS"
    assert res["total"] == 1
    assert res["sessions"][0]["ip"] == "10.0.0.5"
    params = mock_client.query.call_args.kwargs["params"]
    assert _json.loads(params["filter"]) == {"callingstationid": "aa:bb:cc:dd:ee:01"}
    # Filtered path — exactly one server call.
    assert mock_client.query.call_count == 1


def test_get_device_sessions_falls_back_to_client_side_scan_on_filter_error(queries, mock_client):
    """If the server filter errors (field not filterable on this ClearPass build),
    fall back to a bounded unfiltered scan + client-side separator-insensitive MAC
    match so the lookup still returns matches — no 422 error storm, no empty."""
    match = {"id": 7, "framedipaddress": "10.0.0.5",
             "callingstationid": "aa:bb:cc:dd:ee:01",
             "acctstarttime": "", "state": "active"}
    other = {"id": 8, "framedipaddress": "10.0.0.9",
             "callingstationid": "11:22:33:44:55:66",
             "acctstarttime": "", "state": "active"}
    mock_client.query.side_effect = [
        {"status": "ERROR", "message": "cannot filter using 'callingstationid'"},
        {"_embedded": {"session": [match, other]}},
    ]
    res = queries.get_device_sessions("aabbccddee01", limit=20)
    assert res["status"] == "SUCCESS"
    assert len(res["sessions"]) == 1            # only the MAC match, not `other`
    assert res["sessions"][0]["ip"] == "10.0.0.5"
