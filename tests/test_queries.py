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
                                   {"hostname": "ws"}, "t1", "LRB", "NetBox")

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
                                   {"hostname": "ws"}, "t1", "LRB", "NetBox")

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
        "count": 20,
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


def test_get_access_tracker_remains_active_only_and_logs_no_identity(queries, mock_client, caplog):
    """Dashboard counts stay active-only, and session identities are not logged."""
    caplog.set_level("INFO")
    mock_client.query.return_value = {
        "count": 1,
        "_embedded": {"items": [{
            "id": 1, "username": "private-user", "callingstation": "AA:BB:CC:DD:EE:01",
            "acctstarttime": "2026-07-01 10:00:00",
        }]},
    }

    res = queries.get_access_tracker()

    assert res["status"] == "SUCCESS"
    assert res["total"] == 1
    params = mock_client.query.call_args.kwargs["params"]
    assert json.loads(params["filter"]) == {"acctstoptime": {"$exists": False}}
    assert "private-user" not in caplog.text


def test_get_recent_access_tracker_includes_recent_closed_sessions(queries, mock_client):
    """The UI query uses acctstarttime, so recent completed authentications appear."""
    import datetime as _dt

    mock_client.query.return_value = {
        "count": 20,
        "_embedded": {"items": [{
            "id": 42, "username": "alice", "callingstation": "AA:BB:CC:DD:EE:01",
            "framedipaddress": "10.0.0.5", "acctstarttime": "2026-07-01 10:00:00",
            "acctstoptime": "2026-07-01 10:10:00",
        }]},
    }

    res = queries.get_recent_access_tracker(limit=50, offset=10, lookback_hours=24)

    assert res["status"] == "SUCCESS"
    assert res["total"] == 20
    assert res["has_more"] is True
    assert res["sessions"][0]["id"] == 42
    assert res["sessions"][0]["username"] == "alice"
    assert res["sessions"][0]["start_time"] == "2026-07-01T10:00:00"
    assert res["lookback_hours"] == 24
    params = mock_client.query.call_args.kwargs["params"]
    assert params["limit"] == 50
    assert params["offset"] == 10
    assert params["sort"] == "-id"
    filt = json.loads(params["filter"])
    assert "acctstoptime" not in filt
    assert "acctstarttime" in filt and "$gte" in filt["acctstarttime"]
    start = _dt.datetime.strptime(
        filt["acctstarttime"]["$gte"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=_dt.timezone.utc)
    end = _dt.datetime.strptime(
        filt["acctstarttime"]["$lte"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=_dt.timezone.utc)
    assert 0 <= (_dt.datetime.now(_dt.timezone.utc) - end).total_seconds() <= 5
    assert (end - start).total_seconds() == 24 * 3600
    assert res["window_start"] == filt["acctstarttime"]["$gte"]
    assert res["window_end"] == filt["acctstarttime"]["$lte"]


def test_recent_access_tracker_reuses_snapshot_end_for_next_pages(queries, mock_client):
    """Every page uses the first page's fixed upper timestamp boundary."""
    import json as _json

    mock_client.query.return_value = {"count": 1001, "_embedded": {"items": []}}
    end = "2026-07-02T10:00:00Z"

    result = queries.get_recent_access_tracker(
        limit=1000, offset=1000, lookback_hours=24, window_end=end
    )

    assert result["window_end"] == end
    assert result["window_start"] == "2026-07-01T10:00:00Z"
    assert result["has_more"] is True
    filt = _json.loads(mock_client.query.call_args.kwargs["params"]["filter"])
    assert filt["acctstarttime"] == {
        "$gte": "2026-07-01T10:00:00Z", "$lte": end,
    }


def test_recent_access_tracker_rejects_invalid_snapshot_end(queries, mock_client):
    """An invalid snapshot boundary is an explicit error, not a fresh window."""
    result = queries.get_recent_access_tracker(window_end="not-a-timestamp")

    assert result == {
        "status": "ERROR", "message": "Invalid window_end; expected UTC ISO timestamp",
    }
    mock_client.query.assert_not_called()


def test_get_recent_access_tracker_bounds_window_and_propagates_error(queries, mock_client):
    """A bad/oversized lookback cannot create an unbounded history query."""
    import json as _json

    mock_client.query.return_value = {"count": 0, "_embedded": {"items": []}}
    result = queries.get_recent_access_tracker(lookback_hours=10000)

    assert result["lookback_hours"] == 168
    filt = _json.loads(mock_client.query.call_args.kwargs["params"]["filter"])
    assert "acctstarttime" in filt

    mock_client.query.return_value = {"status": "ERROR", "message": "ClearPass unavailable"}
    error = queries.get_recent_access_tracker()
    assert error == {"status": "ERROR", "message": "ClearPass unavailable"}


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


def test_get_all_endpoints_pages_past_the_first_page(queries, mock_client):
    def page(path, params):
        start = params["offset"]
        rows = [{"mac_address": f"m{i}"} for i in range(start, min(start + 2, 5))]
        return {"count": 5, "_embedded": {"items": rows}}
    mock_client.query.side_effect = page

    res = queries.get_all_endpoints(page_size=2)

    assert [d["mac"] for d in res["devices"]] == ["m0", "m1", "m2", "m3", "m4"]
    assert res["total"] == 5


# ── NAC status: a failed count is unknown, not 0 ─────────────────────────────
def _count_reply(n):
    """A ClearPass calculate_count reply holding ``n``."""
    return {"_embedded": {"items": []}, "count": n}


def test_get_nac_status_reports_the_counts(queries, mock_client):
    mock_client.query.side_effect = [_count_reply(3), _count_reply(10), _count_reply(7), _count_reply(0)]
    assert queries.get_nac_status() == {"status": "SUCCESS", "active_sessions": 3,
                                        "total_devices": 10, "known_devices": 7,
                                        "unknown_devices": 0}


def test_get_nac_status_failed_count_is_unknown_not_zero(queries, mock_client):
    # A profile without Session read keeps its device counts; the rest show "—".
    denied = {"status": "ERROR", "message": "403 Client Error", "code": 403}
    mock_client.query.side_effect = [denied, _count_reply(10), _count_reply(7), {"_embedded": {}}]
    assert queries.get_nac_status() == {"status": "SUCCESS", "active_sessions": None,
                                        "total_devices": 10, "known_devices": 7,
                                        "unknown_devices": None}


def test_get_nac_status_all_failed_returns_the_first_error(queries, mock_client):
    # A ClearPass refusing every call (e.g. a read-only node with no token) is
    # not an empty network: the first error, with its reason, comes back.
    first = {"status": "ERROR", "message": "ClearPass refused a database write …", "code": 403}
    other = {"status": "ERROR", "message": "403 Client Error", "code": 403}
    mock_client.query.side_effect = [first, other, other, other]
    assert queries.get_nac_status() is first


def test_get_nac_status_no_counts_at_all_is_an_error(queries, mock_client):
    mock_client.query.return_value = {"_embedded": {"items": []}}
    assert queries.get_nac_status() == {"status": "ERROR", "message": "ClearPass returned no counts"}


# ── session MAC field: callingstationid (confirmed) or callingstation ───────

_MAC_FIELDS = ["callingstationid", "callingstation"]


@pytest.mark.parametrize("field", _MAC_FIELDS)
def test_session_readers_take_the_mac_from_either_calling_station_field(queries, mock_client, field):
    """ClearPass sends ``callingstationid``; older versions ``callingstation``.
    The access tracker and the realtime reverse-sync pull read either."""
    mock_client.query.return_value = {"count": 1, "_embedded": {"items": [{
        "id": 7, "username": "alice", field: "AA:BB:CC:DD:EE:01",
        "framedipaddress": "10.0.0.5", "acctstarttime": "2026-07-01 10:00:00"}]}}

    tracker = queries.get_access_tracker()["sessions"][0]
    assert tracker["mac"] == tracker["calling_station"] == "AA:BB:CC:DD:EE:01"
    recent = queries.get_recent_sessions(lookback_minutes=2)["sessions"]
    assert [s["mac"] for s in recent] == ["AA:BB:CC:DD:EE:01"]


@pytest.mark.parametrize("field", _MAC_FIELDS)
def test_search_finds_and_scopes_a_session_by_either_calling_station_field(queries, mock_client, field):
    """A scoped search matches the session by MAC, returns the MAC, and joins
    it to its endpoint's tenant (an empty MAC would drop it for a tenant)."""
    endpoint = {"id": 1, "mac_address": "aabbccddee01",
                "attributes": {"NetBox_Tenant_ID": "lrb"}}
    session = {"id": 9, "username": "alice", field: "AA:BB:CC:DD:EE:01",
               "framedipaddress": "10.0.0.5"}

    def query_side(path, params=None):
        if path == "/api/session":
            return {"count": 1, "_embedded": {"items": [session]}}
        return {"count": 1, "_embedded": {"items": [endpoint]}}

    mock_client.query.side_effect = query_side
    res = queries.search("aa-bb-cc-dd-ee-01", tenant_id="lrb")
    sessions = [r for r in res["results"] if r["type"] == "session"]
    assert [(r["mac"], r["tenant"]) for r in sessions] == [("AA:BB:CC:DD:EE:01", "lrb")]
