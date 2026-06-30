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
    # Mock a list response (common in CPPM)
    mock_client.query.return_value = [
        {"mac": "00:11:22:33:44:55", "hostname": "test-device", "os": "Windows 10"}
    ]

    result = queries.get_device_by_mac("00:11:22:33:44:55")

    assert result is not None
    assert result["mac"] == "00:11:22:33:44:55"
    assert result["hostname"] == "test-device"
    mock_client.query.assert_called_once_with("/api/endpoint", params={"mac": "00:11:22:33:44:55"})

def test_get_device_by_mac_dict_response(queries, mock_client):
    # Mock a dictionary response containing a list
    mock_client.query.return_value = {
        "endpoints": [
            {"mac": "00:11:22:33:44:55", "hostname": "test-device"}
        ]
    }

    result = queries.get_device_by_mac("00:11:22:33:44:55")

    assert result is not None
    assert result["mac"] == "00:11:22:33:44:55"

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
    mock_client.query.assert_called_once_with("/api/session", params={"username": "testuser"})

def test_list_endpoints_success(queries, mock_client):
    mock_client.query.return_value = [
        {"mac": "MAC1", "vendor": "Apple"},
        {"mac": "MAC2", "vendor": "Dell"}
    ]

    filters = {"vendor": "Apple"}
    result = queries.list_endpoints(filters)

    assert len(result) == 2
    mock_client.query.assert_called_once_with("/api/endpoint", params=filters)

def test_get_auth_logs_success(queries, mock_client):
    mock_client.query.return_value = [
        {"timestamp": "2026-06-07T10:00:00Z", "event": "auth_success"},
        {"timestamp": "2026-06-07T10:05:00Z", "event": "auth_failure"}
    ]

    result = queries.get_auth_logs("2026-06-07T00:00:00Z", "2026-06-07T23:59:59Z")

    assert len(result) == 2
    assert result[0]["event"] == "auth_success"
    mock_client.query.assert_called_once_with("/api/logs/auth", params={"start": "2026-06-07T00:00:00Z", "end": "2026-06-07T23:59:59Z"})


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
