"""Tests for CPPMQueries.sync_endpoints (CPPM_SYNC_ENDPOINTS handler).

Self-contained: inserts src/ on sys.path and uses the flat imports the modules
use themselves, so it runs without a package install.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import MagicMock
import pytest

from client import CPPMClient
from queries import CPPMQueries


@pytest.fixture
def mock_client():
    return MagicMock(spec=CPPMClient)


@pytest.fixture
def queries(mock_client):
    return CPPMQueries(mock_client)


def _hal(items, count=None):
    """Build a ClearPass HAL-style endpoint list response."""
    return {"_embedded": {"items": items}, "count": count if count is not None else len(items)}


def test_sync_endpoints_creates_new_endpoint(queries, mock_client):
    # No existing endpoint by MAC; replace-scan finds no tagged endpoints.
    mock_client.query.return_value = _hal([], 0)
    mock_client._request.return_value = {"id": 123, "mac_address": "aa:bb:cc:dd:ee:ff"}

    result = queries.sync_endpoints(
        tenant_id="lrb", tenant_slug="lrb", tenant_name="LRB",
        source="NetBox", replace=True,
        endpoints=[{"ip": "172.16.1.62", "mac": "AA-BB-CC-DD-EE-FF", "hostname": "ws-01"}],
    )

    assert result["status"] == "SUCCESS"
    assert result["pushed"] == 1
    assert result["errors"] == 0
    assert result["removed"] == 0
    # POST called with normalized MAC + tenant tag attributes.
    method, path = mock_client._request.call_args.args
    assert method == "POST"
    assert path == "/api/endpoint"
    body = mock_client._request.call_args.kwargs["json"]
    assert body["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert body["status"] == "Known"
    assert body["attributes"]["NetBox_Tenant_Slug"] == "lrb"
    assert body["attributes"]["NetBox_Tenant_Name"] == "LRB"
    assert body["attributes"]["NetBox_Tenant_ID"] == "lrb"
    assert body["attributes"]["Tenant"] == "LRB"
    assert body["attributes"]["Tenant_Slug"] == "lrb"
    assert body["attributes"]["IP Address"] == "172.16.1.62"
    assert body["attributes"]["Hostname"] == "ws-01"


def test_sync_endpoints_replace_deletes_absent_tagged(queries, mock_client):
    # One existing endpoint tagged for this tenant; empty incoming batch →
    # it is absent → DELETE. (204 tolerated as SUCCESS by the client.)
    mock_client.query.return_value = _hal([
        {"id": 55, "mac_address": "11:22:33:44:55:66",
         "attributes": {"NetBox_Tenant_Slug": "lrb"}}
    ], 1)
    mock_client._request.return_value = {"status": "SUCCESS"}

    result = queries.sync_endpoints(
        tenant_id="lrb", tenant_slug="lrb", tenant_name="LRB",
        source="NetBox", replace=True, endpoints=[],
    )

    assert result["status"] == "SUCCESS"
    assert result["pushed"] == 0
    assert result["removed"] == 1
    method, path = mock_client._request.call_args.args
    assert method == "DELETE"
    assert path == "/api/endpoint/55"


def test_sync_endpoints_ip_only_no_existing_is_skipped(queries, mock_client):
    # IP-only record, no existing endpoint to tag → skipped (not an error),
    # and replace=False so no scan/delete.
    mock_client.query.return_value = _hal([], 0)

    result = queries.sync_endpoints(
        tenant_id="lrb", tenant_slug="lrb", tenant_name="LRB",
        source="NetBox", replace=False,
        endpoints=[{"ip": "10.0.0.5", "mac": "", "hostname": ""}],
    )

    assert result["status"] == "SUCCESS"
    assert result["pushed"] == 0
    assert result["skipped"] == 1
    assert result["errors"] == 0
    mock_client._request.assert_not_called()


def test_sync_endpoints_updates_existing_merging_attrs(queries, mock_client):
    # Existing endpoint found by MAC (with a profiler attribute that must be
    # preserved) → PUT-merge, not POST.
    mock_client.query.return_value = _hal([
        {"id": 77, "mac_address": "aa:bb:cc:dd:ee:ff",
         "attributes": {"Device Vendor": "Apple"}}
    ], 1)
    mock_client._request.return_value = {"id": 77}

    result = queries.sync_endpoints(
        tenant_id="lrb", tenant_slug="lrb", tenant_name="LRB",
        source="NetBox", replace=False,
        endpoints=[{"ip": "10.0.0.9", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "ws-09"}],
    )

    assert result["status"] == "SUCCESS"
    assert result["pushed"] == 1
    method, path = mock_client._request.call_args.args
    assert method == "PUT"
    assert path == "/api/endpoint/77"
    body = mock_client._request.call_args.kwargs["json"]
    # Profiler attribute preserved + tenant tag added.
    assert body["attributes"]["Device Vendor"] == "Apple"
    assert body["attributes"]["NetBox_Tenant_Slug"] == "lrb"
    assert body["attributes"]["Tenant"] == "LRB"
    assert body["attributes"]["Tenant_Slug"] == "lrb"
    assert body["attributes"]["Hostname"] == "ws-09"


def test_sync_endpoints_ip_only_resolved_via_attribute_ip_map(queries, mock_client):
    # IP-only NetBox record (no MAC). The ClearPass ``ip_address`` filter finds
    # nothing, but the endpoint exists with its IP stored under the ``IP Address``
    # attribute (as the sync itself writes) and a MAC. The batch IP→endpoint map
    # resolves it so the existing endpoint is PUT-tagged for the tenant instead
    # of being skipped.
    ep = {"id": 90, "mac_address": "11:22:33:44:55:66",
          "attributes": {"IP Address": "172.16.1.62", "Device Vendor": "Apple"}}

    def query_side(path, params=None):
        # ``_get_endpoint_by_ip`` sends a ``filter`` param → empty (the field
        # isn't populated); the map scan pages with ``limit``/``offset`` → the
        # endpoint carrying the ``IP Address`` attribute.
        if params and "filter" in params:
            return _hal([], 0)
        return _hal([ep], 1)

    mock_client.query.side_effect = query_side
    mock_client._request.return_value = {"id": 90}

    result = queries.sync_endpoints(
        tenant_id="lrb", tenant_slug="lrb", tenant_name="LRB",
        source="NetBox", replace=False,
        endpoints=[{"ip": "172.16.1.62", "mac": "", "hostname": "ws-62"}],
    )

    assert result["status"] == "SUCCESS"
    assert result["pushed"] == 1
    assert result["skipped"] == 0
    method, path = mock_client._request.call_args.args
    assert method == "PUT"
    assert path == "/api/endpoint/90"
    body = mock_client._request.call_args.kwargs["json"]
    # Existing profiler attribute preserved + tenant tags + IP/hostname added.
    assert body["attributes"]["Device Vendor"] == "Apple"
    assert body["attributes"]["NetBox_Tenant_Slug"] == "lrb"
    assert body["attributes"]["IP Address"] == "172.16.1.62"
    assert body["attributes"]["Hostname"] == "ws-62"


def test_sync_endpoints_ip_only_resolved_via_unexpected_attr_name(queries, mock_client):
    # IP-only NetBox record. The ClearPass ``ip_address`` filter finds nothing,
    # and the endpoint carries its IP under an attribute name NOT in any
    # hardcoded list ("Device IP" — a plausible profiler attribute). The
    # name-agnostic IP→endpoint map scans every attribute value, so the endpoint
    # is still found and PUT-tagged for the tenant instead of being skipped.
    ep = {"id": 91, "mac_address": "22:33:44:55:66:77",
          "attributes": {"Device IP": "10.9.9.9", "Device Vendor": "Cisco"}}

    def query_side(path, params=None):
        if params and "filter" in params:
            return _hal([], 0)
        return _hal([ep], 1)

    mock_client.query.side_effect = query_side
    mock_client._request.return_value = {"id": 91}

    result = queries.sync_endpoints(
        tenant_id="lrb", tenant_slug="lrb", tenant_name="LRB",
        source="NetBox", replace=False,
        endpoints=[{"ip": "10.9.9.9", "mac": "", "hostname": "ws-99"}],
    )

    assert result["status"] == "SUCCESS"
    assert result["pushed"] == 1
    assert result["skipped"] == 0
    method, path = mock_client._request.call_args.args
    assert method == "PUT"
    assert path == "/api/endpoint/91"
    body = mock_client._request.call_args.kwargs["json"]
    assert body["attributes"]["NetBox_Tenant_Slug"] == "lrb"
    assert body["attributes"]["IP Address"] == "10.9.9.9"


def test_sync_endpoints_ip_only_borrows_mac_from_session_then_creates(queries, mock_client):
    # IP-only NetBox record, no existing endpoint by IP (inventory scan empty),
    # but a ClearPass session carries framedipaddress=ip + callingstationid=MAC.
    # The sync borrows the MAC and POSTs a NEW tenant-tagged endpoint instead of
    # skipping.
    session = {"framedipaddress": "10.9.9.9", "callingstationid": "AABBCCDDEEFF",
               "username": "10.9.9.9"}

    def query_side(path, params=None):
        if path == "/api/session":
            return _hal([session], 1)
        # /api/endpoint: empty for both the inventory IP-map scan (no filter) and
        # the get_device_by_mac lookup (filter) → no existing endpoint.
        return _hal([], 0)

    mock_client.query.side_effect = query_side
    mock_client._request.return_value = {"id": 555}

    result = queries.sync_endpoints(
        tenant_id="lrb", tenant_slug="lrb", tenant_name="LRB",
        source="NetBox", replace=False,
        endpoints=[{"ip": "10.9.9.9", "mac": "", "hostname": "ws-99"}],
    )

    assert result["status"] == "SUCCESS"
    assert result["pushed"] == 1
    assert result["skipped"] == 0
    method, path = mock_client._request.call_args.args
    assert method == "POST"
    assert path == "/api/endpoint"
    body = mock_client._request.call_args.kwargs["json"]
    # Borrowed MAC normalized to colon form; tenant tags + IP/hostname written.
    assert body["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert body["status"] == "Known"
    assert body["attributes"]["NetBox_Tenant_Slug"] == "lrb"
    assert body["attributes"]["IP Address"] == "10.9.9.9"
    assert body["attributes"]["Hostname"] == "ws-99"


def test_sync_endpoints_borrowed_mac_merges_existing_no_duplicate(queries, mock_client):
    # IP-only record; session lends a MAC, but an endpoint with that MAC already
    # exists (profiler attribute to preserve). The sync PUT-merges it (tags the
    # tenant) rather than POSTing a duplicate.
    session = {"framedipaddress": "10.9.9.9", "callingstationid": "AABBCCDDEEFF"}
    existing = {"id": 77, "mac_address": "aa:bb:cc:dd:ee:ff",
                "attributes": {"Device Vendor": "Apple"}}

    def query_side(path, params=None):
        if path == "/api/session":
            return _hal([session], 1)
        if params and "filter" in params:
            return _hal([existing], 1)  # get_device_by_mac finds it
        return _hal([], 0)              # inventory IP-map scan: empty

    mock_client.query.side_effect = query_side
    mock_client._request.return_value = {"id": 77}

    result = queries.sync_endpoints(
        tenant_id="lrb", tenant_slug="lrb", tenant_name="LRB",
        source="NetBox", replace=False,
        endpoints=[{"ip": "10.9.9.9", "mac": "", "hostname": "ws-99"}],
    )

    assert result["status"] == "SUCCESS"
    assert result["pushed"] == 1
    method, path = mock_client._request.call_args.args
    assert method == "PUT"
    assert path == "/api/endpoint/77"
    body = mock_client._request.call_args.kwargs["json"]
    assert body["attributes"]["Device Vendor"] == "Apple"  # preserved
    assert body["attributes"]["NetBox_Tenant_Slug"] == "lrb"
    assert body["attributes"]["IP Address"] == "10.9.9.9"


def test_sync_endpoints_drops_records_with_neither_mac_nor_ip(queries, mock_client):
    mock_client.query.return_value = _hal([], 0)
    result = queries.sync_endpoints(
        "lrb", "lrb", "LRB", "NetBox", replace=False,
        endpoints=[{"ip": "", "mac": "", "hostname": "x"}],
    )
    assert result["pushed"] == 0
    assert result["skipped"] == 0
    assert result["errors"] == 0
    mock_client._request.assert_not_called()