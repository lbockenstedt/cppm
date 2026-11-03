"""CPPM_SYNC_NADS: one LM-managed Network Device per tenant subnet."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import MagicMock

from client import CPPMClient
from queries import CPPMQueries


def _queries(existing):
    client = MagicMock(spec=CPPMClient)
    calls = []

    def request(method, path, **kw):
        calls.append((method, path, kw.get("json")))
        if method == "GET":
            return {"_embedded": {"items": existing}}
        return {"id": 1}
    client._request.side_effect = request
    return CPPMQueries(client), calls


def test_creates_updates_and_removes_only_the_tenants_devices():
    q, calls = _queries([
        {"id": 5, "name": "LM-dxp-10.0.0.0_8", "description": "LM-managed tenant=dxp; DXP"},
        {"id": 6, "name": "LM-dxp-192.168.0.0_16", "description": "LM-managed tenant=dxp; DXP"},
        {"id": 7, "name": "LM-dxpx-1.0.0.0_8", "description": "LM-managed tenant=dxpx; X"},
        {"id": 8, "name": "core-switches", "description": "hand made"},
    ])
    res = q.sync_network_devices("dxp", "DXP", ["10.0.0.0/8", "172.16.0.0/12"], radius_secret="r")
    assert (res["created"], res["updated"], res["removed"], res["errors"]) == (1, 1, 1, 0)
    writes = [c for c in calls if c[0] != "GET"]
    assert writes[0][:2] == ("PATCH", "/api/network-device/5")
    assert writes[0][2]["radius_secret"] == "r" and "tacacs_secret" not in writes[0][2]
    assert writes[1][0] == "POST" and writes[1][2]["ip_address"] == "172.16.0.0/12"
    assert writes[1][2]["name"] == "LM-dxp-172.16.0.0_12"
    assert writes[2][:2] == ("DELETE", "/api/network-device/6")
    assert len(writes) == 3


def test_requires_a_secret_and_subnets():
    q, calls = _queries([])
    assert q.sync_network_devices("dxp", "DXP", ["10.0.0.0/8"])["status"] == "ERROR"
    assert q.sync_network_devices("dxp", "DXP", [], radius_secret="r")["status"] == "ERROR"
    assert calls == []
