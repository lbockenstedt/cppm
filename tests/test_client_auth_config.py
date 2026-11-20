"""ClearPass client and spoke config handling: HTTPS only, re-auth on 401, no stale cache.

- A host configured as http:// would have sent the password, client secret and
  bearer token in cleartext; the base URL is always https.
- A cached token ClearPass has revoked (or expired early, e.g. after a restart)
  got 401 on every call until the cached expiry; the client now drops it and
  retries once with a new token.
- UPDATE_CONFIG to another appliance kept serving the old appliance's cached
  dashboard data for up to the TTL.
- UPDATE_CONFIG landing while a request was in flight could pair one
  appliance's URL with the other's token, password, OAuth grant or TLS setting.
"""
import asyncio

import pytest
import json
import requests

from src.client import CPPMClient, _https_base
from src.spoke import CPPMSpoke


@pytest.fixture(autouse=True)
def _no_env_credentials(monkeypatch):
    """Keep any CPPM_* settings of the machine running the tests out of the client."""
    for name in ("CPPM_HOST", "CPPM_USER", "CPPM_PASS", "CPPM_CLIENT_ID", "CPPM_CLIENT_SECRET"):
        monkeypatch.delenv(name, raising=False)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _resp(status, text):
    """A requests.Response with this status code and body."""
    r = requests.Response()
    r.status_code = status
    r._content = text.encode()
    r.url = "https://cppm.example.com/api/x"
    return r


class _FakeSession:
    """Hands out token replies for posts and API replies for requests, in turn."""

    def __init__(self, tokens, replies):
        self.verify = True
        self.auth = None
        self._tokens = iter(tokens)
        self._replies = iter(replies)
        self.posts = []
        self.requests = []

    def post(self, url, **kw):
        self.posts.append(url)
        return _resp(200, '{"access_token": "%s", "expires_in": 3600}' % next(self._tokens))

    def request(self, method, url, headers=None, **kw):
        self.requests.append((method, url, dict(headers or {})))
        return next(self._replies)


@pytest.mark.parametrize("host", ["http://cppm.lab", "HTTP://cppm.lab/", "cppm.lab", "https://cppm.lab"])
def test_base_url_is_always_https(host):
    assert _https_base(host) == "https://cppm.lab"


def test_http_host_never_sends_credentials_in_cleartext():
    client = CPPMClient(host="http://cppm.lab", client_id="lm", client_secret="s")
    client.session = _FakeSession(["t1"], [_resp(200, "{}")])
    client.query("/api/endpoint")
    assert all(u.startswith("https://") for u in client.session.posts)
    assert all(u.startswith("https://") for _, u, _ in client.session.requests)


def test_revoked_token_is_replaced_and_the_call_retried_once():
    client = CPPMClient(host="cppm.lab", client_id="lm", client_secret="s")
    client.session = _FakeSession(["old", "new"], [_resp(401, "{}"), _resp(200, '{"ok": 1}')])
    assert client.query("/api/endpoint") == {"ok": 1}
    auths = [h["Authorization"] for _, _, h in client.session.requests]
    assert auths == ["Bearer old", "Bearer new"]
    # The new token is cached for the next call.
    assert client._token == "new"


def test_second_401_is_reported_without_looping():
    client = CPPMClient(host="cppm.lab", client_id="lm", client_secret="s")
    client.session = _FakeSession(["old", "new"], [_resp(401, "{}"), _resp(401, "{}")])
    out = client.query("/api/endpoint")
    assert out["status"] == "ERROR" and out["code"] == 401
    assert len(client.session.requests) == 2


def test_drop_token_keeps_a_newer_token():
    client = CPPMClient(host="cppm.lab")
    client._token, client._token_expiry = "newer", 9e9
    client._drop_token(client._conn, "older")
    assert client._token == "newer"


def test_update_config_to_another_appliance_drops_the_dashboard_cache():
    spoke = CPPMSpoke("cppm-1", {})
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "cppm-a.lab", "user": "u"}))
    spoke._cache["CPPM_GET_NAC_STATUS"] = {"status": "SUCCESS", "from": "a"}
    spoke._cache_ts["CPPM_GET_NAC_STATUS"] = 9e18
    # The same config re-pushed (reconnect): cache kept.
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "cppm-a.lab", "user": "u"}))
    assert spoke._cache
    # Another appliance: cache dropped.
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "cppm-b.lab", "user": "u"}))
    assert spoke._cache == {} and spoke._cache_ts == {}


@pytest.mark.parametrize("change", [{"password": ""}, {"client_secret": ""}, {"password": "PW-2"},
                                    {"client_secret": "SEC-2"}])
def test_a_credential_change_on_the_same_appliance_is_another_login(change):
    """Same host, user and client_id but another credential (here dropping the
    password moves the client from the password grant to client_credentials):
    the cache is dropped, and a refresh still running under the old login
    does not store its result."""
    spoke = CPPMSpoke("cppm-1", {})
    _run(spoke.handle_command("UPDATE_CONFIG", dict(_A)))
    spoke._cache["CPPM_GET_NAC_STATUS"] = {"status": "SUCCESS", "from": "old login"}
    spoke._cache_ts["CPPM_GET_NAC_STATUS"] = 9e18

    def old_login_result(*a, **k):
        # The credential change lands while this refresh runs under the old login.
        _run(spoke.handle_command("UPDATE_CONFIG", {**_A, **change}))
        return {"status": "SUCCESS", "from": "old login"}

    spoke.queries.get_access_tracker = old_login_result
    spoke.queries.get_device_database = lambda *a, **k: {"status": "SUCCESS", "from": "new login"}
    spoke.queries.get_nac_status = lambda *a, **k: {"status": "SUCCESS", "from": "new login"}
    out = _run(spoke.refresh_cache())
    assert "CPPM_GET_ACCESS_TRACKER" not in spoke._cache
    assert out["refreshed"]["CPPM_GET_ACCESS_TRACKER"].startswith("Skipped")
    assert all(v.get("from") != "old login" for v in spoke._cache.values())


def test_refresh_started_before_a_switch_does_not_cache_old_data():
    spoke = CPPMSpoke("cppm-1", {})
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "cppm-a.lab"}))

    def old_appliance_result(*a, **k):
        # The switch lands while this refresh is talking to the old appliance.
        _run(spoke.handle_command("UPDATE_CONFIG", {"host": "cppm-b.lab"}))
        return {"status": "SUCCESS", "from": "a"}

    spoke.queries.get_access_tracker = old_appliance_result
    spoke.queries.get_device_database = lambda *a, **k: {"status": "SUCCESS", "from": "b"}
    spoke.queries.get_nac_status = lambda *a, **k: {"status": "SUCCESS", "from": "b"}
    out = _run(spoke.refresh_cache())
    assert "CPPM_GET_ACCESS_TRACKER" not in spoke._cache
    assert out["refreshed"]["CPPM_GET_ACCESS_TRACKER"].startswith("Skipped")


# Each appliance's credentials, and the token it issues. A call to one
# appliance must never carry anything that belongs to the other.
_A = {"host": "cppm-a.lab", "user": "USER-A", "password": "PW-A", "client_id": "CID-A", "client_secret": "SEC-A"}
_B = {"host": "cppm-b.lab", "user": "USER-B", "password": "PW-B", "client_id": "CID-B", "client_secret": "SEC-B"}
_OWNED = {"cppm-a.lab": ("USER-A", "PW-A", "CID-A", "SEC-A", "TOK-cppm-a.lab"),
          "cppm-b.lab": ("USER-B", "PW-B", "CID-B", "SEC-B", "TOK-cppm-b.lab")}


class _Net:
    """Records every call made by any Session the client creates."""

    def __init__(self):
        self.calls = []
        self.oauth_ok = True
        self.replies = []
        # Run once, inside the next call, to simulate UPDATE_CONFIG landing mid-request.
        self.during_next_call = None


@pytest.fixture
def net(monkeypatch):
    """Replace requests.Session so every Session (old and new configuration) records into one _Net."""
    rec = _Net()

    class _RecSession:
        def __init__(self):
            self.verify = True
            self.auth = None

        def _call(self, kind, url, kw):
            host = url.split("/")[2]
            rec.calls.append({"kind": kind, "host": host, "verify": self.verify, "sent": repr(kw)})
            hook, rec.during_next_call = rec.during_next_call, None
            if hook:
                hook()
            return host

        def post(self, url, **kw):
            host = self._call("post", url, kw)
            if not rec.oauth_ok:
                return _resp(401, "{}")
            return _resp(200, '{"access_token": "TOK-%s", "expires_in": 3600}' % host)

        def request(self, method, url, **kw):
            self._call("request", url, kw)
            return rec.replies.pop(0) if rec.replies else _resp(200, "{}")

    monkeypatch.setattr(requests, "Session", _RecSession)
    return rec


def _assert_no_crossing(net):
    """No call to one appliance carried the other's credentials or token."""
    for call in net.calls:
        foreign = [v for h, vals in _OWNED.items() if h != call["host"] for v in vals]
        assert not [v for v in foreign if v in call["sent"]], call


def test_switch_during_oauth_keeps_the_grant_run_on_one_appliance(net):
    client = CPPMClient(**_A)
    # The first grant is refused while UPDATE_CONFIG switches to B; the
    # remaining grants of this run must still go to A with A's credentials.
    net.oauth_ok = False
    net.during_next_call = lambda: client.update_config(**_B)
    client.query("/api/endpoint")
    _assert_no_crossing(net)
    assert {c["host"] for c in net.calls} == {"cppm-a.lab"}


def test_switch_before_401_retry_keeps_old_token_off_new_host_and_tls_setting(net):
    client = CPPMClient(**_A)
    client._get_token()
    net.replies = [_resp(401, "{}"), _resp(200, '{"ok": 1}')]
    # The switch to B (TLS verification off) lands while A answers 401; the
    # retry must still fetch A's token from A and send it to A, verifying TLS.
    net.during_next_call = lambda: client.update_config(**_B, verify_ssl=False)
    assert client.query("/api/endpoint") == {"ok": 1}
    _assert_no_crossing(net)
    assert {c["host"] for c in net.calls} == {"cppm-a.lab"}
    assert all(c["verify"] is True for c in net.calls)
    # B's configuration starts clean: no token from A was cached on it.
    assert client._token is None


def test_switch_during_failed_oauth_never_sends_new_basic_auth_to_old_host(net):
    client = CPPMClient(**_A)
    net.oauth_ok = False
    net.during_next_call = lambda: client.update_config(**_B)
    client.query("/api/endpoint")
    _assert_no_crossing(net)
    sent = [c for c in net.calls if c["kind"] == "request"]
    assert len(sent) == 1 and sent[0]["host"] == "cppm-a.lab" and "PW-A" in sent[0]["sent"]


def test_test_auth_switch_mid_run_keeps_old_appliance_and_tls_setting(net):
    spoke = CPPMSpoke("cppm-1", {})
    _run(spoke.handle_command("UPDATE_CONFIG", dict(_A, verify_ssl=True)))
    net.during_next_call = lambda: spoke.client.update_config(**_B, verify_ssl=False)
    out = spoke._test_auth()
    assert out["status"] == "SUCCESS"
    _assert_no_crossing(net)
    assert {c["host"] for c in net.calls} == {"cppm-a.lab"}
    assert all(c["verify"] is True for c in net.calls)


def test_an_empty_get_body_is_an_error_not_an_empty_list():
    """As SUCCESS, an empty GET body read as "not found" or as the end of a
    list; only a write may answer with no body (204 on DELETE)."""
    client = CPPMClient(host="cppm.lab", client_id="lm", client_secret="s")
    client.session = _FakeSession(["t1"], [_resp(200, ""), _resp(204, "")])
    res = client.query("/api/endpoint")
    assert res["status"] == "ERROR" and "Empty response" in res["message"]
    assert client._request("DELETE", "/api/endpoint/1") == {"status": "SUCCESS"}


def test_an_empty_network_device_page_aborts_the_nad_sync():
    """Through the real client: a full first page then an empty-body page must
    not end the list (devices on later pages would be re-created)."""
    from src.queries import CPPMQueries
    full = '{"_embedded": {"items": [%s]}}' % ",".join(
        '{"id": %d, "name": "other-%d", "description": ""}' % (i, i) for i in range(1000))
    client = CPPMClient(host="cppm.lab", client_id="lm", client_secret="s")
    client.session = _FakeSession(["t1"], [_resp(200, full), _resp(200, "")])
    res = CPPMQueries(client).sync_network_devices("dxp", "DXP", ["10.0.0.0/8"], radius_secret="r")
    assert res["status"] == "ERROR"
    assert [m for m, _, _ in client.session.requests if m != "GET"] == []


def test_a_non_json_200_body_is_reported_as_non_json():
    """requests' JSONDecodeError is also a RequestException, so the earlier
    transport branch used to swallow it with the bare decoder message."""
    client = CPPMClient(host="cppm.lab", client_id="lm", client_secret="s")
    client.session = _FakeSession(["t1"], [_resp(200, "<html>login</html>")])
    assert client.query("/api/endpoint") == {
        "status": "ERROR", "message": "Non-JSON response from CPPM"}


@pytest.mark.parametrize("decode_error", [
    json.JSONDecodeError("Expecting value", "<html>", 0),
    ValueError("No JSON object could be decoded")])
def test_a_non_json_body_is_non_json_on_any_requests_release(monkeypatch, decode_error):
    """Before 2.27 requests raised the json module's (or simplejson's) error,
    which has no requests.exceptions.JSONDecodeError to match: still a
    Non-JSON ERROR, never an uncaught exception."""
    client = CPPMClient(host="cppm.lab", client_id="lm", client_secret="s")
    client.session = _FakeSession(["t1"], [_resp(200, "<html>login</html>")])

    def old_json(self, **kw):
        raise decode_error
    monkeypatch.setattr(requests.Response, "json", old_json)
    monkeypatch.delattr(requests.exceptions, "JSONDecodeError", raising=False)
    assert client.query("/api/endpoint") == {
        "status": "ERROR", "message": "Non-JSON response from CPPM"}


def test_an_invalid_url_is_not_reported_as_non_json():
    """InvalidURL is a ValueError too; it must stay a transport error."""
    client = CPPMClient(host="cppm.lab", client_id="lm", client_secret="s")

    class _Bad(_FakeSession):
        def request(self, *a, **kw):
            raise requests.exceptions.InvalidURL("bad url")
    client.session = _Bad(["t1"], [])
    res = client.query("/api/endpoint")
    assert res["status"] == "ERROR" and res["message"] == "bad url"
