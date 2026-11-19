"""A ClearPass node that cannot issue OAuth tokens says why.

A node whose database is read-only (a subscriber, or a node cut off from its
publisher) answers every token request with HTTP 500 "SQLSTATE[P0001]: Raise
exception: 7 ERROR: Replication: Writes on t…" (the RA agent logged this 6014
times, then got 403 on every call). The client names that cause in its logs and
in the error of a request then sent without a token, and TEST_AUTH adds it to
the attempt. Any other failure reads exactly as before.
"""
import asyncio
import logging

import pytest
import requests

from src.client import CPPMClient, auth_failure_hint
from src.spoke import CPPMSpoke

# The start of the reply the RA agent's ClearPass gave (the log cut it off there).
READ_ONLY_BODY = ('{"title":"Internal Server Error","status":500,"detail":"SQLSTATE[P0001]: '
                  'Raise exception: 7 ERROR: Replication: Writes on t"}')
HINT = auth_failure_hint(READ_ONLY_BODY)
TOKEN_BODY = '{"access_token": "tok", "expires_in": 3600}'


@pytest.fixture(autouse=True)
def _no_env_credentials(monkeypatch):
    """Keep any CPPM_* settings of the machine running the tests out of the client."""
    for name in ("CPPM_HOST", "CPPM_USER", "CPPM_PASS", "CPPM_CLIENT_ID", "CPPM_CLIENT_SECRET"):
        monkeypatch.delenv(name, raising=False)


def _resp(status, text):
    """A requests.Response with this status code and body."""
    r = requests.Response()
    r.status_code = status
    r._content = text.encode()
    r.url = "https://cppm.example.com/api/x"
    return r


def _replies(monkeypatch, client, *responses):
    """Make the client's token requests return ``responses`` in turn."""
    queue = iter(responses)
    monkeypatch.setattr(client.session, "post", lambda *a, **k: next(queue))


def _api_client():
    """A client with API-client credentials only, as the RA agent was set up."""
    return CPPMClient(host="cppm.example.com", client_id="lm", client_secret="s")


def test_hint_matches_only_the_read_only_reply():
    assert HINT and "publisher" in HINT
    assert auth_failure_hint(READ_ONLY_BODY.upper()) == HINT
    assert auth_failure_hint('{"error":"invalid_client"}') == ""
    assert auth_failure_hint(None) == ""


def test_read_only_node_named_in_logs_and_in_the_refused_call(monkeypatch, caplog):
    c = _api_client()
    _replies(monkeypatch, c, _resp(500, READ_ONLY_BODY))
    monkeypatch.setattr(c.session, "request", lambda *a, **k: _resp(403, '{"detail":"Forbidden"}'))
    with caplog.at_level(logging.WARNING):
        r = c._request("GET", "api/session")
    # The refusal says what to do first, and still carries ClearPass's own reply.
    assert r["status"] == "ERROR" and r["code"] == 403
    assert r["message"].startswith(HINT) and "| body:" in r["message"]
    logs = [rec.getMessage() for rec in caplog.records]
    assert any("HTTP 500" in m and m.endswith(HINT) for m in logs)
    assert f"All OAuth2 attempts failed: {HINT}" in logs


def test_other_token_failures_read_as_before(monkeypatch, caplog):
    c = _api_client()
    _replies(monkeypatch, c, _resp(401, '{"error":"invalid_client"}'))
    monkeypatch.setattr(c.session, "request", lambda *a, **k: _resp(403, "Forbidden"))
    with caplog.at_level(logging.WARNING):
        r = c._request("GET", "api/session")
    assert r["code"] == 403 and HINT not in r["message"]
    assert "All OAuth2 attempts failed" in [rec.getMessage() for rec in caplog.records]


def test_hint_dropped_when_a_later_grant_works(monkeypatch):
    # Password grants are tried first; the second one gets a token.
    c = CPPMClient(host="cppm.example.com", user="admin", password="pw")
    _replies(monkeypatch, c, _resp(500, READ_ONLY_BODY), _resp(200, TOKEN_BODY))
    hints = []
    assert c._get_token(hints) == "tok"
    assert hints == []


def test_each_token_run_names_only_its_own_cause(monkeypatch):
    c = _api_client()
    _replies(monkeypatch, c, _resp(500, READ_ONLY_BODY), _resp(401, "{}"))
    first, second = [], []
    assert c._get_token(first) is None and first == [HINT]
    # The next run fails for another reason, so the old cause no longer applies.
    assert c._get_token(second) is None and second == []


OTHER_REPLY = (401, '{"error":"invalid_client"}')
READ_ONLY_REPLY = (500, READ_ONLY_BODY)


@pytest.mark.parametrize("a_reply, b_reply", [(OTHER_REPLY, READ_ONLY_REPLY), (READ_ONLY_REPLY, OTHER_REPLY)])
def test_a_concurrent_token_run_never_changes_this_calls_cause(monkeypatch, a_reply, b_reply):
    # Request B's token run on the same client, made while request A's call is in
    # flight, neither lends A its cause nor erases A's own.
    c = _api_client()
    _replies(monkeypatch, c, _resp(*a_reply), _resp(*b_reply))
    b_hints = []

    def a_call(*args, **kwargs):
        """A's API call: B's token run happens while it is in flight, then ClearPass refuses A."""
        assert c._get_token(b_hints) is None
        return _resp(403, "Forbidden")

    monkeypatch.setattr(c.session, "request", a_call)
    r = c._request("GET", "api/session")
    assert r["code"] == 403
    assert r["message"].startswith(HINT) == (a_reply == READ_ONLY_REPLY)
    assert HINT not in r["message"][len(HINT):]
    assert b_hints == ([HINT] if b_reply == READ_ONLY_REPLY else [])


def test_test_auth_attempt_carries_the_hint(monkeypatch):
    spoke = CPPMSpoke("cppm-1", {})
    spoke.client.update_config(host="cppm.example.com", client_id="lm", client_secret="s")
    _replies(monkeypatch, spoke.client, _resp(500, READ_ONLY_BODY))
    r = asyncio.new_event_loop().run_until_complete(spoke.handle_command("TEST_AUTH", {}))
    [attempt] = r["auth_attempts"]
    assert attempt["result"] == "HTTP 500" and attempt["hint"] == HINT


def test_test_auth_other_failure_has_no_hint(monkeypatch):
    spoke = CPPMSpoke("cppm-1", {})
    spoke.client.update_config(host="cppm.example.com", client_id="lm", client_secret="s")
    _replies(monkeypatch, spoke.client, _resp(401, '{"error":"invalid_client"}'))
    r = asyncio.new_event_loop().run_until_complete(spoke.handle_command("TEST_AUTH", {}))
    [attempt] = r["auth_attempts"]
    assert attempt["result"] == "HTTP 401" and "hint" not in attempt
