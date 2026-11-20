"""Diagnostic commands and command logging must not leak ClearPass or TLS secrets."""
import asyncio
import logging

from src.spoke import CPPMSpoke, _mask


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _Resp:
    """Minimal stand-in for a requests.Response from /api/oauth."""

    def __init__(self, status, body):
        self.status_code = status
        self.ok = status < 400
        self._body = body
        self.text = str(body)

    def json(self):
        return self._body


class _Session:
    """Records the OAuth posts and answers each with a token."""

    def __init__(self):
        self.posts = []

    def post(self, url, json=None, timeout=None):
        self.posts.append((url, json))
        return _Resp(200, {"access_token": "LIVE-TOKEN", "refresh_token": "REFRESH",
                           "token_type": "Bearer", "expires_in": 28800, "scope": None})


def test_install_cert_private_key_is_masked_in_the_command_log(caplog):
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----\n"
    masked = _mask({"fullchain": "-----BEGIN CERTIFICATE-----", "privkey": pem,
                    "nested": [{"api_key": "k1", "note": pem}], "domain": "cppm.lab"})
    assert masked["privkey"] == "********"
    assert masked["nested"][0]["api_key"] == "********"
    assert masked["nested"][0]["note"] == "********"
    # Non-secret fields stay readable for troubleshooting.
    assert masked["domain"] == "cppm.lab"
    assert masked["fullchain"] == "-----BEGIN CERTIFICATE-----"

    spoke = CPPMSpoke("cppm-1", {})
    with caplog.at_level(logging.INFO, logger="CPPMSpoke"):
        _run(spoke.handle_command("GET_VERSION", {"privkey": pem, "hub_secret": "s3"}))
    assert "PRIVATE KEY" not in caplog.text
    assert "s3" not in caplog.text


def test_test_auth_never_returns_the_access_token():
    spoke = CPPMSpoke("cppm-1", {})
    spoke.client.update_config(host="cppm.lab", client_id="lm", client_secret="cs")
    spoke.client.session = _Session()
    out = _run(spoke.handle_command("TEST_AUTH", {}))
    assert out["status"] == "SUCCESS"
    attempt = out["auth_attempts"][0]
    assert attempt["result"] == "SUCCESS"
    assert attempt["detail"] == {"token_type": "Bearer", "expires_in": 28800, "scope": None}
    assert "LIVE-TOKEN" not in str(out) and "REFRESH" not in str(out)


def test_test_auth_runs_off_the_event_loop(monkeypatch):
    spoke = CPPMSpoke("cppm-1", {})
    called = []

    async def fake_to_thread(fn, *a, **kw):
        called.append(fn)
        return {"status": "SUCCESS", "auth_attempts": []}

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)
    _run(spoke.handle_command("TEST_AUTH", {}))
    assert called == [spoke._test_auth]


def test_probe_api_refuses_non_get_methods():
    spoke = CPPMSpoke("cppm-1", {})
    sent = []
    spoke.client._request = lambda method, path, **kw: sent.append((method, path, kw)) or {"ok": 1}
    for method in ("DELETE", "post", "PUT", "PATCH"):
        out = _run(spoke.handle_command("PROBE_API", {"path": "/api/endpoint/1", "method": method}))
        assert out["status"] == "ERROR" and "GET only" in out["message"]
    assert sent == []
    # GET (explicit or default) is still relayed, with no body.
    assert _run(spoke.handle_command("PROBE_API", {"path": "/api/endpoint"})) == {"ok": 1}
    assert sent == [("GET", "/api/endpoint", {})]
