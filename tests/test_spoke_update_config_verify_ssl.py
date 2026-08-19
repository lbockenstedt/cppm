"""UPDATE_CONFIG threads a per-device verify_ssl into CPPMClient.

An EXPLICIT verify_ssl (True/False) always wins. When the field is ABSENT
(older/unedited nac_instances records, or the global /setup/cppm-config push
which sends the config verbatim without it) the spoke leaves the client's
current TLS-verify setting UNCHANGED — it must NOT force verification back on,
or a self-signed ClearPass would break on every reconnect/config re-push and the
``LM_CPPM_VERIFY_TLS=false`` escape hatch would be defeated.
"""
import asyncio

from src.spoke import CPPMSpoke


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_update_config_absent_verify_ssl_leaves_env_default(monkeypatch):
    # No env override -> client's secure default (True); an absent-field push
    # must not change it.
    monkeypatch.delenv("LM_CPPM_VERIFY_TLS", raising=False)
    spoke = CPPMSpoke("cppm-1", {})
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "172.16.1.16"}))
    assert spoke.client.session.verify is True


def test_update_config_absent_verify_ssl_preserves_env_disabled(monkeypatch):
    # The regression that broke live self-signed ClearPass: the spoke env
    # disables verification, then the hub pushes a config WITHOUT verify_ssl
    # (e.g. the global cppm-config verbatim push). Verification must STAY off.
    monkeypatch.setenv("LM_CPPM_VERIFY_TLS", "false")
    spoke = CPPMSpoke("cppm-1", {})
    assert spoke.client.session.verify is False
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "172.16.1.16"}))
    assert spoke.client.session.verify is False


def test_update_config_absent_verify_ssl_preserves_prior_false(monkeypatch):
    # A prior explicit "off" (per-instance verify_ssl=False) must survive a
    # later field-less push (e.g. a reconnect global re-push).
    monkeypatch.delenv("LM_CPPM_VERIFY_TLS", raising=False)
    spoke = CPPMSpoke("cppm-1", {})
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "172.16.1.16", "verify_ssl": False}))
    assert spoke.client.session.verify is False
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "172.16.1.16"}))
    assert spoke.client.session.verify is False


def test_update_config_honors_verify_ssl_false():
    spoke = CPPMSpoke("cppm-1", {})
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "172.16.1.16", "verify_ssl": False}))
    assert spoke.client.session.verify is False


def test_update_config_honors_verify_ssl_true_explicit(monkeypatch):
    monkeypatch.setenv("LM_CPPM_VERIFY_TLS", "false")  # explicit True still wins
    spoke = CPPMSpoke("cppm-1", {})
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "172.16.1.16", "verify_ssl": True}))
    assert spoke.client.session.verify is True
