"""Per-device TLS verification toggle (verify_ssl) on CPPMClient.

LM_CPPM_VERIFY_TLS is a process-wide env var fallback; the per-device
`verify_ssl` field (from the nac_instances config, threaded through
CPPMSpoke's UPDATE_CONFIG handler) must be able to override it per client
instance / per reconfigure, defaulting to secure (True) when unset.
"""
import os

import pytest

from src.client import CPPMClient


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("LM_CPPM_VERIFY_TLS", raising=False)


def test_default_construction_verifies_tls():
    c = CPPMClient(host="cppm.example.com")
    assert c.session.verify is True


def test_explicit_verify_ssl_false_on_construction():
    c = CPPMClient(host="cppm.example.com", verify_ssl=False)
    assert c.session.verify is False


def test_explicit_verify_ssl_true_overrides_env_disabled(monkeypatch):
    monkeypatch.setenv("LM_CPPM_VERIFY_TLS", "false")
    c = CPPMClient(host="cppm.example.com", verify_ssl=True)
    assert c.session.verify is True


def test_unset_verify_ssl_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("LM_CPPM_VERIFY_TLS", "false")
    c = CPPMClient(host="cppm.example.com")
    assert c.session.verify is False


def test_update_config_can_disable_verify():
    c = CPPMClient(host="cppm.example.com")
    assert c.session.verify is True
    c.update_config(host="172.16.1.16", verify_ssl=False)
    assert c.session.verify is False


def test_update_config_can_re_enable_verify():
    c = CPPMClient(host="cppm.example.com", verify_ssl=False)
    assert c.session.verify is False
    c.update_config(host="172.16.1.16", verify_ssl=True)
    assert c.session.verify is True


def test_update_config_without_verify_ssl_leaves_setting_unchanged():
    c = CPPMClient(host="cppm.example.com", verify_ssl=False)
    c.update_config(host="172.16.1.16")  # no verify_ssl kwarg
    assert c.session.verify is False


# ── string-valued verify_ssl (the bool("false") is True trap) ────────────────
# The nac_instances config can reach the client as a STRING ("false"/"0") — an
# older UI that stored the select as text, a hand-edited config, or a relay that
# stringified the JSON. Plain bool("false") is truthy, which would silently
# re-enable verification against a self-signed ClearPass and 502 every call.
def test_construction_string_false_disables_verify():
    for falsey in ("false", "False", "0", "no", "off", "none", ""):
        c = CPPMClient(host="cppm.example.com", verify_ssl=falsey)
        assert c.session.verify is False, f"{falsey!r} should disable verify"


def test_construction_string_true_enables_verify():
    for truthy in ("true", "True", "1", "yes", "on"):
        c = CPPMClient(host="cppm.example.com", verify_ssl=truthy)
        assert c.session.verify is True, f"{truthy!r} should enable verify"


def test_update_config_string_false_disables_verify():
    c = CPPMClient(host="cppm.example.com")  # starts verify=True
    c.update_config(host="172.16.1.16", verify_ssl="false")
    assert c.session.verify is False
