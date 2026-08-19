"""UPDATE_CONFIG threads a per-device verify_ssl into CPPMClient, defaulting
to secure (True) when the field is absent (older/unedited nac_instances
records, or a hub that predates this feature)."""
import asyncio

from src.spoke import CPPMSpoke


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_update_config_defaults_verify_ssl_true_when_absent():
    spoke = CPPMSpoke("cppm-1", {})
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "172.16.1.16"}))
    assert spoke.client.session.verify is True


def test_update_config_honors_verify_ssl_false():
    spoke = CPPMSpoke("cppm-1", {})
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "172.16.1.16", "verify_ssl": False}))
    assert spoke.client.session.verify is False


def test_update_config_honors_verify_ssl_true_explicit():
    spoke = CPPMSpoke("cppm-1", {})
    _run(spoke.handle_command("UPDATE_CONFIG", {"host": "172.16.1.16", "verify_ssl": True}))
    assert spoke.client.session.verify is True
