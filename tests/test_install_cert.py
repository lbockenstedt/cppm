"""CPPMQueries.import_cert — install a hub-delivered LE cert as a ClearPass
server cert (default the admin HTTPS(RSA) cert).

ClearPass's server-cert API fetches a PKCS#12 bundle from a URL rather than
accepting inline PEM, so import_cert converts PEM→p12, stands up a short-lived
HTTP server (LM_CPPM_P12_HOST/PORT) serving the p12, discovers the cluster
server UUID via GET /api/cluster/server, then PUTs the p12 URL + passphrase to
/api/server-cert/name/{uuid}/{service}. These tests stub the REST client + the
HTTP fetch (the PUT mock never actually pulls the p12) and assert the request
shape, the routing, the LM_CPPM_P12_HOST gate, and the legacy-p12 fallback.
"""
import asyncio
import os

import pytest
from unittest.mock import MagicMock

from src.client import CPPMClient
from src.queries import CPPMQueries


# ── Real self-signed cert+key so the modern PKCS12 builder (cryptography)
# validates the PEM end-to-end. Skips the suite if cryptography isn't
# installed (the spoke host has it; CI should too). ────────────────────────
def _real_pair():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime
    except Exception:
        pytest.skip("cryptography not installed")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lm-test")])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(subj).issuer_name(subj)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    fullchain = cert.public_bytes(serialization.Encoding.PEM).decode()
    privkey = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    return fullchain, privkey


def _queries_with_cluster(mock_client, uuid="srv-uuid"):
    """A CPPMQueries whose client.query (→ /api/cluster/server) returns one
    server with the given uuid, and whose _request (the PUT) returns SUCCESS
    by default. Tests override _request.return_value / side_effect as needed."""
    mock_client.query.return_value = [{"uuid": uuid, "name": "cppm-node"}]
    mock_client._request.return_value = {"status": "SUCCESS", "id": "1"}
    return CPPMQueries(mock_client)


def test_import_cert_success_builds_p12_url_and_puts(monkeypatch):
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    monkeypatch.delenv("LM_CPPM_P12_PORT", raising=False)
    mock_client = MagicMock(spec=CPPMClient)
    q = _queries_with_cluster(mock_client, uuid="srv-uuid")
    fullchain, privkey = _real_pair()

    res = q.import_cert(fullchain=fullchain, privkey=privkey,
                        domain="a.example.com", service_name="HTTPS(RSA)")

    assert res["status"] == "SUCCESS"
    # PUT went to /api/server-cert/name/{uuid}/{service} with the p12 URL +
    # passphrase body. The URL host is LM_CPPM_P12_HOST; the port is the
    # ephemeral one the server bound.
    assert mock_client._request.called
    args, kwargs = mock_client._request.call_args
    assert args[0] == "PUT"
    assert args[1] == "/api/server-cert/name/srv-uuid/HTTPS(RSA)"
    body = kwargs["json"]
    assert body["pkcs12_file_url"].startswith("http://127.0.0.1:")
    assert body["pkcs12_file_url"].endswith("/bundle.p12")
    assert body["pkcs12_passphrase"]


def test_install_cert_handler_routes_to_import_cert():
    """The spoke's INSTALL_CERT branch unpacks fullchain/privkey/domain/
    service_name from the hub payload and delegates to queries.import_cert
    (in an executor), returning its result. service_name defaults to
    HTTPS(RSA) when the hub omits it."""
    from src.spoke import CPPMSpoke
    spoke = CPPMSpoke("test-cppm", {})
    sentinel = {"status": "SUCCESS", "message": "installed"}
    spoke.queries.import_cert = MagicMock(return_value=sentinel)

    data = {"fullchain": "PEM", "privkey": "KEY", "domain": "a.example.com",
            "chain": "", "module_type": "nac"}
    res = asyncio.new_event_loop().run_until_complete(
        spoke.handle_command("INSTALL_CERT", data))

    assert res == sentinel
    spoke.queries.import_cert.assert_called_once()
    kw = spoke.queries.import_cert.call_args.kwargs
    assert kw["fullchain"] == "PEM"
    assert kw["privkey"] == "KEY"
    assert kw["domain"] == "a.example.com"
    assert kw["service_name"] == "HTTPS(RSA)"  # default when hub omits it


def test_install_cert_handler_passes_explicit_service_name():
    from src.spoke import CPPMSpoke
    spoke = CPPMSpoke("test-cppm", {})
    spoke.queries.import_cert = MagicMock(
        return_value={"status": "SUCCESS"})
    data = {"fullchain": "PEM", "privkey": "KEY", "service_name": "RADIUS"}
    asyncio.new_event_loop().run_until_complete(
        spoke.handle_command("INSTALL_CERT", data))
    assert spoke.queries.import_cert.call_args.kwargs["service_name"] == "RADIUS"


def test_install_cert_handler_missing_material_is_error():
    from src.spoke import CPPMSpoke
    spoke = CPPMSpoke("test-cppm", {})
    spoke.queries.import_cert = MagicMock()
    res = asyncio.new_event_loop().run_until_complete(
        spoke.handle_command("INSTALL_CERT", {"fullchain": "", "privkey": ""}))
    assert res["status"] == "ERROR"
    spoke.queries.import_cert.assert_not_called()


def test_import_cert_missing_p12_host_is_error(monkeypatch):
    monkeypatch.delenv("LM_CPPM_P12_HOST", raising=False)
    mock_client = MagicMock(spec=CPPMClient)
    q = _queries_with_cluster(mock_client)
    fullchain, privkey = _real_pair()

    res = q.import_cert(fullchain=fullchain, privkey=privkey, domain="a.example.com")

    assert res["status"] == "ERROR"
    assert "LM_CPPM_P12_HOST" in res["message"]
    # Never reached the REST calls.
    mock_client._request.assert_not_called()


def test_import_cert_invalid_pem_is_error(monkeypatch):
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    mock_client = MagicMock(spec=CPPMClient)
    q = _queries_with_cluster(mock_client)

    res = q.import_cert(fullchain="not a cert", privkey="not a key")
    assert res["status"] == "ERROR"
    assert "fullchain" in res["message"]
    mock_client._request.assert_not_called()


def test_import_cert_cluster_server_error_is_error(monkeypatch):
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    mock_client = MagicMock(spec=CPPMClient)
    mock_client.query.return_value = {"status": "ERROR", "message": "auth failed"}
    mock_client._request.return_value = {"status": "SUCCESS"}
    q = CPPMQueries(mock_client)
    fullchain, privkey = _real_pair()

    res = q.import_cert(fullchain=fullchain, privkey=privkey, domain="a.example.com")

    assert res["status"] == "ERROR"
    assert "/api/cluster/server" in res["message"]
    assert "auth failed" in res["message"]
    mock_client._request.assert_not_called()


def test_import_cert_legacy_fallback_when_modern_builder_fails(monkeypatch):
    """If the modern PKCS12 builder is unavailable (no cryptography / bad PEM),
    import_cert falls back to the openssl -legacy builder and still PUTs."""
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    mock_client = MagicMock(spec=CPPMClient)
    q = _queries_with_cluster(mock_client)

    q._build_pkcs12 = lambda f, k, p: (_ for _ in ()).throw(
        RuntimeError("cryptography missing"))
    leg = []
    q._build_pkcs12_legacy = lambda f, k, p: leg.append(b"LEGACY-P12") or b"LEGACY-P12"

    res = q.import_cert(fullchain="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
                        privkey="-----BEGIN PRIVATE KEY-----\nY\n-----END PRIVATE KEY-----\n",
                        domain="a.example.com")

    assert res["status"] == "SUCCESS"
    assert leg == [b"LEGACY-P12"]  # legacy builder was used
    body = mock_client._request.call_args.kwargs["json"]
    assert body["pkcs12_file_url"].startswith("http://127.0.0.1:")


def test_import_cert_legacy_retry_on_parse_rejection(monkeypatch):
    """ClearPass rejects the modern p12 (422 parse-error body) → import_cert
    regenerates with openssl -legacy and retries the PUT once → SUCCESS."""
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    mock_client = MagicMock(spec=CPPMClient)
    q = _queries_with_cluster(mock_client)

    q._build_pkcs12 = lambda f, k, p: b"MODERN-P12"
    legacy_calls = []
    q._build_pkcs12_legacy = lambda f, k, p: legacy_calls.append(1) or b"LEGACY-P12"
    # First PUT (modern) → parse rejection; second PUT (legacy) → SUCCESS.
    mock_client._request.side_effect = [
        {"status": "ERROR", "message": "Could not fetch certificate. PKCS12 parse failed."},
        {"status": "SUCCESS"},
    ]

    res = q.import_cert(fullchain="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
                        privkey="-----BEGIN PRIVATE KEY-----\nY\n-----END PRIVATE KEY-----\n",
                        domain="a.example.com")

    assert res["status"] == "SUCCESS"
    assert len(legacy_calls) == 1  # legacy rebuild happened on the retry
    assert mock_client._request.call_count == 2


def test_import_cert_put_error_surfaces(monkeypatch):
    """A non-parse PUT error (e.g. 422 "URL not trusted") is surfaced as ERROR
    without triggering the legacy retry (the body markers don't match a p12
    parse failure)."""
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    mock_client = MagicMock(spec=CPPMClient)
    q = _queries_with_cluster(mock_client)
    fullchain, privkey = _real_pair()
    mock_client._request.return_value = {
        "status": "ERROR", "message": "URL not trusted", "code": 422}

    res = q.import_cert(fullchain=fullchain, privkey=privkey, domain="a.example.com")

    assert res["status"] == "ERROR"
    assert "URL not trusted" in res["message"]
    # No legacy retry — only one PUT.
    assert mock_client._request.call_count == 1