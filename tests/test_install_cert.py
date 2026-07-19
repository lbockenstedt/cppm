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
    by default. Tests override _request.return_value / side_effect as needed.

    The cluster/server item uses ``server_uuid`` (ClearPass's real field); the
    legacy ``uuid``/``id`` keys are NOT present on the wire."""
    mock_client.query.return_value = [{"server_uuid": uuid, "name": "cppm-node"}]
    mock_client._request.return_value = {"status": "SUCCESS", "id": "1"}
    return CPPMQueries(mock_client)


def test_cluster_server_uuid_prefers_publisher(monkeypatch):
    """_cluster_server_uuid returns the publisher's server_uuid when the
    publisher is not the first item (cert should land on the publisher so it
    replicates across the cluster)."""
    monkeypatch.delenv("LM_CPPM_P12_HOST", raising=False)
    mock_client = MagicMock(spec=CPPMClient)
    mock_client.query.return_value = [
        {"server_uuid": "subscriber-uuid", "name": "sub", "is_publisher": False},
        {"server_uuid": "publisher-uuid", "name": "pub", "is_publisher": True},
    ]
    q = CPPMQueries(mock_client)
    assert q._cluster_server_uuid() == "publisher-uuid"


def test_cluster_server_uuid_legacy_is_master(monkeypatch):
    """Pre-6.11 ClearPass uses ``is_master`` instead of ``is_publisher``."""
    monkeypatch.delenv("LM_CPPM_P12_HOST", raising=False)
    mock_client = MagicMock(spec=CPPMClient)
    mock_client.query.return_value = [
        {"server_uuid": "leg-uuid", "name": "old", "is_master": True},
    ]
    q = CPPMQueries(mock_client)
    assert q._cluster_server_uuid() == "leg-uuid"


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
    # Force auto-detection to fail so the unset-env ERROR path is exercised
    # (on a host with a default route _detect_local_ipv4 would otherwise
    # supply a host and proceed past the gate).
    import src.queries as qmod
    monkeypatch.setattr(qmod, "_detect_local_ipv4", lambda: "")
    mock_client = MagicMock(spec=CPPMClient)
    q = _queries_with_cluster(mock_client)
    fullchain, privkey = _real_pair()

    res = q.import_cert(fullchain=fullchain, privkey=privkey, domain="a.example.com")

    assert res["status"] == "ERROR"
    assert "LM_CPPM_P12_HOST" in res["message"]
    # Never reached the REST calls.
    mock_client._request.assert_not_called()


def test_import_cert_auto_detects_p12_host(monkeypatch):
    """Unset LM_CPPM_P12_HOST + a reachable default route → auto-detect the
    source IP and proceed to the PUT (no manual env needed)."""
    monkeypatch.delenv("LM_CPPM_P12_HOST", raising=False)
    import src.queries as qmod
    monkeypatch.setattr(qmod, "_detect_local_ipv4", lambda: "10.0.0.5")
    mock_client = MagicMock(spec=CPPMClient)
    mock_client._request.return_value = {"status": "SUCCESS", "message": "ok"}
    q = _queries_with_cluster(mock_client)
    fullchain, privkey = _real_pair()

    res = q.import_cert(fullchain=fullchain, privkey=privkey, domain="a.example.com")

    assert res["status"] == "SUCCESS"
    # The PUT URL host is the auto-detected IP.
    put_call = mock_client._request.call_args
    url = put_call.kwargs["json"]["pkcs12_file_url"]
    assert url.startswith("http://10.0.0.5:")


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


# ── Certificate Trust List (CTL) auto-import ─────────────────────────────────
# ClearPass 422's a third-party-CA-signed server cert until the issuing root CA
# is imported AND enabled in the CTL. import_cert runs _ensure_trust_list_cas
# BEFORE the server-cert PUT; it's best-effort + non-blocking (a CTL failure
# never aborts the PUT) and idempotent by subject CN.
def _real_chain():
    """A leaf cert + an issuing CA cert (both self-signed for the test). Returns
    (fullchain_pem, chain_pem, leaf_cn, ca_cn, privkey)."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime
    except Exception:
        pytest.skip("cryptography not installed")
    now = datetime.datetime.utcnow()
    leaf_cn, ca_cn = "leaf.example.com", "ISRG Root X1"

    def _self(cn):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        cert = (x509.CertificateBuilder()
                .subject_name(subj).issuer_name(subj)
                .public_key(k.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                .sign(k, hashes.SHA256()))
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        kpem = k.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()).decode()
        return pem, kpem

    leaf_pem, leaf_key = _self(leaf_cn)
    ca_pem, _ = _self(ca_cn)
    fullchain = leaf_pem + ca_pem
    return fullchain, leaf_key, leaf_cn, ca_cn, ca_pem


def test_split_pem_certs_splits_bundle():
    from src.queries import _split_pem_certs
    a = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
    b = "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n"
    blocks = _split_pem_certs(a + b)
    assert len(blocks) == 2
    assert "BEGIN CERTIFICATE" in blocks[0] and "END CERTIFICATE" in blocks[0]
    assert blocks[0] != blocks[1]


def test_ca_certs_to_trust_prefers_chain():
    """Explicit chain (CA chain, no leaf) → all its certs are returned."""
    from src.queries import _ca_certs_to_trust
    leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
    ca = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"
    cas = _ca_certs_to_trust(leaf + ca, ca)
    assert len(cas) == 1
    assert "CA" in cas[0] and "LEAF" not in cas[0]


def test_ca_certs_to_trust_skips_leaf_from_fullchain():
    """No explicit chain → derive from fullchain by skipping the first (leaf)."""
    from src.queries import _ca_certs_to_trust
    leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
    ca = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"
    cas = _ca_certs_to_trust(leaf + ca, "")
    assert len(cas) == 1
    assert "CA" in cas[0]


def test_cert_subject_cn_extracts_cn():
    from src.queries import _cert_subject_cn
    fullchain, _key, leaf_cn, ca_cn, ca_pem = _real_chain()
    assert _cert_subject_cn(ca_pem) == ca_cn


def _le_chain(root_cn="ISRG Root X1"):
    """A certbot-shaped chain: leaf → single intermediate whose ISSUER CN names an
    ISRG root, root OMITTED (exactly certbot's chain.pem/fullchain.pem — leaf +
    intermediate only, never the self-signed root). The intermediate is built
    subject=R3 / issuer=<root_cn> so it is NOT self-signed by name, which is the
    signal ``_missing_root_pem`` keys on. Returns
    (fullchain_pem, chain_pem, intermediate_pem, root_cn, leaf_privkey)."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime
    except Exception:
        pytest.skip("cryptography not installed")
    now = datetime.datetime.utcnow()

    def _cert(subj_cn, iss_cn, key):
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subj_cn)])
        iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, iss_cn)])
        return (x509.CertificateBuilder()
                .subject_name(subj).issuer_name(iss)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                .sign(key, hashes.SHA256())
                .public_bytes(serialization.Encoding.PEM).decode())

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_pem = _cert("leaf.example.com", "R3", leaf_key)
    int_pem = _cert("R3", root_cn, int_key)        # issuer names the root, not self-signed
    return leaf_pem + int_pem, int_pem, int_pem, root_cn, leaf_key


def test_missing_root_pem_none_when_self_signed():
    """A chain that already ends in a self-signed root (issuer == subject) → no
    root to append."""
    from src.queries import _missing_root_pem
    _fullchain, _key, _leaf, _ca_cn, ca_pem = _real_chain()   # ca is self-signed
    assert _missing_root_pem([ca_pem]) is None


def test_missing_root_pem_none_for_unknown_issuer():
    """A non-self-signed intermediate whose issuer isn't a known ISRG root →
    best-effort None (non-LE chains are left as-is, today's behavior)."""
    from src.queries import _missing_root_pem
    _fullchain, chain, _int, _rcn, _key = _le_chain("Some Other Root CA")
    assert _missing_root_pem([chain]) is None


def test_missing_root_pem_appends_isrg_root_x1():
    """An R3 intermediate (issuer ISRG Root X1) → the canonical ISRG Root X1 PEM
    is the missing root."""
    from src.queries import _missing_root_pem, _ISRG_ROOT_X1_PEM
    _fullchain, chain, _int, _rcn, _key = _le_chain("ISRG Root X1")
    assert _missing_root_pem([chain]) == _ISRG_ROOT_X1_PEM


def test_ca_certs_to_trust_appends_isrg_root_x1():
    """A certbot-shaped chain (intermediate only) → _ca_certs_to_trust appends
    the ISRG Root X1 root so it reaches the CTL alongside the intermediate."""
    from src.queries import _ca_certs_to_trust, _ISRG_ROOT_X1_PEM
    fullchain, chain, _int, _rcn, _key = _le_chain("ISRG Root X1")
    cas = _ca_certs_to_trust(fullchain, chain)
    assert _ISRG_ROOT_X1_PEM in cas          # root appended
    assert any("R3" in c for c in cas)      # intermediate still present


def test_ca_certs_to_trust_appends_isrg_root_x2_for_ecdsa_intermediate():
    """An E5/E6-style intermediate (issuer ISRG Root X2) → the X2 root is
    appended (covers ECDSA server certs)."""
    from src.queries import _ca_certs_to_trust, _ISRG_ROOT_X2_PEM
    fullchain, chain, _int, _rcn, _key = _le_chain("ISRG Root X2")
    cas = _ca_certs_to_trust(fullchain, chain)
    assert _ISRG_ROOT_X2_PEM in cas


def test_ca_certs_to_trust_no_append_when_root_present():
    """A chain that already includes a self-signed root is NOT doubled."""
    from src.queries import _ca_certs_to_trust, _ISRG_ROOT_X1_PEM
    fullchain, _key, _leaf, ca_cn, ca_pem = _real_chain()   # ca self-signed = root
    cas = _ca_certs_to_trust(fullchain, "")
    assert len(cas) == 1
    assert _ISRG_ROOT_X1_PEM not in cas      # not appended (root already in chain)


def test_ensure_trust_list_posts_isrg_root_for_certbot_chain(monkeypatch):
    """The live bug: certbot ships leaf+intermediate only, so ClearPass 422's the
    server-cert PUT demanding the ISRG root in the CTL. _ensure_trust_list_cas
    must POST BOTH the intermediate AND the appended root (the root is what
    ClearPass was missing)."""
    from src.queries import _cert_subject_cn
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    mock_client = MagicMock(spec=CPPMClient)
    q = _ctl_queries(mock_client, ctl_items=[])           # empty CTL → POST both
    fullchain, chain, _int, root_cn, _key = _le_chain("ISRG Root X1")

    results = q._ensure_trust_list_cas(fullchain, chain)

    posted_cns = [_cert_subject_cn(c.kwargs["json"]["cert_file"])
                  for c in mock_client._request.call_args_list
                  if c.args[0] == "POST" and c.args[1] == "/api/cert-trust-list"]
    assert "R3" in posted_cns                # intermediate POSTed
    assert root_cn in posted_cns            # ISRG Root X1 POSTed (the fix)
    assert [r["ca"] for r in results] == ["R3", root_cn]


def _ctl_queries(mock_client, ctl_items=None):
    """CPPMQueries with query.side_effect keyed by URL: cluster/server → one
    server, cert-trust-list → ctl_items (default empty). _request default
    SUCCESS. Tests override _request.side_effect/return_value as needed."""
    def _query(path, *a, **k):
        if "cert-trust-list" in path:
            return {"_embedded": {"items": ctl_items or []},
                    "count": len(ctl_items or [])}
        return [{"server_uuid": "srv-uuid", "name": "cppm-node"}]
    mock_client.query.side_effect = _query
    mock_client._request.return_value = {"status": "SUCCESS", "id": "1"}
    return CPPMQueries(mock_client)


def test_ensure_trust_list_posts_new_ca(monkeypatch):
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    mock_client = MagicMock(spec=CPPMClient)
    q = _ctl_queries(mock_client, ctl_items=[])  # empty CTL → POST the CA
    fullchain, _key, leaf_cn, ca_cn, _ = _real_chain()

    results = q._ensure_trust_list_cas(fullchain, "")

    assert len(results) == 1
    assert results[0]["ca"] == ca_cn
    assert results[0]["action"] == "added"
    # POST went to /api/cert-trust-list with cert_file + cert_usage + enabled.
    post_calls = [c for c in mock_client._request.call_args_list
                  if c.args[0] == "POST" and c.args[1] == "/api/cert-trust-list"]
    assert len(post_calls) == 1
    body = post_calls[0].kwargs["json"]
    assert "BEGIN CERTIFICATE" in body["cert_file"]
    assert body["cert_usage"] == ["Others"]
    assert body["enabled"] is True


def test_ensure_trust_list_skips_and_enables_existing(monkeypatch):
    """A CA already in the CTL (matched by subject CN) is PATCH-enabled, not
    re-POSTed — idempotent across cert renewals (the root CA is stable)."""
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    mock_client = MagicMock(spec=CPPMClient)
    fullchain, _key, leaf_cn, ca_cn, _ = _real_chain()
    ctl_items = [{"id": 42, "subject_common_name": ca_cn, "enabled": False}]
    q = _ctl_queries(mock_client, ctl_items=ctl_items)

    results = q._ensure_trust_list_cas(fullchain, "")

    assert results[0]["action"] == "already-trusted"
    assert results[0]["enabled"] is True
    patch_calls = [c for c in mock_client._request.call_args_list
                  if c.args[0] == "PATCH"]
    assert len(patch_calls) == 1
    assert patch_calls[0].args[1] == "/api/cert-trust-list/42"
    assert patch_calls[0].kwargs["json"] == {"enabled": True}
    # No POST of a duplicate.
    assert not any(c.args[0] == "POST" for c in mock_client._request.call_args_list)


def test_ensure_trust_list_duplicate_conflict_is_fine(monkeypatch):
    """A POST that returns 'already exists' (CA present under a usage we didn't
    match on GET) is treated as already-trusted, not an error."""
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    mock_client = MagicMock(spec=CPPMClient)
    q = _ctl_queries(mock_client, ctl_items=[])
    fullchain, _key, leaf_cn, ca_cn, _ = _real_chain()
    mock_client._request.side_effect = [
        {"status": "ERROR", "message": "Certificate already exists in trust list"},
    ]

    results = q._ensure_trust_list_cas(fullchain, "")

    assert results[0]["action"] == "already-trusted"


def test_ensure_trust_list_blind_post_when_get_fails(monkeypatch):
    """If the GET list fails (unknown shape / API error), the step degrades to a
    blind POST — no idempotency index, but the CA still gets added."""
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    mock_client = MagicMock(spec=CPPMClient)
    mock_client.query.side_effect = RuntimeError("api timeout")
    mock_client._request.return_value = {"status": "SUCCESS", "id": "7"}
    q = CPPMQueries(mock_client)
    fullchain, _key, leaf_cn, ca_cn, _ = _real_chain()

    results = q._ensure_trust_list_cas(fullchain, "")

    assert results[0]["action"] == "added"
    assert any(c.args[0] == "POST" for c in mock_client._request.call_args_list)


def test_import_cert_runs_ctl_before_put_and_returns_trust_list(monkeypatch):
    """End-to-end: import_cert adds the CA to the CTL BEFORE the server-cert PUT
    and surfaces the CTL results in the SUCCESS envelope."""
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    mock_client = MagicMock(spec=CPPMClient)
    fullchain, leaf_key, leaf_cn, ca_cn, _ = _real_chain()
    q = _ctl_queries(mock_client, ctl_items=[])  # CA not yet trusted
    q._build_pkcs12 = lambda f, k, p: b"P12"

    res = q.import_cert(fullchain=fullchain, privkey=leaf_key, domain="a.example.com")

    assert res["status"] == "SUCCESS"
    assert "trust_list" in res
    assert res["trust_list"] and res["trust_list"][0]["ca"] == ca_cn
    # Ordering: the CTL POST precedes the server-cert PUT.
    calls = mock_client._request.call_args_list
    methods = [(c.args[0], c.args[1]) for c in calls]
    ctl_post_idx = next(i for i, c in enumerate(methods) if c == ("POST", "/api/cert-trust-list"))
    put_idx = next(i for i, c in enumerate(methods) if c[0] == "PUT")
    assert ctl_post_idx < put_idx


def test_import_cert_ctl_failure_does_not_block_put(monkeypatch):
    """A CTL POST failure is logged + surfaced, but the server-cert PUT still
    runs (non-blocking) — never a new blocker; the PUT gives the real diagnostic."""
    monkeypatch.setenv("LM_CPPM_P12_HOST", "127.0.0.1")
    mock_client = MagicMock(spec=CPPMClient)
    fullchain, leaf_key, leaf_cn, ca_cn, _ = _real_chain()
    # CTL GET ok (empty), CTL POST raises, server-cert PUT returns a 422.
    mock_client.query.side_effect = lambda path, *a, **k: (
        {"_embedded": {"items": []}} if "cert-trust-list" in path
        else [{"server_uuid": "srv-uuid"}])
    mock_client._request.side_effect = [
        RuntimeError("ctl post boom"),
        {"status": "ERROR", "message": "Certificate CA ... must be added"},
    ]
    q = CPPMQueries(mock_client)
    q._build_pkcs12 = lambda f, k, p: b"P12"

    res = q.import_cert(fullchain=fullchain, privkey=leaf_key, domain="a.example.com")

    # PUT still ran → the real 422 surfaces (not swallowed by the CTL failure).
    assert res["status"] == "ERROR"
    assert "must be added" in res["message"]
    # CTL failure recorded in the envelope.
    assert res["trust_list"] and res["trust_list"][0]["action"] == "error"
    # Both REST calls happened (CTL POST then PUT).
    assert mock_client._request.call_count == 2