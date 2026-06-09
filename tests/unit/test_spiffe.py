"""Tests for SPIFFE/SPIRE Workload API client (issue #96)."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from cmcp_runtime.tee.spiffe import (
    SpiffeClientResult,
    SVIDBundle,
    _socket_exists,
    fetch_svid,
    make_self_signed_tls_context,
)

# ── _socket_exists ─────────────────────────────────────────────────────────────


def test_socket_exists_missing_path():
    assert _socket_exists("/nonexistent/path/to/socket") is False


@pytest.mark.skipif(sys.platform == "win32", reason="AF_UNIX not available on Windows")
def test_socket_exists_regular_file(tmp_path):
    f = tmp_path / "notasocket"
    f.write_bytes(b"data")
    assert _socket_exists(str(f)) is True


# ── fetch_svid ─────────────────────────────────────────────────────────────────


def test_fetch_svid_no_socket_returns_not_available(monkeypatch):
    """No socket → not available, no crash."""
    monkeypatch.delenv("CMCP_SPIRE_SOCKET", raising=False)
    with patch("cmcp_runtime.tee.spiffe._socket_exists", return_value=False):
        result = fetch_svid("/nonexistent/socket")

    assert result.available is False
    assert result.has_svid is False
    assert result.failure_reason is not None
    assert "not found" in result.failure_reason.lower()


def test_fetch_svid_socket_present_no_pyspiffe(monkeypatch):
    """Socket exists but pyspiffe not installed → not available with explanation."""
    with patch("cmcp_runtime.tee.spiffe._socket_exists", return_value=True), \
         patch("cmcp_runtime.tee.spiffe._try_pyspiffe") as mock_try:
        mock_try.return_value = SpiffeClientResult(
            svid=None,
            available=False,
            failure_reason="pyspiffe not installed; install pyspiffe for SPIRE integration",
        )
        result = fetch_svid("/fake/socket")

    assert result.has_svid is False
    assert "pyspiffe" in (result.failure_reason or "")


def test_fetch_svid_socket_present_spire_succeeds():
    """Socket exists and SPIRE returns a valid SVID."""
    fake_svid = SVIDBundle(
        spiffe_id="spiffe://cmcp.io/gateway/session/abc123",
        certificate_pem=b"-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n",
        private_key_pem=b"-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----\n",
        bundle_pem=b"-----BEGIN CERTIFICATE-----\nBUNDLE\n-----END CERTIFICATE-----\n",
    )
    with patch("cmcp_runtime.tee.spiffe._socket_exists", return_value=True), \
         patch("cmcp_runtime.tee.spiffe._try_pyspiffe") as mock_try:
        mock_try.return_value = SpiffeClientResult(svid=fake_svid, available=True)
        result = fetch_svid("/fake/socket")

    assert result.has_svid is True
    assert result.svid is not None
    assert result.svid.spiffe_id == "spiffe://cmcp.io/gateway/session/abc123"


def test_fetch_svid_spire_fetch_error():
    """SPIRE reachable but SVID fetch fails → available=True, no SVID."""
    with patch("cmcp_runtime.tee.spiffe._socket_exists", return_value=True), \
         patch("cmcp_runtime.tee.spiffe._try_pyspiffe") as mock_try:
        mock_try.return_value = SpiffeClientResult(
            svid=None,
            available=True,
            failure_reason="SPIRE agent returned no SVID",
        )
        result = fetch_svid("/fake/socket")

    assert result.available is True
    assert result.has_svid is False
    assert result.failure_reason is not None


def test_fetch_svid_uses_env_socket(monkeypatch):
    """CMCP_SPIRE_SOCKET env var overrides default socket path."""
    monkeypatch.setenv("CMCP_SPIRE_SOCKET", "/env/socket/path")
    with patch("cmcp_runtime.tee.spiffe._socket_exists", return_value=False) as mock_exists:
        fetch_svid()
    mock_exists.assert_called_with("/env/socket/path")


def test_fetch_svid_arg_overrides_env(monkeypatch):
    """Explicit socket_path arg overrides env var."""
    monkeypatch.setenv("CMCP_SPIRE_SOCKET", "/env/socket")
    with patch("cmcp_runtime.tee.spiffe._socket_exists", return_value=False) as mock_exists:
        fetch_svid("/explicit/socket")
    mock_exists.assert_called_with("/explicit/socket")


# ── SVIDBundle ─────────────────────────────────────────────────────────────────


def test_svid_bundle_is_valid():
    svid = SVIDBundle(
        spiffe_id="spiffe://example.org/workload",
        certificate_pem=b"CERT",
        private_key_pem=b"KEY",
        bundle_pem=b"BUNDLE",
    )
    assert svid.is_valid is True


def test_svid_bundle_invalid_empty_spiffe_id():
    svid = SVIDBundle(
        spiffe_id="",
        certificate_pem=b"CERT",
        private_key_pem=b"KEY",
        bundle_pem=b"BUNDLE",
    )
    assert svid.is_valid is False


def test_svid_bundle_invalid_empty_cert():
    svid = SVIDBundle(
        spiffe_id="spiffe://example.org/workload",
        certificate_pem=b"",
        private_key_pem=b"KEY",
        bundle_pem=b"BUNDLE",
    )
    assert svid.is_valid is False


# ── make_self_signed_tls_context ───────────────────────────────────────────────


def test_make_self_signed_tls_context_returns_pem():
    cert_pem, key_pem = make_self_signed_tls_context(
        signing_key_hex="a" * 64,
        session_id="test-session-id",
    )
    assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")


def test_make_self_signed_tls_context_encodes_key_prefix():
    cert_pem, _ = make_self_signed_tls_context(
        signing_key_hex="abcdef0123456789" + "0" * 48,
        session_id="session-abc",
    )
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_pem)
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert "abcdef01" in cn  # first 8 chars of signing key hex in CN


# ── startup integration: RuntimeContext.spiffe field ──────────────────────────


def test_gateway_context_has_spiffe_field():
    """RuntimeContext.spiffe is None by default (backward compat)."""
    from unittest.mock import MagicMock

    from cmcp_runtime.audit.keys import SigningKey
    from cmcp_runtime.catalog.loader import ToolCatalog
    from cmcp_runtime.startup import RuntimeContext

    ctx = RuntimeContext(
        config=MagicMock(),
        tee_provider=MagicMock(),
        attestation_report=MagicMock(),
        signing_key=MagicMock(spec=SigningKey),
        policy_bundle=MagicMock(),
        catalog=MagicMock(spec=ToolCatalog),
        spiffe=None,
    )
    assert ctx.spiffe is None


def test_gateway_context_stores_spiffe_result():
    from cmcp_runtime.startup import RuntimeContext

    fake_result = SpiffeClientResult(svid=None, available=False, failure_reason="no socket")
    ctx = RuntimeContext(
        config=MagicMock(),
        tee_provider=MagicMock(),
        attestation_report=MagicMock(),
        signing_key=MagicMock(),
        policy_bundle=MagicMock(),
        catalog=MagicMock(),
        spiffe=fake_result,
    )
    assert ctx.spiffe is fake_result
    assert ctx.spiffe.available is False
