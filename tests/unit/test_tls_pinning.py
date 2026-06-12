"""Tests for upstream TLS fingerprint pinning (#281) against a real local TLS server.

A self-signed certificate is generated with `cryptography` and served by a
local HTTPS server. tls_pinning.default_ssl_context is monkeypatched to a
context that trusts that certificate, so standard CA verification stays ON in
every test - proving the pin is additive to, not a replacement for, PKI
validation.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress
import json
import logging
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.errors import UpstreamUnavailable
from cmcp_runtime.mcp import tls_pinning
from cmcp_runtime.session.state import SessionState

_PROXY_LOGGER = "cmcp_runtime.mcp.proxy"


class _MockMCPHandler(BaseHTTPRequestHandler):
    """Serves canned JSON-RPC responses and counts requests actually received."""

    requests_served = 0

    def do_POST(self):  # noqa: N802
        type(self).requests_served += 1
        length = int(self.headers.get("Content-Length", 0))
        request = json.loads(self.rfile.read(length))
        tool = request["params"]["name"]
        body = {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"content": [{"type": "text", "text": f"echo:{tool}"}]},
        }
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence test output
        pass


class _QuietHTTPServer(HTTPServer):
    """Suppress tracebacks from clients that abort right after the handshake."""

    def handle_error(self, request, client_address):
        pass


def _generate_self_signed_cert() -> tuple[bytes, bytes, bytes]:
    """Return (key_pem, cert_pem, cert_der) for 127.0.0.1 / localhost."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key_pem, cert.public_bytes(serialization.Encoding.PEM), cert.public_bytes(
        serialization.Encoding.DER
    )


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    """Self-signed cert on disk + its catalog-format fingerprint."""
    key_pem, cert_pem, cert_der = _generate_self_signed_cert()
    directory = tmp_path_factory.mktemp("tls-pinning")
    key_file = directory / "key.pem"
    cert_file = directory / "cert.pem"
    key_file.write_bytes(key_pem)
    cert_file.write_bytes(cert_pem)
    return {
        "key_file": str(key_file),
        "cert_file": str(cert_file),
        "fingerprint": tls_pinning.fingerprint_from_der(cert_der),
    }


@pytest.fixture(scope="module")
def tls_server(tls_material):
    server = _QuietHTTPServer(("127.0.0.1", 0), _MockMCPHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tls_material["cert_file"], tls_material["key_file"])
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"https://127.0.0.1:{server.server_port}/mcp"
    server.shutdown()


@pytest.fixture(scope="module")
def http_server():
    server = _QuietHTTPServer(("127.0.0.1", 0), _MockMCPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/mcp"
    server.shutdown()


@pytest.fixture
def trust_test_cert(monkeypatch, tls_material):
    """Make default_ssl_context() trust the test CA (CA verification stays ON)."""
    def _trusting_context() -> ssl.SSLContext:
        return ssl.create_default_context(cafile=tls_material["cert_file"])

    monkeypatch.setattr(tls_pinning, "default_ssl_context", _trusting_context)


def _make_proxy(server_url: str, fingerprint: str):
    from cmcp_runtime.mcp.proxy import CMCPProxy

    entry = CatalogEntry(
        tool_name="test.echo",
        server=ServerIdentity(
            display_name="Pinned",
            url=server_url,
            tls_fingerprint=fingerprint,
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description="echo", input_schema={"type": "object"}, output_schema=None
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="public",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-06-10T00:00:00Z",
        approved_by="test",
    )
    catalog = ToolCatalog(entries={"test.echo": entry}, catalog_hash="sha256:" + "1" * 64)
    config = Config(attestation=AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING))
    session = SessionState(session_id="pin-test")
    chain = AuditChain("pin-test")
    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(
            catalog=catalog,
            policy_evaluator=MagicMock(),
            session=session,
            audit_chain=chain,
            config=config,
        )
    return proxy, entry


def _wrong_fingerprint() -> str:
    """A correctly-formatted pin that no real certificate hashes to."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(b"not the real cert").digest()).decode()


def _pin_warnings(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if "TLS_PIN_UNENFORCED" in r.getMessage()]


# ── https + real pin ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_correct_pin_succeeds(tls_server, tls_material, trust_test_cert, caplog):
    proxy, entry = _make_proxy(tls_server, tls_material["fingerprint"])
    with caplog.at_level(logging.WARNING, logger=_PROXY_LOGGER):
        text = await proxy._forward_to_upstream("c1", entry, "test.echo", {"m": "hi"})
    assert text == "echo:test.echo"
    assert _pin_warnings(caplog) == []  # enforced pins must not warn


@pytest.mark.asyncio
async def test_wrong_pin_fails_closed_before_request_is_sent(
    tls_server, trust_test_cert
):
    proxy, entry = _make_proxy(tls_server, _wrong_fingerprint())
    served_before = _MockMCPHandler.requests_served
    with pytest.raises(UpstreamUnavailable, match="fingerprint does not match"):
        await proxy._forward_to_upstream("c1", entry, "test.echo", {"secret": "x"})
    # Fail closed means pre-request: the server never saw the payload.
    assert _MockMCPHandler.requests_served == served_before


@pytest.mark.asyncio
async def test_wrong_pin_fails_closed_on_every_attempt(tls_server, trust_test_cert):
    """A mismatch must not poison or bypass the pool: every retry fails too."""
    proxy, entry = _make_proxy(tls_server, _wrong_fingerprint())
    for _ in range(2):
        with pytest.raises(UpstreamUnavailable, match="fingerprint does not match"):
            await proxy._forward_to_upstream("c1", entry, "test.echo", {})


@pytest.mark.asyncio
async def test_pin_is_additive_ca_verification_still_applies(tls_server, tls_material):
    """Correct pin but untrusted CA (no monkeypatch): the handshake itself must fail."""
    proxy, entry = _make_proxy(tls_server, tls_material["fingerprint"])
    with pytest.raises(UpstreamUnavailable, match="unreachable"):
        await proxy._forward_to_upstream("c1", entry, "test.echo", {})


# ── dev/demo escape hatches ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_placeholder_fingerprint_warns_once_and_proceeds(
    tls_server, trust_test_cert, caplog
):
    proxy, entry = _make_proxy(tls_server, tls_pinning.PLACEHOLDER_FINGERPRINT)
    with caplog.at_level(logging.WARNING, logger=_PROXY_LOGGER):
        first = await proxy._forward_to_upstream("c1", entry, "test.echo", {})
        second = await proxy._forward_to_upstream("c2", entry, "test.echo", {})
    assert first == "echo:test.echo"
    assert second == "echo:test.echo"
    warnings = _pin_warnings(caplog)
    assert len(warnings) == 1  # once per server, not per call
    assert "placeholder" in warnings[0].getMessage()


@pytest.mark.asyncio
async def test_http_upstream_warns_once_and_proceeds(http_server, caplog):
    proxy, entry = _make_proxy(http_server, _wrong_fingerprint())
    with caplog.at_level(logging.WARNING, logger=_PROXY_LOGGER):
        first = await proxy._forward_to_upstream("c1", entry, "test.echo", {})
        second = await proxy._forward_to_upstream("c2", entry, "test.echo", {})
    assert first == "echo:test.echo"
    assert second == "echo:test.echo"
    warnings = _pin_warnings(caplog)
    assert len(warnings) == 1
    assert "not https" in warnings[0].getMessage()


# ── malformed pins fail closed ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_malformed_fingerprint_fails_closed(tls_server, trust_test_cert):
    proxy, entry = _make_proxy(tls_server, "SHA256:not-valid-base64!")
    served_before = _MockMCPHandler.requests_served
    with pytest.raises(UpstreamUnavailable, match="malformed"):
        await proxy._forward_to_upstream("c1", entry, "test.echo", {})
    assert _MockMCPHandler.requests_served == served_before


# ── helpers ───────────────────────────────────────────────────────────────────

def test_fingerprint_from_der_is_catalog_format():
    fp = tls_pinning.fingerprint_from_der(b"example der bytes")
    assert tls_pinning.FINGERPRINT_PATTERN.match(fp)
    expected = base64.b64encode(hashlib.sha256(b"example der bytes").digest()).decode()
    assert fp == f"SHA256:{expected}"


def test_placeholder_matches_schema_pattern():
    assert tls_pinning.FINGERPRINT_PATTERN.match(tls_pinning.PLACEHOLDER_FINGERPRINT)


def test_fingerprints_equal_tolerates_base64_padding():
    fp = tls_pinning.fingerprint_from_der(b"x")
    assert tls_pinning.fingerprints_equal(fp, fp.rstrip("="))
    assert not tls_pinning.fingerprints_equal(fp, tls_pinning.PLACEHOLDER_FINGERPRINT)
