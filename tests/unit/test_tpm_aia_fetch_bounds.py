"""The AIA walk fetches URLs from an untrusted certificate, so the fetch is bounded.

Real HTTP servers on 127.0.0.1 record every request they receive; a refused
fetch is one the server never sees.
"""

from __future__ import annotations

import datetime
import http.server
import threading
from collections.abc import Iterator

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from cmcp_runtime.tee import tpm
from cmcp_runtime.tee.tpm import TPMProvider


class _Server:
    def __init__(self, body: bytes, redirect_to: str | None = None) -> None:
        self.hits: list[str] = []
        self.body = body
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                outer.hits.append(self.path)
                if redirect_to is not None:
                    self.send_response(302)
                    self.send_header("Location", redirect_to)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *args: object) -> None:
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/ca.der"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def servers() -> Iterator[list[_Server]]:
    started: list[_Server] = []
    yield started
    for server in started:
        server.close()


def _pair(aia_url: str) -> tuple[x509.Certificate, x509.Certificate]:
    """A leaf whose AIA points at ``aia_url``, and the issuer that signed it."""
    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aia-test-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aia-test-leaf")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier(aia_url),
                )
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return leaf, ca


def _walk(leaf: x509.Certificate) -> int:
    chain = TPMProvider._chain_from_leaf(leaf.public_bytes(serialization.Encoding.DER))
    return chain.count(b"BEGIN CERTIFICATE")


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/ca.der",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5/ca.der",
        "http://[::1]/ca.der",
        "ftp://example.com/ca.der",
        "http:///no-host",
    ],
)
def test_non_public_destinations_are_refused(url: str) -> None:
    assert tpm._aia_destination_allowed(url) is False


def test_loopback_aia_url_is_never_contacted(servers: list[_Server]) -> None:
    server = _Server(b"")
    servers.append(server)
    leaf, ca = _pair(server.url)
    server.body = ca.public_bytes(serialization.Encoding.DER)

    assert _walk(leaf) == 1
    assert server.hits == []


def test_redirect_to_a_refused_destination_is_not_followed(
    servers: list[_Server], monkeypatch: pytest.MonkeyPatch
) -> None:
    internal = _Server(b"internal")
    servers.append(internal)
    first = _Server(b"", redirect_to=internal.url)
    servers.append(first)
    # Treat only the first hop as public, so the redirect target is the one refused.
    monkeypatch.setattr(tpm, "_aia_destination_allowed", lambda url: url == first.url)
    leaf, _ = _pair(first.url)

    assert _walk(leaf) == 1
    assert first.hits == ["/ca.der"]
    assert internal.hits == []


def test_oversized_response_is_ignored(
    servers: list[_Server], monkeypatch: pytest.MonkeyPatch
) -> None:
    server = _Server(b"\x00" * (tpm._AIA_MAX_RESPONSE_BYTES + 1))
    servers.append(server)
    monkeypatch.setattr(tpm, "_aia_destination_allowed", lambda url: True)

    assert tpm._fetch_aia(server.url) is None
    assert server.hits == ["/ca.der"]


def test_allowed_destination_still_yields_the_issuer(
    servers: list[_Server], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: the bounded fetch path still builds a chain through a real opener."""
    server = _Server(b"")
    servers.append(server)
    leaf, ca = _pair(server.url)
    server.body = ca.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(tpm, "_aia_destination_allowed", lambda url: True)

    assert _walk(leaf) == 2
    assert server.hits == ["/ca.der"]
