"""The AIA walk fetches URLs from an untrusted certificate, so the fetch is bounded.

Real HTTP servers on 127.0.0.1 record every request they receive; a refused
fetch is one the server never sees.
"""

from __future__ import annotations

import datetime
import http.server
import ipaddress
import socket
import ssl
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
        self.hosts: list[str | None] = []
        self.body = body
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                outer.hits.append(self.path)
                outer.hosts.append(self.headers.get("Host"))
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
    # Treat only the first lookup as public, so the redirect target is the one refused.
    verdicts = iter([True])
    monkeypatch.setattr(tpm, "_aia_address_allowed", lambda address: next(verdicts, False))
    leaf, _ = _pair(first.url)

    assert _walk(leaf) == 1
    assert first.hits == ["/ca.der"]
    assert internal.hits == []


def test_oversized_response_is_ignored(
    servers: list[_Server], monkeypatch: pytest.MonkeyPatch
) -> None:
    server = _Server(b"\x00" * (tpm._AIA_MAX_RESPONSE_BYTES + 1))
    servers.append(server)
    monkeypatch.setattr(tpm, "_aia_address_allowed", lambda address: True)

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
    monkeypatch.setattr(tpm, "_aia_address_allowed", lambda address: True)

    assert _walk(leaf) == 2
    assert server.hits == ["/ca.der"]


# -- the connection goes to the address that was checked ---------------------

PUBLIC = "8.8.8.8"


def _rebinding_resolver(monkeypatch: pytest.MonkeyPatch, host: str, answers: list[str]):
    """getaddrinfo that answers ``host`` with ``answers`` in turn (last one repeats).

    Other names resolve normally. Returns the list of lookups made for ``host``.
    """
    real = socket.getaddrinfo
    lookups: list[str] = []

    def fake(name, port, *args, **kwargs):  # type: ignore[no-untyped-def]
        if name != host:
            return real(name, port, *args, **kwargs)
        address = answers[min(len(lookups), len(answers) - 1)]
        lookups.append(address)
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return lookups


def _recording_connect(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    """Record every TCP connect; refuse any non-loopback literal so no packet leaves."""
    real = socket.create_connection
    connected: list[tuple[str, int]] = []

    def fake(address, *args, **kwargs):  # type: ignore[no-untyped-def]
        host, port = address[0], address[1]
        connected.append((host, port))
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ConnectionRefusedError(f"test refuses {host}")
        except ValueError:
            pass  # a host name: the real call resolves it through the stub
        return real(address, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", fake)
    return connected


def test_dns_rebinding_cannot_redirect_the_connection_to_loopback(
    servers: list[_Server], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check sees a public address; a second lookup would say 127.0.0.1.

    The fetch must connect to the address it checked and never reach the local
    server, however the name resolves afterwards.
    """
    server = _Server(b"secret")
    servers.append(server)
    port = server.httpd.server_address[1]
    lookups = _rebinding_resolver(monkeypatch, "aia.rebind.test", [PUBLIC, "127.0.0.1"])
    connected = _recording_connect(monkeypatch)

    with pytest.raises(OSError):
        tpm._fetch_aia(f"http://aia.rebind.test:{port}/ca.der")

    assert lookups == [PUBLIC]
    assert connected == [(PUBLIC, port)]
    assert server.hits == []


def test_each_redirect_hop_connects_to_its_checked_address(
    servers: list[_Server], monkeypatch: pytest.MonkeyPatch
) -> None:
    final = _Server(b"issuer")
    servers.append(final)
    final_port = final.httpd.server_address[1]
    first = _Server(b"", redirect_to=f"http://hop2.rebind.test:{final_port}/ca.der")
    servers.append(first)
    first_port = first.httpd.server_address[1]
    monkeypatch.setattr(tpm, "_aia_address_allowed", lambda address: True)
    # hop2 resolves to the final server once; any later lookup would point elsewhere.
    lookups = _rebinding_resolver(monkeypatch, "hop2.rebind.test", ["127.0.0.1", "192.0.2.1"])
    connected = _recording_connect(monkeypatch)

    assert tpm._fetch_aia(first.url) == b"issuer"
    assert lookups == ["127.0.0.1"]
    assert connected == [("127.0.0.1", first_port), ("127.0.0.1", final_port)]
    # The validated address is used for the socket, the name for the request.
    assert final.hosts == [f"hop2.rebind.test:{final_port}"]


def test_more_than_three_redirects_are_not_followed(
    servers: list[_Server], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tpm, "_aia_address_allowed", lambda address: True)
    chain: list[_Server] = [_Server(b"issuer")]
    for _ in range(4):
        chain.append(_Server(b"", redirect_to=chain[-1].url))
    servers.extend(chain)

    assert tpm._fetch_aia(chain[-1].url) is None
    assert chain[0].hits == []


def test_https_connects_to_the_checked_address_with_sni_on_the_host_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connected: list[tuple[str, int]] = []
    wrapped: list[str | None] = []
    sentinel = object()

    class Context:
        # http.client reads these in HTTPSConnection.__init__ on current patch releases.
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True

        def wrap_socket(self, sock, server_hostname=None):  # type: ignore[no-untyped-def]
            wrapped.append(server_hostname)
            return sock

    monkeypatch.setattr(
        socket, "create_connection",
        lambda address, *a, **k: connected.append(address) or sentinel,
    )
    target = tpm._AiaTarget("https", "aia.example.com", 443, PUBLIC, "/ca.der")
    conn = tpm._PinnedHTTPSConnection(target, 5, context=Context())  # type: ignore[arg-type]
    conn.connect()

    assert connected == [(PUBLIC, 443)]
    assert wrapped == ["aia.example.com"]
    assert conn.sock is sentinel
