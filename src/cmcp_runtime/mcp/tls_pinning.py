"""
TLS certificate fingerprint pinning for upstream MCP forwarding - implements #281.

The attested catalog binds each tool to a server URL *and* a TLS certificate
fingerprint (``server.tls_fingerprint``, ``"SHA256:" + base64(sha256(peer
certificate DER))``, matching ``^SHA256:[A-Za-z0-9+/=]{43,44}$`` from
schemas/catalog-entry.schema.json). Without enforcement, the catalog only pins
the URL: a DNS or BGP level swap of the upstream MCP server goes undetected as
long as the attacker presents any publicly-trusted certificate.

Enforcement point (fail closed, pre-request):
    ``PinnedTransport`` wraps the httpcore network backend so that the peer
    certificate is checked inside ``AsyncNetworkStream.start_tls()`` - that is,
    immediately after the TLS handshake completes and *before a single request
    byte is written*. On a fingerprint mismatch the connection is closed and
    ``TLSPinMismatchError`` is raised, so the request payload is never exposed
    to the unverified peer.

Standard CA verification is unchanged and runs first as part of the normal
handshake; the pin is additive, never a replacement for PKI validation.

Dev/demo escape hatches (explicit, never silent - the proxy warns once per
server in both cases):
  * ``PLACEHOLDER_FINGERPRINT`` (``"SHA256:" + "A" * 43 + "="``, used by every
    shipped example catalog) means "no pin recorded yet": the proxy proceeds
    with standard CA verification only.
  * ``http://`` upstreams cannot be pinned at all; plain HTTP is for local
    dev/demo only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import ssl
import typing

import httpcore
import httpx

# "No pin recorded" placeholder used by the example catalogs and docs. A real
# SHA-256 fingerprint of all-zero bits would be "SHA256:" followed by 43
# base64 chars of actual digest data; 43 literal "A"s decode to 32 zero bytes,
# which no real certificate hashes to, so the value is safe to special-case.
PLACEHOLDER_FINGERPRINT = "SHA256:" + "A" * 43 + "="

# Mirrors server.tls_fingerprint in schemas/catalog-entry.schema.json.
FINGERPRINT_PATTERN = re.compile(r"^SHA256:[A-Za-z0-9+/=]{43,44}$")


class TLSPinMismatchError(Exception):
    """The peer certificate's fingerprint did not match the catalog pin.

    Raised from inside the TLS handshake hook, before any request bytes are
    written, and deliberately not an ``httpx.HTTPError`` subclass so callers
    cannot accidentally swallow it with a generic transport-error handler.
    """

    def __init__(self, *, expected: str, actual: str) -> None:
        super().__init__(
            f"TLS certificate fingerprint mismatch: expected {expected}, got {actual}"
        )
        self.expected = expected
        self.actual = actual


def fingerprint_from_der(der: bytes) -> str:
    """Catalog-format fingerprint of a certificate in DER encoding."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")


def fingerprints_equal(a: str, b: str) -> bool:
    """Constant-time fingerprint compare, tolerant of optional base64 '=' padding."""
    return hmac.compare_digest(a.rstrip("="), b.rstrip("="))


def default_ssl_context() -> ssl.SSLContext:
    """Standard CA-verifying client SSL context.

    Module-level seam so tests can substitute a context that trusts a local
    test CA while keeping CA verification itself enabled (the pin must stay
    additive to PKI validation, not a replacement for it).
    """
    return httpx.create_ssl_context()


class _PinnedStream(httpcore.AsyncNetworkStream):
    """Delegating stream that verifies the peer certificate in ``start_tls()``."""

    def __init__(self, inner: httpcore.AsyncNetworkStream, expected_fingerprint: str) -> None:
        self._inner = inner
        self._expected = expected_fingerprint

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._inner.read(max_bytes, timeout=timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._inner.write(buffer, timeout=timeout)

    async def aclose(self) -> None:
        await self._inner.aclose()

    def get_extra_info(self, info: str) -> typing.Any:
        return self._inner.get_extra_info(info)

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Complete the TLS handshake, then enforce the fingerprint pin.

        Runs after standard CA verification (part of the handshake itself) and
        before httpcore writes any request bytes, so a mismatched peer never
        sees the request. Fail closed: no peer certificate, or any mismatch,
        tears the connection down and raises TLSPinMismatchError.
        """
        tls_stream = await self._inner.start_tls(
            ssl_context, server_hostname=server_hostname, timeout=timeout
        )
        ssl_object = tls_stream.get_extra_info("ssl_object")
        der: bytes | None = (
            ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        )
        if not der:
            await tls_stream.aclose()
            raise TLSPinMismatchError(expected=self._expected, actual="<no peer certificate>")
        actual = fingerprint_from_der(der)
        if not fingerprints_equal(actual, self._expected):
            await tls_stream.aclose()
            raise TLSPinMismatchError(expected=self._expected, actual=actual)
        return tls_stream


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """Network backend that wraps every new connection in a ``_PinnedStream``."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend, expected_fingerprint: str) -> None:
        self._inner = inner
        self._expected = expected_fingerprint

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._inner.connect_tcp(
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        return _PinnedStream(stream, self._expected)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._inner.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )
        return _PinnedStream(stream, self._expected)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class PinnedTransport(httpx.AsyncHTTPTransport):
    """httpx transport that enforces a TLS certificate fingerprint pin.

    Verification happens at handshake time inside the network backend (see
    ``_PinnedStream.start_tls``), so enforcement is pre-request: a peer whose
    certificate does not hash to ``expected_fingerprint`` never receives the
    request. Connection reuse is safe because the pin is checked on every new
    TLS handshake and a pooled connection keeps the certificate it was
    verified with.

    ``ssl_context`` defaults to ``default_ssl_context()`` (standard CA
    verification); the pin is enforced in addition to, never instead of,
    normal certificate validation.
    """

    def __init__(
        self,
        expected_fingerprint: str,
        *,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        ctx = ssl_context if ssl_context is not None else default_ssl_context()
        super().__init__(verify=ctx)
        # httpx.AsyncHTTPTransport exposes no public hook for a custom httpcore
        # network backend, so rebuild the (not-yet-opened) connection pool with
        # one that pins the handshake. ``self._pool`` is what the inherited
        # handle_async_request() drives; stable across httpx 0.27/0.28.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ctx,
            network_backend=_PinnedBackend(httpcore.AnyIOBackend(), expected_fingerprint),
        )
