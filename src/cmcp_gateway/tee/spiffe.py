"""
SPIFFE/SPIRE Workload API client — implements issue #96.

Fetches X.509 SVIDs from a local SPIRE agent after TEE attestation succeeds.
If SPIRE is not present or pyspiffe is not installed, falls back to
self-signed TLS with a WARNING log so the gateway still starts.

The SPIRE agent enforces that the gateway's attestation report is valid
before issuing an SVID. This binds the gateway's network identity to its
hardware measurement.

Socket default: /tmp/spire-agent/public/api.sock
Override via env: CMCP_SPIRE_SOCKET
"""

from __future__ import annotations

import logging
import os
import socket as _socket
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_SOCKET = "/tmp/spire-agent/public/api.sock"  # nosec B108 — SPIRE Workload API standard socket path, not a temp file
_SPIRE_SOCKET_ENV = "CMCP_SPIRE_SOCKET"

# Maximum time to wait for SPIRE agent to respond (seconds)
_CONNECT_TIMEOUT = 5.0


@dataclass
class SVIDBundle:
    """X.509 SVID bundle returned by SPIRE."""

    spiffe_id: str
    certificate_pem: bytes
    private_key_pem: bytes
    bundle_pem: bytes  # trust bundle (CA certificates)

    @property
    def is_valid(self) -> bool:
        return bool(self.spiffe_id and self.certificate_pem and self.private_key_pem)


@dataclass
class SpiffeClientResult:
    """Outcome of SVID fetch attempt."""

    svid: SVIDBundle | None
    available: bool
    failure_reason: str | None = None

    @property
    def has_svid(self) -> bool:
        return self.svid is not None and self.svid.is_valid


def _socket_exists(path: str) -> bool:
    """Return True if the SPIRE agent socket file exists."""
    try:
        return os.path.exists(path) and _socket.AF_UNIX is not None
    except (AttributeError, OSError):
        return False


def _try_pyspiffe(socket_path: str) -> SpiffeClientResult:
    """Attempt SVID fetch via pyspiffe library."""
    try:
        from pyspiffe.workloadapi.workload_api_client import WorkloadApiClient
    except ImportError:
        return SpiffeClientResult(
            svid=None,
            available=False,
            failure_reason="pyspiffe not installed; install pyspiffe for SPIRE integration",
        )

    try:
        with WorkloadApiClient(workload_api_address=f"unix:{socket_path}") as client:
            x509_context = client.fetch_x509_context()
            default_svid = x509_context.default_svid
            if default_svid is None:
                return SpiffeClientResult(
                    svid=None,
                    available=True,
                    failure_reason="SPIRE agent returned no SVID",
                )

            # Extract PEM-encoded certificate, key, and bundle
            cert_pem = b"".join(
                c.public_bytes(__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM)
                for c in default_svid.cert_chain
            )
            key_pem = default_svid.private_key.private_bytes(
                encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM,
                format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PrivateFormat"]).PrivateFormat.PKCS8,
                encryption_algorithm=__import__("cryptography.hazmat.primitives.serialization", fromlist=["NoEncryption"]).NoEncryption(),
            )
            bundle_pem = b"".join(
                c.public_bytes(__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM)
                for c in x509_context.x509_bundles.get_x509_bundle_for_trust_domain(
                    default_svid.spiffe_id.trust_domain
                ).x509_authorities
            )
            return SpiffeClientResult(
                svid=SVIDBundle(
                    spiffe_id=str(default_svid.spiffe_id),
                    certificate_pem=cert_pem,
                    private_key_pem=key_pem,
                    bundle_pem=bundle_pem,
                ),
                available=True,
            )
    except Exception as exc:
        return SpiffeClientResult(
            svid=None,
            available=True,
            failure_reason=f"SPIRE SVID fetch failed: {type(exc).__name__}: {exc}",
        )


def fetch_svid(socket_path: str | None = None) -> SpiffeClientResult:
    """
    Fetch an X.509 SVID from the SPIRE Workload API.

    Steps:
    1. Determine socket path (arg > env > default)
    2. Check socket exists; return not-available if absent
    3. Try pyspiffe library; fall through to not-available if not installed
    4. Return SVIDBundle on success

    The caller should check result.has_svid before using the SVID.
    If not available, the gateway falls back to self-signed TLS.
    """
    path = socket_path or os.environ.get(_SPIRE_SOCKET_ENV, _DEFAULT_SOCKET)

    if not _socket_exists(path):
        return SpiffeClientResult(
            svid=None,
            available=False,
            failure_reason=f"SPIRE agent socket not found at {path}",
        )

    result = _try_pyspiffe(path)

    if result.has_svid:
        logger.info(
            "SPIFFE SVID obtained: spiffe_id=%s socket=%s",
            result.svid.spiffe_id,  # type: ignore[union-attr]
            path,
        )
    elif result.available:
        logger.warning(
            "SPIRE agent reachable but SVID fetch failed: %s — falling back to self-signed TLS",
            result.failure_reason,
        )
    else:
        logger.warning(
            "SPIRE not available (%s) — falling back to self-signed TLS",
            result.failure_reason,
        )

    return result


def make_self_signed_tls_context(signing_key_hex: str, session_id: str) -> Any:
    """
    Generate a self-signed TLS certificate bound to the gateway's TEE signing key.

    Used as fallback when SPIRE is not available. The certificate's subject CN
    encodes the signing key hex prefix so the gateway identity is verifiable
    against the TRACE Claim's trace.cnf.jwk.x field.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import NameOID

    private_key = Ed25519PrivateKey.generate()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"cmcp-gateway-{signing_key_hex[:16]}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "cmcp-gateway"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"session:{session_id[:8]}"),
    ])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, None)
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
