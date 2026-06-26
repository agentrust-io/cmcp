"""TEE provider abstraction — implements issue #77."""

from __future__ import annotations

import base64
import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime

_ALLOWED_PROVIDERS: frozenset[str] = frozenset({
    "sev-snp",
    "tdx",
    "opaque",
    "tpm",
    "software-only",
})


@dataclass
class AttestationReport:
    """Hardware attestation report produced by a TEE provider."""

    provider: str
    measurement: str  # hex-encoded; format varies by provider
    report_data: str  # hex-encoded nonce binding public key to this report
    raw_evidence: bytes | None  # raw provider-specific evidence blob
    attestation_generated_at: datetime
    attestation_validity_seconds: int
    measurement_note: str | None = None  # e.g. "sha1-bank-fallback"

    def __post_init__(self) -> None:
        if self.provider not in _ALLOWED_PROVIDERS:
            raise ValueError(
                f"AttestationReport.provider '{self.provider}' is not in the allowed set "
                f"{sorted(_ALLOWED_PROVIDERS)}. "
                "Custom TEE providers must use one of the allowed provider names."
            )


class TEEProvider(ABC):
    """Abstract interface all TEE provider implementations satisfy."""

    @abstractmethod
    def detect(self) -> bool:
        """Return True if this provider's hardware is available and accessible."""

    @abstractmethod
    def get_attestation_report(self, nonce: bytes) -> AttestationReport:
        """
        Produce a hardware attestation report.

        nonce is the 64-byte value defined in docs/spec/attestation.md §3.3:
        the RFC 7638 JWK Thumbprint of the gateway public key (32 bytes) followed
        by a random salt (32 bytes). See make_nonce(). This binds the report to a
        specific gateway key (verifiable from cnf.jwk) and makes each instance's
        report fresh. Session linkage is carried separately by the signed claim
        body (gateway.session_id), not by the nonce.
        """

    @abstractmethod
    def provider_name(self) -> str:
        """Return the canonical provider name string for attestation_report.provider."""


def jwk_thumbprint(tee_public_key: bytes) -> bytes:
    """RFC 7638 JWK Thumbprint of an Ed25519 OKP public key (32-byte SHA-256).

    Hashes the canonical JSON of the required OKP members in lexicographic order
    (crv, kty, x), matching what a verifier re-derives from cnf.jwk.x.
    """
    x_b64 = base64.urlsafe_b64encode(tee_public_key).rstrip(b"=").decode()
    members = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": x_b64},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(members).digest()


def make_nonce(tee_public_key: bytes, salt: bytes) -> bytes:
    """Compute the attestation nonce: jwk_thumbprint(pubkey) (32) || salt (32).

    The first 32 bytes bind the report to the gateway key (a verifier re-derives
    the RFC 7638 thumbprint from cnf.jwk.x and checks report_data[:32]). The salt
    is 32 random bytes so each enclave instance/startup produces a distinct nonce
    even with the same key. See docs/spec/attestation.md §3.3.
    """
    if len(salt) != 32:
        raise ValueError(f"salt must be 32 bytes, got {len(salt)}")
    return jwk_thumbprint(tee_public_key) + salt


class SoftwareOnlyProvider(TEEProvider):
    """
    Software-only attestation stub for CI and local development.

    Activated when CMCP_DEV_MODE=1. Produces deterministic-looking but
    cryptographically meaningless attestation data. TRACE Claims from this
    provider carry attestation_report.provider = "software-only" and must
    not be used for compliance purposes.
    """

    def detect(self) -> bool:
        return True  # always available as fallback

    def provider_name(self) -> str:
        return "software-only"

    def get_attestation_report(self, nonce: bytes) -> AttestationReport:
        return AttestationReport(
            provider="software-only",
            measurement="DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION",
            report_data=nonce.hex(),
            raw_evidence=None,
            attestation_generated_at=datetime.now(tz=UTC),
            attestation_validity_seconds=86400,
            measurement_note="software-only mode — not hardware-backed",
        )
