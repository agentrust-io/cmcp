"""TEE provider abstraction — implements issue #77."""

from __future__ import annotations

import hashlib
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

        nonce should be SHA-256(tee_public_key || session_id) as defined in
        docs/spec/attestation.md §3.3 — this binds the report to a specific
        gateway instance and session.
        """

    @abstractmethod
    def provider_name(self) -> str:
        """Return the canonical provider name string for attestation_report.provider."""


def make_nonce(tee_public_key: bytes, session_id: str) -> bytes:
    """Compute the attestation nonce: SHA-256(tee_public_key || session_id_bytes)."""
    return hashlib.sha256(tee_public_key + session_id.encode()).digest()


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
