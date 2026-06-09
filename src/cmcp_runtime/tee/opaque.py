"""Opaque Systems TEE provider stub — not yet implemented."""

from __future__ import annotations

from cmcp_runtime.tee.base import AttestationReport, TEEProvider


class OpaqueProvider(TEEProvider):
    """Placeholder for the Opaque Systems TEE provider (not yet implemented)."""

    def provider_name(self) -> str:
        return "opaque"

    def detect(self) -> bool:
        return False

    def get_attestation_report(self, nonce: bytes) -> AttestationReport:
        raise NotImplementedError("Opaque provider not yet implemented")
