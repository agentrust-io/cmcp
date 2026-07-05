"""OPAQUE managed-runtime TEE provider: not yet implemented.

Selecting this provider raises AttestationProviderNotImplemented rather than
silently reporting "not detected". It is excluded from the auto-detect probe order.
"""

from __future__ import annotations

from cmcp_runtime.errors import AttestationProviderNotImplemented
from cmcp_runtime.tee.base import AttestationReport, TEEProvider

_NOT_IMPLEMENTED_MSG = (
    "The OPAQUE managed-runtime attestation provider is not yet implemented. "
    "Select tpm, sev-snp, or tdx, or set CMCP_DEV_MODE=1 for software-only development."
)


class OpaqueProvider(TEEProvider):
    """Placeholder for the OPAQUE managed-runtime provider (not yet implemented).

    Unlike a hardware provider that is simply absent, ``detect`` and
    ``get_attestation_report`` raise AttestationProviderNotImplemented rather than
    reporting "not detected", so explicitly selecting this provider yields a clear
    error instead of a silent fall-through. It is intentionally excluded from the
    auto-detect probe order (see ``tee/detect.py``).
    """

    def provider_name(self) -> str:
        return "opaque"

    def detect(self) -> bool:
        raise AttestationProviderNotImplemented(_NOT_IMPLEMENTED_MSG)

    def get_attestation_report(self, nonce: bytes) -> AttestationReport:
        raise AttestationProviderNotImplemented(_NOT_IMPLEMENTED_MSG)
