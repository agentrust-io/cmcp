"""cmcp-verify — verify cMCP Runtime TRACE Claims without trusting the operator."""

from cmcp_verify.verify import (
    ApprovedHashes,
    AuditBundleResult,
    VerificationError,
    VerificationResult,
    VerificationStatus,
    verify_audit_bundle,
    verify_trace_claim,
)

__version__ = "0.1.0"
__all__ = [
    "ApprovedHashes",
    "AuditBundleResult",
    "VerificationError",
    "VerificationResult",
    "VerificationStatus",
    "verify_audit_bundle",
    "verify_trace_claim",
]
