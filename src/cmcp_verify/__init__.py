"""cmcp-verify — verify cMCP Gateway TRACE Claims without trusting the operator."""

from cmcp_verify.verify import (
    ApprovedHashes,
    VerificationError,
    VerificationResult,
    VerificationStatus,
    verify_trace_claim,
)

__version__ = "0.1.0"
__all__ = [
    "ApprovedHashes",
    "VerificationError",
    "VerificationResult",
    "VerificationStatus",
    "verify_trace_claim",
]
