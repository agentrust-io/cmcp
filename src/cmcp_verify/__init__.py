"""cmcp-verify - verify cMCP Runtime TRACE Claims without trusting the operator."""

from cmcp_verify.embodied_action import (
    EMBODIED_ACTION_PROFILE,
    EmbodiedActionEvidenceResult,
    ReceiptState,
    compute_action_ref,
    hash_embodied_action_payload,
    verify_embodied_action_evidence,
)
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
    "EMBODIED_ACTION_PROFILE",
    "EmbodiedActionEvidenceResult",
    "ReceiptState",
    "VerificationError",
    "VerificationResult",
    "VerificationStatus",
    "compute_action_ref",
    "hash_embodied_action_payload",
    "verify_audit_bundle",
    "verify_embodied_action_evidence",
    "verify_trace_claim",
]
