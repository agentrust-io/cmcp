"""Central error code registry - mirrors docs/spec/error-codes.md."""

from __future__ import annotations


class CMCPError(Exception):
    """Base class for all cmcp-runtime errors."""

    code: str
    http_status: int

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.detail = detail


class AttestationProviderUnsupported(CMCPError):
    code = "ATTESTATION_PROVIDER_UNSUPPORTED"
    http_status = 500


class AttestationProviderNotImplemented(AttestationProviderUnsupported):
    """A recognized provider was explicitly selected but is not yet implemented.

    Distinct from AttestationProviderUnsupported (hardware simply not present):
    this signals a known placeholder provider (e.g. ``opaque``) so an operator who
    selects it gets an explicit error instead of a silent fall-through. Subclasses
    AttestationProviderUnsupported so the gateway still refuses to start.
    """

    code = "ATTESTATION_PROVIDER_NOT_IMPLEMENTED"
    http_status = 501


class PolicyHashMismatch(CMCPError):
    code = "POLICY_HASH_MISMATCH"
    http_status = 500


class PolicySignatureInvalid(CMCPError):
    """A policy bundle's manifest signature is absent, malformed, or does not
    verify under the pinned signing key; or its version did not increase.

    POLICY-004. Distinct from PolicyHashMismatch, which says the bundle is not the
    one exact artifact that was pinned. This says nobody authorised to change
    policy authorised *this* bundle, which is the question a deployment asks when
    it allows policy to change at runtime at all.
    """

    code = "POLICY_SIGNATURE_INVALID"
    http_status = 500


class CatalogHashMismatch(CMCPError):
    code = "CATALOG_HASH_MISMATCH"
    http_status = 500


class ToolNotInCatalog(CMCPError):
    code = "TOOL_NOT_IN_CATALOG"
    http_status = 403


class PolicyDeny(CMCPError):
    code = "POLICY_DENY"
    http_status = 403

    def __init__(
        self,
        message: str,
        *,
        detail: str | None = None,
        advice: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message, detail=detail)
        # Annotations of the forbid policies that caused this deny - sourced
        # from the hash-pinned policy bundle, safe to reflect to the caller.
        self.advice: dict[str, str] = advice or {}
        # AARM R4: a deny is DENY, STEP_UP, or DEFER depending on the matched
        # policies' annotations. Classified once here so every caller that
        # handles a deny records the same decision instead of re-deriving it.
        # Imported locally to keep errors.py out of a policy-package cycle.
        from cmcp_runtime.policy.decisions import decision_for_deny

        self.aarm_decision = decision_for_deny(self.advice)


class PolicySigningKeyRevoked(PolicyDeny):
    """The policy in force, or a bundle offered to replace it, is signed by a
    revoked policy signing key.

    Raised in two places. On load, a bundle whose signature verifies only under a
    revoked key is refused. On evaluation, a policy that was installed under a key
    revoked since then is no longer trusted, so every tool call is refused until a
    bundle signed by a still-trusted key is installed. That second case is why this
    is a :class:`PolicyDeny`: the proxy already records and returns a deny for it.
    It applies in every enforcement mode, because advisory and silent modes decide
    what to do with a Cedar decision, and here there is no trusted policy to decide.
    """

    code = "POLICY_SIGNING_KEY_REVOKED"
    http_status = 403


class PolicyKeyRevocationInvalid(CMCPError):
    """A policy signing key revocation statement was refused: malformed, not
    signed by a key allowed to issue it, or naming a key it may not revoke."""

    code = "POLICY_KEY_REVOCATION_INVALID"
    http_status = 500


class CatalogToolNameCollision(CMCPError):
    code = "CATALOG_TOOL_NAME_COLLISION"
    http_status = 500


class CatalogDriftDetected(CMCPError):
    code = "CATALOG_DRIFT_DETECTED"
    http_status = 409


class McpParseFailure(CMCPError):
    code = "MCP_PARSE_FAILURE"
    http_status = 400


class ResponseSizeExceeded(CMCPError):
    code = "RESPONSE_SIZE_EXCEEDED"
    http_status = 413


class ResponseInjectionDetected(CMCPError):
    code = "RESPONSE_INJECTION_DETECTED"
    http_status = 403


class ResponseSchemaViolationStrict(CMCPError):
    code = "RESPONSE_SCHEMA_VIOLATION_STRICT"
    http_status = 409


class SessionSensitivityPolicyDeny(CMCPError):
    code = "SESSION_SENSITIVITY_POLICY_DENY"
    http_status = 403


class SessionResetRequired(CMCPError):
    code = "SESSION_RESET_REQUIRED"
    http_status = 428


class TeeFault(CMCPError):
    code = "TEE_FAULT"
    http_status = 500


class SessionCloseIncomplete(CMCPError):
    """Terminal audit or close bookkeeping failed without a safe recovery.

    Repeating accounting/signing is unsafe; operator investigation is required."""

    code = "SESSION_CLOSE_INCOMPLETE"
    http_status = 500


class SessionDrainIncomplete(CMCPError):
    """Calls remain active after the drain deadline and cancellation grace.

    Admission stays sealed; a transition retry must finish draining first."""

    code = "SESSION_DRAIN_INCOMPLETE"
    http_status = 503


class UpstreamUnavailable(CMCPError):
    code = "UPSTREAM_UNAVAILABLE"
    http_status = 502


class UpstreamToolError(CMCPError):
    code = "UPSTREAM_TOOL_ERROR"
    http_status = 502


class AttestationStale(CMCPError):
    code = "ATTESTATION_STALE"
    http_status = 412


class BreakGlassActive(CMCPError):
    """Not an error - signals that a break-glass exception is in use."""

    code = "BREAK_GLASS_ACTIVE"
    http_status = 200


class ConfigError(CMCPError):
    code = "CONFIG_ERROR"
    http_status = 500


class ClaimValidationError(CMCPError):
    code = "CLAIM_VALIDATION_ERROR"
    http_status = 500


class KillSwitchTripped(CMCPError):
    """Raised when a new session is rejected because the agent identity has tripped the kill switch."""

    code = "KILL_SWITCH_TRIPPED"
    http_status = 403
