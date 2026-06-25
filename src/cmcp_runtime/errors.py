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


class PolicyHashMismatch(CMCPError):
    code = "POLICY_HASH_MISMATCH"
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
