"""Central error code registry — mirrors docs/spec/error-codes.md."""

from __future__ import annotations


class GatewayError(Exception):
    """Base class for all cmcp-gateway errors."""

    code: str
    http_status: int

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.detail = detail


class AttestationProviderUnsupported(GatewayError):
    code = "ATTESTATION_PROVIDER_UNSUPPORTED"
    http_status = 500


class PolicyHashMismatch(GatewayError):
    code = "POLICY_HASH_MISMATCH"
    http_status = 500


class CatalogHashMismatch(GatewayError):
    code = "CATALOG_HASH_MISMATCH"
    http_status = 500


class ToolNotInCatalog(GatewayError):
    code = "TOOL_NOT_IN_CATALOG"
    http_status = 403


class PolicyDeny(GatewayError):
    code = "POLICY_DENY"
    http_status = 403


class CatalogToolNameCollision(GatewayError):
    code = "CATALOG_TOOL_NAME_COLLISION"
    http_status = 500


class CatalogDriftDetected(GatewayError):
    code = "CATALOG_DRIFT_DETECTED"
    http_status = 409


class McpParseFailure(GatewayError):
    code = "MCP_PARSE_FAILURE"
    http_status = 400


class ResponseSizeExceeded(GatewayError):
    code = "RESPONSE_SIZE_EXCEEDED"
    http_status = 413


class ResponseInjectionDetected(GatewayError):
    code = "RESPONSE_INJECTION_DETECTED"
    http_status = 403


class ResponseSchemaViolationStrict(GatewayError):
    code = "RESPONSE_SCHEMA_VIOLATION_STRICT"
    http_status = 409


class SessionSensitivityPolicyDeny(GatewayError):
    code = "SESSION_SENSITIVITY_POLICY_DENY"
    http_status = 403


class SessionResetRequired(GatewayError):
    code = "SESSION_RESET_REQUIRED"
    http_status = 428


class TeeFault(GatewayError):
    code = "TEE_FAULT"
    http_status = 500


class AttestationStale(GatewayError):
    code = "ATTESTATION_STALE"
    http_status = 412


class BreakGlassActive(GatewayError):
    """Not an error — signals that a break-glass exception is in use."""

    code = "BREAK_GLASS_ACTIVE"
    http_status = 200


class ConfigError(GatewayError):
    code = "CONFIG_ERROR"
    http_status = 500


class ClaimValidationError(GatewayError):
    code = "CLAIM_VALIDATION_ERROR"
    http_status = 500
