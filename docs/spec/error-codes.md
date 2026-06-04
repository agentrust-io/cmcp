# Error Code Registry

This is the normative registry for all error codes used across the cMCP Gateway. Every error code MUST be registered here before it is referenced in code, configuration, or other spec documents. Implementations MUST NOT emit error codes that do not appear in this registry.

## Gateway Errors

| error_code | HTTP status | log level | description | spec reference |
|---|---|---|---|---|
| `ATTESTATION_REPORT_UNAVAILABLE` | 503 | FATAL | TEE provider did not return an attestation report within timeout | [failure-modes.md FM-1](failure-modes.md) |
| `ATTESTATION_PROVIDER_UNSUPPORTED` | 500 | FATAL | No supported TEE provider detected and `CMCP_DEV_MODE` is not set | [attestation.md §1.1](attestation.md) |
| `POLICY_HASH_MISMATCH` | 500 | FATAL | Measured policy bundle hash does not match deployment manifest | [failure-modes.md FM-4](failure-modes.md) |
| `CATALOG_HASH_MISMATCH` | 500 | FATAL | Measured catalog hash does not match deployment manifest | [attestation.md §5](attestation.md) |
| `TOOL_NOT_IN_CATALOG` | 403 | WARN | Agent requested a tool not present in the attested catalog | [cedar-policy.md](cedar-policy.md) |
| `POLICY_DENY` | 403 | INFO | Cedar policy evaluation returned deny for this call | [cedar-policy.md](cedar-policy.md) |
| `CATALOG_TOOL_NAME_COLLISION` | 500 | FATAL | Two catalog entries register the same `tool_name` | [tool-identity.md](tool-identity.md) |
| `CATALOG_DRIFT_DETECTED` | 409 | ERROR | Upstream server changed a tool definition since catalog was sealed | [attestation.md §5](attestation.md) |
| `MCP_PARSE_FAILURE` | 400 | WARN | Incoming MCP JSON-RPC message failed to parse | [failure-modes.md FM-5](failure-modes.md) |
| `RESPONSE_SIZE_EXCEEDED` | 413 | WARN | Tool response exceeds `max_response_size_bytes` | [response-inspection.md Stage 1](response-inspection.md) |
| `RESPONSE_INJECTION_DETECTED` | 403 | ERROR | Response inspection detected indirect injection pattern | [response-inspection.md Stage 4](response-inspection.md) |
| `RESPONSE_SCHEMA_VIOLATION_STRICT` | 409 | WARN | Tool response contains fields outside approved `output_schema` (strict mode) | [response-inspection.md Stage 2](response-inspection.md) |
| `SESSION_SENSITIVITY_POLICY_DENY` | 403 | INFO | Call denied due to session sensitivity state | [session-policy.md](session-policy.md) |
| `SESSION_RESET_REQUIRED` | 428 | INFO | Agent attempted call that requires session reset first | [session-policy.md](session-policy.md) |
| `TEE_FAULT` | 500 | ERROR | TEE process fault during call execution | [failure-modes.md FM-3](failure-modes.md) |
| `ATTESTATION_STALE` | 412 | WARN | Attestation report validity period has expired | [attestation.md §3](attestation.md) |
| `BREAK_GLASS_ACTIVE` | 200 | WARN | Call allowed via catalog exception (break-glass procedure active) | [tool-identity.md](tool-identity.md) |

## Verification Library Errors

The following error codes are defined and documented in [verification-library.md](verification-library.md). They are listed here for cross-reference completeness; the verification library spec is authoritative for their semantics.

| error_code |
|---|
| `UNSUPPORTED_PROVIDER` |
| `SIGNATURE_INVALID` |
| `PUBLIC_KEY_NOT_BOUND` |
| `POLICY_HASH_MISMATCH` |
| `CATALOG_HASH_MISMATCH` |
| `ATTESTATION_STALE` |
| `CHAIN_BROKEN` |
| `CLAIM_MALFORMED` |

> Note: `POLICY_HASH_MISMATCH`, `CATALOG_HASH_MISMATCH`, and `ATTESTATION_STALE` appear in both tables. The Gateway emits them during startup or request handling; the verification library emits them during offline or client-side verification. The semantics are consistent across both contexts.
