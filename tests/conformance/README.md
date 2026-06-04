# Conformance Test Suite

## Overview

A conforming cMCP Gateway implementation passes all MUST-level tests in this suite. Implementations SHOULD also pass all SHOULD-level tests. Partial conformance (MUST only) is sufficient for certification; SHOULD-level coverage indicates a higher-quality implementation.

Each test case references the spec section it validates. Test IDs are stable: once assigned, an ID is never reused even if the test is removed.

This document defines what a conforming implementation must do, expressed as test cases. It is a spec document, not runnable code. Implementors are expected to write test harnesses that exercise the described behaviors.

---

## Test Suite Index

### Group 1: Attestation

Spec reference: [attestation.md](../../docs/spec/attestation.md)

| ID | Level | Description | Expected outcome |
|---|---|---|---|
| ATTEST-001 | MUST | Gateway refuses to start when no TEE provider is detected and `CMCP_DEV_MODE` is not set. | Exit code 1; log contains `ATTESTATION_PROVIDER_UNSUPPORTED`. |
| ATTEST-002 | MUST | Gateway starts with software-only provider when `CMCP_DEV_MODE=1`. | TRACE Claims have `attestation_report.provider = "software-only"`. |
| ATTEST-003 | MUST | TRACE Claim `tee_public_key` is consistent across all claims in a single session. | All claims in the session carry the same `tee_public_key` value. |
| ATTEST-004 | MUST | New enclave startup produces a different `tee_public_key` than the previous startup. | Key is ephemeral: two independent startups never share a `tee_public_key`. |
| ATTEST-005 | MUST | Policy bundle hash mismatch at startup causes failure. | `POLICY_HASH_MISMATCH` error emitted; exit code 1. |
| ATTEST-006 | SHOULD | Attestation refresh produces a TRACE Claim with updated `attestation_generated_at` without dropping active sessions. | Refreshed claim has a later `attestation_generated_at`; in-flight sessions are not interrupted. |

### Group 2: Policy Enforcement

Spec reference: [cedar-policy.md](../../docs/spec/cedar-policy.md)

| ID | Level | Description | Expected outcome |
|---|---|---|---|
| POLICY-001 | MUST | Tool call to a tool not in the catalog returns an error. | `TOOL_NOT_IN_CATALOG`; call does not reach upstream server. |
| POLICY-002 | MUST | Tool call denied by Cedar policy returns an error. | `POLICY_DENY`; call does not reach upstream server. |
| POLICY-003 | MUST | In advisory mode, a policy-denied call is allowed through but recorded. | Call succeeds; audit entry has `policy_decision = "advisory_deny"`. |
| POLICY-004 | MUST | Per-workflow policy scope: tool in catalog but not in the workflow's `allowed_tools` list is denied. | `POLICY_DENY`; call does not reach upstream server. |
| POLICY-005 | MUST | Policy bundle with invalid Cedar syntax causes startup failure. | Gateway exits with a non-zero exit code and logs a policy parse error. |

### Group 3: Audit Chain

Spec reference: [attestation.md §2](../../docs/spec/attestation.md)

| ID | Level | Description | Expected outcome |
|---|---|---|---|
| AUDIT-001 | MUST | Every allowed tool call produces exactly one audit entry. | Audit log contains exactly one entry per successful call. |
| AUDIT-002 | MUST | Every denied tool call produces exactly one audit entry. | Audit entry has `policy_decision = "deny"`. |
| AUDIT-003 | MUST | `audit_chain_root` equals the `entry_hash` of the first entry in the chain. | Field values match exactly. |
| AUDIT-004 | MUST | Each audit entry's `prev_entry_hash` equals the `entry_hash` of the immediately preceding entry. | Chain is internally consistent with no gaps or duplicates. |
| AUDIT-005 | MUST | A TRACE Claim produced after N calls has the correct `audit_chain_length`. | `audit_chain_length = N + 2` (session_start entry + N tool call entries + session state entries). |

### Group 4: Failure Modes

Spec reference: [failure-modes.md](../../docs/spec/failure-modes.md)

| ID | Level | Description | Expected outcome |
|---|---|---|---|
| FAIL-001 | MUST | TEE fault mid-invocation returns an error to the agent. | `TEE_FAULT` returned; call does not appear as "allowed" in the audit chain. |
| FAIL-002 | MUST | MCP parse failure returns an error; raw payload is not logged. | `MCP_PARSE_FAILURE` returned; audit entry contains SHA-256 hash of payload, not the raw payload. |
| FAIL-003 | MUST | Session continues after a single call parse failure. | Next well-formed call in the same session succeeds (FM-5 is per-call, not per-session). |

### Group 5: Response Inspection

Spec reference: [response-inspection.md](../../docs/spec/response-inspection.md)

| ID | Level | Description | Expected outcome |
|---|---|---|---|
| INSP-001 | MUST | Response exceeding `max_response_size_bytes` is blocked. | `RESPONSE_SIZE_EXCEEDED`; response is not forwarded to agent. |
| INSP-002 | MUST | Response containing an injection pattern string is blocked. | `RESPONSE_INJECTION_DETECTED`; response is not forwarded to agent. |
| INSP-003 | MUST | In redact mode, response fields outside approved `output_schema` are stripped. | Fields not listed in `output_schema` are absent from the forwarded response. |
| INSP-004 | MUST | Session sensitivity state is updated after a high-sensitivity response, even if the response was denied. | `session.sensitivity` reflects the classification of the denied response. |

### Group 6: TRACE Claim Format

Spec references: [SPEC.md §5](../../SPEC.md), [schemas/trace-claim.schema.json](../../schemas/trace-claim.schema.json)

| ID | Level | Description | Expected outcome |
|---|---|---|---|
| TRACE-001 | MUST | Every TRACE Claim validates against the JSON Schema. | No validation errors against `schemas/trace-claim.schema.json`. |
| TRACE-002 | MUST | `signature` field verifies against `tee_public_key` over canonical JSON of the claim. | Signature verification succeeds with `signature` field excluded from the signed payload. |
| TRACE-003 | MUST | `policy_bundle.hash` matches the SHA-256 of the canonical policy bundle. | Hash matches as defined in [cedar-policy.md §1](../../docs/spec/cedar-policy.md). |
