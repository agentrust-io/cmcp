# Response Inspection

Closes #37.

## Overview

The gateway intercepts MCP tool responses before they re-enter the agent context window. Every response passes through an inspection pipeline inside the TEE. A response that fails any check is denied: the agent receives a synthetic error, not the raw tool output.

## Section 1 — Inspection Pipeline

All checks run in order. A failure at any step denies the response.

### 1. Size Check

If the response exceeds the configured `max_response_size_bytes`, deny. This prevents large-payload DoS on the agent context window.

### 2. Schema Validation

If the tool has an approved `output_schema` in the catalog, validate the response against it. Fields not present in the schema are handled according to the per-tool mode (see Section 2):

- **redact mode:** strip non-schema fields before passing to the agent.
- **strict mode:** deny the entire response.

### 3. Surplus Field Detection

Fields present in the response but not in the approved `output_schema` are flagged as `chatty_surplus`. Enforcement depends on mode:

- **redact:** strip surplus fields before passing to agent.
- **strict:** deny entire response.
- **log:** pass through but record the surplus fields in the audit entry.

### 4. Sensitivity Classification

Run Cedar policy against response content (pattern matching, field inspection). If classified as high-sensitivity, update session sensitivity state (see [session-policy.md](session-policy.md)) and add `sensitivity_tags` to the audit entry.

### 5. Indirect Injection Detection

Scan response for patterns that resemble system instructions. Phase 1 uses pattern-based detection:

- XML-like tags wrapping instructions: `<system>`, `<instructions>`, `<context>`
- Markdown code blocks containing policy-like syntax
- Sequences matching "ignore previous instructions" or similar jailbreak patterns

If detected: deny the response (fail-closed), log as `injection_attempt` with the pattern matched.

Note: false positives are possible with legitimate content. The pattern list is configurable and should be tuned carefully per deployment.

## Section 2 — Per-Tool Response Policy in Cedar

```cedar
permit(principal, action == Action::"call_tool", resource == Tool::"salesforce.query")
when { true }
advice {
  response_schema: "catalog.salesforce_query_output",
  mode: "redact"
};
```

This allows the call but enforces the response schema in redact mode, stripping any surplus fields before the response reaches the agent.

## Section 3 — Response-Level Deny

When a response fails any inspection check, the gateway returns a synthetic error to the agent:

```json
{
  "error": {
    "code": -32000,
    "message": "Response failed inspection",
    "data": {
      "reason": "schema_violation | injection_detected | size_exceeded | surplus_stripped_strict_mode",
      "call_id": "uuid"
    }
  }
}
```

The agent sees this error. The tool's raw response is not passed through under any circumstances.

The audit entry records:

```json
"response_inspection_result": "deny",
"inspection_failure_reason": "string"
```
