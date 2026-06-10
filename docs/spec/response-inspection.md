# Response Inspection

Status: Draft v0.1 | Closes #37 | Related: [session-policy.md](session-policy.md) (state handoff), [call-graph.md](call-graph.md) (tagging)

## Overview

Response inspection runs **after** the MCP tool call returns, before the runtime passes the response payload to the agent. This is a deliberate architectural choice: Cedar pre-call policy evaluates context that is known before the call (principal identity, tool catalog entry, session state, request arguments). It cannot inspect a response that does not yet exist. Post-call inspection therefore runs in runtime code, not in Cedar, and produces two outputs: (1) an allow/deny decision that gates whether the response reaches the agent, and (2) updated session state that gates future calls in the same session.

This separation is explicit. Cedar owns pre-call authorization. The inspection pipeline owns post-call classification and session state mutation. Session state then feeds back into Cedar on the next call.

## Inspection Pipeline

The pipeline runs sequentially on every tool response before it is passed to the agent. All stages run even if an earlier stage would deny - this produces a complete inspection record for the audit entry rather than stopping at first failure.

### Stage 1: Size Check

If `Content-Length` (or, where absent, the measured response size) exceeds `max_response_size_bytes` (default: 2 097 152 bytes / 2 MB, configurable per deployment), the response is denied immediately. The size limit exists to prevent memory exhaustion in the runtime and to bound the cost of downstream pattern matching.

Return shape on denial:

```json
{"stage": "size", "result": "deny", "reason": "response exceeds 2097152 bytes"}
```

All remaining stages are still recorded as `"skip"` in the audit entry so the entry schema remains uniform.

### Stage 2: Schema Validation

If the tool has an approved `output_schema` in the catalog, the runtime validates the response JSON against it using JSON Schema draft-07.

- **Surplus fields**: fields present in the response but absent from the approved schema: are collected as `surplus_fields`.
- **Missing required fields**: fields required by the schema but absent from the response: are a tool implementation error, not a policy violation. They are logged and the response passes through.

The handling mode for surplus fields comes from the catalog entry (overridable by Cedar policy):

| Mode | Action |
|------|--------|
| `redact` | Strip surplus fields before passing to agent. Return `surplus_fields_count` in audit entry. |
| `strict` | Deny the response if any surplus fields are present. |
| `log` | Pass through unchanged; record surplus fields in audit entry. |

**Canonical JSON for surplus stripping (redact mode):** The runtime reconstructs the response by walking the approved schema and copying only the fields named there from the raw response. The result is re-serialized as compact JSON (no extra whitespace, keys in schema-definition order). This canonical form is what gets hashed for `response_payload_hash` in the audit entry. If the original response was not valid JSON (e.g., plain text or binary), the entire response is treated as a single opaque value; schema validation is skipped and the mode is recorded as `"skip_non_json"`.

If no approved `output_schema` exists in the catalog, this stage result is `"skip"`.

### Stage 3: Sensitivity Classification

Cedar does not run post-call. Sensitivity classification in Phase 1 is rule-based in runtime code. Three sources are combined in priority order:

1. **Catalog-level `sensitivity_level` annotation** : always applied. If the tool is annotated `"hipaa_phi"`, every response from it carries that tag regardless of content.
2. **Field-level annotations in `approved_definition.output_schema`** : fields tagged with sensitivity labels (e.g., `"ssn"` tagged `"pii"`, `"diagnosis"` tagged `"hipaa_phi"`) contribute their tags to the response if those fields are present and non-null in the response.
3. **Pattern matching on response content** : the configurable pattern list below is applied to the full response body (as a UTF-8 string). Matches contribute their associated sensitivity tags.

Output: a set of sensitivity tags applied to this response, for example `["pii", "hipaa_phi"]`. An empty set means `"public"`. These tags are passed to session state in the handoff call described below.

### Stage 4: Indirect Injection Detection

The runtime scans response content for patterns that resemble injected instructions the LLM would treat as system context. A match causes a denial. The pattern list is configurable per deployment - the set below is the Phase 1 default, maintained as a config file, not hardcoded.

```python
INJECTION_PATTERNS = [
    # (name, regex, notes)
    ("xml_system",         r"<system>.*?</system>",                                            "XML-style system block"),
    ("xml_instructions",   r"<instructions>.*?</instructions>",                               "XML-style instructions block"),
    ("xml_context",        r"<context>.*?</context>",                                         "Can match legitimate XML; tune per deployment"),
    ("ignore_previous",    r"(?i)ignore (previous|all|above) instructions",                   ""),
    ("disregard_system",   r"(?i)disregard (your|the) (previous|system|initial) (prompt|instructions|context)", ""),
    ("persona_hijack",     r"(?i)(you are now|from now on you are|act as) [A-Z][a-zA-Z]+",   "Can match legitimate role descriptions"),
    ("exfil_instruction",  r"(?i)(exfiltrate|send|forward|transmit) (the|all|this|user|customer) (data|information|context|message)", ""),
    ("system_override",    r"SYSTEM OVERRIDE",                                                ""),
    ("begin_system_block", r"---BEGIN SYSTEM---",                                             ""),
    ("llama_inst",         r"\[INST\].*?\[/INST\]",                                          "Llama-style instruction markers"),
    ("conv_reset",         r"Human:.*?Assistant:",                                            "Embedded conversation resets"),
]
```

**False positive notes:** `xml_context` (pattern 3) can match legitimate XML data payloads. `persona_hijack` (pattern 6) can match legitimate role description strings. Deployments handling structured XML output should disable or narrow those patterns in their config.

**On match:** deny the response. Log the pattern name and a 50-character window centered on the match location. Do not log the full response content in the match record (it may itself contain sensitive data; the full payload hash is in the audit entry).

### Inspection Decision Table

| Size | Schema | Classification | Injection | Final decision |
|------|--------|----------------|-----------|----------------|
| pass | pass | any | pass | allow (with sensitivity tags) |
| fail | any | any | any | deny |
| pass | fail (strict) | any | any | deny |
| pass | fail (redact) | any | pass | allow (surplus stripped) |
| pass | any | any | detected | deny |

A response denied at any stage still proceeds through remaining stages (to populate the full audit record) but is not delivered to the agent.

### Handoff to Session Policy

After inspection completes - regardless of the final decision - the gateway calls:

```python
session_state.update_from_inspection(
    call_id=call_id,
    sensitivity_tags=inspection.sensitivity_tags,
    injection_detected=inspection.injection_detected,
    response_allowed=(inspection.final_decision != "deny"),
)
```

This is the **only** place where session sensitivity state is updated. The call happens even for denied responses: a denied high-sensitivity response still raises session sensitivity because the agent knows the call was attempted and may act on that knowledge. The session state machine that consumes this call is defined in [session-policy.md](session-policy.md).

## Audit Entry Fields from Inspection

The following fields are written to the audit entry for the call by the inspection pipeline:

| Field | Type | Description |
|-------|------|-------------|
| `response_inspection_result` | string | Final decision: `"allow"`, `"allow_redacted"`, or `"deny"`. |
| `response_payload_hash` | string | SHA-256 of the canonical response payload (post-redaction if redact mode; pre-denial payload if denied). Hex-encoded. |
| `response_sensitivity_tags` | array of string | Sensitivity tags assigned by Stage 3. Empty array if none. |
| `surplus_fields_count` | integer | Number of surplus fields detected in Stage 2. `0` if schema validation was skipped or found no surplus. |
| `injection_pattern_matched` | string or null | Name of the first injection pattern that matched, or `null` if none. |
