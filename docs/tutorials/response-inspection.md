# Response Inspection

Monitor prompt injection detection in tool responses and understand the audit trail that inspection events produce.

## What you'll learn

- What the response inspection pipeline catches and how it fits into the call flow
- The default injection detection patterns and their false-positive risks
- What happens when a pattern fires: the call is blocked and the audit entry records why
- What audit fields to watch for inspection events

## Prerequisites

```bash
pip install cmcp-runtime
```

---

## Understand where inspection runs

Response inspection runs after the upstream tool server returns a response, before the response is delivered to the agent. Cedar policy evaluation runs before the call; inspection runs after. The two stages are complementary: Cedar controls what calls are allowed, inspection controls what responses reach the agent.

The pipeline has four stages that run in sequence. All stages run even if an earlier stage would deny: this produces a complete audit record rather than stopping at first failure:

1. **Size check**: reject responses over `max_response_size_bytes` (default 2 MB)
2. **Schema validation**: check response against the tool's `output_schema` in the catalog; strip or reject surplus fields
3. **Sensitivity classification**: tag the response with sensitivity labels (`pii`, `hipaa_phi`, etc.) from catalog annotations and field-level schema tags
4. **Injection detection**: scan response content for patterns that resemble injected instructions

A response denied at any stage is not delivered to the agent. Session sensitivity state is updated regardless of whether the response was denied.

---

## Read the default injection patterns

The Phase 1 default pattern list, from `src/cmcp_runtime/inspection/patterns_v1.json`:

| Pattern name | Regex | Notes |
|---|---|---|
| `xml-system-tag` | `<system>[\s\S]*?</system>` | XML-style system block |
| `xml-instructions-tag` | `<instructions>[\s\S]*?</instructions>` | XML-style instructions block |
| `xml-context-tag` | `<context>[\s\S]*?</context>` | Can match legitimate XML |
| `ignore-instructions` | `(?i)ignore (previous\|all\|above) instructions` | |
| `disregard-instructions` | `(?i)disregard (your\|the) (previous\|system\|initial) (prompt\|instructions\|context)` | |
| `persona-hijack` | `(?i)(you are now\|from now on you are\|act as) [A-Z][a-zA-Z]+` | Can match legitimate role descriptions |
| `exfiltrate` | `(?i)(exfiltrate\|send\|forward\|transmit) (the\|all\|this\|user\|customer) (data\|information\|context\|message)` | |
| `system-override` | `SYSTEM OVERRIDE` | |
| `begin-system-marker` | `---BEGIN SYSTEM---` | |
| `llama-instruction-markers` | `\[INST\][\s\S]*?\[/INST\]` | Llama-style instruction markers |

These patterns are matched against the full response body as a UTF-8 string.

The patterns `xml-context-tag` and `persona-hijack` carry documented false-positive risk. A CRM tool that returns contact roles ("Account Executive") can match `persona-hijack`. A data API that returns XML with `<context>` elements will match `xml-context-tag`.

The pattern list is compiled into the binary from `patterns_v1.json`. There is no runtime config key to disable individual patterns or add custom patterns in the current release: customization requires rebuilding with a modified patterns file.

---

## Understand what happens when a pattern fires

When an injection pattern matches a response:

1. The response is denied. It is not delivered to the agent.
2. The audit entry records `response_inspection_result: "injection_detected"` and `injection_pattern_matched: "<pattern_name>"`.
3. A 50-character window centered on the match location is logged for investigation. The full response payload is not logged: it may contain sensitive data. The full response hash is available as `response_payload_hash` in the audit entry.
4. Session sensitivity state is updated even for the denied response.
5. The gateway returns a structured error to the agent.

The audit entry fields written by the inspection pipeline:

| Field | Type | Description |
|---|---|---|
| `response_inspection_result` | string | `"allow"`, `"allow_redacted"`, or `"deny"` |
| `response_payload_hash` | string | SHA-256 of the response payload (hex). Present even for denied responses. |
| `response_sensitivity_tags` | array | Sensitivity tags from Stage 3 |
| `surplus_fields_count` | integer | Fields stripped by schema redaction, or 0 |
| `injection_pattern_matched` | string or null | Name of the matched pattern, or null |

---

## Monitor inspection events in the audit chain

Export the audit bundle for a session to inspect the full record:

```bash
curl http://localhost:8443/audit/export?session_id=<session_id> \
  | python3 -m json.tool > audit-bundle.json
```

Filter for injection events:

```python
import json

with open("audit-bundle.json") as f:
    bundle = json.load(f)

injection_events = [
    e for e in bundle["entries"]
    if e.get("response_inspection_result") == "deny"
    and e.get("injection_pattern_matched") is not None
]

for event in injection_events:
    print(
        f"Tool: {event['tool_name']}, "
        f"Pattern: {event['injection_pattern_matched']}, "
        f"Response hash: {event['response_payload_hash']}"
    )
```

In the TRACE claim, the presence of denied inspection events is reflected in `gateway.call_summary.tool_calls_faulted`. A session with a high ratio of denied responses to total calls is worth investigating.

To verify that the audit chain has not been tampered with after export, use `verify_audit_bundle`:

```python
from cmcp_verify import verify_audit_bundle
import json

with open("audit-bundle.json") as f:
    bundle = json.load(f)
with open("claim.json") as f:
    claim = json.load(f)

result = verify_audit_bundle(bundle, claim)
print(f"Bundle verified: {result.verified}, entries: {result.entry_count}")
if result.failures:
    print(f"Failures: {result.failures}")
```

---

## Summary

The response inspection pipeline runs four stages after every tool call returns. Injection detection in Stage 4 matches the full response body against the patterns in `patterns_v1.json`. When a pattern fires, the response is blocked and the audit chain records the pattern name and a location window. Monitor for injection events by filtering exported audit bundles on `response_inspection_result: "deny"`.

Related tutorials: [Cedar policy walkthrough](./cedar-policy-walkthrough.md): Cedar `advice` blocks in policy rules instruct the inspection pipeline to redact named fields from the response. [Verify a TRACE claim](./verifying-a-trace-claim.md): the audit chain that inspection writes to is verified as part of TRACE claim verification.
