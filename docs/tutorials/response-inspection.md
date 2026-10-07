# Response Inspection

This page is for operators who want to know when a tool sends back something that tries to take over the agent. That is called prompt injection: text hidden in a tool's answer that looks like instructions to the AI. cMCP checks every tool response before the agent sees it and blocks ones that match known injection patterns; here you learn what it catches, where it can misfire, and how to find these events in the log.

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

Your Cedar policy runs before a call and decides whether it may go ahead. Response inspection runs after the tool server answers and before the answer reaches the agent, and decides whether the answer may be passed on. Together they cover both directions.

Inspection has four steps that run in order. All four run even when an earlier one has already refused the response, so the log always has the full picture:

1. **Size check**: reject responses over `max_response_size_bytes` (default 2 MB)
2. **Schema validation**: check the response against the shape the catalog says the tool returns (`output_schema`); strip or reject extra fields
3. **Sensitivity classification**: label the response by the kind of data in it (`pii` for personal data, `hipaa_phi` for health records, and so on), using the catalog's notes on the tool and its fields
4. **Injection detection**: scan response content for patterns that resemble injected instructions

A response refused at any step never reaches the agent. The session's record of how sensitive its data has become is updated either way.

---

## Read the default injection patterns

The default patterns look for text such as `<system>` or `<instructions>` tags, phrases like "ignore previous instructions" or "you are now", requests to send data elsewhere, and instruction markers used by some open models. The full list, with each regular expression, is below.

??? info "Technical detail: the default pattern list"
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

Two patterns are known to flag harmless responses. A CRM tool that returns job titles ("Account Executive") can match `persona-hijack`, and a data service that returns XML with `<context>` elements will match `xml-context-tag`.

The pattern list is built into the software from `patterns_v1.json`. In the current release there is no setting to switch off a pattern or add your own; changing the list means rebuilding with a modified file.

---

## Understand what happens when a pattern fires

When an injection pattern matches a response:

1. The response is denied. It is not delivered to the agent.
2. The audit entry records `response_inspection_result: "injection_detected"` and `injection_pattern_matched: "<pattern_name>"`.
3. The 50 characters around the match are logged so you can investigate. The full response is not logged, because it may contain sensitive data; its fingerprint is kept as `response_payload_hash` in the audit entry.
4. The session's sensitivity record is updated even though the response was refused.
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

In the signed TRACE claim, refused responses show up in the count `gateway.call_summary.tool_calls_faulted`. A session where many responses were refused is worth a closer look.

To check that the exported log has not been changed since it left the gateway, use `verify_audit_bundle`:

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

Response inspection runs four steps on every tool response. The fourth step matches the whole response against the patterns in `patterns_v1.json`. When one matches, the response is blocked and the log records which pattern fired and the text around it. To find these events, filter exported logs on `response_inspection_result: "deny"`.

Related tutorials: in the [Cedar policy walkthrough](./cedar-policy-walkthrough.md), `advice` blocks in rules can tell inspection to remove named fields from a response, and [Verify a TRACE claim](./verifying-a-trace-claim.md) checks the same log that inspection writes to.
