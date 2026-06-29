# Advisory Mode Debugging

Run the gateway in `advisory` mode to understand which calls your Cedar policy would deny: without blocking any traffic. Use this to tune policy before switching to `enforcing`.

## What you'll learn

- The difference between `enforcing`, `advisory`, and `silent` modes
- What changes in the response when a call would have been denied
- How to read the audit chain to find advisory denials
- A workflow for moving from advisory to enforcing

## Prerequisites

```bash
pip install cmcp-runtime
```

---

## Enforcement modes

The `enforcement_mode` field in `cmcp-config.yaml` has three valid values:

| Mode | What happens on a policy deny |
|---|---|
| `enforcing` | Call is blocked, HTTP 403 returned to the agent |
| `advisory` | Call proceeds, `would_have_denied: true` set in `_cmcp` response |
| `silent` | Policy is evaluated but nothing is logged or blocked |

Default is `enforcing`. Silent mode gives you evaluation without any output: useful for baselining before you have policies written. Advisory is the useful middle ground: real traffic continues, but denials are fully visible.

---

## Configure advisory mode

```yaml
# cmcp-config.yaml
attestation:
  provider: auto
  enforcement_mode: advisory
policy_bundle_path: ./policies/
catalog_path: ./catalog.json
```

Start the gateway:

```bash
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
```

---

## Read advisory signals in responses

When a call would have been denied, the `_cmcp` block in the response carries `would_have_denied: true`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{"type": "text", "text": "<tool response>"}],
    "_cmcp": {
      "call_id": "a3f8c1d2-...",
      "audit_entry_hash": "sha256:7f3c9a...",
      "would_have_denied": true,
      "advice": {
        "reason": "pii_tool_requires_dpo_approval",
        "escalate_to": "dpo@example.com"
      },
      "latency_us": 11200,
      "session_id": "s-abc123"
    }
  }
}
```

`would_have_denied: true` means the Cedar policy matched at least one `forbid` rule for this call. The `advice` field, when present, contains annotations from the matched rule: this is operator-authored content from the policy bundle, not caller input.

When `would_have_denied: false`, the call was allowed by policy and no forbid rules matched.

---

## Instrument your agent to surface advisory denials

Log every `would_have_denied: true` response during the advisory period:

```python
import httpx, json, logging

logger = logging.getLogger(__name__)

GATEWAY = "http://localhost:8443"
TOKEN = "dev-token"


def call_tool(tool_name: str, arguments: dict) -> str:
    resp = httpx.post(
        f"{GATEWAY}/mcp",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TOKEN}",
        },
        content=json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }),
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    if "error" in data:
        raise RuntimeError(data["error"]["message"])

    result = data["result"]
    cmcp = result.get("_cmcp", {})

    if cmcp.get("would_have_denied"):
        logger.warning(
            "ADVISORY_DENY: tool=%s call_id=%s advice=%s",
            tool_name,
            cmcp.get("call_id"),
            cmcp.get("advice"),
        )

    return result["content"][0]["text"] if result.get("content") else ""
```

Run your agent workload through the gateway. Collect warnings from `ADVISORY_DENY` log lines. Each one is a call that `enforcing` mode would block.

---

## Read denials from the audit chain

The audit chain records every advisory denial with `policy_decision: "advisory_deny"`. Export the full audit bundle after your test run:

```bash
# Close the session first to get a signed TRACE claim
curl -X POST http://localhost:8443/sessions/<session_id>/close \
  -H "Authorization: Bearer dev-token"

# Export the audit bundle
curl "http://localhost:8443/audit/export?session_id=<session_id>" \
  -H "Authorization: Bearer dev-token" | python -m json.tool
```

Filter for advisory denials in the chain entries:

```python
import json, sys

bundle = json.load(sys.stdin)
entries = bundle.get("entries", [])

advisory = [e for e in entries if e.get("policy_decision") == "advisory_deny"]
for e in advisory:
    print(f"seq={e['sequence_number']} tool={e['tool_name']} rule={e.get('policy_rule_matched')}")
```

`policy_rule_matched` names the Cedar rule that would have triggered the deny. This is the rule you need to review: either the rule is correct and the agent behavior needs to change, or the rule is too broad and needs narrowing.

---

## Common causes of advisory denials

| `policy_rule_matched` pattern | Likely cause |
|---|---|
| Rule matching on `compliance_domain` | Tool is in a restricted domain; agent is missing a required attribute |
| Rule matching on `sensitivity_level` | Session has accumulated high-sensitivity context |
| Rule matching on `tool_name` | Tool is explicitly restricted by name in the policy |
| Rule matching on `workflow_id` | Workflow is not in the policy's approved set |

Check your Cedar policy files (`policies/*.cedar`) for the named rule to understand the condition.

---

## Move from advisory to enforcing

Once advisory run logs show no unexpected denials:

1. Review every `ADVISORY_DENY` and confirm each is either:
   - A legitimate policy enforcement (agent behavior should be fixed), or
   - A policy that needs narrowing (update the rule, recompute bundle hash)
2. Update `cmcp-config.yaml`:

```yaml
attestation:
  enforcement_mode: enforcing
```

3. If you pinned `CMCP_POLICY_HASH`, recompute it after any rule changes:

```bash
cmcp validate-bundle --bundle-path ./policies/ --expected-hash sha256:<new-hash>
```

4. Restart the gateway. First tool call that matches a forbid rule now returns HTTP 403.

---

## Use `silent` for initial baselining

If your policy is still incomplete and `advisory` mode generates too much noise to be useful, start with `silent`:

```yaml
attestation:
  enforcement_mode: silent
```

In silent mode the policy runs but neither logs nor blocks. Use it only to confirm the policy engine loads and evaluates without crashing. Move to `advisory` as soon as you have rules to tune.

---

## Summary

| Step | Mode | Purpose |
|---|---|---|
| Policy skeleton only | `silent` | Confirm engine loads |
| Real workload testing | `advisory` | Observe would-have-denied signals |
| Policy tuned, no surprises | `enforcing` | Full enforcement |

`would_have_denied: true` in `_cmcp` is your per-call signal. `policy_decision: "advisory_deny"` in the audit chain is the durable record. Use both together: the response signal for real-time instrumentation, the audit chain for post-run analysis.

Related tutorials: [Cedar policy walkthrough](./cedar-policy-walkthrough.md): writing the Cedar rules that produce these denials. [Connecting agent frameworks](./connecting-agent-frameworks.md): how to read `_cmcp` metadata from your agent code.
