# AGT SRE Kill Switch

Automatically block a rogue agent identity when its deny rate exceeds a threshold, and produce hardware-attested evidence of the enforcement action.

## What you'll learn

- How to configure the rolling-window kill switch in `cmcp-config.yaml`
- What happens when an agent trips the threshold
- How to read `kill_switch_triggered` in a TRACE claim
- How to unblock an agent identity (operator action)

## Prerequisites

```bash
pip install cmcp-runtime
```

An [Agent Manifest](../../docs/spec/component-model.md) must be bound to the gateway so the runtime has a per-agent SPIFFE URI to track. Anonymous sessions (no manifest) are never blocked.

---

## Background

In a production deployment an agent can go rogue: a bug, a prompt injection, or a misconfiguration causes it to request tool calls that policy forbids. Without automated remediation, the agent keeps running: accumulating denies in the audit chain but never stopping.

The kill switch closes this gap. cMCP tracks policy decisions per agent identity in a rolling time window. When the deny rate crosses a configurable threshold with enough samples, the runtime:

1. Marks the closing TRACE claim with `gateway.kill_switch_triggered: true`: hardware-attested evidence of automated enforcement, verifiable offline by any regulator
2. Blocks all subsequent `create_session()` calls from that agent identity with a `KILL_SWITCH_TRIPPED (403)` response
3. Appends a `break_glass_used` audit entry to the chain recording the trigger event

No other MCP gateway can produce this artifact. The operator or the sovereign oversight body receives a TEE-signed record proving the agent was automatically stopped.

---

## Configure the kill switch

Add a `kill_switch` block to `cmcp-config.yaml`:

```yaml
kill_switch:
  enabled: true
  window_seconds: 300      # rolling window: 5 minutes
  deny_rate_threshold: 0.9 # trip at 90% deny rate
  min_calls: 10            # require at least 10 calls before evaluating
```

All fields have defaults: setting `enabled: false` (the default) disables evaluation without removing the block.

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Master switch. Set to `true` to activate. |
| `window_seconds` | `300` | Rolling window length in seconds. |
| `deny_rate_threshold` | `0.9` | Fraction of calls that must be denied to trip (0–1]. |
| `min_calls` | `10` | Minimum call count in the window before evaluation starts. |

With `deny_rate_threshold: 0.9` and `min_calls: 10`, an agent must have at least 10 calls in the last 5 minutes with at least 90% of them denied before the kill switch fires.

---

## Run a session that trips the kill switch

Start the gateway with the kill switch enabled and an Agent Manifest bound:

```yaml
attestation:
  provider: sev-snp
  enforcement_mode: enforcing
agent_manifest:
  path: agent.manifest.json
  trust_anchor_path: trust-anchor.pem
  authenticated_subject: spiffe://example.com/agent/procurement-bot
kill_switch:
  enabled: true
  window_seconds: 300
  deny_rate_threshold: 0.9
  min_calls: 10
```

```bash
export CMCP_BEARER_TOKEN="$(openssl rand -hex 32)"
cmcp start --config cmcp-config.yaml
```

Run a session where the agent makes mostly denied calls. When the session closes, cMCP evaluates the rolling window and: if the threshold is exceeded: marks the claim:

```json
{
  "gateway": {
    "session_id": "9e1b4c3a-...",
    "kill_switch_triggered": true,
    "call_summary": {
      "tool_calls_total": 12,
      "tool_calls_allowed": 1,
      "tool_calls_denied": 11
    }
  }
}
```

The next session attempt from `spiffe://example.com/agent/procurement-bot` returns:

```
HTTP 403 KILL_SWITCH_TRIPPED
{
  "error": "KILL_SWITCH_TRIPPED",
  "detail": "spiffe://example.com/agent/procurement-bot"
}
```

---

## Verify the kill switch TRACE claim

```python
from cmcp_verify import verify_trace_claim, ApprovedHashes

approved = ApprovedHashes(
    policy_bundle_hash="sha256:<bundle-hash>",
    tool_catalog_hash="sha256:<catalog-hash>",
)
result = verify_trace_claim(claim, approved)

if result.status == "verified":
    if claim["gateway"]["kill_switch_triggered"]:
        print("Agent was automatically blocked: hardware-attested enforcement confirmed.")
```

A verifier running offline: with no connection to the cMCP gateway or to OPAQUE: can confirm that:

- The kill switch fired in this session (`kill_switch_triggered: true`)
- The policy that caused the denies is recorded by hash in `trace.policy.bundle_hash`
- The audit chain tip in `trace.tool_transcript.hash` covers all deny decisions
- The TEE measurement in `trace.runtime.measurement` confirms the unmodified workload produced the claim

---

## Unblock an agent identity

The kill switch is a process-lifetime block: it persists as long as the gateway process is running. To unblock, restart the gateway. This clears all in-memory state including the blocked identity set and the rolling window.

For a manual operator override without restart, cMCP exposes an operator endpoint (requires `CMCP_BEARER_TOKEN`):

```bash
curl -X DELETE https://localhost:8443/admin/kill-switch/spiffe%3A%2F%2Fexample.com%2Fagent%2Fprocurement-bot \
  -H "Authorization: Bearer $CMCP_BEARER_TOKEN"
```

This calls `KillSwitchEvaluator.unblock()`: clearing the block flag and all rolling window events for that identity. The action is logged to the audit chain.

---

## What counts as a deny

Both `deny` and `advisory_deny` policy decisions count toward the deny rate. A `fault` (tool error) does not count: it indicates a tool-side failure, not a policy enforcement event.

| Decision | Counted as deny? |
|---|---|
| `allow` | No |
| `deny` | Yes |
| `advisory_deny` | Yes |
| `fault` | No |
| `redact` | No |

---

## Sovereign context

For UAE federal ministries and other sovereign deployments, `kill_switch_triggered: true` in a TRACE claim is the answer to "what happens when an agent goes rogue." The proof is hardware-rooted:

- The TEE signs the claim: the cloud operator and the ministry IT team cannot produce this artifact for a different outcome
- The audit chain entry records the agent identity, the deny rate window, and the trigger timestamp
- The claim is verifiable offline by the federal oversight body without calling back to any OPAQUE service

This closes the regulatory gap that a log file cannot close: a log entry is something the operator controls. A TEE-signed TRACE claim with `kill_switch_triggered: true` is not.

---

## Summary

You configured the rolling-window kill switch, ran a session that tripped the threshold, and verified that the closing TRACE claim carries `gateway.kill_switch_triggered: true`. Subsequent sessions from the flagged agent identity are rejected with `KILL_SWITCH_TRIPPED (403)`. The hardware-signed artifact is verifiable by any regulator offline.

Related tutorials: [TEE attestation](./tee-attestation.md): hardware-backing the TRACE claim that carries `kill_switch_triggered`. [Verify a TRACE claim](./verifying-a-trace-claim.md): checking `kill_switch_triggered` as part of offline verification.
