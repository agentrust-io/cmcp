# Kill switch

This page is for operators who need a way to stop a misbehaving AI agent. The kill switch blocks an agent automatically when too many of its tool calls are being refused, or by hand when an operator decides to. Each stop leaves signed evidence that someone else can check later without having to take the operator's word for it.

## What you'll learn

- How to configure the rolling-window kill switch in `cmcp-config.yaml`
- What happens when an agent trips the threshold
- How to read `kill_switch_triggered` and the `kill_switch` block in a TRACE claim
- How to check a signed refusal against the claim
- How to trip and unblock an agent identity (operator actions)

## Prerequisites

```bash
pip install cmcp-runtime
```

The gateway needs to know which agent it is serving, so it has something to block. That comes from an [Agent Manifest](../spec/component-model.md), a signed description of the agent that gives it an identity (a SPIFFE URI, a standard ID format for software). With `kill_switch.enabled: true` and no manifest configured, the gateway refuses to start (`KILL_SWITCH_REQUIRES_IDENTITY`), because the switch would look armed while having nothing to stop.

---

## Background

An agent can start asking for things it should not: because of a bug, a bad setting, or a prompt injection (hidden instructions planted in content the agent reads). Your rules refuse each call, but without something more the agent keeps running and the refusals just pile up in the log.

The kill switch handles this. cMCP keeps count of allowed and refused calls for each agent over the last few minutes, and checks the count after every call. Once enough calls have been made and the share refused passes your threshold, it stops the agent at the call that crossed the line:

1. Closes the session at once, without waiting for the client, and signs its TRACE claim with `gateway.kill_switch_triggered: true` and `gateway.kill_switch.trigger: "deny_rate"`
2. Refuses every later call, and every new session, from that agent identity with `KILL_SWITCH_TRIPPED (403)`, each refusal carrying a signed receipt
3. Appends a `break_glass_used` audit entry recording the trip and the call that caused it (`tripping_call_id`)

When cMCP runs on protected hardware (SEV-SNP, TDX, Azure CVM, TPM), the key that signs the claim is named in the hardware's own signed report, so a checker can tie the claim, and every receipt signed by the same key, to the measured gateway without trusting the operator. In Level 0 (`CMCP_DEV_MODE`, software only) the same claim is signed by a software key and shows only that the gateway process signed it.

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

Every field has a default. `enabled: false` (the default) turns the switch off without removing the block.

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Master switch. Set to `true` to activate. |
| `window_seconds` | `300` | Rolling window length in seconds. |
| `deny_rate_threshold` | `0.9` | Fraction of calls that must be denied to trip; above 0 and at most 1. |
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

Run a session where the agent makes mostly denied calls. cMCP evaluates the rolling window as each call completes. At the call that crosses the threshold it closes the session and signs the claim, which is then available at `GET /sessions/{session_id}/trace-claim`:

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
    ks = claim["gateway"].get("kill_switch")
    if ks is None:
        print("The kill switch was not armed for this session.")
    elif claim["gateway"]["kill_switch_triggered"]:
        print(f"Stopped by the kill switch, trigger: {ks['trigger']}")
```

Someone checking the claim offline, with no connection to the gateway, can confirm that:

- The kill switch was armed, and with which settings: the `gateway.kill_switch` block (`window_seconds`, `deny_rate_threshold`, `min_calls`) is present only when the switch is enabled, so its absence means it was not armed
- It stopped this session (`kill_switch_triggered: true`) and why (`kill_switch.trigger`: `deny_rate` or `operator`)
- The policy that caused the denies is recorded by hash in `trace.policy.bundle_hash`
- The audit chain tip in `trace.tool_transcript.hash` covers every decision, including the `break_glass_used` entries for the trip and any unblock
- On a hardware provider, the attestation evidence ties the claim's signing key to the measured gateway

### Check a refusal

Every call refused by a tripped gateway comes back with a signed receipt in `error.data.receipt`. It is signed with the same key as the gateway's claims and names the closed session's claim by its fingerprint (digest). Anyone can send a call to a tripped gateway at any time and check the answer:

```python
from cmcp_verify import verify_kill_switch_refusal

refusal = verify_kill_switch_refusal(receipt, claim)
if refusal.valid:
    print(f"{refusal.agent_id} refused at {refusal.refused_at}")
else:
    print(refusal.errors)
```

The check passes only when the claim's signature verifies, the receipt was signed by the same key, the receipt's `claim_digest` matches the claim, and the claim records that the kill switch stopped that session. Run `verify_trace_claim` on the claim as well: the receipt check ties the refusal to the claim's key, and the claim check ties that key to the hardware. A gateway that was blocked before it started has not yet signed a claim, so its receipts carry no `claim_digest` and do not pass this check until its session is closed.

---

## What a tripped gateway does

The session whose close tripped the switch still returns its signed claim. After that the gateway serves nothing: every `tools/call` is refused at once with `KILL_SWITCH_TRIPPED (403)`, session close and reset return `409`, and `GET /readyz` reports `not_ready` with a `kill_switch` check naming the blocked identity.

The block is stored in the audit database (`audit_db_path`), so restarting the gateway does not lift it. A gateway that starts while its identity is blocked comes up, so the unblock endpoint is reachable, but serves no calls. The first entry after `session_start` in its audit chain is a `break_glass_used` entry with `reason: kill_switch_block_active_at_start`. If the audit database cannot be opened, the gateway does not start.

The rolling window of recent decisions is not stored. After a restart it starts empty, which can delay a trip but cannot lift a block.

## Unblock an agent identity

Only an operator can lift a block. `POST /kill-switch/unblock` is an operator route: when `CMCP_OPERATOR_TOKEN` is configured, it accepts only that token.

```bash
curl -X POST https://localhost:8443/kill-switch/unblock \
  -H "Authorization: Bearer $CMCP_OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "spiffe://example.com/agent/procurement-bot",
       "reason": "deny spike traced to a policy typo, fixed in bundle 42",
       "authorized_by": "oncall@example.com"}'
```

All three fields are required. The block is removed from the audit database and the gateway resumes, on a new session when the trip closed the old one. The unblock is recorded as a `break_glass_used` entry with `reason: kill_switch_unblocked` in the audit chain of the session that resumes service, carrying `authorized_by`, the operator's reason, and which credential was verified. An identity that is not blocked returns `404 NOT_BLOCKED`.

## Trip the switch by hand

An operator can stop the bound agent identity without waiting for its deny rate. `POST /kill-switch/trip` is an operator route and requires the kill switch to be enabled.

```bash
curl -X POST https://localhost:8443/kill-switch/trip \
  -H "Authorization: Bearer $CMCP_OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "exfiltration attempt reported by the SOC",
       "authorized_by": "oncall@example.com"}'
```

The identity is blocked in the audit database, a `break_glass_used` entry with `reason: kill_switch_operator_trip` records who tripped it and why, and the live session is closed. The response carries that session's signed claim. From the moment the trip starts no new call is admitted. Calls already running are drained the same way as on any close: they finish, or are cancelled at `CMCP_SESSION_CLOSE_DRAIN_SECONDS`. A gateway with no Agent Manifest bound has no identity to block and returns `409 NO_AGENT_IDENTITY`; a gateway with the kill switch disabled returns `409 KILL_SWITCH_DISABLED`.

---

## What counts as a deny

Both `deny` and `advisory_deny` decisions count toward the refusal rate. A `fault` (the tool itself failed) does not count, because it says nothing about whether the agent broke a rule.

| Decision | Counted as deny? |
|---|---|
| `allow` | No |
| `deny` | Yes |
| `advisory_deny` | Yes |
| `fault` | No |
| `redact` | No |

---

## What the evidence shows, and what it does not

The claim, its audit chain and the refusal receipts show that the switch was armed and with what settings, that it stopped the session and why, which call crossed the threshold or which operator tripped it, that later calls from the identity reached the gateway and were refused, and who lifted the block.

They do not show what the agent did outside the gateway. A tool the agent can reach by some other path is outside these records, so the stop is only as complete as the network path that forces tool traffic through cMCP. Calls admitted before a trip are drained rather than aborted (see [limitations](../limitations.md)). Receipts exist only for calls that reach the gateway. In Level 0 none of this is bound to hardware.

---

## Summary

You configured the rolling-window kill switch, ran a session that tripped the threshold, and verified that the TRACE claim carries `gateway.kill_switch_triggered: true` and the `kill_switch` block. Later calls and sessions from the stopped identity are refused with `KILL_SWITCH_TRIPPED (403)`, and each refusal carries a receipt that `verify_kill_switch_refusal` checks against the claim.

Related tutorials: [TEE attestation](./tee-attestation.md) covers backing the TRACE claim that carries `kill_switch_triggered` with hardware, and [Verify a TRACE claim](./verifying-a-trace-claim.md) covers checking `kill_switch_triggered` as part of offline verification.
