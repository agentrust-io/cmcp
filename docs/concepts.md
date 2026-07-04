---
description: How cMCP works. The four design ideas behind hardware-attested MCP tool-call governance: tamper-evident audit, TRACE Claims as evidence, TEE-measured Cedar policy, and operator-independent verification.
---

# How cMCP Works

This page explains the four core design ideas behind cMCP. The [quickstart](quickstart.md) shows you how to run it; this page explains why it works.

---

## The problem: logs can be edited

Traditional agent audit logs are written by the agent process or its operator. Any party with write access to the log can modify it after the fact. An operator could:

- Remove tool calls that should not have happened
- Replace a policy hash with a different one after a breach
- Replay a different session's clean audit trail for a production incident

cMCP closes this by moving the audit anchor point to hardware, not software.

---

## TRACE Claims: evidence, not logs

A TRACE Claim is not a log. It is a cryptographically signed statement of what happened during a session, produced by hardware that the operator cannot modify.

The key difference:

| | Log | TRACE Claim |
|---|---|---|
| Who produces it | Agent process or operator | TEE firmware + cMCP runtime |
| Can it be edited post-hoc? | Yes | No: signature would fail |
| Can the operator forge it? | Yes | No: signing key never leaves the TEE |
| Who can verify it? | Anyone with read access | Anyone with the public key (no trust in operator) |

A TRACE Claim is a [TRACE Trust Record](https://trace.agentrust-io.com) with a `GatewayClaim` envelope. The envelope adds the session summary and audit chain. The inner trust record follows the TRACE v0.1 spec.

### What a TRACE Claim asserts

Every cMCP TRACE Claim makes four categories of assertion:

1. **Identity**: Which gateway TEE produced this claim (`subject` field, SPIFFE URI)
2. **Policy**: Which Cedar policy bundle was loaded at startup, and whether it was in enforcing or advisory mode (`policy.bundle_hash`, `policy.enforcement_mode`)
3. **Transcript**: How many tool calls were made, what their Merkle root is, and what the highest-sensitivity data class touched was (`tool_transcript`, `data_class`)
4. **Attestation**: What hardware platform produced the signing key, and what measurement was recorded at boot (`runtime.platform`, `runtime.measurement`)

---

## Hardware attestation: why the claim is trustworthy

The signing key for a cMCP TRACE Claim is generated inside the TEE and never leaves it. The TEE also measures its own state at boot: recording a SHA-384 digest of the firmware, the Cedar policy bundle, and the tool catalog into a PCR/measurement register.

This means:

- If anyone changes the policy bundle between sessions, the `runtime.measurement` changes. Old claims and new claims have different measurements. An auditor can detect the switch.
- If the operator tries to swap the signing key, the new key produces a different `cnf.jwk`. Old claims signed with the original key no longer verify under the new key.
- If the TEE is compromised at the firmware level, the PCR values change. The RIM (Reference Integrity Manifest) check fails.

The verification chain for a Level 1 claim:

```
AMD CA (root of trust)
  └─ VCEK certificate (chip-unique, from AMD KDS)
       └─ SNP attestation report (signed by VCEK)
            └─ runtime.measurement (from report)
            └─ report.REPORT_DATA == SHA-256(tee_public_key)
                  └─ cnf.jwk (TEE-bound signing key)
                       └─ signature (over the TRACE Claim body)
```

Each step in the chain is independently verifiable. The final verifier does not trust the runtime operator at any point.

See [Spec: Attestation](spec/attestation.md) for the full verification protocol.

---

## Audit chains: tamper-evidence for the transcript

Each tool call within a session is recorded as an audit entry. cMCP chains these entries using a Merkle-style hash:

```
entry_0_hash = SHA-256(session_id || tool_name_0 || args_hash_0 || result_hash_0)
entry_1_hash = SHA-256(entry_0_hash || tool_name_1 || args_hash_1 || result_hash_1)
...
chain_tip    = entry_N_hash
```

The TRACE Claim records `audit_chain.root` (the first entry hash) and `audit_chain.tip` (the final entry hash). The `tool_transcript.hash` in the inner trust record equals the chain tip.

**Why this matters:** An auditor who has the individual audit log entries can recompute the chain tip and verify it matches the TRACE Claim. If any entry was modified, deleted, or reordered, the recomputed tip will not match. The audit log is self-certifying.

The audit chain does not need to be stored on-chain or in a third-party system. The signed TRACE Claim is sufficient to detect tampering after the fact: as long as the claim itself was not forged (which the hardware attestation prevents).

See [Spec: Call Graph](spec/call-graph.md) for the full chain construction.

---

## Cedar policy: authorization that is auditable by design

Cedar is an authorization policy language designed to be auditable. cMCP uses it for three reasons:

**1. The policy is versioned and hash-bound.** The SHA-256 of the policy bundle is measured into the TEE at startup. Every TRACE Claim carries that hash. An auditor can compare the hash in a claim to the policy bundle in the repository and prove which policy was active for a given session: even if the policy was later changed.

**2. Policy effects are data, not code.** Cedar policies are declarative and cannot execute arbitrary code. A `forbid` rule can block a tool call; it cannot read files or make network requests. This means policy review is tractable: the policy file is the complete specification of what the agent is allowed to do.

**3. Cedar supports fine-grained context conditions.** Policies can condition on session attributes like `session_max_sensitivity`, `workflow_id`, or `data_class`. This enables dynamic policy enforcement without code changes: the same binary can enforce different rules for different tenant configurations.

Example: this policy blocks `salesforce.contacts` once PII has entered the session:

```cedar
forbid (
  principal,
  action == cMCP::Action::"call_tool",
  resource == cMCP::Resource::"salesforce.contacts"
) when {
  context.session_max_sensitivity == "pii"
};
```

If the agent tries to call `salesforce.contacts` after handling PII data, cMCP records the denial in the audit chain and (in `enforcing` mode) returns HTTP 403. The TRACE Claim records the attempt and the denial count, so the auditor can see that the policy blocked the call.

See [Spec: Cedar Policy](spec/cedar-policy.md) for the full schema and supported context attributes.

---

## How the pieces fit together

```
 ┌─────────────────────────────────────────────────────┐
 │  At startup:                                        │
 │  1. TEE generates Ed25519 key (never leaves TEE)    │
 │  2. Cedar policy bundle measured into PCR           │
 │  3. Tool catalog loaded and hashed                  │
 └─────────────────────────────────────────────────────┘
                         │
                         │ session begins
                         ▼
 ┌─────────────────────────────────────────────────────┐
 │  Per tool call:                                     │
 │  4. Cedar policy evaluated (allow / deny)           │
 │  5. Audit entry appended to hash chain              │
 │  6. Call forwarded (or blocked) based on policy     │
 └─────────────────────────────────────────────────────┘
                         │
                         │ session ends
                         ▼
 ┌─────────────────────────────────────────────────────┐
 │  TRACE Claim produced:                              │
 │  7. Build GatewayClaim with chain root/tip          │
 │  8. Sign with TEE-bound key                         │
 │  9. Return to caller / push to registry             │
 └─────────────────────────────────────────────────────┘
```

The signed claim ties together: hardware identity (attestation), policy version (policy hash), transcript integrity (audit chain), and cryptographic non-repudiation (TEE signature).

## Next steps

- [Quickstart](quickstart.md): run a cMCP gateway locally in under 30 minutes
- [Configuration](configuration.md): full configuration reference
- [Tutorial: Cedar policy walkthrough](tutorials/cedar-policy-walkthrough.md): write and test policies
- [Tutorial: Verify a TRACE claim](tutorials/verifying-a-trace-claim.md): verify a claim without trusting the operator
- [Spec: Component Model](spec/component-model.md): detailed architecture
