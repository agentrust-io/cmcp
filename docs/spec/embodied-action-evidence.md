# Embodied Action Evidence Profile

Status: Proposal v0.1 | Related: [verification-library.md](verification-library.md), [session-policy.md](session-policy.md), [issue #337](https://github.com/agentrust-io/cmcp/issues/337), [trace-spec#66](https://github.com/agentrust-io/trace-spec/issues/66)

This profile defines a small evidence shape for embodied-agent workflows where
an agent requests a physical-world action and cMCP records the governance
decision, controller handoff, and optional external receipt as auditable
evidence.

The profile builds on the existing `external_execution_evidence` audit entry
field. It does not change the core audit schema in v0.1. Instead, it defines how
an embodied-action producer should construct the detached evidence payload that
is committed by `external_execution_evidence.evidence_hash`.

## Scope

This profile is about evidence binding, not actuation or safety certification.

It can prove that:

- the cMCP gateway recorded a specific tool call and policy decision;
- the call was bound to a detached embodied-action evidence payload;
- an external issuer signed an evidence envelope for the same audit `call_id`;
- a verifier with the detached payload and issuer key can recompute the hashes
  and verify the binding.

It cannot prove that:

- a physical action occurred;
- the action was safe;
- a robot, controller, or plant-floor system satisfied IEC 61508, ISO 13849, or
  any other functional-safety regime;
- the external issuer is trustworthy beyond the configured issuer key.

## Evidence Layers

An embodied-action record has three layers:

| Layer | Field or artifact | Purpose |
|-------|-------------------|---------|
| cMCP audit entry | `call_id`, `policy_decision`, `request_payload_hash`, `response_payload_hash` | Records what the gateway decided and forwarded. |
| Evidence envelope | `external_execution_evidence` | Binds an external issuer signature to the audit `call_id`. |
| Detached payload | Embodied action evidence JSON | Defines the action, governance context, controller handoff, and optional downstream receipt. |

The evidence envelope remains the existing cMCP shape:

```json
{
  "issuer": "spiffe://factory.example/controller/robot-cell-7",
  "issuer_key_id": "<sha256 of issuer public key>",
  "signature": "<base64url Ed25519 signature>",
  "evidence_hash": "sha256:<hash of detached embodied-action evidence payload>",
  "evidence_type": "controller-execution-receipt/v1",
  "linked_call_id": "<audit entry call_id>"
}
```

`linked_call_id` MUST equal the cMCP audit entry `call_id`. It MUST NOT be
overloaded with a controller-specific `action_ref`. If a controller or receipt
system uses a content-derived action identifier, that identifier belongs in the
detached payload as `action_ref`.

## Relationship to TRACE Action Receipts

TRACE `verification.action_receipts` defines whether a verifier expects
per-action evidence below the session-level TRACE Claim. This cMCP profile is a
concrete embodied-action evidence shape that can satisfy that axis for
externally consequential tool or controller handoffs.

For embodied AI, `verification.action_receipts: required` SHOULD mean every
externally consequential action has offline-verifiable receipt evidence bound to
the session or cMCP audit `call_id`. It SHOULD NOT mean TRACE proves physical
completion, controller safety, functional-safety certification, or that the
real world changed as intended.

Profile-aware verifiers SHOULD keep three layers separate:

| Layer | Verifier question | Example evidence |
|-------|-------------------|------------------|
| Session | Did this agent session run under the appraised policy/runtime context? | TRACE Claim, audit bundle, policy hashes |
| Action | Was this specific action handoff authorized and receipt-bound? | Detached payload, `action_ref`, receipt signature |
| Physical outcome | What did a controller, monitor, human, or safety system observe? | Controller verdicts, monitor logs, external safety records |

When action receipts are required by verifier policy, profile-aware verifiers
SHOULD:

- recompute `action_ref` from the canonical action preimage;
- verify receipt signatures against pinned or Agent Manifest-bound issuer keys,
  not only keys embedded in the receipt itself;
- verify receipt ordering when receipts are hash-chained;
- verify the receipt binds to the TRACE session, cMCP `call_id`, or
  `action_ref`;
- classify missing, stale, mismatched, or unverifiable receipts distinctly from
  negative controller outcomes;
- treat a valid `rejected` receipt as evidence that the controller rejected the
  action, not as a verifier failure by itself.

This gives cMCP an action-level evidence convention that composes with TRACE
without making the gateway an actuation path or a safety authority.

## Detached Payload

The detached payload is the JSON object hashed by
`external_execution_evidence.evidence_hash`. For this profile, JSON payloads MUST
be canonicalized with RFC 8785/JCS and hashed as UTF-8 bytes.

Minimum v0.1 payload:

```json
{
  "profile": "cmcp.embodied_action_evidence.v0",
  "call_id": "<audit entry call_id>",
  "action_ref": "sha256:<hash of canonical action preimage>",
  "agent_id": "spiffe://factory.example/agent/material-movement/dev",
  "action_type": "move_material",
  "action_scope": "robot-cell-7/material-bin-a",
  "action_timestamp": "2026-06-25T16:30:00Z",
  "governance_decision": "allow",
  "policy_bundle_hash": "sha256:<policy bundle hash>",
  "tool_catalog_hash": "sha256:<tool catalog hash>",
  "controller_target": "spiffe://factory.example/controller/robot-cell-7",
  "handoff_timestamp": "2026-06-25T16:30:01Z",
  "receipt": {
    "receipt_type": "controller-execution-receipt/v1",
    "receipt_hash": "sha256:<hash of controller-native receipt>",
    "verdict": "accepted"
  },
  "limitations": [
    "receipt proves issuer signature over an assertion, not physical completion"
  ]
}
```

Required fields:

- `profile`
- `call_id`
- `action_ref`
- `agent_id`
- `action_type`
- `action_scope`
- `action_timestamp`
- `governance_decision`
- `policy_bundle_hash`
- `tool_catalog_hash`
- `controller_target`
- `handoff_timestamp`

Optional fields:

- `receipt`
- `approval_context`
- `operator_approval_id`
- `limitations`

`action_timestamp` and `handoff_timestamp` MUST be RFC3339 UTC strings with a
`Z` suffix. Producers SHOULD NOT use integer millisecond timestamps in the
profile preimage because different producers otherwise hash the same moment
into different identifiers.

## Action Reference

`action_ref` is a content-derived identifier for the action request. It is
separate from cMCP `call_id`.

For v0.1, compute:

```text
action_ref = "sha256:" + SHA-256(JCS({
  "agent_id": agent_id,
  "action_type": action_type,
  "action_scope": action_scope,
  "action_timestamp": action_timestamp
}))
```

This keeps `call_id` as the audit-chain binding and gives external controllers a
stable content identifier they can reproduce without knowing cMCP internals.

## Governance Decision

`governance_decision` records the decision cMCP made before the handoff. Allowed
values:

- `allow`
- `deny`
- `advisory_deny`
- `fault`

The value SHOULD match the audit entry `policy_decision`. If it does not match,
a profile-aware verifier MUST report the detached payload as inconsistent with
the audit entry.

## Agent Manifest Binding

When the TRACE Claim includes `gateway.agent_identity`, profile-aware verifiers
SHOULD compare:

- detached payload `agent_id`;
- `gateway.agent_identity.agent_id`;
- signed Agent Manifest `agent_id`, when the manifest is supplied.

If all three are present, they MUST match. A mismatch means the evidence no
longer answers "which reviewed agent identity requested this embodied action?"

When `gateway.agent_identity` is absent, verifiers MAY still verify the
external receipt and audit-chain binding, but they MUST NOT claim that the
action was bound to a signed Agent Manifest identity.

## Receipt States

The `receipt` object is optional because some embodied-action evidence is
produced before a downstream controller responds.

Profile-aware verifiers SHOULD classify receipt state as:

| State | Meaning |
|-------|---------|
| `absent` | No downstream receipt was attached. The audit entry can still verify, but no controller assertion was provided. |
| `untrusted` | Receipt is present, but the verifier has no trusted issuer key. |
| `invalid` | Receipt is present but hash, signature, or call binding fails. |
| `stale` | Receipt timestamp is outside verifier policy. |
| `accepted` | Receipt verifies and issuer verdict is accepted. |
| `rejected` | Receipt verifies and issuer verdict is rejected. |

The base cMCP audit bundle verifier validates the evidence envelope signature and
`linked_call_id` when `external_evidence_keys` are provided. The profile-aware
`verify_embodied_action_evidence()` helper adds detached-payload checks without
changing the base audit bundle verification contract.

## ROS 2 Action Fixture

The repository includes a ROS 2 Kilted `rclpy` fixture at
`tests/fixtures/embodied-action-evidence/ros2-fibonacci-aborted.json`.

The fixture is based on a tutorial-scope `example_interfaces/action/Fibonacci`
action run where:

- the client-side and server-side serialized goal preimage hashes matched;
- the ROS action goal UUID matched on both sides;
- the server reported a terminal `aborted` outcome;
- the receipt uses `physical_completion_claim: none`.

The fixture exercises profile fields for:

- `ros2.goal_uuid`;
- `ros2.goal_preimage_hash`;
- `ros2.goal_preimage_method`;
- ROS distribution and RMW implementation;
- terminal controller state;
- receipt issuer role and issuer independence.

It is intentionally a binding fixture, not a live ROS dependency in CI. It does
not prove physical completion, controller honesty, functional safety,
cross-RMW stability, or arbitrary ROS interface compatibility.

## Verifier Flow

Given a TRACE Claim, audit bundle, detached embodied-action payload, optional
Agent Manifest, and trusted issuer keys:

1. Verify the TRACE Claim and audit chain as usual.
2. Locate the audit entry by `call_id`.
3. Verify `external_execution_evidence.linked_call_id == audit_entry.call_id`.
4. Verify the external evidence envelope signature with `external_evidence_keys`.
5. Canonicalize the detached payload with JCS and verify its hash equals
   `external_execution_evidence.evidence_hash`.
6. Verify detached payload `call_id == audit_entry.call_id`.
7. Recompute `action_ref` from the action preimage fields.
8. Compare `governance_decision` to the audit entry `policy_decision`.
9. Compare `policy_bundle_hash` and `tool_catalog_hash` to the TRACE Claim.
10. If `gateway.agent_identity` is present, compare its `agent_id` to the
    detached payload `agent_id`.
11. Classify receipt state using the table above.

A verifier that completes steps 1-10 can claim the embodied-action evidence is
bound to the cMCP audit chain and runtime policy context. It still cannot claim
physical completion or safety certification.

## Compatibility Notes

Existing producers that emit a controller-native receipt with a field such as
`action_ref` SHOULD wrap that receipt in the detached payload and keep the cMCP
evidence envelope `linked_call_id` equal to the audit entry `call_id`.

The profile intentionally preserves the distinction between:

- `response_payload_hash`: the exact response bytes the gateway forwarded;
- `external_execution_evidence.evidence_hash`: the detached evidence payload
  asserted by an external issuer;
- `action_ref`: the content-derived identifier for the requested embodied
  action.

Keeping these three identifiers separate avoids making the gateway claim it
observed physical execution.
