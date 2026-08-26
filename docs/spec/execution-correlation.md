# Session Independent Execution Correlation

Status: agreed design for
[#565](https://github.com/agentrust-io/cmcp/issues/565). Implementation remains
separate. This document does not itself change the cMCP protocol.

[mcp-2026-roadmap-impact.md](mcp-2026-roadmap-impact.md) places this work first
in the issue sequence. cMCP needs an execution identifier that survives
independent requests while TRACE evidence remains joinable without implying an
MCP protocol session.

## What binds evidence today

The current dependence is not where the phrase "MCP session" suggests.

`initialize` does not create an identity. `MCPServer._handle_mcp` answers it at
`server.py:449` by negotiating a protocol version and returning capabilities.
No session is minted, no `Mcp-Session-Id` is issued, and nothing about the
handshake is carried into evidence.

The binding is entirely inside the gateway:

| Identifier | Origin | Scope |
|---|---|---|
| `session_id` | `SessionManager.create_session`, `session/manager.py:118`, a `uuid4` | One gateway session |
| `call_id` | `server.py:569`, a fresh `uuid4` per `tools/call` | One tool call attempt |
| `workflow_id` | supplied through `params._cmcp.workflow_id`, `server.py:571-575` | Caller defined grouping |

The current path therefore has three identifiers but no validated correlation
key that a caller can carry across independent requests. The gateway mints
`session_id` and `call_id`. The caller supplies `workflow_id`, but cMCP does
not validate it as execution identity.

`session_id` is what evidence joins on today. Audit entries carry it, the TRACE
Claim is issued per session on close and stored under it
(`manager.py:182`), and the read paths are
`/sessions/{session_id}/trace-claim` and
`/audit/export?session_id=` (`server.py:341`, `server.py:705`). At session
creation the audit chain root is bound into TEE `report_data` where the
platform supports it. `manager.py` warns when that binding fails.

A cMCP session is a gateway lifetime with one chain root and one claim at the
end. It is not an MCP protocol session.

## The gap

`session_id` is the only validated correlation key, and it carries two jobs
that stop fitting together when work arrives through independent requests:

1. It scopes one evidence bundle, one chain root, and one claim.
2. It relates calls that belong to one execution.

One long lived session preserves correlation, but its claim grows without bound
and is unavailable until close. A session per request keeps claims bounded and
prompt, but each request gets a separate chain root and multiple request work
becomes impossible to join.

`workflow_id` groups related work by caller intent, but it is not a validated
execution identity and cannot carry this responsibility alone.

Issue [#571](https://github.com/agentrust-io/cmcp/issues/571) makes the failure
concrete. A fault after upstream invocation can leave the effect uncertain. A
later request gets a fresh `call_id`, so cMCP cannot relate the attempts. With
one session per request, the attempts also land in separate chain roots.

## Agreed design

cMCP adds `execution_id` with these rules:

1. `execution_id` is a typed `AuditEntry` field, not a `detail` key. The
   field is always serialized, including `null` when absent.
2. Collision within one authenticated agent identity is refused.
3. The TRACE Claim does not enumerate `execution_id` values.
4. Reuse after a terminal outcome is refused with no replay window.
5. `execution_id` and `workflow_id` remain independent.

The caller supplies the value beside `workflow_id` in `params._cmcp`. The
gateway validates it and scopes it under the authenticated agent identity.
`execution_id` does not replace `session_id`, `call_id`, or `workflow_id`.
Audit bundles remain joinable offline because each relevant entry carries the
identifier.

The existing `params._cmcp` envelope keeps the design neutral across
transports and avoids depending on future HTTP header design.

## Identity and claim boundary

The action receipt discussion in
[trace-spec#66](https://github.com/agentrust-io/trace-spec/issues/66#issuecomment-5428368994)
states the boundary directly:

`attempt identity ≠ logical operation identity ≠ external outcome identity`

1. `call_id` identifies one attempt.
2. `execution_id` supplies validated correlation for one executable unit across
   requests and attempts.
3. External outcome evidence, when present and independently verifiable,
   establishes what can be claimed about the external effect.

A shared `execution_id` establishes a validated correlation claim. It does not
by itself prove that two requests express the same logical operation, and it
does not prove that an external effect occurred.

Classifying a later request as the same logical operation also requires an
immutable canonical action or intent binding. If the same `execution_id` is
presented with a different binding, the request is a collision or a mutated
operation, not a retry, and the gateway must refuse it before upstream
invocation.

This document does not add another schema field for that binding. The
implementation must define how it verifies the binding. Until it can verify one,
it may report that records share an asserted `execution_id`, but it must not
claim that they are the same logical operation.

## Collision, replay, and missing context

Collision is scoped under authenticated agent identity. The same value used by
different agent identities does not collide. Within one agent identity, a value
that conflicts with the existing immutable action or intent binding is refused
and recorded as a collision.

Reuse after a terminal outcome is refused. There is no replay window. This rule
includes `outcome_unknown`: uncertainty must not become permission to repeat an
irreversible effect. The refusal remains auditable under the asserted
`execution_id`, so offline verification can relate it to the earlier terminal
record without allowing another upstream invocation.

An execution that never reaches a terminal outcome is never reusable and never
expires. A stuck execution therefore holds its identifier until an explicit
recovery design exists. This is the fail closed result.

Missing `execution_id` remains legal for compatibility. The typed audit field
records `null` rather than synthesizing a value. Consumers can trust that a
present value came from the validated caller path.

## Implementation invariants

Collision and replay decisions require one authoritative execution state keyed
by authenticated agent identity and `execution_id`.

Admission must atomically reserve a new identifier and its immutable action or
intent binding before upstream invocation. A concurrent request must not be
able to reserve the same key with a conflicting binding. A terminal transition
must be durable before a later request is classified as replay.

The storage and recovery mechanism remains implementation work. This document
does not add a wire field for it. The implementation evidence must include
concurrent collision, process restart, terminal persistence failure, and replay
tests.

## Relationship to workflow identity

`workflow_id` and `execution_id` remain independent.

`workflow_id` groups work that belongs together by intent.
`execution_id` correlates one executable unit across requests and attempts.
Deriving either value from the other would collapse two distinct questions and
would not be reversible.

If operational evidence later shows a one to one relationship, that is an
observation, not a constraint.

## Against #565 acceptance evidence

**Correlation across retries and multiple request work.** A caller asserted
value lets independent audit entries retain one validated correlation key. The
identifier makes records joinable. It does not grant permission to execute a
replay after a terminal outcome.

**Explicit collision, replay, and missing context failures.** Collision within
one authenticated agent identity is refused. Reuse after a terminal outcome is
refused without a time window. Missing context is represented by a typed
`null`.

**Protocol version vectors.** The SDK conformance matrix owns protocol version
coverage. This design does not invent version negotiation behavior.

**TRACE records remain joinable offline.** The audit entry carries the join key.
The Claim binds the chain and does not duplicate its identifiers.
