# Session Policy

Status: Draft v0.1 | Closes #36 | Related: [response-inspection.md](response-inspection.md) (feeds this), [call-graph.md](call-graph.md) (uses this)

## Overview

Individual call policy - Cedar evaluated before each tool call - is necessary but not sufficient. It answers "is this call permitted given what we know right now?" It cannot answer "has this session already seen PHI, and does that change what downstream calls are permitted?" That question requires session-level state that accumulates across calls.

Phase 1.5 introduces session sensitivity tracking to close this gap. Once a session has handled data at a given sensitivity level, outbound calls to destinations that are not approved for that sensitivity level are denied - even if each individual call would pass pre-call Cedar policy in isolation. The session sensitivity state is monotonically increasing within a session: it can only go up, never down, short of an explicit operator-authorized reset.

## Session Sensitivity State Machine

### States

Sensitivity states, ordered from lowest to highest:

```
public < pii < confidential < hipaa_phi = mnpi = trade_secret
```

`hipaa_phi`, `mnpi`, and `trade_secret` are all at the highest level. There is no ordering among them: a session that has seen MNPI is equally restricted as one that has seen PHI. Once a session reaches any of the three, the same egress rules apply.

### State Transitions

State is **monotonically increasing** within a session. It never decreases automatically. The only way to return to a lower state is an explicit operator-authorized session reset (see below).

The transition trigger is the `update_from_inspection` call made by the response inspection pipeline after every tool call. See [response-inspection.md](response-inspection.md) for when and how that call is made.

```python
SENSITIVITY_ORDER = {
    "public": 0,
    "pii": 1,
    "confidential": 2,
    "hipaa_phi": 3,
    "mnpi": 3,
    "trade_secret": 3,
}

def update_from_inspection(
    self,
    call_id: str,
    sensitivity_tags: list[str],
    injection_detected: bool,
    response_allowed: bool,
) -> None:
    for tag in sensitivity_tags:
        if SENSITIVITY_ORDER[tag] > SENSITIVITY_ORDER[self.max_sensitivity]:
            self.max_sensitivity = tag
            self.sensitivity_raised_at = now()
            self.sensitivity_raised_by_call = call_id
    if injection_detected:
        self.injection_events.append({
            "call_id": call_id,
            "timestamp": now(),
            "response_allowed": response_allowed,
        })
```

Note that `response_allowed` is recorded in injection events but does not affect state transition logic. A denied response that carried high-sensitivity tags still raises `max_sensitivity` - the agent is aware the call was attempted.

## Cedar Egress Policy Using Session State

Cedar evaluates pre-call policy with session state available as a context attribute. Three representative policies:

**Policy 1: Block PHI egress to uncovered external destinations**

```cedar
forbid(
  principal,
  action == Action::"call_tool",
  resource
)
when {
  context.session.max_sensitivity == "hipaa_phi" &&
  resource.tool.destination_type == "external" &&
  !resource.tool.hipaa_covered
};
```

**Policy 2: Block MNPI egress to communication tools**

```cedar
forbid(
  principal,
  action == Action::"call_tool",
  resource
)
when {
  context.session.max_sensitivity == "mnpi" &&
  resource.tool.category == "communication"
};
```

**Policy 3: Block any high-sensitivity session from writing to public channels**

```cedar
forbid(
  principal,
  action == Action::"call_tool",
  resource
)
when {
  [3].contains(context.session.sensitivity_level_int) &&
  resource.tool.output_visibility == "public"
};
```

In Policy 3, `sensitivity_level_int` is a derived integer attribute on the session context object (computed from `SENSITIVITY_ORDER` at context construction time) so Cedar can use numeric comparison.

## Session Reset Protocol

**Endpoint:** `POST /session/reset`

**Credential required:** Operator credential. Agent credentials are not accepted. This is intentional - see below.

**Effect:**
- `max_sensitivity` is reset to `"public"`
- A new `session_id` is generated; the old session ID is retired
- An audit chain entry of type `"session_reset"` is written:

```json
{
  "type": "session_reset",
  "reason": "<operator-supplied string>",
  "authorized_by": "<operator principal>",
  "previous_session_id": "<old session id>",
  "new_session_id": "<new session id>",
  "timestamp": "<ISO-8601>"
}
```

**When reset is not possible or not yet called:** If the runtime is in enforcement mode and `max_sensitivity` is `"hipaa_phi"`, `"mnpi"`, or `"trade_secret"`, outbound calls to non-covered or non-approved destinations are denied by Cedar egress policy (see above). The agent cannot unblock itself. There is no agent-callable override endpoint.

This is intentional. The agent is an LLM: it is non-deterministic, and the runtime cannot trust agent assertions about what is or is not in its context window. Once a session has handled high-sensitivity data, the only entity that can attest "this session is now clean" is a human operator who has verified the agent's context. The reset endpoint is the mechanism for that attestation.

If an operator reset is not available (e.g., the runtime is processing automated batch jobs with no operator in the loop), the correct architectural response is to provision short-lived sessions scoped to a single sensitivity domain, rather than relying on reset.

## Session Lifetime and Attestation Validity

A session's maximum duration is bounded by the attestation validity period of the agent's TRACE token. When the TRACE token expires, the session must end - the gateway cannot continue to enforce session-level policy for an agent whose identity and configuration are no longer attested.

In practice: session `max_duration_seconds` is set to `min(configured_session_max, trace_token_ttl_remaining)` at session creation. A session that is still active when its TRACE token would expire is terminated by the runtime with an audit entry of type `"session_expired"`.

This means a long-running agent that handles high-sensitivity data early in its session will face increasingly tight call restrictions as the session progresses - both because `max_sensitivity` is monotonically increasing and because the TRACE token TTL is monotonically decreasing. Deployments should size TRACE token lifetimes to match expected task durations.

## Agent Manifest Identity Binding

When `agent_manifest` is configured, session creation is bound to a signed Agent Manifest. The runtime loads the manifest and issuer trust anchor, verifies the Ed25519 signature over the Agent Manifest `signed_fields` pre-image, and extracts:

- `manifest_id`
- `agent_id`
- `artifacts.policy_bundle.hash`
- `artifacts.tool_manifest.catalog_hash`

The authenticated agent subject for the session MUST be a SPIFFE URI and MUST equal `manifest.agent_id`. In the current HTTP runtime this subject is supplied by `agent_manifest.authenticated_subject`; production deployments SHOULD wire this value from the inbound agent SVID/mTLS identity. If the subject, manifest signature, policy hash, or catalog hash does not match, the runtime fails closed before serving the session.

This binding answers "who acted" for the session. It does not replace `trace.subject`, which continues to identify the cMCP gateway session (`spiffe://cmcp.gateway/session/<uuid>`). Instead, the TRACE Trust Record carries `gateway.agent_identity` alongside the session subject:

```json
{
  "trace": {
    "subject": "spiffe://cmcp.gateway/session/<session-id>"
  },
  "gateway": {
    "agent_identity": {
      "manifest_id": "<manifest UUID>",
      "agent_id": "spiffe://factory.example/agent/material-movement/dev",
      "authenticated_subject": "spiffe://factory.example/agent/material-movement/dev",
      "issuer": "spiffe://factory.example/signing-authority/development",
      "issuer_key_id": "<sha256 of issuer public key>",
      "policy_bundle_hash": "sha256:<manifest policy hash>",
      "tool_catalog_hash": "sha256:<manifest catalog hash>"
    }
  }
}
```

Offline verifiers SHOULD cross-check `gateway.agent_identity` against the signed manifest and trusted issuer key. This keeps the runtime boundary check and the evidence artifact self-checking.

## TRACE Claim Fields from Session State

The following fields from session state are included in the TRACE attestation record for the session (written at session close):

| Field | Type | Description |
|-------|------|-------------|
| `session_max_sensitivity` | string | The highest `max_sensitivity` value reached during the session. |
| `session_reset_count` | integer | Number of times `POST /session/reset` was called during the session lifetime. Normally `0`; a non-zero value warrants review. |
| `agent_identity` | object | Optional Agent Manifest binding: manifest ID, bound agent ID, authenticated subject, issuer key ID, policy hash, and catalog hash. Present only when `agent_manifest` is configured and verified. |
