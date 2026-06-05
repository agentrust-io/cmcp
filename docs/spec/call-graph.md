# Call Graph Tracking

Status: Draft v0.1 | Closes #35 | Related: session-policy.md, cedar-policy.md

## Overview

Individual call authorization is insufficient for cross-system compliance boundary enforcement (P1.3). A session may issue a sequence of tool calls where each individual call is individually authorized, yet the combination crosses a compliance boundary. For example: call A retrieves PHI from an EHR tool (authorized for the principal), and call B posts to an external webhook (also authorized for the principal in isolation). Neither call is individually impermissible, but together they represent an unauthorized export of PHI across a regulatory boundary.

The gateway tracks a per-session call log inside the enclave to detect and enforce against these cross-boundary patterns. This document specifies how that tracking works, what the gateway can and cannot observe, and what the resulting enforcement guarantees actually mean.

## The Gateway's Observability Limit (Critical)

The gateway sits at the MCP transport boundary. It can observe:

- Which tool calls are made (tool name, server, arguments)
- Which responses are returned to the agent runtime
- The sequence and timing of calls and responses within a session
- The compliance metadata attached to each tool in the catalog

The gateway **cannot** observe:

- Whether the agent included a specific response in its next context window
- Whether the agent reformulated, summarized, or discarded a response before issuing a subsequent call
- Whether a response was used verbatim, paraphrased, or only consulted for a yes/no decision
- The agent's internal reasoning about which data influenced which subsequent call
- The contents of the agent's context window at any given moment

This is not a gap that can be closed by the gateway alone. The gateway has no privileged access to the agent runtime, the model's context, or the orchestration layer's memory management. Agents may truncate context, use summarization, apply sliding windows, or selectively include only parts of prior responses. These are design choices of the agent system, not observable behaviors at the MCP transport layer.

This means the call graph the gateway maintains is an **approximation based on temporal adjacency**, not true data provenance. Any implementation claiming to track "which data from tool A flowed into tool B's request" is making an inference, not an observation. This distinction has material consequences for compliance claims: a TRACE Claim generated from gateway-observable data cannot assert true data lineage, only temporal co-occurrence within a session.

## Tag-Propagation Model (Phase 1)

Instead of attempting to track data flow (which is not observable by the gateway), Phase 1 uses a **tag-propagation model**: sensitivity tags are associated with tool responses and accumulated conservatively at the session level based on observable events.

The governing principle is conservatism. The gateway cannot know whether a high-sensitivity response influenced a subsequent call, so it assumes that it did. This may produce false positives (blocking a call that would not actually use sensitive data), but it will not produce false negatives (allowing a call that does use sensitive data). For regulated data categories, false negatives are the unacceptable failure mode.

### What Gets Tagged

When the gateway receives a tool response, it classifies the response and assigns sensitivity tags based on three sources, evaluated in order:

1. **The tool's catalog entry** (`compliance_domain`, `sensitivity_level`) — known at call time, before the response arrives
2. **Cedar policy annotations on the tool** (for example, `"this tool always returns PHI"`) — known at call time
3. **Response inspection results** (pattern matching against the response content body) — known only after the response is received

Catalog-based and policy-based classification is performed pre-response and establishes a baseline sensitivity floor for any response from that tool. Response inspection can raise sensitivity further but cannot lower it below the catalog floor.

Available tags and their precedence (lowest to highest):

```
public < pii < confidential < hipaa_phi
public < pii < confidential < mnpi
public < pii < confidential < trade_secret
```

`hipaa_phi`, `mnpi`, and `trade_secret` are terminal high-sensitivity tags. Once any of these is present in `session_max_sensitivity`, that status persists for the session lifetime unless an explicit session reset is issued via the API.

### What the Gateway Stores

Per-session call log (maintained inside the enclave as in-memory working state; this is distinct from the immutable audit chain entry, which is written once per call at decision time):

```json
{
  "session_id": "uuid",
  "call_log": [
    {
      "call_id": "uuid",
      "sequence_number": 0,
      "tool_name": "string",
      "server_identity": "string",
      "compliance_domain": "hipaa_phi | pci_data | mnpi | pii | internal | external | public",
      "timestamp_utc": "ISO8601",
      "policy_decision": "allow | deny",
      "response_sensitivity_tags": ["hipaa_phi"],
      "response_received": true
    }
  ],
  "session_max_sensitivity": "hipaa_phi",
  "high_sensitivity_call_ids": ["uuid-of-phi-call"]
}
```

`session_max_sensitivity` is the running maximum sensitivity tag across all responses received so far in the session. `high_sensitivity_call_ids` contains the call IDs whose responses contributed at least one high-sensitivity tag, for use in the TRACE Claim summary.

### Tag Propagation Algorithm

```
on_response_received(call_id, response):
  tags = classify_response(call_id, response)
  call_log[call_id].response_sensitivity_tags = tags
  max_tag = max_sensitivity(tags + [session_max_sensitivity])
  session_max_sensitivity = max_tag
  if max_tag in HIGH_SENSITIVITY_TAGS:
    add call_id to high_sensitivity_call_ids

on_tool_call_request(call_id, tool, args):
  evaluate Cedar policies with:
    context.session_max_sensitivity = current session_max_sensitivity
    context.sequence_number = len(call_log)
  return allow | deny
```

This is **not** "data follows edges in a graph." It is "session sensitivity is the maximum of all response sensitivities observed so far." A subsequent call to a low-sensitivity destination is evaluated against `session_max_sensitivity`, not against a hypothetical edge representing specific data provenance. This is conservative (it may over-restrict) but it is implementable by the gateway without any cooperation from the agent runtime.

## Edges in the Call Graph (For TRACE Claim Reporting Only)

For the purpose of the TRACE Claim `call_graph_summary` field, an edge is recorded between call A and call B when both of the following hold:

- B's request timestamp is strictly greater than A's response timestamp (A completed before B was initiated)
- `session_max_sensitivity` at the time B was requested includes sensitivity tags from A's response

This produces a temporal adjacency edge, not a data provenance edge. The edge means "A's response was available to the agent before B was requested, and A's response raised session sensitivity." It does not mean "the agent used data from A when formulating B's arguments."

The TRACE Claim metadata **must** document this distinction explicitly. See the TRACE Claim Extension section below.

## Cross-System Compliance Boundary Policy

Cedar policy that enforces cross-boundary restrictions using `session_max_sensitivity` (which the gateway observes directly):

```cedar
forbid(principal, action == Action::"call_tool", resource)
when {
  context.session_max_sensitivity == "hipaa_phi" &&
  resource.destination_class == "external" &&
  !resource.baa_covered
};
```

This correctly expresses: "if any call in this session has received a PHI-tagged response, do not allow calls to external destinations that are not covered by a BAA."

It does **not** express: "data from this specific PHI call flows to this specific external destination." That statement cannot be made from gateway-observable data. The Cedar policy is intentionally written around what the gateway knows.

Additional cross-boundary policies follow the same pattern:

```cedar
forbid(principal, action == Action::"call_tool", resource)
when {
  context.session_max_sensitivity == "mnpi" &&
  resource.compliance_domain == "public" &&
  resource.tool_category == "publishing"
};

forbid(principal, action == Action::"call_tool", resource)
when {
  context.session_max_sensitivity == "trade_secret" &&
  resource.destination_class == "external"
};
```

## TRACE Claim Extension

Add to the `call_summary` block of the TRACE Claim:

```json
"call_graph_summary": {
  "tracking_model": "temporal_adjacency_v1",
  "provenance_disclaimer": "Edges represent temporal adjacency within session, not observed data flow. Gateway cannot verify agent context window contents.",
  "session_max_sensitivity": "hipaa_phi",
  "compliance_domains_touched": ["hipaa_phi", "external"],
  "high_sensitivity_call_ids": ["uuid-of-phi-call"],
  "cross_boundary_events": [
    {
      "from_domain": "hipaa_phi",
      "to_domain": "external",
      "call_id": "uuid-of-subsequent-call",
      "policy_decision": "deny",
      "session_sensitivity_at_decision": "hipaa_phi"
    }
  ],
  "temporal_adjacency_edges": [
    {
      "from_call_id": "uuid-of-phi-call",
      "to_call_id": "uuid-of-subsequent-call",
      "edge_type": "temporal_adjacency",
      "note": "A's response was received before B was initiated and contributed high-sensitivity tags to session state"
    }
  ]
}
```

The `provenance_disclaimer` field is required in every TRACE Claim that includes a `call_graph_summary`. Consumers of TRACE Claims must not interpret temporal adjacency edges as data provenance assertions.

## Phase 2: Agent-Cooperative Tagging

Phase 1 conservatism is the correct starting point but may produce unacceptable false-positive rates in agents that routinely retrieve high-sensitivity data and interact with many downstream tools, where most downstream calls do not actually use the sensitive data.

Phase 2 addresses this by adding agent-side SDK hooks that report context window contents at call time. With agent cooperation, the gateway could receive a manifest of which prior call IDs are represented in the current context window when a new call is issued. This would enable true data provenance edges rather than temporal adjacency approximations.

Phase 2 is out of scope for the current implementation. It requires:

1. A defined SDK interface for agent runtimes to report context state
2. An attestation model for the gateway to verify that context reports are not fabricated
3. Revised Cedar policy semantics that distinguish "agent reports this response is in context" from "gateway inferred this response might be in context"

Until Phase 2 is implemented, all call graph tracking is temporal adjacency. The TRACE Claim format defined above accommodates both models via the `tracking_model` field.

## Compliance Domain Classification

Each tool in the catalog carries a `compliance_domain` annotation:

```json
{
  "tool_name": "ehr.get_patient",
  "compliance_domain": "hipaa_phi",
  "requires_baa": true,
  "sensitivity_level": "hipaa_phi"
}
```

A tool call inherits its `compliance_domain` from its catalog entry. If not specified, the default is `"external"`. The default is intentionally conservative: an unclassified tool is treated as reaching an external boundary.

| `compliance_domain` value | Description | Default sensitivity floor |
|---|---|---|
| `hipaa_phi` | Tool accesses protected health information | `hipaa_phi` |
| `pci_data` | Tool accesses payment card data | `confidential` |
| `mnpi` | Tool accesses material non-public information | `mnpi` |
| `pii` | Tool accesses personally identifiable information | `pii` |
| `trade_secret` | Tool accesses proprietary or trade secret data | `trade_secret` |
| `internal` | Tool accesses internal systems, no regulated data | `confidential` |
| `external` | Tool calls external services or public APIs | `public` |
| `public` | Tool accesses only public data | `public` |

The sensitivity floor means that even if response inspection finds no sensitive patterns in a given response, the session sensitivity is raised to at least the floor value when that tool's response is received.

## Session Reset

A session reset clears `session_max_sensitivity` back to `"public"` and starts a new `session_id`. The prior session's call log is finalized and written to the audit chain. Session resets are available via explicit API call only; they are not triggered automatically by time or call count.

Session reset does not retroactively alter the audit chain entries for the prior session. TRACE Claims are generated per session and are immutable after session finalization.
