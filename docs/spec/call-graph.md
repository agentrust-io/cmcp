# Call Graph Tracking

Closes #35.

## Overview

Individual call authorization is insufficient for cross-system compliance boundary enforcement (P1.3). A session may issue a sequence of tool calls where each individual call is authorized, but the combination crosses a compliance boundary. The gateway tracks a per-session call graph inside the enclave to detect and enforce against these patterns.

## Section 1 — Call Graph Data Structure

Per-session call graph stored inside the enclave:

```json
{
  "session_id": "string",
  "nodes": {
    "[call_id]": {
      "call_id": "string",
      "tool_name": "string",
      "server_identity": "string",
      "compliance_domain": "hipaa_phi | pci_data | mnpi | pii | internal | external | public",
      "timestamp_utc": "string",
      "policy_decision": "allow | deny",
      "sensitivity_tags": ["string"]
    }
  },
  "edges": [
    {
      "from_call_id": "string",
      "to_call_id": "string",
      "data_flow": "context_window"
    }
  ]
}
```

`sensitivity_tags` are derived from Cedar policy or tool definition.

An edge exists when the response from call A was part of the agent context when call B was made. Phase 1 uses conservative labeling: if call A's response was received before call B, add an edge.

## Section 2 — Compliance Domain Classification

Each tool in the catalog carries a `compliance_domain` annotation:

```json
{
  "tool_name": "ehr.get_patient",
  "compliance_domain": "hipaa_phi",
  "requires_baa": true
}
```

A tool call inherits its `compliance_domain` from its catalog entry. If not specified, the default is `"external"`.

Cross-boundary policy in Cedar:

```cedar
forbid(principal, action == Action::"call_tool", resource)
when {
  context.session_max_sensitivity == "hipaa_phi" &&
  resource.compliance_domain == "external" &&
  !resource.baa_covered
};
```

## Section 3 — Conservative Tainting Algorithm (Phase 1)

Phase 1 uses context-level tainting (conservative, simpler than semantic provenance):

1. `session_sensitivity` starts at `"public"`.
2. When a tool call returns a response classified as high-sensitivity (by Cedar policy or tool annotation), `session_sensitivity` is raised to `max(current, tool.sensitivity_level)`.
3. `session_sensitivity` is monotonically increasing within a session (once raised, never lowered).
4. A session reset (explicit via API call) clears `session_sensitivity` back to `"public"` and starts a new `session_id`.

## Section 4 — TRACE Claim Extension

Add to `call_summary`:

```json
"call_graph_summary": {
  "compliance_domains_touched": ["string"],
  "cross_boundary_events": [
    {
      "from_domain": "string",
      "to_domain": "string",
      "call_id": "string",
      "policy_decision": "allow | deny"
    }
  ]
}
```
