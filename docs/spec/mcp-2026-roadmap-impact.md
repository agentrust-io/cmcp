# MCP 2026 Roadmap Impact on cMCP and Agent Manifest

Status: design backlog, 2026-08-24. This document is informative and does not
change the cMCP protocol.

The MCP project's August 2026 roadmap changes four assumptions that matter to
the AgenTrust stack: protocol-level sessions are gone, Tasks carry long-running
multi-round-trip work, discovery can be progressive, and enterprise identity
must distinguish workload identity from delegated user authority.

## Required cMCP work

| Priority | Gap | Required invariant and deliverable |
|---|---|---|
| P0 | Session-independent correlation | Replace dependence on MCP initialization/session lifetime with a cMCP execution identifier carried across requests. A TRACE claim must remain joinable without implying an MCP protocol session. |
| P0 | Task evidence | Define how task creation, updates, cancellation, webhook delivery, and terminal results bind to one call graph and one policy context. Add replay and out-of-order event tests. |
| P0 | Delegated identity | Record workload identity, represented user, token audience, proof-of-possession key binding, and delegation reference as separate claims. Authentication alone must never be treated as runtime attestation. |
| P1 | Progressive discovery | Bind every authorized tool call to the exact discovered tool schema and catalog checkpoint. Define refresh, cache, removal, and stale-catalog failure behavior for `server/discover`. |
| P1 | HTTP-native transport | Re-evaluate transport protections and evidence correlation for standard HTTP semantics, retries, caching, and resumable operations. |
| P1 | SDK conformance | Add protocol-version vectors and a compatibility matrix so the gateway fails explicitly when an SDK's Tasks, discovery, or transport behavior is unsupported. |

## Required Agent Manifest work

1. Define an MCP discovery artifact containing the server identity, discovery
   endpoint, protocol version, and approved catalog-checkpoint policy.
2. Clarify that `tool_manifest.catalog_hash` can pin a versioned discovery
   checkpoint rather than assuming that the complete catalog is static.
3. Bind workload identity configuration separately from cA2A or OAuth delegated
   authority. A SPIFFE identity says which workload is present; it does not say
   which user powers that workload may exercise.
4. Specify lifecycle evidence for task-capable agents, including callback
   endpoints, cancellation authority, and the maximum validity window.

## Proposed issue sequence

1. cMCP [#565](https://github.com/agentrust-io/cmcp/issues/565): stateless execution correlation profile and compatibility tests.
2. cMCP [#567](https://github.com/agentrust-io/cmcp/issues/567): Tasks and authenticated callback evidence profile.
3. cMCP [#568](https://github.com/agentrust-io/cmcp/issues/568): identity/delegation claim split with DPoP and token-exchange mappings.
4. cMCP [#566](https://github.com/agentrust-io/cmcp/issues/566): progressive discovery catalog checkpoints.
5. Agent Manifest [#340](https://github.com/agentrust-io/agent-manifest/issues/340): MCP discovery artifact and dynamic catalog clarification.

Source reviewed: [MCP Roadmap, August 22,
2026](https://blog.modelcontextprotocol.io/posts/mcp-roadmap/).
