# MCP Spec Evolution Strategy

This document covers the cMCP Gateway strategy for monitoring MCP spec evolution and contributing an attestation extension as an open standard.

## Monitoring Checklist (Weekly)

Track the Agentic AI Foundation GitHub for MCP spec PRs. Watch for proposals in these high-risk areas:

- **Authentication/authorization extensions.** Could commoditize Phase 1 if the base spec absorbs a gateway-like control plane. Monitor closely; a competing proposal here could reduce cMCP differentiation.
- **Streaming protocol changes.** Affects the Phase 2 proxy. Streaming behavior changes require proxy parser updates and regression testing before adoption.
- **Tool identity extensions.** A competitor or the spec working group could propose tool identity as a base-spec feature. If this happens before the attestation extension is submitted, the window for setting the standard narrows.
- **`notifications/tools/list_changed` semantics.** This notification is the primary rug-pull surface (P4.2). Any semantic change to when or how it is sent affects the catalog hash pinning mechanism in Phase 1.

## Attestation Extension Proposal

The window for proposing an attestation extension to the MCP spec as an open standard is 6-12 months from now. The proposal positions cMCP as the reference implementation of an open standard, which is preferable to a proprietary protocol.

### Key elements

**Capability negotiation.** The server advertises `attestation-support` with a list of supported TEE providers during the MCP capability handshake. Non-attested servers do not advertise this capability; the extension is fully backward compatible.

**New message types.** Two new messages:
- `attestation_request`: sent by the agent (or agent's gateway) to request an attestation report
- `attestation_response`: sent by the server, containing a JSON body matching the Phase 2 server TRACE Claim schema

**Attestation response format.** JSON matching the Phase 2 server TRACE Claim schema (fields: `trace_version`, `session_id`, `timestamp_utc`, `tee_public_key`, `attestation_report`, `policy_bundle`, `tool_catalog`, `call_summary`, `audit_chain_root`, `audit_chain_tip`, `signature`).

**Backward compatibility.** Non-attested servers do not advertise the capability and do not need to handle `attestation_request`. Agents that do not request attestation are unaffected.

### Proposal strategy

Submit to the Agentic AI Foundation working group before or alongside the CC Summit launch. Position as an open standard that any TEE provider can implement. The `cmcp-verify` library (see [verification-library.md](verification-library.md)) is the reference client implementation and should be submitted alongside the proposal to demonstrate that the standard is verifiable without trusting the operator.

## Proxy Version Pinning Policy

The Phase 2 proxy must declare the MCP spec version it supports in its gateway configuration:

```yaml
mcp_spec_version: "1.x.y"
```

**Upgrade policy.** Before adopting a new MCP spec version, the proxy runs a compatibility test suite covering:
- All MCP message types the proxy parses
- All notification types, including `notifications/tools/list_changed`
- Edge cases in streaming behavior
- The fuzz corpus in `test/corpus/` (see [proxy-security.md](proxy-security.md))

A version upgrade is blocked until the test suite passes with zero regressions.

**Deprecation.** If MCP releases a breaking change to a message type the proxy depends on, the proxy maintains the old parser for one spec version cycle before requiring an upgrade. This gives operators one cycle to update their deployments.
