# Transport Compatibility Specification

Covers: Phase 1 transport scope, stdio gap analysis, SPIFFE-to-TEE attestation binding.

Closes #20, #21.

---

## Transport Compatibility Matrix

| Transport | Phase 1 Status | Reason |
|-----------|---------------|--------|
| HTTP/SSE | **In scope** | MCP server runs as a network-addressable process. The gateway terminates the connection at the TEE boundary, inspects each call, and forwards to the upstream server over a separate internal connection. No subprocess spawning required. |
| stdio | **Out of Phase 1 scope** | The stdio transport requires the agent (or MCP client) to spawn the MCP server as a child subprocess. A subprocess cannot cross the TEE boundary: the agent process lives outside the enclave and cannot fork a child that executes inside isolated TEE memory. The memory isolation guarantee of SEV-SNP, TDX, and TPM Trusted Launch is per-VM or per-enclave, not per-process-tree. Bridging stdio into the TEE would require a new component (see options below), deferred to Phase 2 or a future extension. |
| WebSocket | **TBD** | WebSocket provides bidirectional framing over HTTP/1.1 or HTTP/2. The gateway can terminate WebSocket connections in principle; evaluation is deferred pending the MCP specification WebSocket profile stabilizing. |

---

## stdio Gap: Technical Reason

The MCP stdio transport works as follows:

```
Agent process
  └── spawns MCP server as child process
        └── communicates over stdin/stdout (JSON-RPC 2.0 framing)
```

For the gateway to intercept this traffic, it would need to run inside the same process tree as the agent, which contradicts TEE isolation. TEE isolation works at the VM boundary (SEV-SNP, TDX) or at the TPM-measured boot boundary. A process inside the TEE cannot be a child of a process outside the TEE. Allowing it would defeat the hardware attestation guarantee: the enclave measurement would no longer cover the full execution context.

---

## stdio Bridging Options

### Option A: stdio-to-HTTP Bridge (new component at TEE boundary)

A new sidecar component runs outside the TEE and translates stdio JSON-RPC to HTTP/SSE. The gateway (inside the TEE) connects to the sidecar over localhost HTTP.

```
Agent
  └── spawns stdio-bridge (outside TEE)
        └── translates stdio <-> HTTP/SSE
              └── cMCP Gateway (inside TEE)
                    └── MCP Server (HTTP/SSE)
```

| Dimension | Assessment |
|-----------|-----------|
| Agent changes required | Minimal: configure MCP client to use stdio-bridge binary instead of MCP server binary directly |
| Attack surface | Increased. The stdio-bridge runs outside the TEE and can be tampered with. An attacker who compromises the bridge can inject or suppress tool calls before they reach the gateway. |
| Attestation coverage | The bridge is not inside the TEE. Its behavior is not covered by the hardware attestation report. TRACE Claims reflect gateway decisions, not bridge fidelity. |
| Complexity | New component to build, deploy, and maintain. |
| Recommended for Phase 1 | No. The untrusted bridge segment weakens the security model. |

### Option B: Agent-side stdio Proxy (agent wraps stdio server, exposes HTTP/SSE)

The agent developer wraps the stdio MCP server in a thin HTTP adapter that speaks HTTP/SSE externally. The gateway connects to the adapter endpoint as if it were a native HTTP/SSE MCP server.

```
Agent
  └── stdio-http-adapter (agent-side, outside TEE)
        └── spawns MCP server (stdio)
        └── exposes HTTP/SSE on localhost port
              └── cMCP Gateway (inside TEE)
```

| Dimension | Assessment |
|-----------|-----------|
| Agent changes required | Agent developer must run an adapter (e.g., mcp-proxy or equivalent) alongside the stdio server |
| Attack surface | Same as Option A at the adapter layer, but the responsibility is clearer: the agent developer owns the adapter |
| Attestation coverage | Same gap: adapter is outside the TEE |
| Complexity | Lower than Option A: no new first-party component. Reuses existing open-source adapters. |
| Recommended for Phase 1 | Acceptable as a workaround documented under "unsupported configurations." Not a supported path. |

### Comparison Table

| | Option A: Bridge at TEE boundary | Option B: Agent-side proxy |
|---|---|---|
| New first-party component | Yes | No |
| Attack surface added | High (bridge at trust boundary) | Medium (adapter is agent-developer-owned) |
| Attestation covers it | No | No |
| Agent developer effort | Low | Medium |
| Recommended | No | Workaround only |

**Decision for Phase 1**: stdio transport is unsupported. Agents using stdio-only MCP servers must either migrate those servers to HTTP/SSE or use Option B as an undocumented workaround at their own risk.

---

## "Zero Code Changes" Claim: Precise Scope

The "zero code changes" claim applies only to the following configuration:

- The MCP server is containerized (Docker or OCI image).
- The MCP server already supports HTTP/SSE transport (not stdio-only).
- The MCP server does not depend on host-level resources: local filesystem mounts, host network interfaces, or host-specific library versions (e.g., a specific glibc ABI not present in the TEE base image).
- The agent MCP client is configured to point to the gateway endpoint rather than the MCP server directly.

If any of these conditions are not met, code or configuration changes are required before the gateway can be used.

---

## Concrete Agent-Side Configuration

The gateway is the sole MCP endpoint the agent host is configured to reach. All MCP servers are registered with the gateway, not with the agent directly.

### YAML example

```yaml
# agent-config.yaml
mcp:
  # The agent host connects only to the cMCP Gateway.
  # No direct connections to individual MCP servers.
  gateway_endpoint: "https://cmcp-gateway.internal:4433"
  tls:
    ca_cert: "/etc/cmcp/gateway-ca.pem"
    # SPIFFE SVID for mutual TLS (issued only after TEE attestation succeeds)
    client_cert: "/var/run/spire/svids/agent.pem"
    client_key:  "/var/run/spire/svids/agent.key"

  # The agent does not list individual MCP servers here.
  # The gateway tool catalog is the authoritative list of available tools.
  # servers: []  # empty -- gateway handles routing
```

### JSON example (alternative)

```json
{
  "mcp": {
    "gateway_endpoint": "https://cmcp-gateway.internal:4433",
    "tls": {
      "ca_cert": "/etc/cmcp/gateway-ca.pem",
      "client_cert": "/var/run/spire/svids/agent.pem",
      "client_key": "/var/run/spire/svids/agent.key"
    }
  }
}
```

The agent host must not have direct network routes to any MCP server. Network policy (Kubernetes NetworkPolicy, security group, or firewall rule) enforces this. The gateway is the only reachable MCP endpoint from the agent network namespace.

---

## SPIFFE-to-TEE Attestation Binding (Issue #21)

### Problem Statement

SPIFFE SVID issuance must be conditioned on successful TEE attestation. If a SVID can be issued without attestation, any process -- attested or not -- can claim a gateway identity. The binding is the critical-path item for Phase 1: without it, the chain of trust has a gap between hardware measurement and workload identity.

### Standards Basis

- **IETF RATS RFC 9334**: Defines the reference architecture for remote attestation. The Attester (TEE) produces Evidence; the Verifier checks Evidence against Reference Values and produces an Attestation Result; the Relying Party (SPIRE) consumes the Attestation Result to make a trust decision.
- **SPIFFE/SPIRE**: SPIRE issues X.509 SVIDs and JWT SVIDs. SPIRE node attestation plugin model supports custom attestors. The TEE attestation plugin produces an attestation result that SPIRE uses as the basis for SVID issuance.

### Binding Mechanism

```
TEE boots
  └── TEE produces attestation Evidence (measurement)
        └── SPIRE node attestation plugin receives Evidence
              └── Plugin forwards to Verifier (external or embedded)
                    └── Verifier checks measurement against Reference Values
                          └── On success: SPIRE issues SVID to TEE workload
                                └── Gateway uses SVID for mTLS with agents and MCP servers
```

### Per-Provider Attestation Evidence Formats

| Provider | Evidence Type | Description |
|----------|--------------|-------------|
| TPM | PCR values | Platform Configuration Registers (PCR0-PCR7 minimum) contain hashed measurements of each boot component: firmware, bootloader, kernel, initrd. The SPIRE TPM plugin reads PCR values via the TPM2 TSS stack and verifies them against expected values. |
| SEV-SNP | SEV measurement | A SHA-384 hash of the encrypted VM memory contents at launch time, produced by the AMD PSP. The measurement covers the initial memory pages loaded into the encrypted VM. The SPIRE SEV-SNP plugin submits the measurement to AMD attestation service (or a self-hosted equivalent) for verification. |
| TDX | RTMR values | Runtime Measurement Registers (RTMR0-RTMR3) accumulate hashes of components loaded after the TD is created (analogous to TPM PCRs but for TDs). The SPIRE TDX plugin reads the RTMR values from the TD Quote and verifies them against expected values. |
| Opaque | Opaque Managed Runtime measurement | The Opaque platform produces a composite measurement of the enclave and its configuration. The SPIRE plugin delegates to the Opaque attestation API. |

### Validation Spike

**Goal**: Confirm that a SPIFFE SVID can be issued if and only if TEE attestation succeeds, using at least one provider (TPM recommended for accessibility).

**Pass conditions**:
1. SPIRE issues an SVID to the gateway workload only after the TEE attestation plugin returns a successful result.
2. If the TPM PCR values are tampered with (e.g., by modifying the boot sequence in a test VM), SPIRE refuses to issue the SVID and the gateway does not start.
3. The SVID contains a SPIFFE ID that encodes the TEE provider and measurement (or a reference to it).

**Fail conditions**:
1. SPIRE issues an SVID without consulting the attestation plugin.
2. No existing SPIRE plugin supports the target TEE provider; a custom plugin would require more than 2 days to build.
3. The attestation API is not reachable from the TEE environment (network policy or credential bootstrap problem).

**Estimated duration**: 1-2 days.

**If the spike fails**: Phase 1 timeline slips. The binding is non-negotiable for the security model. A failed spike triggers one of:
- Switch to a provider with a working SPIRE plugin (e.g., TPM if the SEV-SNP plugin is missing).
- Build a minimal custom SPIRE plugin (adds 1-2 weeks).
- Defer SPIFFE and use a simpler credential bootstrap (e.g., pre-provisioned TLS cert pinned to the TEE measurement via a separate verification step) -- requires a security architecture review before proceeding.