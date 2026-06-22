# Phase 2 cMCP Server Specification

---
Status: Draft v0.1
Last updated: 2026-06-04
Stability: Unstable , expect breaking changes before v1.0
---

## Section 1 : Phase 2 Architecture Overview

Phase 2 targets a different deployer than Phase 1. The Phase 1 deployer is an agent developer who runs a runtime in front of their own agents. The Phase 2 deployer is a SaaS vendor or AI platform provider who exposes MCP endpoints to enterprise customers. Those enterprise customers — Phase 1 deployers — eventually ask: "prove your server code has not changed since I approved it." Phase 2 answers that question.

Phase 1 closes from the agent side: the runtime attests what the agent sent and what policy was applied. Phase 2 closes from the server side: the MCP server binary, its tool surface, and its egress behavior are all measured inside a TEE and published as a second TRACE Claim that any enterprise verifier can check without trusting the SaaS operator.

Phase 2 also closes two Phase 1 residuals:

- **P1.4 Transitive trust**: Phase 1 attests that the gateway ran, but not that the server the gateway called is trustworthy. Phase 2 attests the server.
- **P4.1 Typosquatted packages / P4.2 tool-definition mutation**: Phase 2 measures the tool catalog at TEE startup; any post-startup mutation produces a verifiable mismatch.

```
Agent developer environment
        |
        v
      Agent
        |
        v
   MCP Client
        | (verify attestation)
        v
SaaS / Platform Provider
  +-----------------------------------------------+
  |  OPAQUE TEE                                   |
  |  +------------------------------------------+ |
  |  |  Provider MCP Server                     | |
  |  |  (binary measured at startup)            | |
  |  +------------------------------------------+ |
  |  Attestation + trust artifact                 |
  +-----------------------------------------------+
        |
        v
  Provider backend
  (DB / APIs / customer data)
```

The combined trust artifact delivered to the verifier is a pair of TRACE Claims: the Phase 1 runtime claim (proves runtime policy ran) and the Phase 2 server claim (proves server binary and tool surface are attested). Neither claim requires trusting the other party's operator.

**Sequencing note.** Phase 2 is the natural pull from Phase 1 adoption. It is not the current build focus. Revisit after Phase 1 GA and early production feedback.

---

## Section 2 : Five Unique Attestable Properties

Each property below is something a TEE measurement can prove that a software-only signature or audit log cannot.

### Property 1: Server Runtime Hardware-Measured

**Definition.** The binary running right now is the binary attested - not just signed at some earlier moment.

**What is measured.** At TEE startup, the container image digest of the MCP server binary is measured into the attestation report. This is the same mechanism Phase 1 uses for the runtime, now applied to the server.

**Attestation field.** `server_attestation.container_image_digest`

**Verification.** The verifier computes the expected hash of the approved server image (from the customer's approved build artifact) and compares it against `server_attestation.container_image_digest` in the server's TRACE Claim. A match means the binary in memory at runtime matches the approved build.

**Why software cannot substitute.** A compromised maintainer who reissues a valid code-signing certificate can reissue a valid signature for malicious code. The hardware measurement is taken at runtime - the binary in memory is measured, not a signature from build time. The TEE measurement cannot be forged after the fact without invalidating the attestation report.

---

### Property 2: Server Tool Surface Measured at Startup

**Definition.** The server cannot expose a tool whose definition differs from the measurement taken at startup.

**What is measured.** At TEE startup, the server's tool catalog - all tool names, descriptions, and input schemas - is hashed and the hash is measured into the attestation report.

**Attestation field.** `server_attestation.tool_catalog_hash`

**Verification.** The verifier computes the expected tool catalog hash from the customer-approved tool definitions (from the vendor's security review artifacts) and compares it against `server_attestation.tool_catalog_hash`. Any rug-pull via `notifications/tools/list_changed` that alters a tool description or schema after startup produces a mismatch detectable on the next verification cycle.

**What this closes.** P4.2 tool-definition mutation. A server that changes its tool descriptions after approval to manipulate agent behavior will produce a tool catalog hash that does not match the approved value.

---

### Property 3: Server Egress Profile Attested

**Definition.** The server's own downstream API calls are within its declared scope. The dependency chain is measurable end-to-end.

**What is measured.** The server's egress policy - an allowlist of upstream APIs the server is permitted to call - is hashed and measured at TEE startup.

**Attestation field.** `server_attestation.egress_policy_hash`

**Verification.** The verifier checks the egress policy hash against the approved policy on record. An enterprise can verify that the MCP server cannot call an unapproved upstream service (for example, an external model API that was not in scope when the server was approved) because any deviation from the measured egress policy is detectable.

**What this closes.** P1.4 transitive trust. Phase 1 attests that the runtime ran the approved policy against the agent's call. Phase 1 cannot attest what the server did next. Phase 2 closes this: the server's own upstream dependencies are part of the attested measurement, and a verifier can confirm the server's transitive call graph was bounded at startup.

---

### Property 4: Multi-Tenant Isolation Hardware-Provable

**Definition.** SaaS providers can demonstrate that tenant data boundaries were enforced in hardware, not just configured in software.

**What is measured.** Each tenant's data path either runs in a separate TEE or in a shared TEE with hardware-enforced memory partitioning. The tenant isolation configuration is measured at startup.

**Attestation field.** `server_attestation.tenant_isolation_mode`

Valid values:

| Value | Meaning |
|---|---|
| `separate_tee` | Each tenant runs in a dedicated enclave. Full hardware isolation. |
| `shared_tee_hw_partitioned` | One enclave, hardware-enforced memory partitioning between tenants. |
| `shared_tee_sw_only` | One enclave, software-only isolation. Not hardware-attested. |

Software-only isolation (`shared_tee_sw_only`) must be labeled explicitly. Verifiers that require hardware-enforced isolation must reject claims with this value.

**Verification.** The verifier checks that `tenant_isolation_mode` is one of the hardware-enforced options (`separate_tee` or `shared_tee_hw_partitioned`) and that the customer's tenant ID appears in the server's attested tenant registry.

---

### Property 5: Cross-Organizational Attestation Chains

**Definition.** Party A (an agent from enterprise A) can verify party B's (a SaaS vendor's) MCP server directly - without a shared operator in the chain and without trusting either party's infrastructure claims.

**Implementation.** The Phase 1 runtime TRACE Claim includes a `server_trace_claim_ref` field pointing to the server's Phase 2 TRACE Claim. The agent (or its runtime) performs two independent verifications:

1. Phase 1 gateway TRACE Claim : proves the gateway's Cedar policy ran and was hardware-attested.
2. Phase 2 server TRACE Claim : proves the server binary and tool surface are attested.

Neither verification requires trusting the other party's operator. Both claims are signed with TEE-sealed keys. The attestation reports are verifiable against the TEE provider's public endorsement chain (AMD ARK/ASK/VCEK for SEV-SNP, Intel PCS for TDX, TPM endorsement certificates for vTPM).

**Combined trust artifact format** (delivered to a cross-org verifier):

```json
{
  "phase1_runtime_claim": "<Phase 1 TRACE Claim>",
  "phase2_server_claim_url": "https://attestation.vendor.com/claims/<session-id>",
  "phase2_server_claim": "<Phase 2 TRACE Claim>"
}
```

The `phase2_server_claim_url` is the canonical reference. The `phase2_server_claim` inline copy is provided for offline verification and archival. The verifier should use the URL to check for revocation and to fetch the latest measurement for the session.

---

## Section 3 : Phase 2 Proxy Architecture for Streaming

The Phase 2 proxy adds payload inspection - content classification and per-field policy evaluation - between the agent and the tool. MCP is moving toward streaming tool responses (chunked HTTP / server-sent events), not just request-response. The proxy architecture must handle both.

### Classification Pipeline Placement

Three placement options:

**Inline (synchronous).** The runtime buffers the entire response before classifying. Latency penalty: `response_size / classification_throughput`. Not viable for streaming - buffering defeats the purpose of streaming and introduces unbounded latency for large payloads.

**Async (default).** The runtime begins streaming the response to the agent immediately. Classification runs concurrently on the streamed chunks. If classification detects a violation partway through:

1. Send a control message to the agent signaling that the in-progress response is being terminated.
2. Close the streaming connection to the agent.
3. Log the partial response hash in the audit chain.

The agent must handle mid-stream termination. This is a protocol contract, not a best-effort behavior.

**Hybrid (configurable).** For high-sensitivity tools (as tagged in the policy bundle), buffer and classify before streaming. For low-sensitivity tools, use async. The policy bundle can annotate each tool with `inspection_mode: buffered | async`.

### Partial-Response Denial Protocol

When the proxy must terminate a streaming response mid-stream, it sends the following MCP event before closing the connection:

```json
{
  "type": "stream_terminated",
  "reason": "inspection_violation",
  "call_id": "<uuid>",
  "data_transmitted_bytes": <N>
}
```

Agents that consume Phase 2 proxied streams must handle `stream_terminated` and treat any partial response as invalid. A partial response that is acted on without checking for `stream_terminated` is a client-side protocol violation.

### Backpressure

If the classification engine is slower than the stream rate, the proxy applies TCP-level backpressure: it stops reading from the upstream (server) connection until classification catches up. This creates natural flow control without dropping data.

Maximum bytes buffered before forced termination: configurable per tool, default 1 MB. When the buffer limit is reached and classification has not completed, the proxy terminates the stream and logs the event as `buffer_limit_exceeded`.

---

## Section 4 : Phase 2 Proxy Reliability Targets

These targets apply to the proxy classification path under nominal load with a representative policy suite. They are design targets for the Phase 2 implementation milestone; final values will be validated against benchmark results from early production deployments.

| Metric | Target | Notes |
|---|---|---|
| False rejection rate | < 0.05% | 1 in 2000 legitimate tool calls incorrectly denied |
| False acceptance rate | < 0.1% | < 0.1% of calls that would be denied by a ground-truth oracle are allowed through; this is a security target |
| Proxy-induced failure rate | < 0.01% | Infrastructure failures causing calls to fail that would have succeeded without the proxy |
| Latency - pattern-based classification | p99 < 10 ms | Cedar policy evaluation + regex/pattern classification |
| Latency - model-based classification | p99 < 100 ms | External classifier inference call included |
| Latency - end-to-end proxy path | p99 < 15 ms | Cedar eval + pattern classification; model-based is separate |

**Fail behavior on proxy unavailability.** Default: fail-closed (deny all calls). This is the safe default for production. Configurable to fail-open for development environments via explicit flag (`enforcement_mode: fail_open_on_proxy_unavailable`). Fail-open must be blocked in production policy bundles.

**False acceptance rate measurement.** This target is harder to measure objectively than false rejection rate. The proxy team will maintain a labeled test corpus of policy-violating payloads, run it against the proxy in a test environment, and report the escape rate. The 0.1% target is a cap on the escape rate against that corpus.

---

## Section 5 : Multi-Tenant Isolation Model

### Phase 1 Stance

Phase 1 is single-tenant by design. One runtime instance = one policy bundle = one audit chain = one customer or business unit. If multiple business units deploy the same runtime binary with different policy bundles, each instance is treated as a separate single-tenant deployment. Multi-tenancy is out of Phase 1 scope.

### Phase 2 Options for Multi-Tenant MCP Servers

SaaS providers running MCP servers typically serve multiple enterprise customers from shared infrastructure. Phase 2 supports two isolation options.

**Option A - Separate TEE per tenant.** Each customer gets a dedicated enclave. The customer's policy bundle, audit chain, and TRACE Claims are fully isolated at the hardware level. No shared memory, no shared scheduler, no shared key material.

- Assurance level: highest.
- Cost: one TEE instance per customer. Not economical at scale for small customers.
- Recommended for: highest-assurance deployments, regulated industries, customers who require hardware isolation as a contractual commitment.

**Option B - Shared TEE with tenant namespacing.** One enclave serves multiple tenants. The policy bundle includes per-tenant policy namespacing: `tenant_id` is a Cedar entity with its own policy set. Audit chains are tagged by `tenant_id`. TRACE Claims are scoped to a `tenant_id`. Isolation is policy-enforced within the TEE.

- Assurance level: high (TEE boundary is shared, but policy enforcement is hardware-attested within it).
- Cost: one TEE instance per server deployment, amortized across tenants.
- Recommended for: standard SaaS deployments where hardware-per-tenant is not economical.
- Limitation: isolation is not hardware-isolated between tenants at the memory level. The `tenant_isolation_mode` field in the attestation report must be set to `shared_tee_hw_partitioned` or `shared_tee_sw_only` to communicate this accurately to verifiers.

Both options are supported in Phase 2. The `server_attestation.tenant_isolation_mode` field tells verifiers which option is in use. Enterprise customers whose compliance requirements mandate hardware-isolated tenancy should verify that the value is `separate_tee` before accepting the server's TRACE Claim.

