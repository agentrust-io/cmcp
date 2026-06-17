# Limitations

This document describes what cMCP does not prevent, where its guarantees end, and what operators and verifiers must address through separate controls.

## What cMCP does not prevent

**Prompt injection into Cedar policy**
Cedar policy evaluation is only as correct as the policy the operator wrote and approved. cMCP measures the policy bundle hash into the TEE attestation report, which proves the policy that ran is the policy that was approved. It does not evaluate whether that policy achieves the intended security outcome. A policy that contains `permit(principal, action, resource);` without conditions permits every tool call. Policy correctness is the operator's responsibility; policy review is a separate control.

**Compromised TEE firmware or microcode**
Hardware attestation proves the workload hash was measured in silicon. It does not protect against vulnerabilities in the TEE firmware or CPU microcode itself (Spectre-class side channels, cache timing, power analysis, fault injection targeting the TEE boundary). Protection at this level is the responsibility of the hardware vendor. Operators must keep TEE firmware and microcode up to date; see [Compensating Controls](docs/spec/threat-model.md#compensating-controls-operator-responsibilities) in the threat model.

**Operator-controlled key material**
The TEE-sealed signing key is generated inside the enclave and cannot be extracted by a privileged operator under normal circumstances. However, if the operator can substitute the TEE firmware, modify the enclave startup measurement, or compromise the SPIRE infrastructure that issues SVIDs, they can effectively control what key material is used. The trust root is the hardware platform vendor (AMD, Intel, or the TPM manufacturer), not cMCP. Deployments that do not independently verify the attestation report before routing traffic treat attestation as post-hoc audit evidence only.

**Phase 2 completeness: server-side attestation**
Phase 1 attests the gateway boundary. It does not attest what happens on the other side of that boundary. The `tool_transcript.hash` field in the TRACE Claim records a hash of the audit chain tip, but the tool transcript binding that ties a specific tool execution to a specific response is Phase 2 work. Phase 1 partially addresses P1.4 (transitive trust into upstream dependencies) and P4.1 (typosquatted packages added to catalog) -- both are fully closed by Phase 2. Any compliance claim that relies on server-side proof must wait for Phase 2.

**External execution evidence (issue #301)**
An audit entry may carry an optional `external_execution_evidence` receipt: a signature from an independent authority (for example a safety controller) attesting to an outcome, bound to a specific `call_id`. This is deliberately distinct from `response_payload_hash`, which records what the gateway forwarded. The receipt establishes that the named issuer signed an assertion about that call. It does not establish that a physical action occurred, that it was safe, or that it meets any functional-safety standard, and it is only as trustworthy as the issuer key behind it. cMCP does not observe the actuation; it records the receipt and, when a verifier is configured with the issuer trusted key, checks the signature and the `call_id` binding. Trust in the issuer key is an out-of-band PKI concern, the same shape as the manifest issuer trust anchor in issue #302. Verification is opt-in: receipt-less entries, and verifiers that do not configure issuer keys, are unaffected.

In the proxy path, cMCP binds the receipt when an allowed upstream tool response is a JSON object with a top-level `external_execution_evidence` object matching the audit schema. The full response, including that receipt if present, remains covered by `response_payload_hash`.

The TRACE Claim does not carry a separate "external evidence present" flag. Verifiers learn that external evidence was bound by fetching the committed audit bundle and checking entries under the TRACE Claim's `gateway.audit_chain.tip`.

**LLM inference and model output**
cMCP intercepts tool calls at the MCP protocol boundary. It does not observe or modify LLM inference, the contents of the agent's context window, or model outputs that do not produce a tool call. A model could hallucinate a response, leak sensitive context in a chat reply, or receive a poisoned tool response that influences subsequent reasoning -- none of these are visible to the gateway. cMCP controls the tool boundary, not the model boundary.

**Response injection evasion via novel patterns**
The response inspector uses pattern-based detection for prompt injection in tool responses. Pattern-based detection has false negatives. A sufficiently sophisticated injection may evade the current pattern list. The pattern list must be maintained and updated by the operator as new injection techniques emerge; see [Compensating Controls](docs/spec/threat-model.md#compensating-controls-operator-responsibilities).

**APM and telemetry payload capture**
The TEE prevents plaintext from leaving the enclave to any destination not covered by the egress policy. This protection is structural only when the egress policy explicitly denies APM and telemetry endpoints. If the operator allowlists those endpoints in the Cedar policy, the TEE boundary does not prevent payload capture by the APM agent. A TRACE Claim with an egress policy that permits APM or SDK telemetry endpoints does not provide this protection. Verifiers must inspect the policy bundle hash and confirm the policy excludes those endpoints.

**Tool name collision via malicious catalog entries**
The catalog binds each tool name to a specific upstream server identity, which prevents routing ambiguity for approved servers. It does not prevent a typosquatted or look-alike package from being added to the catalog in the first place. Catalog approval is human-gated. The gateway trusts the catalog; it cannot detect that a catalog entry was added via a compromised reviewer or a social engineering attack.

## What Level 0 (CMCP_DEV_MODE) does not provide

`CMCP_DEV_MODE=1` uses a software-only TEE provider. It is suitable for development, testing, and demo scenarios. It does not satisfy production governance requirements because:

- **No hardware root of trust.** The signing key is held in software and is accessible to any process running as the same user. A privileged operator can extract it.
- **No verifiable measurement.** The `trace.runtime.measurement` field is all zeros in dev mode. There is no hardware-measured enclave identity, so a verifier cannot confirm which binary ran.
- **Threat classes T1 through T4 are not covered.** These are the rogue administrator, host OS compromise, post-incident audit log reconstruction, and policy substitution threats described in the [threat model](docs/spec/threat-model.md). All four require a hardware TEE to close. In software-only mode, all four remain open.
- **TRACE Claims are partially verified only.** The `cmcp_verify` library returns `status: partially_verified` and reports `hardware_attestation: software-only mode -- not hardware-backed`. Claims produced in dev mode must not be presented as hardware-attested proof to auditors or regulators.

## What cMCP does not do

- **cMCP is not a WAF.** It does not inspect HTTP traffic for SQL injection, XSS, or other web application attack patterns. It operates at the MCP tool call layer, not the HTTP layer.
- **cMCP is not a content filter.** It does not classify or filter free-text content for harmful material, bias, or policy violations in the LLM inference path. Response inspection is scoped to tool response payloads at the gateway boundary.
- **cMCP is not a network proxy.** It does not perform general-purpose HTTP proxying, TLS termination for arbitrary traffic, or routing outside the MCP protocol. It proxies MCP tool calls only.
- **cMCP is not responsible for MCP server bugs.** The gateway enforces policy and records what happened. Bugs in upstream MCP servers -- memory corruption, logic errors, incorrect data handling -- are outside the gateway's control and are not attested by the TRACE Claim.

## Performance

Attestation is a startup cost, not a per-call cost. Per-call gateway overhead covers Cedar policy evaluation, audit entry creation, and routing. Upstream tool execution time is excluded.

### Attestation handshake (one-time, at startup)

| Provider | Typical latency |
|----------|----------------|
| TPM | less than 500ms (hardware I/O bound) |
| SEV-SNP | less than 100ms (Azure DCasv5, AWS C6a Nitro) |
| TDX | less than 100ms (Azure DCedsv5, GCP C3) |
| Opaque Managed | less than 50ms |
| software-only | negligible |

### Per-call gateway overhead

| Percentile | Target |
|------------|--------|
| p50 | less than 1ms |
| p95 | less than 3ms |
| p99 | less than 5ms |

Expected component breakdown for a 10-rule policy bundle:

| Component | Estimated cost |
|-----------|---------------|
| Cedar evaluation (10 rules) | 0.2 to 0.5ms |
| Audit entry hash computation | approximately 0.1ms |
| Network routing overhead | 0.5 to 2ms |

These are targets from [docs/testing/benchmarks.md](docs/testing/benchmarks.md). Actual results on real TEE hardware will vary by provider and payload size; benchmark results are committed per provider to `benchmarks/` in CI.
