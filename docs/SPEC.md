# cMCP Runtime - Product Specification

Status: Draft v0.1

Architectural conviction: in the agent era, the agent-to-tool boundary is a primary control surface, not a backup to deterministic backends. Primary control surfaces must be tamper-evident in hardware. Phase 1 attests that boundary on the consumer side (the gateway). Phase 2 attests it on the provider side (the server).

---

## 1. Problem

Enterprise AI teams deploying agents through MCP face four governance problems without complete answers.

### Problem 1 : Data exposure through tool calls

Agents send prompts containing PII, IP, internal records, and customer data to MCP servers that may persist, log, or forward them. Enterprises have no systematic way to inspect, scrub, or block this traffic.

Five shapes:

**P1.1 Over-sharing context.** The agent passes more of its context to a tool than the task requires. The tool persists or relays the surplus downstream. Nothing in the chain inspects the payload against a policy because nothing in the chain is responsible for inspecting it.

**P1.2 Chatty tool responses.** The tool returns more data than was asked for. The surplus sits in the agent context window for the rest of the session and propagates as context into every subsequent tool call, including ones with looser destinations than the original.

**P1.3 Cross-system compliance boundary violations.** Each individual tool call is authorized. The combination crosses a compliance boundary. The agent acts as a confused deputy between a covered system and an uncovered one, and nothing in the chain sees the data flow because nothing is watching the graph of calls, only the individual permissions on each.

**P1.4 Transitive trust into upstream dependencies.** The customer approves an MCP server from their catalog. That server internally calls a third-party API the customer never authorized. The customer's data protection agreement covers the gateway. It does not cover the gateway's upstream dependencies. Phase 1 partially addresses this shape. Phase 2 closes it.

**P1.5 Session-context bleed.** Sensitive data from an earlier high-sensitivity tool call persists in the agent context window and bleeds into unrelated later tool calls. The leak surface is the session, not any single tool call.

OWASP: MCP10 (primary) - MCP01, MCP02, MCP05 (adjacent)

### Problem 2 : Unsanctioned tool use and tool poisoning

Agents are non-deterministic by construction. A model can choose to call any tool in the MCP catalog. Adversaries register tools under legitimate names or modify tool descriptions to embed hidden instructions.

Four shapes:

**P2.1 Poisoned tool descriptions.** A tool description contains hidden instructions that the LLM reads as authoritative system context. The human admin sees a benign description in the catalog UI. The LLM treats the planted instruction as authoritative. Every call to that tool now triggers the injected behavior.

**P2.2 Drive-by server installs.** A developer installs an MCP package, adds it to a shared config, or downloads from a marketplace without security review. The agent host auto-aggregates it with legitimate servers. There is no central registration authority for MCP servers.

**P2.3 Tool name collisions.** Two MCP servers expose the same tool name with the same JSON schema. The agent host has no protocol-level way to disambiguate by publisher identity. Routing depends on registration order or hash-map iteration order. MCP defines no signed manifest binding a tool name to a publisher.

**P2.4 Install-time scope too coarse for runtime.** The approved catalog contains tools that are correct for some workflows but catastrophic in others. There is no per-workflow scope narrowing. Install-time approval is too coarse for what a non-deterministic model might pick at runtime.

OWASP: MCP02 (primary) - MCP03, MCP07, MCP09 (adjacent)

### Problem 3 : Lack of provable governance

Even when policies exist, enterprises cannot prove to auditors, regulators, or customers that those policies were actually enforced on every request. Software-only enforcement is opaque to outside parties. Audit logs live in operator-controlled storage and ultimately rest on the operator's word.

Two shapes:

**P3.1 Regulatory proof requests.** Regulators examining AI processing ask for per-decision evidence: which tool was invoked, which policy decided it, what payload left the boundary. A software-only gateway produces logs. Those logs are signed with software-held keys. The regulator's follow-up question -- "can you prove this was true at the time of processing, not just at the time of audit?" -- has no answer that does not bottom out in trusting the operator. (EU AI Act Art. 12, DORA Art. 9, NIST AI RMF)

**P3.2 Customer pre-renewal questionnaires.** An AI vendor in late-stage renewal receives a questionnaire: for every agent action that touched customer data via MCP last quarter, can you provide evidence of which tool was invoked, which policy decided it was allowed, and what was in the payload after egress scrubbing? A SOC 2 report and an architecture diagram describe intended behavior, not proven runtime behavior.

OWASP: MCP08

### Problem 4 : Identity and supply-chain risk on the server side

When an agent calls a third-party MCP endpoint, it has no cryptographic basis for trusting that the endpoint is what it claims to be, runs the code it claims to run, or behaves as advertised -- and no way to detect when that changes.

Two shapes:

**P4.1 Typosquatted or look-alike MCP packages.** MCP package registries are being seeded with malicious lookalikes. A developer installs the wrong package on autopilot, or an AI coding assistant suggests an install command with the wrong spelling. The malicious package presents a plausible MCP server interface and exfiltrates everything it sees. Phase 1 partially addresses this shape. Phase 2 closes it.

**P4.2 Rug-pull at runtime via silent tool-definition mutation.** A previously-approved MCP server uses the MCP notifications/tools/list_changed message to silently modify tool definitions after the security review concluded. The tool name stays the same. The JSON schema stays the same. Only the description changes. The agent host does not flag the change because nothing in the protocol distinguishes drift from the approved manifest from a routine update.

OWASP: MCP04, MCP09, MCP03 (runtime variant)

---

## 2. Why software-only enforcement is structurally insufficient

In the API era, gateways were secondary controls. Deterministic backends (DB schemas, auth checks, business-rule validators) caught misconfigured or bypassed gateways. In the agent era that contract breaks. Agents are non-deterministic by construction. Tool choices and payloads are model outputs, not deterministic code paths. There is no deterministic backstop behind the gateway that will catch an agent calling a tool it should not, sending data it should not, or being tricked by a poisoned response.

The gateway and the server are now primary control surfaces -- the only enforcement layers between an autonomous reasoning loop and the real world. Software enforcement was acceptable when these were backups. It is structurally insufficient when they are the only thing standing between a non-deterministic agent and sensitive data. Hardware is what makes those primary control surfaces themselves tamper-evident.

---

## 3. Solution: cMCP Runtime

The cMCP Runtime intercepts every MCP tool call, evaluates it against a Cedar policy bundle, and enforces the result from inside a TEE. The policy bundle hash is measured into the hardware attestation report before any code runs. The audit chain is signed with a key that is hardware-sealed inside the enclave.

The output is a TRACE Claim: a signed, hardware-attested artifact the enterprise hands to an auditor, regulator, or customer instead of a written response. The verifier does not need to trust the operator.

---

## 4. Architecture

```
Agent
  |
  v
cMCP Runtime (TEE boundary) -- the sole MCP endpoint the agent host sees
  +-- MCP Protocol Interceptor
  |     receives every tool call before it reaches the tool
  |
  +-- Cedar Policy Engine
  |     per-call policy (allow / deny / require-approval)
  |     per-workflow scope (narrower than catalog)
  |     policy_bundle_hash measured at enclave startup
  |
  +-- Call Graph Tracker
  |     tracks which data from Tool A flows to Tool B
  |     enforces cross-system compliance boundary policy
  |
  +-- Response Inspector
  |     content-policy checks on tool responses before they re-enter agent context
  |     session-context classification (high-sensitivity tag propagation)
  |
  +-- Enforcement Decision
  |     allow / deny / redact / advisory
  |
  +-- TRACE Claim Generator
  |     signs with TEE-sealed key
  |
  +-- Audit Chain (append-only inside enclave)
  |
  v
Tool (MCP Server) -- identity bound to catalog entry, not just tool name
```

Network position: sits between agent host and MCP servers. The gateway is the only MCP endpoint the agent host is configured to reach. No changes required to existing MCP servers (HTTP/SSE transport -- see issue for stdio).

---

## 5. TRACE Claim Schema

The unit of proof handed to an auditor, produced per session (or per call, configurable).
The normative schema is [`schemas/trace-claim.schema.json`](../schemas/trace-claim.schema.json),
and a full worked example is in [the quickstart](quickstart.md). The envelope is a
`GatewayClaim`: canonical TRACE v0.1 fields live under `trace`, cMCP-specific addenda live
under `gateway`, and `signature` is detached (computed over every other field).

```json
{
  "cmcp_version": "1.0",
  "trace": {
    "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
    "iat": 1730000000,
    "subject": "spiffe://cmcp.gateway/tee/<key-prefix>",
    "runtime": {
      "platform": "amd-sev-snp | intel-tdx | tpm2 | software-only",
      "measurement": "sha256:<hex>",
      "nonce": "<base64url nonce binding the report to this session>"
    },
    "policy": {
      "bundle_hash": "sha256:<hex>",
      "enforcement_mode": "enforce | advisory | silent",
      "version": "<semver>"
    },
    "data_class": "<highest sensitivity reached this session>",
    "tool_transcript": {
      "hash": "sha256:<audit chain tip>",
      "call_count": 42,
      "entries": [
        { "tool_name": "salesforce.query", "data_class": "pii", "decision": "allow" }
      ]
    },
    "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "<base64url>", "kid": "cmcp-<id>" } }
  },
  "gateway": {
    "session_id": "<uuid>",
    "sequence_number": 1,
    "audit_chain": { "root": "sha256:<hex>", "tip": "sha256:<hex>", "length": 43 },
    "call_summary": {
      "tool_calls_total": 42,
      "tool_calls_allowed": 40,
      "tool_calls_denied": 2,
      "tool_calls_faulted": 0,
      "tools_invoked": ["salesforce.query", "snowflake.read"],
      "session_max_sensitivity": "pii",
      "call_graph_summary": { "compliance_domains_touched": [], "cross_boundary_events": [] }
    },
    "catalog": { "hash": "sha256:<hex>", "drift_detected": false },
    "attestation_generated_at": "<ISO 8601>",
    "attestation_validity_seconds": 86400,
    "attestation_stale": false,
    "catalog_exceptions": []
  },
  "signature": "<base64url Ed25519 over the canonical JSON of every field except signature>"
}
```

Verification (no operator trust required):
1. Verify the `trace.cnf.jwk` public key against `trace.runtime` (hardware-rooted attestation)
2. Verify `signature` using that key
3. Check `trace.policy.bundle_hash` against the approved bundle hash on record
4. Check `gateway.catalog.hash` against the approved catalog hash on record
5. Recompute `trace.tool_transcript.hash` and walk `gateway.audit_chain` root to tip for call-level detail

---

## 6. Attestation Bindings (Phase 1 unique properties)

Each binding makes a software-only-impossible property externally verifiable.

| Binding | Attestation field | What it makes provable |
|---------|-------------------|----------------------|
| Cedar policy bundle measured at enclave startup before any user code runs | policy_bundle_hash | The policy that ran is the policy that was approved -- no silent substitution |
| Enforcement mode bound into attestation | enforcement_mode | Gateway ran in enforcing, not advisory |
| Tool catalog measured at startup | tool_catalog.hash | Runtime catalog drift (P4.2 rug-pull) produces a measurement mismatch |
| Audit signing key generated and sealed inside TEE, never exported | audit_chain_root + hardware-sealed key | Audit log cannot be reconstructed by a privileged insider |
| Workload integrity bound to hardware measurement | container_image_digest | The gateway code running is the gateway code attested |

---

## 7. Threat Model

### Formal threat classes

| Class | Threat | Why software fails | Why hardware wins |
|-------|--------|-------------------|------------------|
| T1 | Rogue administrator or privileged insider modifies policy or log | Hash chain generation runs inside the compromised OS; operator holds the signing key | Policy bundle hash measured into attestation before enclave starts; signing key is TEE-sealed and cannot be extracted |
| T2 | Host OS compromise flips policy evaluator via IPC | Policy evaluator and IPC channel exist in the attacker address space | Policy evaluator runs in isolated enclave memory; communication through attested channel |
| T3 | Post-incident audit log reconstruction | SHA-256 chains prove internal consistency only; any party with the key can reconstruct a valid chain | Signing key is hardware-sealed; audit_chain_root is in the attestation report; external verifier detects mismatch |
| T4 | Policy substitution at enforcement time | Hash verification and policy loading run in a mutable process; comparator can be patched | Policy bundle measured before any user code runs; substituted bundle produces a different measurement |

### Coverage corrections (from threat model review)

APM payload capture (P1 shapes): Mitigated with default-deny egress policy, not Closed. Protection is operator-dependent -- an allowlist that permits the APM endpoint removes the protection. This must be stated as Mitigated in the threat model, not Closed.

SDK telemetry capture: Same as above. Mitigated with default-deny, not Closed.

Tool identity / server swap (T1 adjacent): Closed only if the agent verifies the attestation report before sending traffic. Without agent-side verification (see verification library issue), the gateway produces an attestation report that nobody checks.

---

## 8. Phase 1 Coverage Matrix

Across the four problems and 13 shapes, Phase 1 covers 11 outright and partially covers 2 (the residuals Phase 2 closes).

| Problem | Shape | Phase 1 coverage |
|---------|-------|-----------------|
| P1 Data leakage | P1.1 Over-sharing context | Strong -- gateway egress DLP, attested |
| P1 Data leakage | P1.2 Chatty tool responses | Strong -- response inspection and classification-tag propagation, attested |
| P1 Data leakage | P1.3 Cross-system boundary violations | Strong -- call graph tracked; cross-boundary policy attested |
| P1 Data leakage | P1.4 Transitive trust into upstream dependencies | Partial -- gateway attests the immediate server; cannot reach into that server's own upstream calls. Phase 2 closes. |
| P1 Data leakage | P1.5 Session-context bleed | Strong -- gateway-attested session-level egress policy with sensitivity propagation |
| P2 Unsanctioned tools | P2.1 Poisoned tool descriptions | Strong -- tool-definition scanner inside attested gateway; catalog hash pinned |
| P2 Unsanctioned tools | P2.2 Drive-by server installs | Strong -- gateway is the sole MCP endpoint; new server registration is a measurable policy change |
| P2 Unsanctioned tools | P2.3 Tool name collisions | Strong -- catalog binds each tool name to a specific upstream server identity |
| P2 Unsanctioned tools | P2.4 Install-time scope too coarse | Strong -- per-workflow Cedar policy, attested |
| P3 Provable governance | P3.1 Regulatory proof requests | Strong (signature win) -- TRACE claim answers all three regulator questions directly |
| P3 Provable governance | P3.2 Customer questionnaires | Strong -- TRACE claim as portable proof artifact |
| P4 Supply chain | P4.1 Typosquatted packages | Partial -- gateway refuses non-catalog servers, but cannot detect a typosquat added to catalog. Phase 2 closes. |
| P4 Supply chain | P4.2 Rug-pull via tool-definition mutation | Strong -- catalog hash pinned; runtime drift produces measurement mismatch |

---

## 9. Attestation Provider Hierarchy

| Provider | Hardware | Assurance |
|----------|----------|-----------|
| tpm | TPM 2.0 / vTPM | Medium |
| sev-snp | AMD SEV-SNP (Azure DCasv5, AWS C6a Nitro) | High |
| tdx | Intel TDX (Azure DCedsv5, GCP C3) | High |
| opaque | OPAQUE Managed Runtime (opt-in; not yet implemented) | n/a |

Auto-detection probe order: `tpm -> sev-snp -> tdx`. The first provider whose `detect()`
succeeds is selected. `opaque` is a not-yet-implemented placeholder: it is excluded from
auto-detect, and selecting it explicitly raises `ATTESTATION_PROVIDER_NOT_IMPLEMENTED` rather
than falling through silently. If no hardware provider is detected, the gateway starts only
under `CMCP_DEV_MODE=1` (a non-attested software-only fallback) and otherwise refuses to
start. Default `enforcement_mode` is `enforcing`.

---

## 10. Policy Lifecycle

1. Author - Cedar bundle committed to version control with machine-readable provenance manifest
2. Seal - bundle hash recorded in deployment manifest
3. Measure - TEE measures hash into attestation report at startup, before any calls
4. Enforce - every tool call evaluated against the sealed bundle; no runtime updates without full enclave restart
5. Audit - TRACE Claim records policy_bundle.hash; verifier checks against approved hash

---

## 11. Phase 1 Scope

In scope:
- MCP protocol interception (agent to MCP servers, HTTP/SSE transport)
- Cedar policy evaluation inside TEE (per-call and per-workflow)
- Call graph tracking for cross-system boundary enforcement
- Response inspection before content re-enters agent context
- Session-context sensitivity tagging and bleed detection
- Tool catalog binding (tool name to specific upstream server identity)
- TRACE Claim generation and signing
- Hardware attestation: TPM, SEV-SNP, TDX (OPAQUE Managed is an opt-in placeholder, not yet implemented)
- Enforcement modes: enforcing, advisory, silent
- Egress policy: allow/deny/redact per tool and per field
- Per-session TRACE Claim with call summary
- Agent-side verification library (cmcp-verify)
- Python SDK (cmcp-runtime), config file (cmcp-config.yaml)

Not in Phase 1:
- MCP server-side attestation (Phase 2)
- stdio transport (requires bridge -- see issue)
- Real-time policy updates without enclave restart
- Multi-tenant TRACE Claim routing
- Tool identity verification for packages added to catalog (typosquat P4.1 residual -- Phase 2 closes)
- Transitive trust into upstream dependencies (P1.4 residual -- Phase 2 closes)
- cMCP registry

---

## 12. Phase 2: cMCP Server (provider-side)

Phase 2 closes the two residuals Phase 1 leaves open (P1.4 transitive trust, P4.1 typosquatting) and enables four new use cases that Phase 1 structurally cannot reach because they live on the provider side of the trust boundary.

Five attestable properties unique to Phase 2:

| Property | What it makes provable |
|----------|----------------------|
| Server runtime hardware-measured | The binary running now is the binary attested -- not just signed at some earlier moment. Compromised-maintainer reissue is detected. |
| Server tool surface measured at startup | Rug-pull caught at the source: server cannot expose a tool whose definition differs from the attested catalog. |
| Server egress profile attested | Closes P1.4 transitive trust: customer verifies the server's own downstream calls are within declared scope. |
| Multi-tenant isolation hardware-provable | SaaS providers demonstrate that tenant boundaries were enforced, not just configured. |
| Cross-organizational attestation chains | Party A verifies party B's server directly -- no shared operator, no SOC 2 in between. |

Not the current build focus. Revisit after Phase 1 GA and early production feedback.
