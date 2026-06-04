# cMCP Gateway - Product Specification

Status: Draft | Target: CC Summit June 23, 2026
Primary opportunity: Enterprises cannot prove to regulators, auditors, or customers how their data was handled during AI processing.

---

## 1. Problem

Enterprise AI teams deploying agents through MCP face a structural proof gap. They can describe their governance policies in documents. They cannot prove, to a third party, that those policies ran on specific traffic at a specific time - and that the policy engine itself was not modified.

Software-only gateways (AGT, Kong, Cloudflare) close the policy enforcement problem but not the proof problem. An auditor asking to prove the approved policy ran on December 2nd gets a log file. Logs are software-signed. An operator with the signing key can reconstruct a clean chain after the fact.

Evidence:
- 20% of BFSI research respondents (n=15) named this as their top priority
- Capital Group: We are not giving them evidence. We are giving them a written response. 30-40% of requestors push back and demand phone calls.
- Dell: A screenshot used to work five years ago. Now they want to know what triggered it.
- Live medical customer (Armacuni): I do not know how we will prove data access was blocked or not.
- Regulatory surface: EU AI Act Art. 12/14, DORA Art. 9, HIPAA, GDPR Art. 32, NYDFS CISO certification

The follow-up question AGT cannot answer: Prove that the gateway running on December 2nd was the version you say it was, not a modified version someone swapped in. Hardware attestation changes this structurally. An auditor asking to prove the approved policy ran gets a cryptographic answer.

---

## 2. Solution: cMCP Gateway

The cMCP Gateway intercepts every MCP tool call, evaluates it against a Cedar policy bundle, and enforces the result from inside a TEE. The policy bundle hash is measured into the hardware attestation report before any code runs. The audit chain is signed with a key that is hardware-sealed inside the enclave.

The output is a TRACE Claim: a signed, hardware-attested artifact the enterprise hands to an auditor, regulator, or customer instead of a written response. The verifier does not need to trust the operator.

---

## 3. Architecture

```
Agent
  |
  v
cMCP Gateway (TEE boundary)
  +-- MCP Protocol Interceptor
  |     receives every tool call before it reaches the tool
  |
  +-- Cedar Policy Engine
  |     evaluates against sealed policy bundle
  |     policy_bundle_hash measured at enclave startup
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
Tool (MCP Server)
```

Network position: sits between agent host and MCP servers. No changes required to existing MCP servers.

---

## 4. TRACE Claim Schema

The unit of proof handed to an auditor. Produced per-session or per-call (configurable).

```json
{
  "trace_version": "1.0",
  "session_id": "<uuid>",
  "timestamp_utc": "<ISO 8601>",
  "tee_public_key": "<hex>",
  "attestation_report": {
    "provider": "sev-snp | tdx | tpm | opaque",
    "measurement": "<PCR values or SEV measurement>",
    "report_data": "<nonce binding key to report>"
  },
  "policy_bundle": {
    "hash": "<sha256>",
    "enforcement_mode": "enforcing | advisory | silent",
    "policy_version": "<semver>"
  },
  "call_summary": {
    "tool_calls_total": 42,
    "tool_calls_allowed": 40,
    "tool_calls_denied": 2,
    "tools_invoked": ["salesforce.query", "snowflake.read"]
  },
  "audit_chain_root": "<sha256 of first entry>",
  "audit_chain_tip": "<sha256 of last entry>",
  "signature": "<TEE-sealed key signature over canonical JSON>"
}
```

Verification (no operator trust required):
1. Verify tee_public_key against attestation_report (hardware-rooted)
2. Verify signature using tee_public_key
3. Check policy_bundle.hash against the approved hash on record
4. Walk audit_chain_root to audit_chain_tip for call-level detail

---

## 5. Threat Model Coverage

| Threat | Software Governance | cMCP Gateway |
|--------|--------------------|----|
| Admin replaces Cedar policy on disk | Undetected | Policy hash measured by hardware before code runs |
| Supply chain CVE flips allow/deny signal | Undetected | Evaluator in isolated enclave memory |
| Admin regenerates audit log post-breach | Anyone with signing key can reconstruct | Key hardware-sealed; new valid signatures impossible |
| Permissive policy loaded at evaluation time | Undetected | Bundle measured at enclave startup |
| Tool call payload captured by APM/logging | No structural protection | Plaintext never leaves the enclave |

OWASP: LLM02, LLM06, MCP08, V8.6 Policy-Execution Decoupling, V8.7 Attestation and Proof Gaps, V2.2 Data-in-Use, V4.1 Logs with Payloads, V5.2 Tool Invocation

---

## 6. Attestation Provider Hierarchy

| Provider | Hardware | Assurance |
|----------|----------|-----------|
| tpm | TPM 2.0 / vTPM | Medium |
| sev-snp | AMD SEV-SNP (Azure DCasv5, AWS C6a Nitro) | High |
| tdx | Intel TDX (Azure DCedsv5, GCP C3) | High |
| opaque | Opaque Managed Runtime | Highest |

Auto-detection: tpm -> sev-snp -> tdx -> opaque. Default enforcement_mode: advisory.

---

## 7. Policy Lifecycle

1. Author - Cedar bundle committed to version control
2. Seal - bundle hash recorded in deployment manifest
3. Measure - TEE measures hash into attestation report at startup, before any calls
4. Enforce - every tool call evaluated against the sealed bundle; no runtime updates without full enclave restart
5. Audit - TRACE Claim records policy_bundle.hash; verifier checks against approved hash

---

## 8. Phase 1 Scope

In scope:
- MCP protocol interception (agent to MCP servers)
- Cedar policy evaluation inside TEE
- TRACE Claim generation and signing
- Hardware attestation: TPM, SEV-SNP, TDX, Opaque Managed
- Enforcement modes: enforcing, advisory, silent
- Egress policy: allow/deny/redact per tool and per field
- Per-session TRACE Claim with call summary
- Python SDK (cmcp-gateway), config file (cmcp-config.yaml)

Not in Phase 1:
- MCP server-side attestation (Phase 2)
- Real-time policy updates without enclave restart
- Multi-tenant TRACE Claim routing
- Tool identity verification (typosquatting, rug-pull)
- Agent authorization model
- cMCP registry

---

## 9. Phase 2: cMCP Server (provider-side)

The Phase 2 buyer is a SaaS vendor exposing MCP endpoints to enterprise customers. Those customers (Phase 1 buyers) eventually ask: prove your server code has not changed since I approved it. Phase 2 closes the proof gap in the vendor-to-customer direction. Not the current build focus.

---

## 10. Target Customer

Enterprise AI platform teams and CISOs with a working agent system blocked from production by compliance, legal, or audit requirements.

Qualifying question: What business are you giving up today because you cannot prove data stays protected during processing?

GTM note: For production-bound regulated buyers, the entry point is the proof gap, not the software layer. Do not lead with AGT as the on-ramp and frame cMCP as an upgrade. This reintroduces the Kong/Zscaler comparison. For this segment the entry point is the proof gap itself.

---

## 11. Success Metric

Three enterprise design partners signed on cMCP Gateway by July 15, 2026.

Current signal: ServiceNow DT (external MCP endpoint governance), Across AI.

---

## 12. Open Research Questions

| ID | Question | Why it matters |
|----|----------|----------------|
| RQ1 | Are MCP practitioners experiencing tool-call payload leakage specifically at the tool call layer? | Confirms O2a/O2b are Phase 1 requirements, not inferences from the broader AI pipeline problem |
| RQ4 | What escalates the proof gap from SOC 2 is fine to blocking production? | Determines the qualifying trigger for the sales motion |
| RQ5 | How are enterprises solving the authorization model for agents calling external tools? | Determines near-term Phase 1 scope |
| RQ6 | Are SaaS vendors receiving enterprise questionnaires about MCP server behavior? | Validates Phase 2 demand before building |

---

## 13. Hypotheses Under Investigation

Not yet on the opportunity tree - no primary customer validation.

| ID | Hypothesis | Evidence Level |
|----|-----------|----------------|
| H1 | AI governance policies exist in documents but nothing gets enforced in production | Partial (Dell interview) |
| H2 | Enterprises need and are building an authorization model for agents calling external tools | Partial (Wells Fargo named this as a dedicated engineering project) |
| H3 | Typosquatted MCP packages and rug-pull via tool-definition mutation are exploited in production | No customer signal; CVE and threat research only |
| H4 | Two approved MCP servers exposing the same tool name are indistinguishable to the agent routing logic | No customer signal; protocol analysis only |
