# Threat Model

Status: Draft v0.1 | Covers: Phase 1 cMCP Runtime

## Assets

| Asset                                                     | Sensitivity | Why it matters                                     |
| --------------------------------------------------------- | ----------- | -------------------------------------------------- |
| Tool call payloads (PII, PHI, financial data in requests) | Critical    | Core data the runtime is protecting                |
| Tool responses (data returned to agent)                   | High        | May contain more data than requested               |
| Cedar policy bundle                                       | Critical    | Defines what is allowed; tampering enables bypass  |
| Audit chain + signing key                                 | Critical    | Tampered audit chain can't be detected post-breach |
| Tool catalog                                              | High        | Wrong catalog enables routing to wrong server      |
| SPIFFE SVIDs / TLS private keys                           | High        | Compromise enables impersonation                   |
| Session sensitivity state                                 | Medium      | Incorrect state can allow data leakage             |

## Adversaries

**A1: Rogue operator / privileged insider**

- Has root access to the host VM
- Can read/write host memory, modify files, access environment variables
- Cannot read TEE-encrypted memory (SEV-SNP, TDX) or TPM-sealed secrets
- Goal: bypass policy, forge audit entries, or exfiltrate data

**A2: Supply chain attacker**

- Has compromised a dependency, a build pipeline, or a package registry
- Can insert malicious code into the runtime binary or its dependencies
- Cannot change the binary after TEE measurement without invalidating the attestation report
- Goal: modify runtime behavior without detection

**A3: Malicious or compromised MCP server**

- Controls the tool's response payload
- Can craft responses designed to inject instructions or exfiltrate data
- Cannot modify runtime policy or audit entries
- Goal: indirect prompt injection, data exfiltration via crafted responses

**A4: External attacker (network)**

- Can attempt to connect to the runtime or intercept traffic
- Runtime uses mTLS; must have a valid SPIFFE SVID to connect
- Goal: bypass auth, replay attacks, MitM

**A5: Compromised agent**

- The agent (LLM) produces unexpected or adversarial tool calls
- The runtime treats all agent tool calls as untrusted inputs
- Goal: call unauthorized tools, exfiltrate via authorized tools, exceed workflow scope

## STRIDE Analysis

### cMCP Runtime (inside TEE)

| STRIDE                 | Threat                                       | Mitigated by                                                                                               | Residual risk                                                                                              |
| ---------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Spoofing               | Attacker impersonates the gateway            | SPIFFE SVID issued only after TEE attestation; TRACE Claim signed with TEE-sealed key                      | If SPIRE is compromised, SVID issuance can be faked - SPIRE integrity is out of scope                      |
| Tampering              | A1 modifies Cedar policy on disk             | Policy bundle hash measured at TEE startup; tampered bundle produces measurement mismatch                  | Runtime config injection (env vars, mounted secrets) not covered by measurement                            |
| Repudiation            | A1 rewrites audit log after breach           | Audit chain signing key is TEE-sealed; new valid signatures are computationally infeasible without the key | If the TEE is breached (physical attack, firmware vulnerability), key extraction is theoretically possible |
| Information Disclosure | A1 reads tool call payloads from host memory | SEV-SNP/TDX encrypts enclave memory; host hypervisor cannot read plaintext                                 | Side-channel attacks (Spectre, cache timing) on the TEE boundary; TEE firmware vulnerabilities             |
| Denial of Service      | A1 kills the runtime process                 | Standard process management; runtime has no availability SLA from the TEE itself                           | TEE cannot prevent the host from killing the process                                                       |
| Elevation of Privilege | A5 calls a tool not in the approved workflow | Per-workflow Cedar policy prevents out-of-workflow calls                                                   | Catalog must be correctly configured; a too-permissive catalog is operator error                           |

### MCP Protocol Interceptor

| STRIDE                 | Threat                                                                                     | Mitigated by                                                             | Residual risk                                                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| Spoofing               | A4 sends forged MCP messages                                                               | mTLS with SPIFFE SVID required; SVID issued only to attested agent hosts | Attacker who compromises agent host can send arbitrary MCP messages                                             |
| Tampering              | A3 injects instructions in tool response payload                                           | Response inspection (Stage 4: injection detection patterns)              | Pattern-based detection has false negatives; sophisticated injection may evade patterns                         |
| Repudiation            | Tool server denies a call was made                                                         | Audit entry records call, tool server identity, and response hash        | Tool server can deny it produced a specific response (only response hash is recorded, not content)              |
| Information Disclosure | A3 returns more data than requested                                                        | Response schema validation strips surplus fields (redact mode)           | Strict mode may be too disruptive; redact mode requires correct schema in catalog                               |
| Denial of Service      | A3 returns oversized responses                                                             | Stage 1 size check (default 2MB limit)                                   | DDoS via many simultaneous large responses                                                                      |
| Elevation of Privilege | A5 calls escalating sequence of individually-authorized tools crossing compliance boundary | Call graph tracking + session sensitivity policy                         | Runtime uses temporal adjacency, not true data provenance; sophisticated cross-system flows may not be detected |

### Tool Catalog

| STRIDE                 | Threat                                                         | Mitigated by                                                                             | Residual risk                                                                                        |
| ---------------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Spoofing               | A3 serves different tool definition than registered (rug-pull) | Tool catalog hash pinned in TEE attestation; drift detected via delta check              | If the rug-pull happens before the runtime starts, it is measured into the catalog hash as correct   |
| Tampering              | A1 modifies catalog file on disk                               | Catalog hash measured at enclave startup; tampered catalog produces mismatch             | Same as Cedar policy tampering                                                                       |
| Repudiation            | Unauthorized server added to catalog                           | Policy provenance manifest records who approved each catalog entry                       | Approver's identity is only as trustworthy as the identity system backing it                         |
| Information Disclosure | Catalog exposes sensitive server details                       | Catalog is inside the TEE; not externally accessible                                     | N/A                                                                                                  |
| Denial of Service      | A2 seeds catalog with malicious package                        | Catalog approval process is human-gated                                                  | Depends on reviewer vigilance; typosquatted packages may pass review (see CVE-2025-54136 / MCPoison) |
| Elevation of Privilege | A3 uses tool name collision to route to wrong server           | Catalog binds tool_name to specific server_identity; collisions rejected at catalog load | N/A                                                                                                  |

## Precision Corrections to SPEC.md Coverage Claims

These corrections were identified during security review and must be reflected in any compliance claim referencing these controls.

### APM Payload Capture and SDK Telemetry (status: Mitigated, not Closed)

The SPEC claims structural protection against APM payload capture. The protection is structural only when the egress policy denies the APM/telemetry endpoint. The TEE prevents plaintext from leaving the enclave, but if the operator allowlists the APM endpoint in the egress policy, the protection is not active. This threat is mitigated by correct configuration, not eliminated structurally.

Verifiers must confirm that the egress policy hash excludes APM and telemetry endpoints. A TRACE Claim with an egress policy that permits APM endpoints does not provide this protection and the verifier should flag it.

### Server Swap / Tool Identity : T.1 (status: requires agent-side verification)

The SPEC states T.1 is closed by the runtime producing an attestation report. T.1 is only closed if the agent (or the agent's runtime) verifies the attestation report before sending traffic. Without verification, the attestation exists as post-hoc evidence but provides no runtime protection against server swap at the moment of the call.

The verification library (`cmcp-verify`, see [verification-library.md](https://cmcp.agentrust-io.com/docs/spec/verification-library/index.md)) is required to close this threat. Deployments that do not run `cmcp-verify` (or an equivalent) treat attestation as audit evidence only, not as a runtime gate.

### P4.1 Supply Chain (status: binary-level only)

Hardware measurement at launch time proves the binary is what it should be. Runtime configuration injection - environment variables, mounted secrets, configuration files loaded after startup - happens after the measurement. A supply chain attack that operates via runtime configuration changes server behavior without changing the binary measurement.

The binary-level protection is real and valuable. The runtime config gap must be stated explicitly in any compliance claim referencing this control. This is reflected in the Tampering row for the Runtime STRIDE table above (residual risk: runtime config injection not covered by measurement).

## Compensating Controls (operator responsibilities)

These threats are real but outside the TEE's scope. Operators must address them separately:

1. TEE firmware and microcode must be kept up to date (addresses Spectre-class side channels and the Information Disclosure residual risk in the Runtime table)
1. SPIRE infrastructure must be secured (compromise enables SVID forgery, which negates the Spoofing mitigation for the runtime)
1. Catalog approval process must be documented and audited (catalog entries are human-approved; the runtime trusts the catalog)
1. Pattern list for injection detection must be maintained and updated (pattern-based detection in the MCP Protocol Interceptor has a residual false-negative risk)
1. Egress policy must explicitly exclude APM and telemetry endpoints to make the payload capture protection structural rather than operator-dependent
