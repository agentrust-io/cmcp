# cMCP Spec

cMCP Runtime is a hardware-attested MCP (Model Context Protocol) runtime. Every MCP tool call an agent makes passes through a TEE-isolated gateway that evaluates it against a Cedar policy bundle and produces a TRACE Claim: a signed, hardware-attested proof artifact a verifier can check without trusting the operator.

Phase 1 attests the agent-to-tool boundary on the consumer side (the runtime). Phase 2 attests it on the provider side (the server). Together they close the proof gap that software-only runtimes leave open: "prove that the policy you describe in documents is the policy that actually ran on your traffic."

This repository contains the product specification. Implementation lives in a separate repo.

---

## Start here

**Understanding the problem space:**
Read SPEC.md. It defines the four problems (P1 data leakage, P2 unsanctioned tools, P3 provable governance, P4 supply chain), the 13 threat shapes, and the coverage matrix showing what Phase 1 closes vs. what Phase 2 closes.

**Implementing the runtime (Phase 1):**
Read in this order:
1. SPEC.md : problem context and scope
2. docs/spec/component-model.md : what you are building and where trust boundaries are
3. docs/spec/transport.md : how the runtime intercepts MCP traffic
4. docs/spec/attestation.md : how TEE attestation works and how to produce TRACE Claims
5. docs/spec/cedar-policy.md : the policy engine, bundle format, and enforcement modes
6. docs/spec/failure-modes.md : what happens when things go wrong
7. schemas/ : machine-readable schemas to validate your outputs against

**Contributing to the spec:**
Issues in this repo track spec decisions, not implementation bugs. Each issue corresponds to a specific design question. When a spec file resolves an issue, the issue is closed with a reference to the relevant file. To propose a change, open an issue describing the problem with the current spec, then submit a PR.

---

## Spec File Index

| File | Covers | Phase | Status | Issues |
|------|--------|-------|--------|--------|
| docs/SPEC.md | Problem taxonomy, coverage matrix, Phase 1/2 scope | 1+2 | Draft v0.1 | - |
| docs/spec/component-model.md | All MCP components, trust levels, hardware vs. software boundaries | 1+2 | Draft v0.1 | #43 |
| docs/spec/transport.md | HTTP/SSE scope, stdio gap, SPIFFE-to-TEE binding spike | 1 | Draft v0.1 | #20, #21 |
| docs/spec/attestation.md | TEE provider detection, audit chain, key management, catalog pinning | 1 | Draft v0.1 | #5, #6, #23, #33, #38 |
| docs/spec/cedar-policy.md | Policy bundle format, Cedar examples, enforcement modes, provenance | 1 | Draft v0.1 | #4, #7, #26, #39, #41 |
| docs/spec/tool-identity.md | Server identity binding, catalog schema, collision detection | 1 | Draft v0.1 | #40 |
| docs/spec/failure-modes.md | Runtime failure scenarios, decision table, log formats | 1 | Draft v0.1 | #22 |
| docs/spec/call-graph.md | Tag-propagation model, observability limits, cross-boundary policy | 1 | Draft v0.1 | #35 |
| docs/spec/session-policy.md | Session sensitivity state machine, egress policy, session reset | 1 | Draft v0.1 | #36 |
| docs/spec/response-inspection.md | 4-stage response inspection pipeline, injection patterns | 1 | Draft v0.1 | #37 |
| docs/spec/error-codes.md | Central error code registry for all runtime and verification errors | 1+2 | Draft v0.1 | - |
| docs/spec/threat-model.md | Assets, adversaries, STRIDE analysis per component | 1 | Draft v0.1 | #18, #24 |
| docs/spec/verification-library.md | cmcp-verify Python library interface and per-provider verification steps | 1 | Draft v0.1 | #25 |
| docs/spec/mcp-spec-strategy.md | MCP spec monitoring and attestation extension contribution window | 1+2 | Draft v0.1 | #30 |
| docs/spec/proxy-security.md | Phase 2 proxy parser fuzzing DoD | 2 | Draft v0.1 | #34 |
| docs/spec/phase2-server.md | Provider-side attestation, 5 unique properties, streaming proxy, multi-tenant | 2 | Draft v0.1 | #17, #28, #29, #32, #42 |
| docs/testing/benchmarks.md | Latency targets and benchmark methodology | 1 | Draft v0.1 | #27 |
| docs/testing/soak-test.md | 72-hour soak test plan | 1 | Draft v0.1 | #31 |

---

## Schema Files

Machine-readable schemas in `schemas/` let implementations validate their outputs before shipping.

| File | What it validates | Use with |
|------|------------------|---------|
| schemas/trace-claim.schema.json | TRACE Claim JSON (draft-07) | jsonschema, ajv, any JSON Schema validator |
| schemas/audit-entry.schema.json | Single audit chain entry | jsonschema, ajv |
| schemas/catalog-entry.schema.json | Tool catalog entry | jsonschema, ajv |
| schemas/cedar-schema.cedarschema | Cedar entity types and context attributes | cedar-policy CLI: `cedar validate` |

To validate a TRACE Claim:
```
ajv validate -s schemas/trace-claim.schema.json -d your-trace-claim.json
```

To validate Cedar policies:
```
cedar validate --schema schemas/cedar-schema.cedarschema --policies policies/
```

---

## Conformance Tests

`tests/conformance/README.md` defines the conformance test suite: 22 test cases across 6 groups (ATTEST, POLICY, AUDIT, FAIL, INSP, TRACE). Each case specifies:
- Input conditions
- Expected behavior (pass/fail, error code, field values)
- The spec section it validates

A conforming implementation passes all MUST-level tests. SHOULD-level tests indicate higher-quality conformance.

---

## Contributing

**Spec versioning:** All files use `Status: Draft/Review/Accepted/Superseded` plus a version number (e.g. `v0.1`). Stability is `Unstable` until v1.0.

**Process:**
1. Open an issue describing the spec gap or design question
2. Discuss in the issue : the issue body captures the decision context
3. Submit a PR with the spec change, referencing the issue
4. PR is merged when the spec change is accepted

**Scope:** This repo is spec-only. Implementation bugs go in the implementation repo (link TBD). Spec issues are about design decisions, not code behavior.

---

## Glossary

| Term | Definition |
|------|-----------|
| TRACE Claim | The signed, hardware-attested proof artifact produced by the runtime per session |
| TEE | Trusted Execution Environment (TPM, SEV-SNP, TDX, or Opaque Managed) |
| SPIFFE SVID | Short-lived cryptographic identity issued by SPIRE after TEE attestation succeeds |
| Cedar | The policy language used for tool call authorization |
| Audit chain | The append-only hash-chained log of all runtime decisions, signed with a TEE-sealed key |
| Session sensitivity | The maximum sensitivity level seen in any tool response within the current session |
| Tag-propagation | The runtime's mechanism for tracking sensitivity across calls based on observable events |
| Catalog entry | The runtime's approved record for one tool: name, server identity, approved definition |
| Attestation report | The hardware-produced evidence that a specific binary ran in a specific TEE at a specific time |
| policy_bundle_hash | SHA-256 of the canonical Cedar policy bundle, measured into the TEE at startup |
| tool_catalog_hash | SHA-256 of the canonical tool catalog, measured into the TEE at startup |
| Call graph | Per-session record of tool calls and temporal adjacency edges (approximation, not data provenance) |
