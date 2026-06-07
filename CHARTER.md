# Technical Charter — cMCP

**Proposed hosting**: Agentic AI Foundation (AAIF).  
**Status**: Pre-acceptance draft — effective upon host organization acceptance.

> **Note for external contributors:** This charter is a working draft and has not yet been accepted by a host organization. Governance terms, IP policy, and trademark ownership described here are proposed, not final. Do not assume binding foundation commitments until formal acceptance.

**Version**: 0.1 (aligned with gateway v0.1)

---

## 1. Mission

The cMCP project develops and maintains an open implementation of the Confidential MCP (Model Context Protocol) gateway — hardware-attested policy enforcement for AI agent tool calls. The mission is to make tool-call authorization cryptographically verifiable by any party, without trusting the operator, without requiring closed infrastructure, and without vendor lock-in to any silicon vendor, cloud provider, or AI platform.

## 2. Scope

The project includes:

- **cMCP Gateway** — the reference open-source implementation of the confidential gateway, including the gRPC/HTTP proxy, policy engine, and hardware attestation bridge.
- **Hardware Provider API** — the normalized interface (`BaseProvider`) for integrating TEE platforms (TPM, AMD SEV-SNP, Intel TDX, and others).
- **Python SDK** — the `cmcp-gateway` package and client libraries for policy authoring and runtime integration.
- **TRACE integration** — built-in emission of TRACE Trust Records for every attested tool call (see [agentrust-io/trace-spec](https://github.com/agentrust-io/trace-spec)).
- **Agent Manifest binding** — verification of agent identity via Agent Manifest at tool-call time (see [agentrust-io/agent-manifest](https://github.com/agentrust-io/agent-manifest)).
- **Integration examples** — working examples across financial services, healthcare, and multi-tenant SaaS deployment patterns.

Out of scope: AI model governance beyond tool-call enforcement, hardware TEE platform SDKs, network-level policy outside the MCP protocol boundary, and MCP server implementations themselves.

## 3. Technical Steering Committee

Upon host organization acceptance, governance transitions from the current Project Lead model to a Technical Steering Committee (TSC).

**Composition**: 3–7 members. No single organization may hold more than 40% of TSC seats. The founding Project Lead (Imran Siddique, Opaque Systems) holds one founding seat for the v1.0 release cycle.

**Election**: TSC members are elected annually by active contributors (at least one merged pull request in the preceding 12 months). Each contributor has one vote.

**Quorum**: Two-thirds of TSC members must participate for a vote to be valid.

**Decisions**:
- Patch releases and editorial changes: simple TSC majority
- Minor releases (new hardware providers, new policy primitives): two-thirds TSC majority + 7-day public comment
- Breaking API changes (gateway protocol, provider API): two-thirds TSC majority + 30-day public comment + explicit migration guide

**Meetings**: Monthly public TSC meeting. Notes published within 5 business days.

## 4. Intellectual Property Policy

All contributions must be made under the terms of [LICENSE](LICENSE). Contributors must sign commits with the Developer Certificate of Origin (DCO). No contribution may incorporate material covered by a patent the contributor is unwilling to license royalty-free to conforming implementations.

Code and schemas are licensed under Apache 2.0 with Patent Promise (see LICENSE).

## 5. Trademark Policy

"cMCP" and "cMCP-compatible" as project and conformance marks are currently held by Opaque Systems, Inc. Upon host organization acceptance, trademark ownership transfers to AAIF under their standard trademark policy.

Use of "cMCP-compatible" to describe a gateway deployment requires that the implementation satisfies the hardware attestation and policy enforcement requirements defined in the project documentation for the version being claimed.

## 6. Relationship to other projects

cMCP builds on and does not replace:

- **MCP (Model Context Protocol, Anthropic)** — the underlying tool-call protocol that cMCP extends with attestation
- **TRACE** ([agentrust-io/trace-spec](https://github.com/agentrust-io/trace-spec)) — governance record emitted per attested tool call
- **Agent Manifest** ([agentrust-io/agent-manifest](https://github.com/agentrust-io/agent-manifest)) — agent identity bound at tool-call time
- **SPIFFE / SPIRE** — workload identity for gateway and agent services
- **RATS / EAT (RFC 9711)** — attestation evidence format
- **OPA / Cedar** — policy engine integration surface

## 7. Transition timeline

| Milestone | Target |
|---|---|
| v0.1 developer preview — CC Summit announcement | June 2026 |
| Hardware provider API stabilization, TRACE v0.2 integration | Q3 2026 |
| AAIF project proposal submission | Q3 2026 |
| v1.0 stable release under TSC governance | 2027 |

## 8. Amendments

Amendments to this charter require a two-thirds TSC majority and a 30-day public comment period. Before host organization acceptance, amendments require Project Lead approval and 14-day notice to contributors.
