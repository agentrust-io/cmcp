# cMCP Roadmap

## v0.1: Initial Release (June 2026)

Scope: Minimal viable trust layer for MCP servers, sufficient for early adopters to evaluate the attestation and policy model.

- TEE attestation support (quote generation and basic verification)
- Cedar policy engine integration for request authorization
- TRACE Claim generation from attestation evidence
- Standalone verifier CLI for offline claim inspection

## v0.2: Released (June 2026)

Provider-specific attestation verification (report parsing plus certificate-chain
verification, validated against real vendor roots; report-signature paths validated with
synthetic vectors):
- TPM2 quote verification
- AMD SEV-SNP attestation report parsing and verification
- Intel TDX attestation report parsing and verification

> Report *generation* requires the corresponding TEE hardware. Until a backend verifies a
> real quote end to end against a golden measurement on a confidential VM, these verifiers
> should not be described as fully hardware-attested. This is the same status tracked for
> the shared verifier code in the sibling [ca2a](https://github.com/agentrust-io/ca2a) repo.

Server integration:
- Session-scoped TRACE Claim emission wired into `server.py` request lifecycle
- Claim correlation across multi-turn sessions

Observability:
- OpenTelemetry spans for Cedar policy decisions (allow/deny with policy id)
- Structured policy audit log export

Transparency:
- Transparency log integration for TRACE Claim anchoring (write and lookup)

## v1.0: Stable Targets

- Stable `GatewayClaim` schema with documented versioning guarantees
- Full RATS/EAT conformance (RFC 9334, draft-ietf-rats-eat)
- SLSA Level 3 build provenance for cMCP release artifacts
