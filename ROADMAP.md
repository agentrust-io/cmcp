# cMCP Roadmap

## v0.1: Initial Release (June 2026)

Scope: Minimal viable trust layer for MCP servers, sufficient for early adopters to evaluate the attestation and policy model.

- TEE attestation support (quote generation and basic verification)
- Cedar policy engine integration for request authorization
- TRACE Claim generation from attestation evidence
- Standalone verifier CLI for offline claim inspection

## v0.2: Released (June 2026)

Provider-specific attestation verification (report parsing, certificate-chain verification
against real vendor roots, and report-signature verification):
- TPM2 quote verification (synthetic vectors only)
- AMD SEV-SNP attestation report parsing and verification (**validated against a real Azure
  CVM report**)
- Intel TDX attestation report parsing and verification (**validated against a real GCP C3
  DCAP v4 quote**)

> Report *generation* requires the corresponding TEE hardware, so these runs validate the
> verifier against genuine evidence rather than cMCP running inside the TEE. Each run is
> recorded in [`docs/testing/hardware-validation.md`](docs/testing/hardware-validation.md).
> TPM has no real-hardware run yet. The shared verifier code in the sibling
> [ca2a](https://github.com/agentrust-io/ca2a) repo tracks the same status.

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
