# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Azure confidential-VM attestation (`cmcp_runtime.tee.azure_cvm.AzureCVMProvider` + `cmcp_verify.azure_cvm`), **hardware-validated on live Azure SEV-SNP silicon**. Azure runs SNP behind a Hyper-V paravisor with no `/dev/sev-guest`; the SNP report is read from the vTPM NV index `0x01400001` and the guest cannot control `REPORT_DATA` (the paravisor binds the vTPM AK there). cMCP's nonce (`jwk_thumbprint || audit-root`) is therefore committed into an AK-signed TPM quote's qualifying data, with the AK rooted in silicon via the SNP report (`REPORT_DATA == sha256(runtime_data)`) and the VCEK→ASK→ARK chain (reusing `cmcp_verify.sev_snp`). Auto-detected first (before TPM/SEV-SNP) since Azure exposes no `/dev/sev-guest`. Carries its own `runtime.platform` value `azure-cvm-sev-snp` (requires `agentrust-trace>=0.4`) so a consumer keying on `runtime.platform` knows the root of trust is vTPM-rooted, not a guest-controlled SNP `report_data`.
- `tool_transcript.entries`: privacy-preserving per-call view in the TRACE Claim (one entry per tool call with `tool_name`, `data_class` from the catalog, and the policy `decision`), derived from the audit chain so no raw parameters or response bodies are exposed. `tool_transcript.hash` continues to bind the full transcript to the audit-chain tip. Adds `transcript_entries_hash()` for offline recomputation. (#126)

## [0.3.0] - 2026-06-30

### Security

- Software-only (non-hardware-backed) claims now return `partially_verified` instead of `verified` (fail-closed); a real verification failure is never downgraded.
- An external-execution receipt whose `linked_call_id` does not match the entry is no longer reported signature-valid (short-circuits).

## [0.2.0] - 2026-06-12

### Added

- Bearer-token auth (`Authorization: Bearer`) wired into the live gateway server
- Upstream MCP forwarding: AGT pre-call interception, JSON-RPC forward to the attested catalog server, response size guard, injection/credential/PII response scanning
- Durable SQLite audit store (WAL mode, synchronous) with TEE-anchored hash chains and orphaned-session detection
- `POST /sessions/{id}/close` issues the signed TRACE Trust Record and rotates the session
- Cedar `@annotation` metadata returned as structured advice on deny decisions (HITL payloads)
- `cmcp-verify`: one-command verification of claims and signed audit bundles, tamper-evident
- Fail-closed hardware verifiers (TPM, SEV-SNP, TDX, OPAQUE): no attestation evidence means no verification
- Dev-mode records carry `platform: software-only`, never `tpm2` (requires `agentrust-trace>=0.1.1`)
- Silent mode contract: operational logs quiet, audit evidence always recorded

## [0.1.0] - 2026-06-09

### Added

- Initial TEE gateway with provider support for TPM, SEV-SNP, TDX, and OPAQUE
- Cedar policy enforcement for request authorization at the gateway layer
- TRACE Claim generation using the `GatewayClaim` envelope from `agentrust-trace`
- `cmcp-verify` standalone verifier for validating TRACE Claims offline
- Audit chain with Ed25519 signing for tamper-evident log integrity

[Unreleased]: https://github.com/agentrust-io/cmcp/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/agentrust-io/cmcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/agentrust-io/cmcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/agentrust-io/cmcp/releases/tag/v0.1.0
