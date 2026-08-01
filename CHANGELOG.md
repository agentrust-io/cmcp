# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The Azure vTPM certificate hierarchy is fleet variance, not a migration (hardware, 2026-08-01).** `docs/testing/hardware-validation.md` recorded on 2026-07-31 that "Azure has changed its vTPM PKI", after finding the AK certificate at NV `0x01C101D0` issued by `Azure Cloud Virtual TPM CA - 11` with a walkable AIA chain, superseding an earlier no-AIA observation. A VM provisioned 2026-08-01 (`Standard_D2s_v7`, eastus2) presented the older form again: 994 bytes, issued by `Global Virtual TPM CA - 03`, **no AIA extension at all**, and `tpm2_getcap handles-nv-index` confirmed no intermediates stored in NV as a fallback. Both hierarchies are live concurrently, so the planning assumption must be that a host may present either and **AIA cannot be relied on**. The practical consequence, now stated in the doc and in `cmcp_verify/tpm_roots.py`: pinning the 2023 root does not make Azure verify everywhere, and chained verification is impossible on a host presenting the no-AIA hierarchy. This is worth re-reading against #431, which was closed on the basis that chains ship with the evidence.

### Added

- **Hardware validation for the gateway measurement NV extend index (#432, #451).** The TPM calls in `cmcp_runtime.tee.measurement` were written against the documented tpm2-pytss API without ever executing against a TPM. All of them work on a real Azure Trusted Launch vTPM: `nv_define_space` with `TPMA_NV.parse(...) | (TPM2_NT.EXTEND << 4)` created a genuine extend index (`TPM_NT = 4` read back from the public area), `nv_extend` accumulated as `H(old || data)` across calls, an existing index was reused rather than redefined, and **a plain `nv_write` to the index was refused by the TPM**, which is the check the tamper-evidence argument actually rests on. Recorded in `docs/testing/hardware-validation.md`.

- **The gateway is now measured into a TPM NV extend index at startup (#432).** PCRs 0 through 7 cover firmware, option ROMs, boot configuration, and the bootloader, and there was no `PCR_Extend` anywhere in the codebase, so replacing the policy bundle or the gateway itself produced an identical measurement and the TPM enforced nothing about the thing the TPM path exists to protect. `cmcp_runtime.tee.measurement` digests the installed distributions' recorded per-file hashes (pip's `RECORD`), the policy bundle bytes, and the resolved configuration with secrets excluded, then extends that digest into NV `0x01500432` before the gateway serves traffic. `RuntimeContext` carries the result.

  An NV index with `TPM_NT_EXTEND` rather than an application PCR, per the decision on #432: PCR 23 and PCR 16 are both resettable from locality 0, so an adversary with local code execution could reset and re-extend a chosen value, which is exactly the adversary this tier addresses. Extend writes are one-way (`new = H(old || data)`), so forgery needs a preimage, which is what carries the security argument rather than the write policy the original proposal called for.

  Scope is deliberately honest about two things. Measuring dependencies means an editable install, which has no `RECORD`, cannot be measured: that is fatal in production and a warning under `CMCP_DEV_MODE`, rather than a confident digest over an unknown subset of code. And because extends accumulate across reboots, the index is a hash chain over every start rather than a predictable absolute value, so the collector reports the value both before and after the extend and continuity is what a relying party checks.

### Changed

- **RFC section 5 P2 (`docs/spec/tpm-security-model.md`) rewritten** to record the NV-extend decision instead of leading with the application PCR it rejected, along with the residual-risk analysis: `TPM2_NV_UndefineSpace` with owner auth can erase the measurement, which guest root holds on Azure, so the property is tamper-evident rather than tamper-proof. Section 4.3 now separates what landed from what has not: the index value travels as an ordinary NV read, which the quote signature does not cover, so it is a local integrity control and not yet remote-verifiable evidence. `TPM2_NV_Certify` is the primitive that closes it; committing an NV read into the quote's qualifying data is not sound, because the collector would be asserting the value it read.

### Changed

- **BREAKING: TRACE Claims now carry the v0.2 profile** `tag:agentrust-io.com,2026:trace-v0.2`, and `agentrust-trace` is pinned to `>=0.5`. The v0.1 URI named `agentrust.io`, a domain this project never controlled, which RFC 4151 does not permit for a tag URI (agentrust-io/trace-spec#107). A verifier on the v0.2 suite rejects a v0.1 claim, so producers and verifiers move together. Nothing else about the claim format changed.

### Changed

- Moved every `agentrust.io` identifier to `agentrust-io.com`: the JSON Schema `$id` values for `trace-claim`, `audit-entry`, and `catalog-entry`, the `@context` URL in test fixtures, and the maintainer email. `agentrust.io` is not ours and resolves to parked AWS addresses, so these identifiers pointed at a domain we do not control. They never resolved, so nothing that worked stops working. The `tag:agentrust-io.com,2026:trace-v0.2` EAT profile identifier is deliberately unchanged; it is a cross-repo identifier inside signed payloads and needs a transition decision, not a rename.

### Fixed

- README no longer claims hardware attestation unconditionally. "Each session produces a signed, hardware-attested TRACE Claim" contradicted the TL;DR two paragraphs below it, which tells you to `pip install cmcp-runtime` and start in software mode with no hardware. It now reads "hardware-attested when the gateway runs in a TEE and signed-only in software mode", which is what the runtime actually does.

### Fixed

- Raised the `agent-manifest` floor to `>=0.6.1` and made an unappraisable manifest fail closed with a diagnostic message. `verify_agent_manifest_binding` runs the SDK verifier over a peer-supplied manifest, and before 0.6.1 a manifest declaring `ML-DSA-65` or `hybrid-Ed25519-ML-DSA-65` crashed the SDK with an uncaught `RuntimeError` on any install without the optional `[pq]` extra, so this path answered a crash instead of a rejection. The SDK now returns `UNVERIFIABLE`, which cMCP already rejects; the `UNVERIFIABLE` message now distinguishes "could not be verified" (missing trusted key or unavailable algorithm) from "verification failed" (a bad signature) and surfaces the verifier's own reason, because those call for different operator responses.
- **The TDX verifier rejected every genuine DCAP v4 quote.** Real quotes nest the Quoting Enclave material: the bytes after the attestation key are a certification-data header of type 6 (`QE_REPORT_CERTIFICATION_DATA`) wrapping the QE report, its PCK signature, the auth data and the type-5 PCK chain. `parse_td_quote` read the QE report directly after the attestation key, six bytes early, so a real GCP C3 quote failed with `attestation_key_not_bound_to_qe`. The synthetic test fixture emitted the same flat layout, so CI validated the defect. Failure was closed, so this was a false negative rather than an unsound accept, but the TDX path had never worked against real evidence. The parser now handles the nested layout, the fixture builds the real shape, and a new test rejects the flat layout outright.

### Added

- **Real-hardware validation for SEV-SNP and TDX**, recorded in [`docs/testing/hardware-validation.md`](docs/testing/hardware-validation.md). `cmcp_verify` now verifies a genuine Azure CVM SEV-SNP report (VCEK chain to the AMD ARK-Milan root, ECDSA-P384 report signature, paravisor `REPORT_DATA` binding) and a genuine GCP C3 Intel TDX DCAP v4 quote (PCK chain to the pinned Intel SGX Root CA, QE binding, quote signature) end to end. Both are env-gated (`CMCP_AZURE_FIXTURE_DIR`, `CMCP_TDX_FIXTURE_DIR`) because the evidence embeds per-CPU identifiers and cannot be committed. `test_real_tdx_quote_agrees_with_agent_manifest` pins cMCP's verdict to the shared verifier so the two cannot drift apart silently. STATUS and ROADMAP now say which platforms have been validated against real evidence and which have not (TPM has not).

### Changed

- Attestation crypto now delegates to agent-manifest's shared verification library (`agent-manifest>=0.5`) instead of cMCP's own copies: the SEV-SNP report signature (`verify_snp_signature`) and the VCEK/PCK certificate-chain verification (the generic `verify_cert_chain`) are shared across the org rather than duplicated. cMCP keeps its own DCAP quote parser, `*VerificationResult` shapes, TR-field semantics, and report_data/qualifying-data bindings; behavior is unchanged (all tests pass unchanged). cMCP's TPM verifier stays local (Phase-1 parse-only: no AK signature/chain to share).

### Added

- Azure confidential-VM attestation (`cmcp_runtime.tee.azure_cvm.AzureCVMProvider` + `cmcp_verify.azure_cvm`), **hardware-validated on live Azure SEV-SNP silicon**. Azure runs SNP behind a Hyper-V paravisor with no `/dev/sev-guest`; the SNP report is read from the vTPM NV index `0x01400001` and the guest cannot control `REPORT_DATA` (the paravisor binds the vTPM AK there). cMCP's nonce (`jwk_thumbprint || audit-root`) is therefore committed into an AK-signed TPM quote's qualifying data, with the AK rooted in silicon via the SNP report (`REPORT_DATA == sha256(runtime_data)`) and the VCEK→ASK→ARK chain (reusing `cmcp_verify.sev_snp`). Auto-detected first (before TPM/SEV-SNP) since Azure exposes no `/dev/sev-guest`. Carries its own `runtime.platform` value `azure-cvm-sev-snp` (requires `agentrust-trace>=0.4`) so a consumer keying on `runtime.platform` knows the root of trust is vTPM-rooted, not a guest-controlled SNP `report_data`.
- `tool_transcript.entries`: privacy-preserving per-call view in the TRACE Claim (one entry per tool call with `tool_name`, `data_class` from the catalog, and the policy `decision`), derived from the audit chain so no raw parameters or response bodies are exposed. `tool_transcript.hash` continues to bind the full transcript to the audit-chain tip. Adds `transcript_entries_hash()` for offline recomputation. (#126)

### Fixed

- Bare-metal `SEVSNPProvider` now obtains the SNP report via the kernel configfs-TSM interface (`/sys/kernel/config/tsm/report`) instead of a `/dev/sev-guest` ioctl. The previous ioctl number and inline request ABI were incorrect and failed on real hardware with `ENOTTY` ("inappropriate ioctl for device"). **Hardware-validated on a non-paravisor SEV-SNP guest (GCP N2D, AMD Milan):** the guest-supplied nonce lands in the report's `REPORT_DATA` and the report verifies against the AMD VCEK.
- SNP report-version check in `cmcp_verify.sev_snp` now accepts version `>= 2` (was `(2, 3)` only). Real Milan hardware emits report version 5, which the old allowlist wrongly rejected as `invalid_snp_report_version`; the field offsets read are layout-stable across v2..v5 and the VCEK signature is the real gate.

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
