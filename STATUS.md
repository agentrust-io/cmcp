# cMCP — current status

This file is the single source of truth for what ships today versus what is on the roadmap.
Other docs (README, SPEC, quickstart) should link here rather than restate status, so the
picture is stated once. Developer Preview: interfaces may change before v1.0.

## Defaults (from `cmcp_runtime.config`)

| Setting | Default |
|---|---|
| `attestation.provider` | `auto` (probe order `tpm -> sev-snp -> tdx`) |
| `attestation.enforcement_mode` | `enforcing` |
| `attestation.staleness_policy` | `fail_closed` |
| `attestation.validity_seconds` | `86400` |
| `policy_reload_interval_seconds` | `0` (disabled; policy change requires an enclave restart) |
| `attestation.allow_unmeasured_spawn` | `false` (a stdio server the catalog does not pin is not spawned) |
| `attestation.required_provenance_kind` | `null` (server provenance is recorded, not enforced) |

## Capabilities

| Capability | Status | Notes |
|---|---|---|
| MCP interception + Cedar policy evaluation inside the TEE | Shipped | HTTP/SSE transport. |
| `stdio` transport | Shipped | The gateway spawns the server as its own child **inside the enclave**, rather than bridging from outside, which is what the two rejected options in [`docs/spec/transport.md`](docs/spec/transport.md) did. It measures the entrypoint against the catalog and refuses to spawn on a mismatch, so a stdio upstream carries a stronger binding than a network one: a TLS pin identifies an endpoint, a digest identifies code. The cost is real and stated in [`docs/spec/stdio-transport.md`](docs/spec/stdio-transport.md): the server then runs in the same isolation domain as the policy evaluator, and the gateway's launch measurement does not cover a child spawned later. Recorded as `spawn-measured`, or `spawn-unmeasured` when `attestation.allow_unmeasured_spawn` is on. |
| Enforcement modes (`enforcing` / `advisory` / `silent`) | Shipped | Default is `enforcing`. |
| Hash-chained audit log, TEE-sealed signing key | Shipped | |
| `GatewayClaim` (TRACE Claim) generation + signing | Shipped | Normative schema: [`schemas/trace-claim.schema.json`](schemas/trace-claim.schema.json). |
| Offline verification (`cmcp_verify`) | Shipped | No operator trust required when the verifier independently checks the attestation report. |
| Agent Manifest identity binding | Shipped | Optional; trust in the issuer key is an out-of-band PKI concern. |
| Attestation verifiers: `sev-snp`, `tdx` | Shipped | Verified end to end against genuine hardware evidence: an Azure CVM SEV-SNP report (VCEK chain to the AMD ARK-Milan root, ECDSA-P384 report signature, paravisor `REPORT_DATA` binding) and a GCP C3 Intel TDX DCAP v4 quote (PCK chain to the pinned Intel SGX Root CA, QE binding, quote signature). Runs are recorded in [`docs/testing/hardware-validation.md`](docs/testing/hardware-validation.md). This validates the *verifier* against real quotes; quote generation still requires the corresponding hardware, and TCB status stays in `unverified_fields`. |
| Attestation verifier: `tpm` | Shipped in 0.4.0, with a host-dependent limit | **0.3.0 reported a forged TPM quote as hardware-attested and should not be used.** The `tpm2` branch of `verify_trace_claim` called only `verify_tpm_measurement`, which takes no signature parameter, so a `TPMS_ATTEST` with correct magic and matching `qualifying_data` passed with no signature and no chain (#370). `verify_tpm_quote_chained` existed and was hardware-validated on 2026-07-31 (an AK-signed quote from an Azure Trusted Launch vTPM verified end to end, tampered copies rejected, see [`docs/testing/hardware-validation.md`](docs/testing/hardware-validation.md)); nothing in production called it. Fixed in #469: the quote signature and the AK certificate chain now gate `hardware_attestation`, supplied-but-invalid material is fatal, and absent material degrades to `unverified` as SNP does. Signed evidence travels as `gateway.attestation_evidence`, which is why 0.4.0 is a break for older verifiers. **The remaining limit is the host, not the code (#453):** Azure Trusted Launch presents two AK certificate hierarchies concurrently at NV index `0x01C101D0`, and on the `Global Virtual TPM CA - 03` variant the AIA extension is absent entirely, so there is nothing to walk and no chain to a pinnable root. On such a host the chain cannot be established and the claim reports `unverified` rather than verified. Pin the root your own hosts present; a mixed fleet needs both. |
| `opaque` provider | Not implemented | Opt-in placeholder; excluded from auto-detect. Selecting it explicitly raises `ATTESTATION_PROVIDER_NOT_IMPLEMENTED` rather than falling through silently. |
| `gpu-cc` (NVIDIA H100/H200/Blackwell, via NRAS) | Planned (v0.2) | |
| Transparency-log anchoring for TRACE Claims | v0.2 | Write and lookup. |
| Server-side (provider) attestation | Not yet (Phase 2) | Phase 1 attests the gateway boundary only. |
| Server provenance checking | Shipped | Consumes [server-provenance-v1](https://github.com/agentrust-io/trace-spec/blob/main/spec/server-provenance-v1.md) records: verifies the signature against a configured publisher key, then compares the record's tool-catalog hash against the tools the server advertises **to this gateway**. Five outcomes reach the audit chain and none of them is silent: `verified`, `catalog-mismatch` (the document is fine and the server is not), `invalid`, `unchecked` (verified but the tool list was unavailable, so the comparison that matters never ran), `absent`. Absence is recorded and non-fatal by default, because almost no MCP server has a record and a gateway that refuses to route without one gets disabled on first contact. Set `attestation.required_provenance_kind` for a floor. |
| Real-time policy update without enclave restart | Not yet | `policy_reload_interval_seconds` is `0`; a policy change requires a restart. |
| AARM R4 five decision types | Shipped, with caveats | ALLOW, DENY, MODIFY, STEP_UP, DEFER are recorded in the audit chain. MODIFY is recorded as `redact`, DEFER is classified but not asynchronously enforced, and the TRACE Claim still carries the pre-AARM vocabulary. See [LIMITATIONS.md](LIMITATIONS.md). |
| AARM R8 telemetry export | Shipped | OpenTelemetry spans mirroring audit entries. Opt in with `CMCP_OTEL_ENABLED=1` and `pip install cmcp-runtime[otel]`; a no-op otherwise. Exports digests, never payloads. The audit chain stays authoritative. |
| AARM R2/R3 declared intent | Not implemented | cMCP takes no declared-intent input, so the intent-alignment half of R2 and R3 is unmet. Adding one changes the MCP-facing surface. |
| AARM R7 semantic distance from intent | Not implemented | Catalog rug-pull detection and injection detection are present; neither measures distance from a stated intent. |
| Full RATS/EAT conformance | v1.0 target | Claims are EAT-shaped today; full conformance is tracked for v1.0. |

See [ROADMAP.md](ROADMAP.md) for version sequencing,
[`docs/testing/hardware-validation.md`](docs/testing/hardware-validation.md) for what has been
verified against real TEE hardware, and [LIMITATIONS.md](LIMITATIONS.md) for what cMCP does not
prevent.
