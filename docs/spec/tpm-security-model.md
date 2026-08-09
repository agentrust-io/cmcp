# TPM Security Model on Non-Confidential-Compute Devices

**Status:** Approved; see section 8 for the decisions taken and what remains open
**Tracking issues:** #429, #430, #431, #432, #433, #434, #435, #436, #453
**Supersedes nothing. Complements** [attestation.md](attestation.md) and [threat-model.md](threat-model.md).

---

## 1. Purpose

cMCP runs a policy enforcement broker inline between an agent and the tools it calls. On a confidential VM the trust story is straightforward: the workload runs in an encrypted, measured VM and the CPU vendor signs evidence of that. On a consumer or workstation device there is no confidential compute, only a TPM, and the story is materially different.

This document states what the TPM path guarantees today, what it does not, and the target model. Anyone evaluating a deployment on a device without confidential compute asks the same question first: what integrity claims can be made with only a TPM. The answer needs to be precise rather than reassuring, and it is not written down anywhere else.

## 2. Current implementation

`src/cmcp_runtime/tee/tpm.py` (collection), `src/cmcp_verify/tpm.py` (verification).

`TPMProvider.detect()` selects the TPM when no confidential-compute provider is present. Auto-detect probe order is `azure-cvm`, `tpm`, `sev-snp`, `tdx`, first match wins. The provider reads PCRs 0 through 7 from the SHA-256 bank via `tpm2-pytss` ESAPI, falling back to a `tpm2_pcrread` subprocess. The measurement is `sha256(PCR0 || ... || PCR7)`.

The ESAPI path attempts `TPM2_Quote` with the first 32 bytes of the attestation nonce as `qualifyingData` and keeps `attestationData` as `raw_evidence`. The subprocess path never produces a quote.

`verify_tpm_measurement(measurement, raw_evidence, expected_qualifying_data)` validates the measurement string format, parses `TPM2B_ATTEST`, checks the `TPMS_ATTEST` magic value, and compares the embedded `qualifyingData` against the expected nonce in constant time.

If the SHA-256 bank is unavailable the provider falls back to SHA-1, downgrades the reported provider to `software-only`, and records `measurement_note = "sha1-bank-fallback"`. If no provider is detected the gateway refuses to start unless `CMCP_DEV_MODE=1`.

## 3. What is claimable today

The gateway observed a platform boot state, expressed as a digest over PCRs 0 through 7, and the nonce was carried through the flow. Firmware, bootloader, and kernel changes change the digest. The SHA-1 degradation path is explicit and does not present weak evidence as strong.

## 4. What is not claimable, and why

### 4.1 The evidence is not cryptographically bound to the TPM (#429, #430) — closed in the verifier

Historically `ESAPI.quote()` returned `Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]` and the signature was discarded at the call site, so verification was structural parsing plus a nonce comparison. Any code executing in the gateway process could synthesise attestation data with arbitrary PCR values and the expected nonce, and it verified.

That hole is closed. The producer now captures the marshalled `TPMT_SIGNATURE`, the AK public key, and the AK certificate chain onto `AttestationReport` (`quote_signature`, `attestation_key_pem`, `attestation_key_chain_pem`). `verify_trace_claim`'s `tpm2` branch verifies the signature over the `TPMS_ATTEST` and the AK chain against an operator-pinned root supplied as `trusted_tpm_ca_pem` (#370), and `hardware_attestation` is reported verified only when both check out — the same gating the SNP VCEK chain uses. Supplied-but-invalid chain material is fatal; absent chain material degrades to `unverified` for back-compatibility with evidence predating these fields.

One transport gap remains. `RuntimeInfo` in `agentrust-trace` is `extra="forbid"` and carries no evidence fields, so a claim built through `_build_runtime()` cannot yet carry `raw_evidence`, `quote_signature`, or `cert_chain`. The verifier reads them from the raw claim dict, which means the chained path only engages for evidence supplied out of band. Closing this needs the `RuntimeInfo` schema change upstream and is the same constraint the SNP `cert_chain` field is under.

### 4.2 There is no attestation key identity (#431) — partially closed

An AK certificate chain is now provisioned and verified to a pinned manufacturer root (`tpm_roots.py`), so a verified quote does distinguish a key certified by a known TPM vendor from an attacker-generated one. `verify_ak_ek_chain` will additionally verify an EK certificate's own path to the pinned CA when a producer bundles one, at which point `ek_cert_chain` is genuinely established rather than carrying the old `requires_ca_lookup` note.

What is still open is the **binding** between the two, and it cannot be closed with certificates. An EK is a restricted decryption key: it cannot sign, so it cannot issue an AK certificate and cannot appear in the AK's issuance path. Issue #370's "verify AK->EK" is therefore only half realisable — `EK->manufacturer-CA` is a real path, `AK->EK` is not. TPM 2.0 binds them by credential activation (`TPM2_MakeCredential` / `TPM2_ActivateCredential`), a challenge-response the verifier runs, and that is not implemented. Verifying both chains proves each key is individually certified; it does not prove they live in the same TPM. A platform that certifies an AK without activation is trusted on the strength of its CA alone.

One sharp edge worth recording, because it produced a false pass during implementation: the TCG EK EKU (`2.23.133.8.1`) does **not** identify an Endorsement Key. Azure's real vTPM chain carries it on the *issuing CAs* (`Azure Cloud Virtual TPM CA - 11` and `... CA 2025`), where it means "may issue EK certificates". Matching on the EKU alone reported `ek_cert_chain` verified for a chain containing no EK at all. Identification requires the EKU **and** `ca=False`.

### 4.3 The gateway is not measured (#432, closed)

PCRs 0 through 7 cover firmware, option ROMs, boot configuration, and bootloader. Replacing the policy bundle or the gateway binary produced an identical measurement, so the stated purpose of the TPM path, protecting policy from tampering, was not enforced by the TPM.

Both halves are now closed. The gateway is measured into an NV extend index at startup, before it serves traffic, and the value is bound by two `TPM2_NV_Certify` calls bracketing the extend, so both the pre and post values are TPM-signed and a verifier checks `post == H(pre || expected_gateway_digest)` with nothing collector-asserted and no verifier-side state. See P2 in section 5 for the construction and why one certify is not enough. Both were validated on an Azure Trusted Launch vTPM on 2026-08-01; the certify run found two defects in already-merged code, recorded in [hardware-validation.md](../testing/hardware-validation.md).

What the appraisal does not give you: it proves the gateway extended a specific digest into a specific index, not that the digest corresponds to known-good code, unless the relying party supplies an expected value. Key provenance for the certifying key also remains host-dependent on Azure, per section 7.

### 4.4 PCR digests are uninterpretable (#433)

No TCG event log is collected or replayed. A verifier can tell that state differs from a known-good value but not what changed, cannot express policy over individual boot components, and cannot debug a mismatch. Any allowlist of golden measurements becomes unmaintainable, since every firmware update invalidates it with no explanation.

### 4.5 Sealing is documented but not implemented

[attestation.md](attestation.md) section 4.2 describes sealing the signing key with `TPM2_Create` under a PCR-bound parent. That is correctly scoped as Phase 2, but a reader may assume it exists. It does not.

### 4.6 The measurement itself was wrong (#434, fixed in #437)

`_parse_tpm2_pcrread_output` removed the `0x` prefix with `lstrip("0x")`, which strips a character set rather than a prefix. An all-zero PCR collapsed to one byte, a value beginning `0x0A` became odd-length and was dropped, and every later PCR shifted index. The subprocess path therefore produced a measurement over a misaligned seven-entry list whenever any PCR had a leading zero, which is the normal case. Stable per machine, so it looked correct, but not a digest of the actual PCR values.

### 4.7 Claim tiering (#436, proposed)

Unsigned PCR reads report `provider="tpm"` and present downstream as hardware-attested. The proposal is to downgrade them to `software-only` with note `tpm-pcr-read-unsigned`, matching the existing SHA-1 policy rather than inventing a second one.

This is a behaviour change, not a bug fix: `tests/unit/test_tee_providers.py` currently asserts the opposite, that the subprocess path keeps `provider == "tpm"`. It therefore ships separately and depends on the decision in section 8.

## 5. Target model

Ordered by trust gained per unit of effort.

**P0. Retain and verify the quote signature (#429, #430).** Keep `TPMT_SIGNATURE`, carry it through `AttestationReport`, verify against the AK public area. Nothing downstream has value without this.

**P1. Provision an AK and validate its chain (#431).** Restricted signing AK certified against the EK, EK certificate shipped with the evidence, chain verified to a TPM vendor root. Open dependency: vendor CA root distribution.

**P2. Measure the gateway (#432).** Extend an **NV index defined with `TPM_NT_EXTEND`** at startup with a digest over installed code, the policy bundle, and the effective configuration, before the gateway serves traffic.

**Decided: NV extend index, not an application PCR.** Per the TCG PC Client Platform TPM Profile, PCR 23 is Application Support and PCR 16 is Debug, and **both are resettable from locality 0**. An adversary with local code execution can reset PCR 23 and re-extend a value of their choosing, so an application PCR is advisory, not tamper-resistant, against precisely the adversary this tier exists to address. An NV extend index is not resettable from locality 0. The alternatives considered and not chosen were sealing the signing key to a policy spanning the application PCR and non-resettable SRTM PCRs (kept as P3, which is enforcement rather than measurement) and DRTM (unavailable on the platforms in scope).

What the extend semantics buy, and what they do not:

- **Forgery is infeasible without a write policy.** `TPM_NT_EXTEND` writes are one-way, `new = H(old || data)`, so an adversary who can call `TPM2_NV_Extend` can append but cannot set the index to a chosen value without a preimage. The write policy the original proposal called for is therefore not what carries the security argument.
- **Destruction is possible, but not silent.** `TPM2_NV_UndefineSpace` then a fresh define resets the index, and owner authorization permits it. Guest root holds owner auth on an Azure VM. A redefined index reads back with `TPMA_NV_WRITTEN` clear until written again, so the erasure is visible. The property claimed is therefore **tamper-evident, not tamper-proof**. Tamper-proof needs the platform hierarchy, which a guest VM cannot reach; that is the same client-firmware dependency in section 6.
- **The value is not predictable.** Extends accumulate and NV is persistent, so after N gateway starts the index is a hash chain over all N digests rather than `H(0 || digest)`. A verifier cannot recompute it from the current gateway digest. The collector therefore reports the index value both before and after the extend, so continuity (`after == H(before || digest)`) is checkable, which is the hash-chain idiom the audit log already uses.

What is measured is the installed distributions' recorded per-file hashes (pip's `RECORD` metadata), plus the policy bundle bytes and the resolved configuration with secrets excluded. RECORD covers dependencies, so a swapped transitive package is caught; measuring only cMCP's own source would report an identical digest for it. An editable install has no RECORD, so the measurement is refused rather than computed over an unknown subset: fatal in production, a warning under `CMCP_DEV_MODE`.

An NV read is not covered by the quote signature, so the value needs its own signed freshness argument. `TPM2_NV_Certify` is the primitive: the TPM signs a `TPM_ST_ATTEST_NV` structure over the index contents with the AK, under caller-supplied qualifying data. Reading the index and committing the result into the quote's qualifying data is **not** sound, because the collector would be asserting the value it read and a compromised gateway is the adversary.

Because extends accumulate, one certified value cannot be checked against anything: there is no absolute value to expect, and `TPM2_NV_Certify` signs only the current value. **Decided: certify twice, bracketing the extend.** The collector certifies the index, extends it, and certifies again, so both values are TPM-signed and a verifier checks `post == H(pre || expected_gateway_digest)` with nothing collector-asserted and no verifier-side state. This proves that this gateway extended exactly this digest; it deliberately does not attempt to prove the history behind the first value, which would require the verifier to remember prior attestations. The two calls commit different qualifying data (`pre` / `post`), so each blob's role is signed rather than inferred from its position.

**P2 is now implemented.** Collection is `cmcp_runtime.tee.measurement.certify_and_extend_gateway_measurement`, appraisal is `cmcp_verify.nv_certify.verify_gateway_measurement`, and startup wires both at step 3b. Only the platform attestation key is used to certify: a transient key would give a verifiable signature with no provenance, which is worse than an honest absence because it looks like evidence, so a platform without a certified key falls back to the unsigned extend and ships no evidence at all.

`agent_manifest.verify_tpm_quote` cannot appraise this, because it rejects any attest type that is not `TPM_ST_ATTEST_QUOTE` and its parser assumes a `TPML_PCR_SELECTION` union. The certificate chain is still delegated to `agent_manifest.verify_cert_chain`; only the `TPM_ST_ATTEST_NV` and `TPMT_SIGNATURE` wire formats are local, tracked upstream as agentrust-io/agent-manifest#255.

**What P2 still does not give you.** The appraisal proves the gateway extended a specific digest into a specific index. It does not prove that digest corresponds to *known-good* code unless the relying party supplies an expected value; without one, `verify_gateway_measurement` reports the pair as internally consistent and says so in its details rather than implying more. Deciding what the expected digest should be for a given release is a release-engineering question, not a TPM one.

**P3. Seal the TRACE signing key (attestation.md 4.2).** Implement the documented Phase 2 design over the P2 policy, so a modified gateway cannot unseal the key that signs claims. This is what converts measurement into enforcement.

**P4. Ship the TCG event log (#433).** Collect and replay it so evidence is interpretable and policy can name specific components.

**Reordered 2026-08-01: sealing moved ahead of the event log.** The event log is 0 bytes on both Azure and GCP, so replay cannot be validated on any cloud vTPM we can provision and P4 is gated on physical client hardware. Sealing is reachable today and it is the step that converts measurement into enforcement, so it earns more trust per unit of effort. P3 does still depend on P2 finishing, since the policy it seals against is the NV index.

**P5. Crypto policy.** Keep the SHA-1 downgrade, document it as a hard failure for regulated deployments, and add a flag that refuses SHA-1 outright.

## 6. Open ecosystem questions

1. **EK certificate roots.** A supported path for programmatically obtaining and pinning TPM vendor EK CA roots for offline verification, covering discrete TPMs and firmware TPMs. This is the blocking dependency for P1 and it has no good answer today.
2. **Hosted verification services.** Can a hosted attestation verifier cover TPM quotes as well as confidential-compute reports, giving relying parties one verification interface across tiers? If so, it changes the verifier design.
3. **DRTM.** Is a dynamic root of trust realistic on commodity client hardware, or is SRTM plus an NV extend index the practical ceiling?
4. **Windows and Linux parity.** Recommended interface for AK provisioning and event log access on Windows, where Measured Boot already owns part of this.
5. **Claim vocabulary.** Is there an established way to express TPM-tier versus confidential-compute-tier evidence, so cMCP does not invent tiering language that later conflicts with the ecosystem?

## 7. Positioning

cMCP should describe three tiers rather than one attestation story.

| Tier | Evidence | Adversary resisted |
|---|---|---|
| Confidential compute (TDX, SEV-SNP) | Vendor-signed report, memory encrypted | Host operator and local code execution |
| TPM, target model in section 5 | AK-signed quote chained to a vendor CA, gateway measured into a non-resettable index, signing key sealed to that policy | Local code execution below the gateway measurement |
| TPM, as implemented today | AK-signed quote over PCRs 0-7, gateway measured into a `TPM_NT_EXTEND` NV index and bound by a bracketing `TPM2_NV_Certify` pair, AK chain verified to a pinned root **where the host's AK certificate permits it** | Remote and passive adversaries, accidental drift, and forgery of the gateway measurement |

Two things about row three, both load-bearing and neither visible in a one-line summary.

**Chain verification is host-dependent, not a given.** Azure Trusted Launch runs two vTPM CA hierarchies concurrently: one chains to the root pinned in `cmcp_verify/tpm_roots.py` over AIA, the other carries no AIA extension at all and therefore cannot produce a chain. On the latter, evidence is signed and fresh but proves nothing about *where* the key lives, so key provenance is unavailable. See [hardware-validation.md](../testing/hardware-validation.md) and #453.

**The gateway measurement is signed evidence, but it does not carry known-good.** The NV index value is bound by a bracketing `TPM2_NV_Certify` pair, so a relying party can appraise it rather than take the collector's word for it (#432, closed, hardware-validated 2026-08-01). What the pair proves is that this gateway extended this digest. Whether that digest is the right one is a release-engineering question: without an expected value supplied by the relying party, the appraisal reports the pair as internally consistent and says so, rather than implying more.

The gap between rows two and three is the remaining work in section 5. Naming it plainly is more useful to anyone evaluating the project than any claim we could round up to.

## 8. Decisions taken

The target model in section 5, its ordering, and the three-tier vocabulary in section 7 are approved, so documentation and public materials should describe the TPM tier consistently with them. Recorded here rather than left open, since an RFC that stays "pending approval" while the code moves underneath it stops being a reference.

| Decision | Where it lives |
|---|---|
| Measure the gateway into a `TPM_NT_EXTEND` NV index, not an application PCR | section 5 P2, #432 |
| Bind the measurement with two `TPM2_NV_Certify` calls bracketing the extend, so both values are TPM-signed and the verifier stays stateless | section 5 P2, #432 |
| Sealing (P3) precedes the event log (P4), because the log is 0 bytes on every cloud vTPM and sealing is what converts measurement into enforcement | section 5 |
| The three-tier vocabulary stands, with row three carrying the host-dependency and unsigned-measurement caveats explicitly | section 7 |
| Azure TPM key provenance is hierarchy-dependent until the second CA root is sourced | section 7, #453 |

What remains genuinely open is in section 6, and it is not ours to decide: vendor root distribution for client firmware TPMs, and whether Microsoft publishes the `Global Virtual TPM CA - 03` chain in a citable location (#453).
