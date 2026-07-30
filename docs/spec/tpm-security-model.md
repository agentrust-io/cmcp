# TPM Security Model on Non-Confidential-Compute Devices

**Status:** Draft, awaiting approval
**Approvers required:** @podcastinator, @AaronRoeF
**Tracking issues:** #429, #430, #431, #432, #433, #434, #435, #436
**Supersedes nothing. Complements** [attestation.md](attestation.md) and [threat-model.md](threat-model.md).

---

## 1. Purpose

cMCP runs a policy enforcement broker inline between an agent and the tools it calls. On a confidential VM the trust story is straightforward: the workload runs in an encrypted, measured VM and the CPU vendor signs evidence of that. On an AI PC or any standard machine there is no confidential compute, only a TPM, and the story is materially different.

This document states what the TPM path guarantees today, what it does not, and the target model. It exists because partners evaluating the AI PC deployment ask exactly one question first: what integrity claims can you make with a TPM on a non-CC device. The answer needs to be precise rather than reassuring.

## 2. Current implementation

`src/cmcp_runtime/tee/tpm.py` (collection), `src/cmcp_verify/tpm.py` (verification).

`TPMProvider.detect()` selects the TPM when no confidential-compute provider is present. Auto-detect probe order is `azure-cvm`, `tpm`, `sev-snp`, `tdx`, first match wins. The provider reads PCRs 0 through 7 from the SHA-256 bank via `tpm2-pytss` ESAPI, falling back to a `tpm2_pcrread` subprocess. The measurement is `sha256(PCR0 || ... || PCR7)`.

The ESAPI path attempts `TPM2_Quote` with the first 32 bytes of the attestation nonce as `qualifyingData` and keeps `attestationData` as `raw_evidence`. The subprocess path never produces a quote.

`verify_tpm_measurement(measurement, raw_evidence, expected_qualifying_data)` validates the measurement string format, parses `TPM2B_ATTEST`, checks the `TPMS_ATTEST` magic value, and compares the embedded `qualifyingData` against the expected nonce in constant time.

If the SHA-256 bank is unavailable the provider falls back to SHA-1, downgrades the reported provider to `software-only`, and records `measurement_note = "sha1-bank-fallback"`. If no provider is detected the gateway refuses to start unless `CMCP_DEV_MODE=1`.

## 3. What is claimable today

The gateway observed a platform boot state, expressed as a digest over PCRs 0 through 7, and the nonce was carried through the flow. Firmware, bootloader, and kernel changes change the digest. The SHA-1 degradation path is explicit and does not present weak evidence as strong.

## 4. What is not claimable, and why

### 4.1 The evidence is not cryptographically bound to the TPM (#429, #430)

`ESAPI.quote()` returns `Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]`. The signature is discarded at the call site, and `verify_tpm_measurement` has no signature parameter. Verification is structural parsing plus a nonce comparison.

Compounding this, the quote is called with `object_handle=ectx.get_capability(TPM2_ALG.NULL)`, which is a capability query rather than a loaded key handle. The call raises, a bare `except` sets `raw_evidence = None`, and the provider degrades silently. The quote path is effectively dead code.

Consequence: any code executing in the gateway process can synthesise attestation data with arbitrary PCR values and the expected nonce, and it verifies. Local code execution is the primary adversary on an AI PC, so this removes the security value of the TPM path.

### 4.2 There is no attestation key identity (#431)

No AK is provisioned. `ek_cert_chain` is unconditionally listed as unverified with the note `requires_ca_lookup`. Even with a verified signature, nothing distinguishes a discrete TPM from a software emulator or an attacker-generated key.

### 4.3 The gateway is not measured (#432)

PCRs 0 through 7 cover firmware, option ROMs, boot configuration, and bootloader. There is no `PCR_Extend` anywhere in the codebase. Replacing the policy bundle or the gateway binary produces an identical measurement, so the stated purpose of the TPM path, protecting policy from tampering, is not enforced by the TPM.

### 4.4 PCR digests are uninterpretable (#433)

No TCG event log is collected or replayed. A verifier can tell that state differs from a known-good value but not what changed, cannot express policy over individual boot components, and cannot debug a mismatch. Any allowlist of golden measurements becomes unmaintainable, since every firmware update invalidates it with no explanation.

### 4.5 Sealing is documented but not implemented

[attestation.md](attestation.md) section 4.2 describes sealing the signing key with `TPM2_Create` under a PCR-bound parent. That is correctly scoped as Phase 2, but a reader may assume it exists. It does not.

### 4.6 The measurement itself was wrong (#434, fixed in #437)

`_parse_tpm2_pcrread_output` removed the `0x` prefix with `lstrip("0x")`, which strips a character set rather than a prefix. An all-zero PCR collapsed to one byte, a value beginning `0x0A` became odd-length and was dropped, and every later PCR shifted index. The subprocess path therefore produced a measurement over a misaligned seven-entry list whenever any PCR had a leading zero, which is the normal case. Stable per machine, so it looked correct, but not a digest of the actual PCR values.

### 4.7 Claim tiering (#436, fixed in #437)

Unsigned PCR reads reported `provider="tpm"` and presented downstream as hardware-attested. They now downgrade to `software-only` with note `tpm-pcr-read-unsigned`, matching the SHA-1 policy.

## 5. Target model

Ordered by trust gained per unit of effort.

**P0. Retain and verify the quote signature (#429, #430).** Keep `TPMT_SIGNATURE`, carry it through `AttestationReport`, verify against the AK public area. Nothing downstream has value without this.

**P1. Provision an AK and validate its chain (#431).** Restricted signing AK certified against the EK, EK certificate shipped with the evidence, chain verified to a TPM vendor root. Open dependency: vendor CA root distribution.

**P2. Measure the gateway (#432).** Extend an application PCR at startup with a digest over binary, policy bundle, and effective configuration, and include it in the quote selection.

Important caveat that changes the design. Per the TCG PC Client Platform TPM Profile, PCR 23 is Application Support and PCR 16 is Debug, and **both are resettable from locality 0**. An adversary with local code execution can reset PCR 23 and re-extend a value of their choosing, so an application PCR alone is advisory, not tamper-resistant, against precisely the adversary this tier is meant to address. Options:

- An NV extend index (`TPM_NT_EXTEND`) with a write policy, which is not resettable from locality 0. Preferred.
- Sealing the signing key to a policy spanning the application PCR and non-resettable SRTM PCRs, so a reset breaks unseal.
- DRTM where the platform supports it.

**P3. Ship the TCG event log (#433).** Collect and replay it so evidence is interpretable and policy can name specific components.

**P4. Seal the TRACE signing key (attestation.md 4.2).** Implement the documented Phase 2 design over the P2 policy, so a modified gateway cannot unseal the key that signs claims. This is what converts measurement into enforcement.

**P5. Crypto policy.** Keep the SHA-1 downgrade, document it as a hard failure for regulated deployments, and add a flag that refuses SHA-1 outright.

## 6. Open questions for Intel

1. **EK certificate roots.** Supported path for programmatically obtaining and pinning Intel PTT EK CA roots for offline verification. Blocking dependency for P1.
2. **Intel Trust Authority.** Can ITA verify TPM quotes as well as TDX, giving relying parties one verification interface across tiers? If yes, it changes the verifier design.
3. **DRTM.** Is a dynamic root of trust realistic on AI PC, or is SRTM plus an NV extend index the practical ceiling?
4. **Windows and Linux parity.** Recommended interface for AK provisioning and event log access on Windows, where Measured Boot already owns part of this.
5. **Claim vocabulary.** Is there an Intel-endorsed way to express TPM-tier versus confidential-compute-tier evidence, so cMCP does not invent tiering language that later conflicts with the ecosystem?

## 7. Positioning

cMCP should describe three tiers rather than one attestation story.

| Tier | Evidence | Adversary resisted |
|---|---|---|
| Confidential compute (TDX, SEV-SNP) | Vendor-signed report, memory encrypted | Host operator and local code execution |
| TPM, target model in section 5 | AK-signed quote chained to a vendor CA, gateway measured into a non-resettable index, signing key sealed to that policy | Local code execution below the gateway measurement |
| TPM, as implemented today | Unsigned self-reported PCR digest | Remote and passive adversaries, accidental drift |

The gap between rows two and three is the work in section 5. Naming it plainly is more useful to an evaluating partner than any claim we could round up to.

## 8. Decision requested

Approve the target model in section 5 and its ordering, and the three-tier vocabulary in section 7, so that public materials and partner conversations describe the TPM tier consistently. Approvals needed from @podcastinator and @AaronRoeF.
