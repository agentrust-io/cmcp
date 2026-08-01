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

### 4.1 The evidence is not cryptographically bound to the TPM (#429, #430)

`ESAPI.quote()` returns `Tuple[TPM2B_ATTEST, TPMT_SIGNATURE]`. The signature is discarded at the call site, and `verify_tpm_measurement` has no signature parameter. Verification is structural parsing plus a nonce comparison.

Compounding this, the quote is called with `object_handle=ectx.get_capability(TPM2_ALG.NULL)`, which is a capability query rather than a loaded key handle. The call raises, a bare `except` sets `raw_evidence = None`, and the provider degrades silently. The quote path is effectively dead code.

Consequence: any code executing in the gateway process can synthesise attestation data with arbitrary PCR values and the expected nonce, and it verifies. Local code execution is the primary adversary on a device without confidential compute, so this removes the security value of the TPM path.

### 4.2 There is no attestation key identity (#431)

No AK is provisioned. `ek_cert_chain` is unconditionally listed as unverified with the note `requires_ca_lookup`. Even with a verified signature, nothing distinguishes a discrete TPM from a software emulator or an attacker-generated key.

### 4.3 The gateway is not measured (#432, measurement landed, binding open)

PCRs 0 through 7 cover firmware, option ROMs, boot configuration, and bootloader. Replacing the policy bundle or the gateway binary produced an identical measurement, so the stated purpose of the TPM path, protecting policy from tampering, was not enforced by the TPM.

The gateway is now measured into an NV extend index at startup, before it serves traffic, per P2 below. What is still missing is the signed binding: the index value travels as an ordinary NV read, which the quote signature does not cover, so a verifier cannot yet distinguish a genuine value from one a compromised gateway reported. `TPM2_NV_Certify` closes that, and until it does the measurement is a local integrity control rather than remote-verifiable evidence.

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

**Remaining for P2:** an NV read is not covered by the quote signature, so the value needs its own signed freshness argument. `TPM2_NV_Certify` is the primitive: the TPM signs a `TPM_ST_ATTEST_NV` structure over the index contents with the AK, under caller-supplied qualifying data. Reading the index and committing the result into the quote's qualifying data is **not** sound, because the collector would be asserting the value it read and a compromised gateway is the adversary. That half also needs a `TPM_ST_ATTEST_NV` parser, which agent-manifest does not currently model.

Because extends accumulate, one certified value cannot be checked against anything: there is no absolute value to expect. **Decided: certify twice, bracketing the extend.** The collector certifies the index, extends it, and certifies again, so both values are TPM-signed and a verifier checks `after == H(before || expected_gateway_digest)` with nothing collector-asserted and no verifier-side state. This proves that this gateway extended exactly this digest; it deliberately does not attempt to prove the history behind the first value, which would require the verifier to remember prior attestations.

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
| TPM, as implemented today | AK-signed quote over PCRs 0-7, gateway measured into a `TPM_NT_EXTEND` NV index, AK chain verified to a pinned root **where the host's AK certificate permits it** | Remote and passive adversaries, accidental drift, and forgery of the gateway measurement |

Two things about row three, both load-bearing and neither visible in a one-line summary.

**Chain verification is host-dependent, not a given.** Azure Trusted Launch runs two vTPM CA hierarchies concurrently: one chains to the root pinned in `cmcp_verify/tpm_roots.py` over AIA, the other carries no AIA extension at all and therefore cannot produce a chain. On the latter, evidence is signed and fresh but proves nothing about *where* the key lives, so key provenance is unavailable. See [hardware-validation.md](../testing/hardware-validation.md) and #453.

**The gateway measurement is not yet signed evidence.** The NV index value travels as an ordinary read that no signature covers, so it is a local integrity control rather than something a relying party can appraise. `TPM2_NV_Certify` closes that and is the open half of #432.

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
