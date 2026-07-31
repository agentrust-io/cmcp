# Hardware validation

What has been verified against real confidential-computing hardware, what has
not, and how to reproduce each run. [STATUS.md](../../STATUS.md) links here
rather than restating it.

The rule this page exists to enforce: no document describes cMCP as
hardware-attested for a platform until a genuine quote from that platform has
been verified end to end by `cmcp_verify`, and the run is recorded below.

## Current state

| Platform | Report parsing | Certificate chain | Report signature | Verified against real hardware evidence |
|---|---|---|---|---|
| AMD SEV-SNP (Azure CVM, vTPM-rooted) | Yes | Yes, to the real AMD ARK-Milan root | Yes | **Yes**, 2026-07-27, both from a stored capture and **live inside a running CVM** |
| Intel TDX (GCP C3, non-paravisor) | Yes | Yes, to the pinned Intel SGX Root CA | Yes | **Yes**, 2026-07-27, capture of 2026-07-21 |
| TPM 2.0 (Azure vTPM, Trusted Launch) | Yes | Not yet (`ek_cert_chain` stays unverified, see #431) | Yes | **Yes**, 2026-07-31. AK-signed quote verified end to end, tampered copies rejected; certificate chain still open |
| NVIDIA GPU CC (H100/H200) | Not implemented | | | No |

"Verified against real hardware evidence" means the committed verifier accepted a
quote produced by that silicon, with signature and chain checks live, and rejects
a tampered copy. It does not mean cMCP has run *inside* that TEE in production;
quote generation still requires the corresponding hardware.

## Scope of the guarantee

Verification is bounded to a remote or rogue-admin adversary. It does not hold
against an adversary with physical access to the hardware:
[TEE.fail](https://tee.fail) demonstrates attestation-key extraction from
fully-patched SEV-SNP and TDX with a sub-$1000 DDR5 interposer. See
[LIMITATIONS.md](../../LIMITATIONS.md).

## SEV-SNP, Azure confidential VM

Evidence: an HCL report read from the vTPM NV index `0x01400001` on an Azure
DCasv5 CVM (family 0x19 / model 0x01, Milan), plus the VCEK and the AMD
ASK/ARK chain. Azure SEV-SNP is paravisor-mediated, so `REPORT_DATA` binds the
vTPM attestation key rather than a cMCP-supplied nonce directly; the nonce is
carried in the AK-signed TPM quote's `extraData` and the two are bound together
by `cmcp_verify.azure_cvm.verify_azure_cvm_measurement`.

What the run checks: the paravisor `REPORT_DATA == sha256(runtime_data)`
binding, the VCEK chain to the genuine AMD ARK-Milan root, and the ECDSA-P384
report signature over the report body.

```
CMCP_AZURE_FIXTURE_DIR=<capture dir> pytest tests/unit/test_azure_cvm_verify.py
```

The capture directory holds `hcl.bin`, `vcek.der` and `cert_chain.pem`. It is
**not** committed: the SNP report's 64-byte `CHIP_ID` is a per-CPU hardware
identifier. Zeroing it invalidates the signature, so a redacted vector cannot
exercise the signature path, which is why this test is env-gated instead of
running in CI.

## Live run inside a SEV-SNP confidential VM

The runs above appraise stored evidence. On 2026-07-27 the collector and the
verifier were also run **inside** a real Azure confidential VM
(`Standard_DC2ads_v5`, Ubuntu 24.04 CVM image, eastus; the guest reports
`Detected confidential virtualization sev-snp` and `Memory Encryption Features
active: AMD SEV`, with `SEV: Status: vTom` and no `/dev/sev-guest`, the expected
paravisor shape).

`AzureCVMProvider.detect()` returned true, the provider collected 13,004 bytes of
live evidence under a caller nonce, and `verify_azure_cvm_measurement` returned
`verified: true` with **no unverified fields**:

| Verified field | What it establishes |
|---|---|
| `quote_nonce_binding` | The caller's nonce is in the AK-signed TPM quote's extraData |
| `ak_binding` | The vTPM AK is bound into the SNP report's `REPORT_DATA` by the paravisor |
| `runtime_data_binding` | `REPORT_DATA == sha256(runtime_data)` holds on the live report |
| `measurement` | The launch measurement matches the collected report |
| `vcek_cert_chain` | The VCEK fetched from AMD KDS for this CPU chains to `CN=ARK-Milan` |
| `report_signature` | The SNP report signature verifies under that VCEK |

A wrong nonce was rejected with `quote_nonce_mismatch`, so freshness is enforced
rather than assumed.

Two deployment facts this surfaced, both worth knowing before anyone repeats it:

- The gateway process needs TPM device access. `AzureCVMProvider` shells out to
  `tpm2_nvread` without elevation, so the service user must be in the `tss`
  group (`/dev/tpmrm0` is `tss:tss`). Without it the provider fails with a TCTI
  load error, not an attestation error, which reads as a broken TPM rather than
  a permissions problem.
- `verify_azure_cvm_measurement(..., trusted_ark_pem=...)` wants the ARK alone.
  Passing AMD KDS's `cert_chain` endpoint output, which is the ASK **and** the
  ARK, yields `vcek_chain_invalid`. Extract the self-signed root first.

What this still does not establish: cMCP serving live MCP traffic from inside the
enclave with a policy bundle measured at boot. This validates attestation
collection and verification in situ, which is the part that was never exercised
on hardware, not a production gateway deployment.

## Intel TDX, GCP C3 confidential VM

Evidence: a DCAP v4 ECDSA quote from a GCP C3 CVM (non-paravisor TDX, kernel
6.17, configfs-TSM `tdx_guest` provider). Non-paravisor TDX is guest-controlled,
so `REPORTDATA` carries the value cMCP supplies.

What the run checks: the attestation key's ECDSA-P256 signature over the quote
header plus TD report body, the QE report binding
(`report_data[:32] == sha256(att_pub || qe_auth)`), the PCK signature over the
QE report, and the PCK chain to the pinned Intel SGX Root CA.

```
CMCP_TDX_FIXTURE_DIR=<capture dir> pytest tests/unit/test_tdx_quote_verify.py
```

The capture directory holds `tdx_quote.bin`. Optional: `collateral/intel_root_ca.pem`
to override the pinned root, and `report_data.hex` to assert the report_data
binding. The quote is not committed: the PCK certificate identifies the CPU.

This run is what found the parser defect fixed alongside this page. Real DCAP v4
quotes nest the Quoting Enclave material under a type-6
`QE_REPORT_CERTIFICATION_DATA` header; the parser read the QE report six bytes
early, so every genuine quote was rejected with
`attestation_key_not_bound_to_qe` while the synthetic tests, which emitted the
same flat layout, passed. Failure was closed, so this was a false negative
rather than an unsound accept, but the TDX path had never worked against real
evidence. Synthetic self-consistency is not validation.

## TPM 2.0, Azure Trusted Launch vTPM

Evidence: a `TPMS_ATTEST` quote over PCRs 0-7 (SHA-256) from a `Standard_D2s_v7`
Ubuntu 24.04 VM with Trusted Launch, vTPM and secure boot enabled, taken under a
fresh 32-byte nonce.

What the run checks, within Phase 1's parse-only scope: parsing a real attest
blob, the magic constant, the PCR digest matching the measurement field, and the
qualifying-data binding equalling the nonce (with a different nonce correctly
leaving `qualifying_data` unverified).

```
CMCP_TPM_FIXTURE_DIR=<capture dir> pytest tests/unit/test_tpm_verify.py
```

This run also surfaced an interop gap, fixed alongside it. The parser required
the outer `TPM2B_ATTEST` two-byte size prefix, but `tpm2_quote -m` writes a bare
`TPMS_ATTEST`, so every quote produced by the standard tooling was rejected with
`TPM2B_ATTEST size field invalid`. Both framings are now accepted, told apart by
the magic constant.

The AK signature is now verified (see the 2026-07-31 run below). The EK/AK
certificate chain remains in `unverified_fields`. **Corrected 2026-07-31.** An earlier run recorded that Azure's pre-provisioned AK
certificate carries no AIA extension and that its issuing intermediate is
therefore not fetchable. That is no longer true: Azure has changed its vTPM PKI.
On a VM provisioned 2026-07-31 in eastus, the certificate at vTPM NV index
`0x01C101D0` is issued by `CN=Azure Cloud Virtual TPM CA - 11`, not
`CN=Global Virtual TPM CA - 03`, and it does carry an AIA extension with four CA
Issuers URIs. The intermediate was fetched from the public CDN and verified to
have signed the AK certificate. See the certificate-chain section below.

It remains true that this certificate certifies a different key than an in-guest
`tpm2_createak` AK. The resolution is not to certify our own AK: it is to use the
key Azure already certified, which is live at persistent handle `0x81000003`.

## TPM 2.0 quote signature, Azure Trusted Launch vTPM, 2026-07-31

Evidence: an AK-signed quote from a `Standard_D2s_v5` Ubuntu 24.04 VM with Trusted
Launch, vTPM and secure boot enabled, eastus. The guest reports TPM 2.0 with
`TPM2_PT_MANUFACTURER` = `MSFT`. The attestation key was created with
`tpm2_createek` followed by `tpm2_createak` (RSA, RSASSA, SHA-256), and the quote
taken over PCRs 0-7 in the SHA-256 bank under a fresh 32-byte nonce:

```
tpm2_createek -c ek.ctx -G rsa -u ek.pub
tpm2_createak -C ek.ctx -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub -n ak.name
tpm2_readpublic -c ak.ctx -f pem -o ak.pem
tpm2_quote -c ak.ctx -l sha256:0,1,2,3,4,5,6,7 -q $NONCE -m quote.msg -s quote.sig -g sha256
```

What the run checks: the `TPMS_ATTEST` magic constant, `extraData` equalling the
nonce, and the RSASSA-SHA256 signature over the attest blob verifying under the AK
public key. It also confirms rejection of a one-bit tampered attest blob, a
tampered signature, and a correct signature checked against a different key.

Unlike the SEV-SNP captures, this vector **is committed**, in
`tests/unit/test_tpm_quote_signature.py`. It carries no per-CPU hardware
identifier: the AK public key belongs to a virtual TPM in a VM that no longer
exists, and the PCR values describe a stock Ubuntu image. Committing it means the
signature path is exercised on every PR rather than only when a fixture directory
is set.

```
pytest tests/unit/test_tpm_quote_signature.py
```

Not closed by this run: the EK certificate chain (#431). The EK certificate was
not present at NV index `0x01C00002` on this VM, and as recorded above Azure's
pre-provisioned AK certificate certifies a different key and carries no AIA
extension. Binding an in-guest AK to the platform EK needs
`TPM2_ActivateCredential`, which is the next step for #431.

## TPM 2.0 attestation key certificate chain, Azure Trusted Launch, 2026-07-31

This run establishes that a chain to a public CA is reachable on Azure, which the
earlier note had concluded was not possible.

Findings on a `Standard_D2s_v5` Ubuntu 24.04 Trusted Launch VM in eastus:

- The only NV index defined is `0x01C101D0` (1596 bytes). There is **no EK
  certificate**, at `0x01C00002` or anywhere else. `tpm2_createek` succeeds but
  produces an uncertified key, so credential activation against a platform EK
  certificate is not available on this platform.
- Two persistent handles exist, `0x81000003` and `0x81010001`. The public key at
  **`0x81000003` is exactly the key certified by the certificate at
  `0x01C101D0`**, and that handle can produce a quote directly.
- The certificate carries Extended Key Usage `2.23.133.8.3`, the TCG
  Attestation Identity Key certificate OID, alongside `1.3.6.1.4.1.311.10.3.12`.
- Chain, verified end to end:
  `CN=<vm-id>.TrustedVM.Azure.windows.net`
  signed by `CN=Azure Cloud Virtual TPM CA - 11` (fetched over AIA from
  `primary-cdn.pki.core.windows.net`), itself issued by
  `CN=Azure Cloud Virtual TPM CA 2025`.

So the route for #431 on Azure is not `TPM2_ActivateCredential`. It is to quote
with the platform attestation key at `0x81000003` and present the certificate
from `0x01C101D0`, letting the relying party build the chain over AIA and pin the
Azure vTPM root. Credential activation remains the route on hardware that ships
an EK certificate, which is the client fTPM case.

Not yet implemented: the runtime does not read the NV certificate or use the
persistent handle, and `cmcp_verify` does not build or pin the chain. `#431`
tracks that work.

## TCG event log availability, Azure Trusted Launch, 2026-07-31

`/sys/kernel/security/tpm0/binary_bios_measurements` exists on this platform but
is **zero bytes**. The Azure Gen2 UEFI does not hand a TCG log to the guest, so
event-log replay cannot be exercised on an Azure vTPM at all. The replay code in
`cmcp_verify.tcg_event_log` is covered by synthetic logs, and validating it
against a real log needs a platform that publishes one, which in practice means
physical client hardware. `#433` tracks that.

## Not yet validated

- **TPM signature and certificate chain**: out of Phase 1 scope here. The
  sibling [ca2a](https://github.com/agentrust-io/ca2a) verifier does check the AK
  signature and has now done so against this same real quote.
- **NVIDIA GPU CC**: not implemented, planned for v0.2 via NRAS.
- **cMCP serving traffic from inside the TEE**: attestation collection and
  verification now run in situ on a CVM (above). A production gateway serving
  MCP traffic from inside the enclave, with the policy bundle measured at boot
  and TRACE Claims emitted per session, is still a separate milestone.
- **TCB appraisal**: TCB status and QE identity need Intel PCS collateral by
  FMSPC and are reported in `unverified_fields`. Do not read a `verified=True`
  TDX result as a full TCB appraisal.
