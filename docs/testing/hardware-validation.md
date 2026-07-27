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
| AMD SEV-SNP (Azure CVM, vTPM-rooted) | Yes | Yes, to the real AMD ARK-Milan root | Yes | **Yes**, 2026-07-27, capture of 2026-07-20 |
| Intel TDX (GCP C3, non-paravisor) | Yes | Yes, to the pinned Intel SGX Root CA | Yes | **Yes**, 2026-07-27, capture of 2026-07-21 |
| TPM 2.0 | Yes | Yes, to a caller-supplied vendor root | Yes | No. Synthetic vectors only |
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

## Not yet validated

- **TPM 2.0**: the verifier is implemented and synthetic-vector validated. It
  needs a real AK-signed quote plus a vendor AK certificate chain.
- **NVIDIA GPU CC**: not implemented, planned for v0.2 via NRAS.
- **cMCP running inside the TEE end to end**: these runs validate the verifier
  against real evidence. A production gateway serving traffic from inside a CVM,
  emitting TRACE Claims with live attestation, is a separate milestone.
- **TCB appraisal**: TCB status and QE identity need Intel PCS collateral by
  FMSPC and are reported in `unverified_fields`. Do not read a `verified=True`
  TDX result as a full TCB appraisal.
