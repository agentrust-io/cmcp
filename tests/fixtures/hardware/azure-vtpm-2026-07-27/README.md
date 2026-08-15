# Azure vTPM quote capture, 2026-07-27

A genuine TPM 2.0 quote from an Azure Trusted Launch VM, captured to close the
last synthetic-only attestation path in cmcp, ca2a and agent-manifest.

## Capture

- VM: `Standard_D2s_v7`, Ubuntu 24.04, eastus2, Trusted Launch with vTPM and
  secure boot enabled. Resource group `ca2a-tpm-capture`, deleted immediately
  after the capture.
- Device: `/dev/tpm0` (vTPM, Hyper-V backed).
- AK: created in-guest with `tpm2_createak -C ek.ctx -G rsa -g sha256 -s rsassa`.
- Quote: `tpm2_quote -c ak.ctx -l sha256:0,1,2,3,4,5,6,7 -q <nonce> -g sha256 -f plain`
  with a fresh 32-byte random nonce.

## Files

| File | What it is |
|---|---|
| `quote.msg` | The `TPMS_ATTEST` blob, 145 bytes |
| `quote.sig` | Raw RSA PKCS#1 v1.5 signature over it, 256 bytes |
| `ak.pub` | The AK public key (PEM) that signed the quote |
| `nonce.hex` | The 32-byte qualifying data supplied to the quote |
| `pcrs.bin` | The PCR values the digest was computed over |
| `akcert_0x01C101D0.der` | Azure's pre-provisioned AK certificate, read from vTPM NV |

## What this validates

Run against `ca2a_verify.tpm` / `cmcp_verify` / `agent_manifest`:

- `TPMS_ATTEST` parsing against a real blob: magic is `0xFF544347`
  (`TPM_GENERATED`), attest type is `0x8018` (`TPM_ST_ATTEST_QUOTE`).
- Qualifying-data binding: the parsed value equals the nonce byte for byte, so
  the verifier's freshness check works on real evidence.
- PCR-digest binding: the parsed digest equals
  `461684441feb67717a22b7f43096ec2f92a6582f5987f82729b3749180fede61`, which is
  the `calcDigest` the TPM itself reported at quote time.
- AK signature: the quote signature verifies against `ak.pub` under RSA PKCS#1
  v1.5 with SHA-256, and a single flipped bit in the attest blob is rejected.

## What this does NOT validate, and why

**The AK certificate chain.** Two separate reasons, both worth stating:

1. `akcert_0x01C101D0.der` certifies Azure's **pre-provisioned** AK, not the AK
   created in-guest for this quote. It is a real Microsoft-issued certificate
   (subject `CN=f859864a6a31.TrustedVM.Azure.windows.net`, issuer
   `CN=Global Virtual TPM CA - 03`), but it covers a different key, so the
   quote's signature does not verify against it. Passing it to the verifier
   fails, correctly. To get a quote signed by the certified AK, use Azure's
   pre-provisioned AK persistent handle instead of `tpm2_createak`.
2. The AK certificate carries **no AIA extension**, so the issuing intermediate
   (`Global Virtual TPM CA - 03`) is not fetchable from the certificate itself
   and Microsoft does not distribute it alongside. Chain-to-vendor-root is
   therefore not exercised even with the right AK.

This is precisely why the TPM verifier takes caller-supplied trust roots rather
than pinning one, unlike SEV-SNP (AMD ARK) and TDX (Intel SGX Root CA). The
shared `verify_cert_chain` those two use is the same code path, and it is
exercised against real vendor roots there.

**A discrete hardware TPM.** This is a Hyper-V vTPM. It validates the vTPM path,
which is what Azure confidential and Trusted Launch VMs actually present, not a
discrete TPM chip.

## Reproducing

```
CA2A_TPM_FIXTURE_DIR=<this dir> pytest tests/unit/test_tpm.py       # ca2a
CMCP_TPM_FIXTURE_DIR=<this dir> pytest tests/unit/test_tpm_verify.py  # cmcp
```
