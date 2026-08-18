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
| Intel TDX (GCP C3, non-paravisor) | Yes | Yes, to the pinned Intel SGX Root CA | Yes | **Yes**, 2026-07-27, capture of 2026-07-21. DCAP quote path only; the TDREPORT path is unvalidated, see below |
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

What this run does not cover: the TDREPORT path. `verify_tdx_measurement()`
parses the 1024-byte TDREPORT_STRUCT returned by the `TDX_CMD_GET_REPORT0`
ioctl, which is a different artifact from the DCAP quote captured here, and no
real TDREPORT has been checked against it. #371 found both of its field offsets
wrong -- `MRTD` read from inside `REPORTMACSTRUCT.report_data` and `REPORTDATA`
read from the leading RESERVED block -- and #527 corrected them against the
published Intel TDX Module ABI. The correction is asserted against the ABI and
against a property no hardware is needed to state (a measurement must not move
when only the nonce moves), which is not the same as a capture. The row above
covers quote verification; read it as covering measurement provenance only once
a TDREPORT capture appears here.

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
pytest tests/unit/test_tpm_verify.py
```

The committed capture is loaded from
`tests/fixtures/hardware/azure-vtpm-2026-07-27` by default. Set
`CMCP_TPM_FIXTURE_DIR=<capture dir>` to replay a newly captured vector instead.

This run also surfaced an interop gap, fixed alongside it. The parser required
the outer `TPM2B_ATTEST` two-byte size prefix, but `tpm2_quote -m` writes a bare
`TPMS_ATTEST`, so every quote produced by the standard tooling was rejected with
`TPM2B_ATTEST size field invalid`. Both framings are now accepted, told apart by
the magic constant.

The AK signature is now verified (see the 2026-07-31 run below). The EK/AK
certificate chain remains in `unverified_fields`. **Corrected 2026-07-31.** An earlier run recorded that Azure's pre-provisioned AK
certificate carries no AIA extension and that its issuing intermediate is
therefore not fetchable. On a VM provisioned 2026-07-31 in eastus, the
certificate at vTPM NV index `0x01C101D0` is issued by
`CN=Azure Cloud Virtual TPM CA - 11`, not `CN=Global Virtual TPM CA - 03`, and it
does carry an AIA extension with four CA Issuers URIs. The intermediate was
fetched from the public CDN and verified to have signed the AK certificate. See
the certificate-chain section below.

**Corrected again 2026-08-01: this is fleet variance, not a migration.** The
2026-07-31 note above concluded that "Azure has changed its vTPM PKI", which
implies the old presentation is gone and AIA can be relied on going forward. That
is wrong. A VM provisioned 2026-08-01 (`Standard_D2s_v7`, eastus2) presented the
*old* form again:

| | 2026-07-31, `D2s_v5` eastus | 2026-08-01, `D2s_v7` eastus2 |
|---|---|---|
| Certificate size | 1596 bytes | **994 bytes** |
| Issuer | `Azure Cloud Virtual TPM CA - 11` | **`Global Virtual TPM CA - 03`** |
| AIA extension | present, 4 CA Issuers URIs | **absent entirely** |
| Chain to a pinnable root | yes | **no** |

Both hierarchies are live concurrently, so the correct planning assumption is that
**an Azure Trusted Launch host may present either, and AIA cannot be relied on.**
On the 2026-08-01 host `tpm2_getcap handles-nv-index` returned only `0x01C101D0`
(plus a test index), confirming the intermediates are not stored in NV as a
fallback. Chained verification against the root pinned in
`cmcp_verify/tpm_roots.py` is therefore impossible on such a host, and it fails
closed with "AK chain root is not among the supplied trusted TPM roots", which is
correct: key provenance genuinely cannot be established there.

Consequence for #431 and for any deployment: pinning the 2023 root does not make
Azure verify everywhere. A deployment must obtain and pin the root for the
hierarchy its own hosts present, and a fleet spanning both needs both.

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

Unlike the SEV-SNP captures, this vector **is committed**. It carries no per-CPU
hardware identifier: the AK public key belongs to a virtual TPM in a VM that no
longer exists, and the PCR values describe a stock Ubuntu image. Committing it
means the signature path is exercised on every PR rather than only when a fixture
directory is set.

**The vector now lives in agent-manifest**, alongside the code it validates: the
`TPMT_SIGNATURE` parse and both `TPMS_ATTEST` framings consolidated there in
agent-manifest 0.8.0, and cMCP imports them rather than carrying its own copies.
Keeping the evidence with the implementation is the point: a capture that
validates code in another repository drifts away from it. It runs on every
agent-manifest PR.

```
# in agent-manifest
pytest python/tests/test_tpm_hardware_vector.py
```

The provenance above is the record of how the capture was taken and stays here;
`tests/unit/test_tpm_quote_signature.py` still covers cMCP's own layer, which is
result shaping and fail-closed handling of blobs agent-manifest rejects.

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

## Gateway measurement NV extend index, Azure Trusted Launch vTPM, 2026-08-01

`Standard_D2s_v7`, Ubuntu 24.04, Trusted Launch with vTPM and secure boot, eastus2.
This validates `cmcp_runtime.tee.measurement` (#432, #451), whose TPM calls had
been written against the documented tpm2-pytss API without ever executing against
a TPM. All of them work:

- `nv_define_space(None, nv_public, auth_handle=ESYS_TR.OWNER)` created the index,
  and `TPMA_NV.parse("ownerwrite|ownerread|authread|no_da") | (TPM2_NT.EXTEND << 4)`
  produced the intended attributes. Reading the public area back gave
  `TPM_NT = 4`, confirming a genuine `TPM_NT_EXTEND` index rather than an
  ordinary one. `tpm2_getcap handles-nv-index` listed `0x01500432` at size 32.
- `nv_extend(handle, digest, auth_handle=ESYS_TR.OWNER)` extended it. First call
  reported `provisioned=True`, second `provisioned=False`, so an existing index is
  reused rather than redefined, which matters because redefining each boot would
  hand an adversary the reset the design exists to prevent.
- The extend semantics the security argument rests on hold on hardware: after the
  second extend, `before` equalled the first `after`, the value moved, and both
  extends satisfied `after == H(before || digest)`.
- **A plain `nv_write` to the index was refused by the TPM.** This is the
  load-bearing check: it is what makes an adversary unable to write a chosen clean
  value, and it is confirmed independently by the `TPM_NT` field above rather than
  only by an exception.

Not covered by this run: the index value still travels as an ordinary NV read,
which no signature covers, so it is a local integrity control and not yet
remote-verifiable evidence. `TPM2_NV_Certify` is the remaining half of #432.

## TPM2_NV_Certify for the gateway measurement, Azure Trusted Launch vTPM, 2026-08-01

`Standard_D2s_v7`, eastus2. Validates the signed half of #432 (#459, corrected by
#461). This run **found two defects in code that had already merged**, which is the
argument for running it.

**Defect 1: the call was wrong and could never have worked.** `ESAPI.nv_certify`
takes `in_scheme` (a `TPMT_SIG_SCHEME`) and `size` as *required positional*
arguments. The shipped call omitted both, so it raised `TypeError` before reaching
the TPM. The unit tests passed because the fake accepted any signature.

**Defect 2: a freshly provisioned index cannot be certified at all.** A newly
defined `TPM_NT_EXTEND` index is uninitialised, and `TPM2_NV_Certify` on it fails
with `TPM_RC_NV_UNINITIALIZED`. So on a first gateway start there was no pre-value
to certify. Fixed by seeding the index once at provision time, which keeps the
verifier's `post == H(pre || digest)` check free of a first-boot special case.

With both fixed, the following hold on hardware:

- `nv_certify(sign_handle, nv_index, qualifying_data, TPMT_SIG_SCHEME(NULL), 32, 0,
  auth_handle=ESYS_TR.OWNER)` returns a 173-byte attest and a 262-byte
  `TPMT_SIGNATURE`. A NULL scheme resolves to the key's own, RSASSA/SHA-256 here.
- **The platform AK at `0x81000003` can sign an NV certify.** This was an open
  question, since it is a restricted signing key; the answer is yes.
- **`parse_nv_certify`'s field offsets are correct against a real blob.** This was
  the highest-risk item, as the offsets came from the TCG structures spec and had
  never met real bytes. `indexName`, `offset` and `nvContents` all parse, and
  `nvContents` equals the value returned by `TPM2_NV_Read`.
- The extend relation holds on hardware across two consecutive starts: run 1
  provisioned the index and run 2 reused it, with run 2's `pre` equal to run 1's
  `post`, which is the accumulation the two-certify design exists to handle.
- `verify_gateway_measurement` passes all seven appraisal steps, and rejects both a
  wrong expected digest (`gateway_digest_mismatch`) and a replayed nonce
  (`pre_binding_mismatch`) on genuine evidence.

One limit on this run: the VM drew the `Global Virtual TPM CA - 03` hierarchy, whose
AK certificate has no AIA, so the chain is the leaf alone. The verification above
was therefore anchored on the leaf itself, which exercises the verifier's plumbing
but proves **no key provenance**. Chained verification against a vendor root still
needs a host of the other hierarchy, or the root from #453.

## Not yet validated

- **TPM certificate chain on every Azure host**: the AK signature is verified, and
  the sibling [ca2a](https://github.com/agentrust-io/ca2a) verifier has done so
  against real quotes. Chaining that key to a pinned root is **host-dependent**:
  see the fleet-variance correction above, where a host presenting the
  `Global Virtual TPM CA - 03` hierarchy with no AIA extension cannot produce a
  chain at all.
- **The NV certify pair against a real vendor-rooted chain**: the 2026-08-01 run
  anchored on the leaf because that host presented the no-AIA hierarchy, so key
  provenance for the certifying key is still unproven on Azure (#453).
- **NVIDIA GPU CC**: not implemented, planned for v0.2 via NRAS.
- **cMCP serving traffic from inside the TEE**: attestation collection and
  verification now run in situ on a CVM (above). A production gateway serving
  MCP traffic from inside the enclave, with the policy bundle measured at boot
  and TRACE Claims emitted per session, is still a separate milestone.
- **TCB appraisal**: TCB status and QE identity need Intel PCS collateral by
  FMSPC and are reported in `unverified_fields`. Do not read a `verified=True`
  TDX result as a full TCB appraisal.
