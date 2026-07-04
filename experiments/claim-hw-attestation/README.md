# Hardware TEE attestation experiment

This is the one experiment that needs real confidential-computing hardware. Every
other experiment in `experiments/` runs in software-only mode and produces TRACE
Claims with `attestation_assurance: none`. This one exercises the real path:
a genuine attestation report from the TEE, bound to the gateway key, wrapped in a
signed TRACE Claim, and checked by the verifier.

`run.py` is safe to run anywhere. On a host with no TEE it prints `SKIP` and exits
0, so it never breaks CI or a laptop. The properties below can only be observed on
real hardware.

## What it checks

| # | Property | Hardware-only |
|---|----------|---------------|
| P1 | A real provider is detected (sev-snp / tdx / tpm), not software-only | yes |
| P2 | `report.report_data` equals the nonce the gateway supplied | yes |
| P3 | The measurement is a real value, not the dev-mode placeholder | yes |
| P4 | A different nonce yields different `report_data` (freshness) | yes |
| P5 | The provider-specific verifier accepts the raw hardware evidence | yes |
| P6 | A full TRACE Claim verifies end to end (schema, signature, key binding) | yes |

## Hardware you need

Any one of:

| Platform | Azure | GCP |
|----------|-------|-----|
| AMD SEV-SNP | `Standard_DC2as_v5` (DCasv5) | `n2d-standard-4` + `--confidential-compute-type=SEV_SNP` |
| Intel TDX | `Standard_DC2es_v6` (DCesv6) | `c3-standard-4` + `--confidential-compute-type=TDX` |
| TPM 2.0 | any Trusted Launch VM | any VM with vTPM |

The repo's deploy scripts provision these directly:

```bash
# Azure (SEV-SNP by default; pass tdx to switch)
scripts/deploy-azure.sh

# GCP
scripts/deploy-gcp.sh
```

See `docs/tutorials/deploy-azure.md` and `docs/tutorials/deploy-gcp.md` for the
full walkthrough.

## Run it on the VM

```bash
# 1. SSH into the confidential VM provisioned above.
# 2. Install cMCP.
pip install -e .

# 3. (optional) Pin the provider explicitly instead of auto-detect.
export CMCP_DEV_MODE=          # must be UNSET so software-only fallback is disabled
# either rely on auto-detection, or set provider in cmcp-config.yaml:
#   attestation:
#     provider: sev-snp        # or tdx / tpm
#     expected_measurement: "sha256:<golden>"   # optional, enables HW-002 check

# 4. Run the experiment.
python experiments/claim-hw-attestation/run.py
```

Expected output on a SEV-SNP VM (abridged):

```
P1  Hardware provider detected
  Provider: sev-snp
  PASS: a hardware TEE provider is active (not software-only)
P2  Report binds the gateway-supplied nonce
  report_data == nonce -- report is bound to this gateway key
...
P6  Full TRACE Claim verifies end to end
  PASS: schema + signature verify; claim is bound to the TEE key
```

## What is NOT covered yet (needs the vendor services, not just hardware)

P5 verifies report format, measurement, and the nonce binding. It does **not** yet
verify the cert chain that proves the report was signed by genuine TEE silicon.
Those appear under `unverified_fields` until the following are wired into
`cmcp_verify`:

- **AMD SEV-SNP:** VCEK/VLEK cert-chain validation via AMD KDS
  (`src/cmcp_verify/sev_snp.py`)
- **Intel TDX:** DCAP quote signature + TCB status
  (`src/cmcp_verify/tdx.py`)
- **TPM:** EK certificate chain to the manufacturer CA
  (`src/cmcp_verify/tpm.py`)

These require the vendor endpoints (and, for development, real reports to test
against), so they are the last step and are tracked separately from this runner.
