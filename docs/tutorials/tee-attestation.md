# TEE Attestation

Deploy cMCP on real Trusted Execution Environment hardware so TRACE claims carry hardware-backed measurements instead of software-only placeholders.

## What you'll learn

- The valid `CMCP_TEE_PROVIDER` values and what each one requires
- What hardware attestation actually proves (and what it does not)
- What changes in the TRACE record when you switch from software-only to real hardware
- AMD SEV-SNP setup: the attestation report path and what the measurement covers
- When to use software-only versus a production TEE

## Prerequisites

```bash
pip install cmcp-runtime
```

For AMD SEV-SNP: an Azure DCasv5 VM or any host running a kernel with `/dev/sev-guest`.
For Intel TDX: an Azure DCedsv5 VM or any host with a TDX-capable processor.

---

## Understand the provider values

The `provider` field in `cmcp-config.yaml` controls which TEE the runtime uses. Valid values (from the startup source):

| `provider` value | What it requires |
|---|---|
| `auto` | Probes in order: `tpm`, `sev-snp`, `tdx`. Falls back to `software-only` only when `CMCP_DEV_MODE=1` is set. |
| `tpm` | TPM 2.0 chip present and accessible. |
| `sev-snp` | AMD SEV-SNP hardware. Requires `/dev/sev-guest` (device path is hardcoded; no env var override). |
| `tdx` | Intel TDX hardware. |
| `opaque` | OPAQUE Managed Runtime. Requires `OPAQUE_ATTESTATION_URL` env var. |
| `software-only` | No hardware. Requires `CMCP_DEV_MODE=1`. |

`software-only` is rejected at startup unless `CMCP_DEV_MODE=1` is set. Do not set `CMCP_DEV_MODE=1` in production.

---

## Understand what hardware attestation proves

When the runtime starts on real TEE hardware, the TEE produces an attestation report. This report:

- Is signed by hardware-resident keys that the operator cannot access
- Contains a measurement of the workload: a hash of the code and configuration loaded into the enclave
- Commits a runtime-supplied nonce (which includes the Ed25519 signing key fingerprint) into the report, binding the report to the specific key that will sign TRACE claims

What this proves: the measurement in the TRACE claim was produced by a known workload running on the reported hardware platform. A verifier who trusts the hardware vendor's root certificates can confirm that no operator intervention occurred between enclave load and attestation.

What this does not prove: the contents of individual tool call arguments or responses are not measured by the TEE. The TEE measures the workload binary and its startup configuration. Per-call evidence lives in the audit chain (hashed and chained by the workload), not in the TEE hardware report.

---

## Compare Level 0 (software-only) to Level 1+

In `software-only` mode:

- `trace.runtime.platform` is `"software-only"` (or `"tpm2"` with the dev firmware sentinel on older builds)
- `trace.runtime.measurement` is all zeros: `sha256:0000000000000000000000000000000000000000000000000000000000000000`
- `verify_trace_claim` returns `status: "partially_verified"` with `hardware_attestation` in `unverified_fields`

On a real TEE host:

- `trace.runtime.platform` reflects the hardware: `"amd-sev-snp"`, `"tpm2"`, `"intel-tdx"`, etc.
- `trace.runtime.measurement` is the real hardware measurement: a non-zero hash specific to the loaded workload
- `verify_trace_claim` returns `status: "verified"` with `hardware_attestation` in `verified_fields`

The measurement value is deterministic for a given workload binary and startup config. If the workload binary changes (e.g., an update to `cmcp-runtime`) the measurement changes, and verifiers who pinned the previous measurement will see a mismatch.

---

## Set up AMD SEV-SNP

On an AMD SEV-SNP VM (Azure DCasv5 or equivalent):

1. Confirm the device is present:

```bash
ls -la /dev/sev-guest
```

2. Set the provider in `cmcp-config.yaml`:

```yaml
attestation:
  provider: sev-snp
  enforcement_mode: enforcing
  validity_seconds: 86400
  staleness_policy: fail_closed
```

3. Set the required production env vars before starting:

```bash
export CMCP_BEARER_TOKEN="$(openssl rand -hex 32)"
export CMCP_POLICY_HASH="sha256:<bundle hash>"
export CMCP_CATALOG_HASH="sha256:<catalog hash>"
cmcp start --config cmcp-config.yaml
```

At startup the runtime calls `get_attestation_report(nonce)` where the nonce encodes the signing key fingerprint in its first 32 bytes. The SEV-SNP hardware commits this nonce into the attestation report's `REPORT_DATA` field. The TRACE claim carries this nonce as `trace.runtime.nonce`. Verifiers re-derive the key fingerprint from `trace.cnf.jwk.x` and compare against `nonce[:32]` to confirm the signing key is bound to this specific attestation report.

---

## Read the changed TRACE fields

After switching from software-only to SEV-SNP, the TRACE claim shows:

```json
{
  "trace": {
    "runtime": {
      "platform": "amd-sev-snp",
      "measurement": "sha384:7f3c9a1b2e4d8f6a0c5b7e9d3f1a4c8b2e6f0d4a8c1b3e5f7a9d2c4e6f8a0b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
      "firmware_version": "1.51.00",
      "nonce": "<base64url 64-byte nonce>"
    }
  }
}
```

`measurement` is the value the SEV-SNP hardware measures at enclave load. Pin this value in `attestation.expected_measurement` to reject unknown workload versions at startup:

```yaml
attestation:
  provider: sev-snp
  enforcement_mode: enforcing
  expected_measurement: "sha384:7f3c9a1b2e4d8f6a0c5b7e9d3f1a4c8b2e6f0d4a8c1b3e5f7a9d2c4e6f8a0b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
```

If the deployed binary differs from the expected measurement, the runtime exits at startup rather than producing claims with an unexpected measurement.

---

## Choose between software-only and a production TEE

Use `software-only` when:
- Running locally during development
- Running CI tests that do not have access to TEE hardware
- Evaluating policy logic before deploying to hardware

Use a real TEE in production when:
- Consumers of TRACE claims need hardware-backed evidence (compliance requirements, contractual obligations, regulated data)
- You need the signing key bound to the hardware report (CRYPTO-001 check in `verify_trace_claim`)
- You are protecting against threat classes T1-T4 as defined in the threat model (operator tampering, policy substitution, catalog substitution, key substitution)

Software-only mode leaves all four threat classes open. The audit chain and policy hash checks still run and provide evidence, but nothing prevents an operator from restarting the runtime with a different policy bundle and a different key.

---

## Summary

You configured cMCP for AMD SEV-SNP, confirmed the `trace.runtime.platform` and `trace.runtime.measurement` fields reflect real hardware values, and pinned the expected measurement in config. On a real TEE host, `verify_trace_claim` returns `status: "verified"` with `hardware_attestation` in `verified_fields`, providing hardware-backed assurance that the workload was not tampered with.

Related tutorials: [Verify a TRACE claim](./verifying-a-trace-claim.md): hardware attestation is one of the verification steps that determines overall status. [Multi-tenant deployment](./multi-tenant-config.md): each tenant's policy bundle hash is separate; the hardware measurement is shared across tenants on the same host.
