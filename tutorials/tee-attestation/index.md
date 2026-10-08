# TEE Attestation

This page is for operators moving cMCP from a laptop demo to protected hardware. A TEE (trusted execution environment) is a sealed-off area of a processor that the machine's owner cannot read or change, and it can produce a signed report, called an attestation, of exactly what software started inside it. Running cMCP in one means each signed session record (TRACE claim) carries that hardware report instead of a placeholder, and this page explains what that does and does not prove.

## What you'll learn

- The valid `CMCP_TEE_PROVIDER` values and what each one requires
- What hardware attestation actually proves (and what it does not)
- What changes in the TRACE record when you switch from software-only to real hardware
- AMD SEV-SNP setup: the attestation report path and what the measurement covers
- When to use software-only versus a production TEE

## Prerequisites

```
pip install cmcp-runtime
```

For AMD SEV-SNP: an Azure DCasv5 VM or any host running a kernel with `/dev/sev-guest`. For Intel TDX: an Azure DCedsv5 VM or any host with a TDX-capable processor.

______________________________________________________________________

## Understand the provider values

The `provider` field in `cmcp-config.yaml` sets which kind of protected hardware cMCP uses. The accepted values, taken from the startup code:

| `provider` value | What it requires                                                                                            |
| ---------------- | ----------------------------------------------------------------------------------------------------------- |
| `auto`           | Probes in order: `tpm`, `sev-snp`, `tdx`. Falls back to `software-only` only when `CMCP_DEV_MODE=1` is set. |
| `tpm`            | TPM 2.0 chip present and accessible.                                                                        |
| `sev-snp`        | AMD SEV-SNP hardware. Requires `/dev/sev-guest` (device path is hardcoded; no env var override).            |
| `tdx`            | Intel TDX hardware.                                                                                         |
| `software-only`  | No hardware. Requires `CMCP_DEV_MODE=1`.                                                                    |

cMCP refuses to start with `software-only` unless `CMCP_DEV_MODE=1` is set. Never set `CMCP_DEV_MODE=1` in production.

______________________________________________________________________

## Understand what hardware attestation proves

When cMCP starts on real TEE hardware, the processor produces an attestation report. The report:

- Is signed by keys built into the hardware, which the operator cannot get at
- Contains a measurement: a fingerprint (hash) of the code and configuration that were loaded
- Names the key cMCP will use to sign its TRACE claims, so the claims can be tied back to this report

What this proves: the measurement in the TRACE claim came from a known piece of software running on the hardware named in the report. Someone who trusts the chip maker's root certificates can confirm that the operator did not interfere between start-up and the report.

What this does not prove: the hardware does not measure the contents of individual tool calls or responses. It measures the software and its start-up configuration. Evidence about each call lives in the audit chain (the gateway's linked, fingerprinted log), not in the hardware report.

Technical detail: how the signing key is bound

The runtime supplies a nonce that includes the Ed25519 signing key fingerprint, and the hardware commits that nonce into the report, binding the report to the specific key that will sign TRACE claims.

______________________________________________________________________

## Compare Level 0 (software-only) to Level 1+

In `software-only` mode:

- `trace.runtime.platform` is `"software-only"` (or `"tpm2"` with the dev firmware sentinel on older builds)
- `trace.runtime.measurement` is all zeros: `sha256:0000000000000000000000000000000000000000000000000000000000000000`
- `verify_trace_claim` returns `status: "partially_verified"` with `hardware_attestation` in `unverified_fields`

On a real TEE host:

- `trace.runtime.platform` reflects the hardware: `"amd-sev-snp"`, `"tpm2"`, `"intel-tdx"`, etc.
- `trace.runtime.measurement` is the real hardware measurement: a non-zero hash specific to the loaded workload
- `verify_trace_claim` returns `status: "verified"` with `hardware_attestation` in `verified_fields`

The same software and start-up config always give the same measurement. If the software changes (for example, an update to `cmcp-runtime`), the measurement changes, and anyone who pinned the old value will see a mismatch.

______________________________________________________________________

## Set up AMD SEV-SNP

On an AMD SEV-SNP VM (Azure DCasv5 or equivalent):

1. Confirm the device is present:

```
ls -la /dev/sev-guest
```

1. Set the provider in `cmcp-config.yaml`:

```
attestation:
  provider: sev-snp
  enforcement_mode: enforcing
  validity_seconds: 86400
  staleness_policy: fail_closed
```

1. Set the required production env vars before starting:

```
export CMCP_BEARER_TOKEN="$(openssl rand -hex 32)"
export CMCP_POLICY_HASH="sha256:<bundle hash>"
export CMCP_CATALOG_HASH="sha256:<catalog hash>"
cmcp start --config cmcp-config.yaml
```

At start-up cMCP asks the hardware for a report that includes a fingerprint of its signing key, so a checker can later confirm that the key which signed the claims belongs to this report.

Technical detail: the SEV-SNP nonce

At startup the runtime calls `get_attestation_report(nonce)` where the nonce encodes the signing key fingerprint in its first 32 bytes. The SEV-SNP hardware commits this nonce into the attestation report's `REPORT_DATA` field. The TRACE claim carries this nonce as `trace.runtime.nonce`. Verifiers re-derive the key fingerprint from `trace.cnf.jwk.x` and compare against `nonce[:32]` to confirm the signing key is bound to this specific attestation report.

______________________________________________________________________

## Read the changed TRACE fields

After switching from software-only to SEV-SNP, the TRACE claim shows:

```
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

`measurement` is the fingerprint the SEV-SNP hardware takes when cMCP starts. Write it into `attestation.expected_measurement` and cMCP will refuse to start as any other version:

```
attestation:
  provider: sev-snp
  enforcement_mode: enforcing
  expected_measurement: "sha384:7f3c9a1b2e4d8f6a0c5b7e9d3f1a4c8b2e6f0d4a8c1b3e5f7a9d2c4e6f8a0b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
```

If the deployed software does not match, cMCP stops at start-up instead of signing claims with a measurement you did not expect.

______________________________________________________________________

## Choose between software-only and a production TEE

Use `software-only` when:

- Running locally during development
- Running CI tests that do not have access to TEE hardware
- Evaluating policy logic before deploying to hardware

Use a real TEE in production when:

- Whoever relies on your TRACE claims needs evidence backed by hardware (compliance rules, contracts, regulated data)
- You need the signing key tied to the hardware report (the CRYPTO-001 check in `verify_trace_claim`)
- You need protection against threats T1 to T4 in the threat model: the operator tampering with the gateway, or swapping its policy, its tool catalog or its signing key

Software-only mode leaves all four of those open. The log and policy fingerprint checks still run and still produce evidence, but nothing stops an operator from restarting cMCP with different rules and a different key.

______________________________________________________________________

## Summary

You configured cMCP for AMD SEV-SNP, confirmed that `trace.runtime.platform` and `trace.runtime.measurement` show real hardware values, and pinned the expected measurement in the config. On a real TEE host, `verify_trace_claim` returns `status: "verified"` with `hardware_attestation` in `verified_fields`: the hardware vouches that the software was the version you expected.

Related tutorials: [Verify a TRACE claim](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/index.md) shows where the hardware check fits in the overall result, and in a [multi-tenant deployment](https://cmcp.agentrust-io.com/tutorials/multi-tenant-config/index.md) each tenant has its own policy fingerprint while tenants on the same host share the hardware measurement.
