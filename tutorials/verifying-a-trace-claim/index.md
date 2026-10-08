# Verify a TRACE Claim

This page is for whoever has to decide whether to trust what an agent did, such as an auditor or the next job in a pipeline. cMCP signs a record of each session, called a TRACE claim, and the `cmcp_verify` library checks it: that the signature is genuine, that the policy and tool list it names are the ones you approved, and that its hardware report (attestation) is recent. You get a clear verdict and a small script that refuses unverified records.

## What you'll learn

- How to install and call `verify_trace_claim`
- What `ApprovedHashes` fields are and where the values come from
- What each field in `VerificationResult` means
- The difference between `verified`, `partially_verified`, and `unverified`
- Where to integrate verification in a pipeline that consumes agent output

## Prerequisites

```
pip install cmcp-runtime   # includes cmcp_verify
```

______________________________________________________________________

## Install the verify library

`cmcp_verify` comes with `cmcp-runtime`, so there is nothing extra to install:

```
from cmcp_verify import verify_trace_claim, ApprovedHashes
```

______________________________________________________________________

## Obtain the approved hashes

To check a claim you need the fingerprints (hashes) of the policy and catalog you approved, and they must come from a source you trust. The [quickstart](https://cmcp.agentrust-io.com/quickstart/#confirm-your-setup) computes them from the local files before the gateway starts. The gateway's own logs print them too, but a log line from the gateway does not show that anyone approved those values:

```
[cmcp] policy bundle loaded: sha256:abc123...
[cmcp] catalog loaded: 3 tools, sha256:def456...
```

In production, take these values from your deployment pipeline, never from the operator. The whole point is to confirm the gateway loaded what your organisation approved without taking the operator's word for it. Save the hashes in your build system's artifact store or secrets manager when the policy is built, and read them back when you check a claim.

______________________________________________________________________

## Call verify_trace_claim

Save this as `inspect_claim.py` beside the quickstart's `claim.json` and `approved-hashes.json`, then run `python inspect_claim.py`:

```
import json
from pathlib import Path
from cmcp_verify import verify_trace_claim, ApprovedHashes

claim = json.loads(Path("claim.json").read_text())
hashes = json.loads(Path("approved-hashes.json").read_text())
approved = ApprovedHashes(**hashes)
result = verify_trace_claim(claim, approved)

print(f"Status: {result.status.value}")
print(f"Verified fields: {result.verified_fields}")
print(f"Unverified fields: {result.unverified_fields}")
print(f"Details: {result.details}")
```

This script only prints the result; it does not accept or reject anything. On the software quickstart it should report `partially_verified`. If a job must refuse output that lacks evidence, use the example at the end of this page.

The function also takes optional parameters, sketched below. Replace the key placeholder with a key you have approved before running it:

```
result = verify_trace_claim(
    claim_json=claim,
    approved=approved,
    max_attestation_age_seconds=3600,       # default 86400; tighten for short-lived sessions
    trusted_public_key_hex="abcdef...",     # optional: cross-check against a pinned key
)
```

______________________________________________________________________

## Verify a TPM claim from the CLI

For a claim from a TPM 2.0 chip (the security chip in many servers and VMs), supply the certificate authority certificates you trust for that chip's attestation keys:

```
cmcp verify claim.json \
  --policy-hash sha256:abc123... \
  --catalog-hash sha256:def456... \
  --trusted-tpm-ca /etc/cmcp/trust/tpm-ca-roots.pem
```

The PEM file may hold one or more certificates you have approved. Keep it in a store you control, and never take it from the claim or from the gateway that made the claim. The certificates are one input to the TPM check; the claim still has to carry the signed TPM report (quote) and the attestation-key evidence.

`--trusted-tpm-ca` applies to TPM only, on purpose. It does not set the trusted roots for AMD SEV-SNP or Intel TDX, and it does not change how claims from those platforms are checked.

______________________________________________________________________

## Read the VerificationResult

`VerificationResult` has these fields:

| Field                     | Type                        | Description                                                             |
| ------------------------- | --------------------------- | ----------------------------------------------------------------------- |
| `status`                  | `VerificationStatus`        | Overall result: `"verified"`, `"partially_verified"`, or `"unverified"` |
| `verified_fields`         | `list[str]`                 | Fields that passed their checks                                         |
| `unverified_fields`       | `list[str]`                 | Fields that failed or could not be checked                              |
| `failure_reason`          | `VerificationError \| None` | First failure code, or `None` on full verification                      |
| `attestation_age_seconds` | `int`                       | Seconds since the attestation report was generated                      |
| `is_attestation_fresh`    | `bool`                      | `True` if `attestation_age_seconds <= max_attestation_age_seconds`      |
| `details`                 | `dict[str, str]`            | Structured detail for individual check failures                         |

`verified_fields` can include: `schema`, `signature`, `public_key_binding`, `policy_bundle.hash`, `tool_catalog.hash`, `attestation_freshness`, `audit_chain`, `hardware_attestation`, `trusted_public_key`.

______________________________________________________________________

## Understand partially_verified

`partially_verified` means some checks passed and at least one did not. In a correctly set up test, the usual reason is that the gateway ran in software-only mode (`CMCP_DEV_MODE=1`): there is no hardware report to check, but the signatures and fingerprints are all valid.

Example output for a dev-mode claim:

```
Status:           partially_verified
Verified fields:  ['schema', 'signature', 'policy_bundle.hash', 'tool_catalog.hash', 'attestation_freshness', 'audit_chain']
Unverified fields:['hardware_attestation']
Attestation age:  8s
Attestation fresh:True
Details:          {'hardware_attestation': 'software-only mode - not hardware-backed'}
```

`hardware_attestation` is listed in `unverified_fields`, with no `failure_reason` of its own, and the overall result is `partially_verified` because the other fields passed. A hardware deployment reaches `verified` only when all the required checks pass; just running the gateway on protected hardware (a TEE) is not enough.

`unverified` (no fields verified at all) means the claim is badly formed, its signature is wrong, or the fingerprints do not match. Always reject it.

______________________________________________________________________

## Integrate verification at job start

If a job that uses the agent's output needs fully verified evidence, it must reject **every** other result before it touches that output. `partially_verified` can hide failures other than missing hardware, and a recent timestamp on its own is not a reason to accept.

Save the following as `accept_claim.py`. It uses the same two files as the earlier script. Deliver `approved-hashes.json` through a channel your deployment trusts. This script accepts or rejects; if your deployment needs extra trusted inputs for its hardware platform, pass them when calling the verifier.

```
import json
from pathlib import Path
from cmcp_verify import verify_trace_claim, ApprovedHashes


def verify_session_claim(claim_path, approved_path):
    claim = json.loads(Path(claim_path).read_text())
    hashes = json.loads(Path(approved_path).read_text())
    result = verify_trace_claim(claim, ApprovedHashes(**hashes))
    if result.status.value != "verified":
        raise SystemExit(
            f"CLAIM REJECTED: {result.status.value}; "
            f"failed or unchecked: {result.unverified_fields}"
        )
    return claim


if __name__ == "__main__":
    claim = verify_session_claim("claim.json", "approved-hashes.json")
    print(f"Claim verified. Tools called: {claim['gateway']['call_summary']['tools_invoked']}")
```

Run `python accept_claim.py`. On the software quickstart record it must fail with a nonzero exit and `CLAIM REJECTED: partially_verified`. If a development setup is allowed to accept software-only evidence, write that down as its own, narrower acceptance rule, and keep the difference visible in its output.

Next: [Cedar policy walkthrough](https://cmcp.agentrust-io.com/tutorials/cedar-policy-walkthrough/index.md), [TEE attestation](https://cmcp.agentrust-io.com/tutorials/tee-attestation/index.md), and [verification library reference](https://cmcp.agentrust-io.com/spec/verification-library/index.md).
