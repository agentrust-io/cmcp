# Verify a TRACE Claim

Use `cmcp_verify` to confirm that a TRACE claim produced by cMCP is cryptographically valid, bound to the approved policy and catalog, and backed by a fresh attestation.

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

`cmcp_verify` ships as part of `cmcp-runtime`. No separate install is needed:

```
from cmcp_verify import verify_trace_claim, ApprovedHashes
```

______________________________________________________________________

## Obtain the approved hashes

The approved hashes are the SHA-256 values printed by the gateway at startup:

```
[cmcp] policy bundle loaded: sha256:abc123...
[cmcp] catalog loaded: 3 tools, sha256:def456...
```

In production, these values come from your deployment pipeline: not from the operator. The point of verification is to confirm the runtime loaded what your organization approved, without trusting the operator's assertion. Store the hashes in your CI artifact registry or secrets manager at bundle-build time and retrieve them at verification time.

______________________________________________________________________

## Call verify_trace_claim

```
import json
from cmcp_verify import verify_trace_claim, ApprovedHashes

with open("claim.json") as f:
    claim = json.load(f)

approved = ApprovedHashes(
    policy_bundle_hash="sha256:abc123...",
    tool_catalog_hash="sha256:def456...",
)

result = verify_trace_claim(claim, approved)

print(f"Status:           {result.status.value}")
print(f"Verified fields:  {result.verified_fields}")
print(f"Unverified fields:{result.unverified_fields}")
print(f"Attestation age:  {result.attestation_age_seconds}s")
print(f"Attestation fresh:{result.is_attestation_fresh}")
if result.failure_reason:
    print(f"Failure reason:   {result.failure_reason}")
if result.details:
    print(f"Details:          {result.details}")
```

The function also accepts optional parameters:

```
result = verify_trace_claim(
    claim_json=claim,
    approved=approved,
    max_attestation_age_seconds=3600,       # default 86400; tighten for short-lived sessions
    trusted_public_key_hex="abcdef...",     # optional: cross-check against a pinned key
)
```

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

`partially_verified` means some checks passed and at least one failed. The most common reason in a correct deployment is that the gateway ran in software-only mode (`CMCP_DEV_MODE=1`): hardware attestation cannot be verified, but all cryptographic fields are valid.

Example output for a dev-mode claim:

```
Status:           partially_verified
Verified fields:  ['schema', 'signature', 'policy_bundle.hash', 'tool_catalog.hash', 'attestation_freshness', 'audit_chain']
Unverified fields:['hardware_attestation']
Attestation age:  8s
Attestation fresh:True
Details:          {'hardware_attestation': 'software-only mode - not hardware-backed'}
```

`hardware_attestation` is in `unverified_fields` but no `failure_reason` is set for it in isolation: the status rolls up to `partially_verified` because other fields were verified. On a real TEE host, `hardware_attestation` moves to `verified_fields` and status becomes `verified`.

`unverified` (with no verified fields at all) means the claim is either malformed, signature-invalid, or the hashes do not match. Treat this as a hard rejection.

______________________________________________________________________

## Integrate verification at job start

The right integration point is before your pipeline processes any agent output. Verify the TRACE claim at the start of the consuming job, before reading `tool_transcript` or acting on results:

```
import json
import sys
from cmcp_verify import verify_trace_claim, ApprovedHashes

def load_approved_hashes() -> ApprovedHashes:
    # Fetch from your secrets manager / artifact registry
    return ApprovedHashes(
        policy_bundle_hash=get_secret("cmcp/policy-bundle-hash"),
        tool_catalog_hash=get_secret("cmcp/catalog-hash"),
    )

def verify_session_claim(claim_path: str) -> None:
    with open(claim_path) as f:
        claim = json.load(f)

    result = verify_trace_claim(claim, load_approved_hashes())

    if result.status.value == "unverified":
        print(f"CLAIM REJECTED: {result.failure_reason}", file=sys.stderr)
        sys.exit(1)

    if result.status.value == "partially_verified":
        # Accept in staging; reject in production if hardware attestation is required
        if not result.is_attestation_fresh:
            print(f"CLAIM STALE: age={result.attestation_age_seconds}s", file=sys.stderr)
            sys.exit(1)
        print(f"WARNING: partially verified: {result.unverified_fields}")

    print(f"Claim verified. Tools called: {claim['gateway']['call_summary']['tools_invoked']}")
```

______________________________________________________________________

## Summary

You called `verify_trace_claim` with `ApprovedHashes` sourced from your deployment pipeline (not from the operator), read `VerificationResult` fields to distinguish full verification from partial (dev-mode) verification, and integrated the check at pipeline entry. A claim that returns `unverified` must be rejected before any downstream processing uses the session output.

Related tutorials: [Cedar policy walkthrough](https://cmcp.agentrust-io.com/docs/tutorials/cedar-policy-walkthrough/index.md): the policy bundle hash you verify here is the hash of the Cedar bundle loaded at runtime. [TEE attestation](https://cmcp.agentrust-io.com/docs/tutorials/tee-attestation/index.md): switching from software-only to a real TEE makes `hardware_attestation` move from `unverified_fields` to `verified_fields`.
