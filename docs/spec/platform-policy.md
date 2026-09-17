# Explicit SNP platform requirements

A signed report establishes authenticity. A relying party must separately decide
which reported platform settings it accepts. The Python verifier can enforce
that choice for native AMD SEV-SNP and Azure vTPM-rooted SEV-SNP evidence:

```python
from cmcp_verify import SnpPlatformPolicy, verify_trace_claim

platform_policy = SnpPlatformPolicy(
    require=frozenset({
        "ciphertext_hiding_dram_enabled",
        "alias_check_complete",
    }),
    forbid=frozenset({"smt_enabled"}),
    reject_unrecognized_bits=True,
)
result = verify_trace_claim(
    claim,
    approved,
    trusted_ark_pem=pinned_amd_root,
    snp_platform_policy=platform_policy,
)
```

This example is an explicit policy choice, not a universal safe-platform profile.
It may reject available hardware. Do not weaken it merely to obtain a passing
result without reconsidering the adversary model. `require` names fields that
must be true; `forbid` names fields that must be false. Supported field names
are those of `agent_manifest.PLATFORM_INFO_BITS`. Unknown names, contradictory
requirements, and malformed policy values are configuration errors.

The policy belongs to the verifier. Do not deserialize it from untrusted claim
content and treat it as the relying party's decision. It is immutable after
construction, including when initialized from a mutable set.

## Acceptance and rejection

The verifier checks the pinned chain and report signature before appraising the
signed `PLATFORM_INFO` word. The native SNP and Azure CVM standalone APIs accept
the same object as `platform_policy=`. A supplied policy, including an empty
one, requires authenticated SNP evidence. Missing roots, missing evidence, and
claims selecting a non-SNP or software provider cannot bypass the requirement.

An unmet policy sets `failure_reason` on the public verification result to
`HARDWARE_ATTESTATION_FAILED`, records the detail, and never returns `VERIFIED`.
A result can retain `PARTIALLY_VERIFIED` status for unrelated successful checks;
it is not permission to release data. Require no failure, `VERIFIED` status,
and `platform_state` in `verified_fields` for this particular gate.

Successful appraisal records `platform_state` and the authenticated raw word
in `details["platform_info"]`. Omitting the policy preserves previous behavior
and does not assert platform state. The CLI and gateway startup do not configure
this policy; applications calling the Python verifier must supply it.

## Limits

This check covers only SNP `PLATFORM_INFO`. It does not cover the separate guest
`POLICY` word (including debug mode), minimum TCB versions, revocation, workload
correctness, key residency, CPU/GPU channel protection, or remote tools. It is an
offline evidence check, not proof of current liveness. Protect data only after
the complete admission policy, including freshness and channel binding, passes.

`tests/unit/test_snp_platform_policy.py` exercises signed synthetic reports with
acceptable settings, missing required bits, forbidden bits, unknown bits,
missing trust roots, tampered platform state, and provider downgrade attempts.
The tests exercise real cryptographic verification with a synthetic PKI. They
do not constitute a new live hardware demonstration.
