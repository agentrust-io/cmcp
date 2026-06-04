# cmcp-verify: Verification Library Interface Spec

This document is the interface specification for the `cmcp-verify` Python library. Implementation is separate from this spec. All type stubs below define the public interface that the implementation must satisfy.

## Type Stubs

```python
from dataclasses import dataclass
from enum import Enum
from typing import Optional
import datetime

class TEEProvider(Enum):
    TPM = "tpm"
    SEV_SNP = "sev-snp"
    TDX = "tdx"
    OPAQUE = "opaque"
    SOFTWARE_ONLY = "software-only"

class VerificationStatus(Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    PARTIALLY_VERIFIED = "partially_verified"

@dataclass
class VerificationResult:
    status: VerificationStatus
    verified_fields: list[str]   # fields successfully verified
    unverified_fields: list[str] # fields present but not verified (provider not supported, etc.)
    failure_reason: Optional[str] # None if status != UNVERIFIED
    attestation_age_seconds: int  # how old the attestation is
    is_attestation_fresh: bool    # attestation_age_seconds < configured validity window

@dataclass
class ApprovedHashes:
    policy_bundle_hash: str   # sha256 hex string of approved policy bundle
    tool_catalog_hash: str    # sha256 hex string of approved tool catalog

def verify_trace_claim(
    claim_json: dict,
    approved: ApprovedHashes,
    max_attestation_age_seconds: int = 86400,
) -> VerificationResult:
    """
    Verify a TRACE Claim without trusting the operator.

    Steps:
    1. Verify tee_public_key is bound to attestation_report (provider-specific)
    2. Verify signature over canonical claim body using tee_public_key
    3. Check policy_bundle.hash against approved.policy_bundle_hash
    4. Check tool_catalog.hash against approved.tool_catalog_hash
    5. Check attestation freshness (timestamp within max_attestation_age_seconds)
    6. Verify audit chain continuity (audit_chain_root, audit_chain_tip)

    Returns VerificationResult with status and details.
    """
    ...
```

## Provider-Specific Verification Notes

**TPM.** Verify `attestation_report.measurement` against expected PCR values using TSS2 or tpm2-tools. Requires access to the TPM endorsement key certificate chain.

**SEV-SNP.** Verify `attestation_report.measurement` against AMD's VCEK certificate chain. AMD provides a public verification service at `kdsintf.amd.com`.

**TDX.** Verify against Intel's DCAP attestation service. Requires Intel attestation collateral (PCK certificate, TCB info, QE identity).

**Opaque.** Verify against Opaque's managed attestation service. The managed runtime handles collateral retrieval.

**Phase 1 support matrix.** Phase 1 must support TPM and SEV-SNP at minimum. TDX is high priority for the first release. Opaque is handled by the managed runtime and does not require a separate implementation path.

`SOFTWARE_ONLY` is a valid enum value for local development and CI environments. A claim with `provider: software-only` must always return `VerificationStatus.PARTIALLY_VERIFIED` with `failure_reason` set, never `VERIFIED`.

## Usage Example

```python
from cmcp_verify import verify_trace_claim, ApprovedHashes
import json

trace_claim = json.load(open("session-trace.json"))
approved = ApprovedHashes(
    policy_bundle_hash="sha256:abc123...",
    tool_catalog_hash="sha256:def456..."
)
result = verify_trace_claim(trace_claim, approved)
print(f"Status: {result.status.value}")
print(f"Verified fields: {result.verified_fields}")
if not result.is_attestation_fresh:
    print(f"WARNING: attestation is {result.attestation_age_seconds}s old")
```

## Relationship to Threat Model

As noted in [threat-model.md](threat-model.md), T.1 (server swap / tool identity) is only closed if the agent or the agent's gateway runs `verify_trace_claim` before sending traffic. Attestation without verification is post-hoc evidence, not a runtime gate.
