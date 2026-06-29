# cmcp-verify: Verification Library Interface Spec

!!! warning "Draft"
    Status: Draft v0.1 · Stability: Unstable — expect breaking changes before v1.0

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
    *,
    trusted_public_key_hex: Optional[str] = None,
    agent_manifest: Optional[dict] = None,
    trusted_agent_manifest_keys: Optional[dict[str, bytes]] = None,
) -> VerificationResult:
    """
    Verify a TRACE Claim without trusting the operator.

    Steps:
    1. Verify tee_public_key is bound to attestation_report (provider-specific)
    2. Verify signature over canonical claim body using tee_public_key
    3. Check policy_bundle.hash against approved.policy_bundle_hash
    4. Check tool_catalog.hash against approved.tool_catalog_hash
    5. If agent_manifest and trusted_agent_manifest_keys are provided, verify
       the Agent Manifest issuer signature with agent-manifest SDK
       verify_manifest() and cross-check gateway.agent_identity:
       manifest_id, agent_id/authenticated_subject, subject_source, policy hash,
       catalog hash, and manifest expiry.
    6. Check attestation freshness (timestamp within max_attestation_age_seconds)
    7. Verify audit chain continuity (audit_chain_root, audit_chain_tip)

    Returns VerificationResult with status and details.
    """
    ...
```

`trusted_agent_manifest_keys` keeps cMCP's runtime-facing shape as raw Ed25519
public key bytes keyed by issuer `key_id`; the verifier base64url-encodes those
keys when calling the Agent Manifest SDK.

### Audit Bundle Verification and External Execution Evidence

```python
@dataclass
class AuditBundleResult:
    verified: bool
    entry_count: int
    failures: list[str]

def verify_audit_bundle(
    bundle_json: dict,
    claim_json: Optional[dict] = None,
    *,
    external_evidence_keys: Optional[dict[str, bytes]] = None,
) -> AuditBundleResult:
    """
    Verify an exported audit bundle. When external_evidence_keys is supplied,
    each key is issuer_key_id -> raw 32-byte Ed25519 public key. issuer_key_id
    is lowercase hex SHA-256(public_key_bytes).
    """
    ...
```

`external_execution_evidence.evidence_hash` is the digest of the detached evidence payload attested by the issuer, not the digest of the receipt envelope. For JSON evidence payloads, the hash pre-image is the UTF-8 bytes of the RFC 8785/JCS canonical JSON representation. For non-JSON evidence payloads, the pre-image is the exact byte string identified by the issuer's evidence format. The field value is `sha256:<hex>` or `sha384:<hex>`.

Runtime ingestion convention: when an allowed upstream tool response is a JSON object with a top-level `external_execution_evidence` object matching the audit schema, cMCP copies that receipt into the `tool_call` audit entry. The response itself is not rewritten; `response_payload_hash` still covers the bytes returned to the caller.

The verifier computes the receipt signing input as canonical JSON over the receipt object excluding `signature`, with sorted keys and compact separators. It then checks:

1. `linked_call_id` equals the audit entry `call_id`.
2. `issuer_key_id` is lowercase hex SHA-256 of the trusted issuer public key.
3. `evidence_hash` has a supported hash prefix and hex digest.
4. `evidence_type` is one of the documented receipt types.
5. The Ed25519 signature verifies over the canonical receipt signing input.

If any external evidence check fails, the audit bundle result is `verified=False` and the failure string includes `EXTERNAL_EVIDENCE_VERIFICATION_FAILED`.

## Per-Provider Verification Steps

### TPM Verification

1. Obtain the TPM Endorsement Key (EK) certificate from the TPM manufacturer (e.g., fetched from the TPM itself via Esys_ReadPublic or from the manufacturer's certificate authority at ek.{manufacturer}.com).
2. Verify the EK certificate chains to a trusted manufacturer CA (TPM manufacturer CA roots are published by Microsoft, Amazon, Google for their vTPM implementations).
3. Extract the TPM2B_ATTEST structure from attestation_report.raw_evidence.
4. Verify the TPM2_Quote signature using the Attestation Key (AK) public key, which must be certified by the EK.
5. Confirm the quote's qualifying_data matches SHA-256(tee_public_key || session_id) from the TRACE Claim -- this binds the quote to the specific runtime instance.
6. Confirm the PCR values in the quote match attestation_report.measurement (compare byte-by-byte).
7. If all checks pass: TEE identity is verified for TPM.

### SEV-SNP Verification

1. Fetch the AMD VCEK (Versioned Chip Endorsement Key) certificate for the specific CPU. VCEK fetch URL format: https://kdsintf.amd.com/vcek/v1/{product}/{hwid}?{tcb_params}. Product is "Milan" or "Genoa". hwid and tcb_params come from the SNP attestation report.
2. Verify VCEK certificate chains to AMD Root CA (download from https://kdsintf.amd.com/vcek/v1/Milan/cert_chain).
3. Parse the SNP attestation report from attestation_report.raw_evidence (binary format per AMD SEV-SNP Firmware ABI Specification, Table 22).
4. Verify the report signature using the VCEK public key.
5. Confirm report.REPORT_DATA == SHA-256(tee_public_key || session_id) (bytes 0-31 of REPORT_DATA).
6. Confirm report.MEASUREMENT == bytes decoded from attestation_report.measurement (the 48-byte launch measurement).
7. Confirm report.POLICY fields match expected configuration (no debug mode, SMT policy as expected).
8. If all checks pass: TEE identity is verified for SEV-SNP.

### Intel TDX Verification

1. Fetch TDX Quote Collateral using Intel's DCAP (Data Center Attestation Primitives) API at https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity.
2. Parse the TDX Quote from attestation_report.raw_evidence (follows Intel TDX Quote Generation Service format).
3. Verify the Quote using the QE (Quoting Enclave) identity and PCK (Provisioning Certification Key) certificate chain from the collateral.
4. Confirm TD_REPORT.REPORT_DATA == SHA-256(tee_public_key || session_id).
5. Confirm TD_REPORT.MRTD || RTMR0 || RTMR1 || RTMR2 || RTMR3 == attestation_report.measurement (concatenated).
6. If all checks pass: TEE identity is verified for TDX.

### OPAQUE Managed Verification

1. Call the OPAQUE attestation verification endpoint (provided at deployment time) with the attestation_report.raw_evidence as the request body.
2. The endpoint returns: {verified: true|false, measurement_matched: true|false, error?: string}.
3. If verified and measurement_matched: TEE identity is verified for OPAQUE Managed.

## What "partially_verified" means

VerificationStatus.PARTIALLY_VERIFIED is returned when:
- tee_public_key and signature are verified, but the attestation provider is not supported by this version of cmcp-verify (e.g., a new provider added after the library version)
- Some fields are verified but others are absent from the claim (e.g., tool_catalog.hash is missing -- older TRACE Claim format)
- verified_fields lists what passed; unverified_fields lists what was skipped with reason

## Error codes

VerificationError enum:
- UNSUPPORTED_PROVIDER: attestation_report.provider is not in the supported list for this library version
- SIGNATURE_INVALID: signature does not verify against tee_public_key
- PUBLIC_KEY_NOT_BOUND: tee_public_key is not bound to the attestation_report (measurement mismatch or quote verification failed)
- POLICY_HASH_MISMATCH: policy_bundle.hash != approved.policy_bundle_hash
- CATALOG_HASH_MISMATCH: tool_catalog.hash != approved.tool_catalog_hash
- AGENT_MANIFEST_MISMATCH: gateway.agent_identity does not match the signed Agent Manifest, the manifest signature is invalid, or trusted issuer keys were not supplied for a requested manifest check
- ATTESTATION_STALE: attestation_generated_at is older than max_attestation_age_seconds
- CHAIN_BROKEN: audit_chain_root -> audit_chain_tip traversal fails (missing entries or hash mismatch)
- CLAIM_MALFORMED: claim_json fails JSON Schema validation against the TRACE Claim schema
- EXTERNAL_EVIDENCE_VERIFICATION_FAILED: an audit bundle entry contains external_execution_evidence whose call binding, key id, evidence hash, evidence type, or issuer signature cannot be verified

## Phase 1 support matrix

Phase 1 must support TPM and SEV-SNP at minimum. TDX is high priority for the first release. OPAQUE is handled by the managed runtime and does not require a separate implementation path.

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

As noted in [threat-model.md](threat-model.md), T.1 (server swap / tool identity) is only closed if the agent or the agent's runtime runs `verify_trace_claim` before sending traffic. Attestation without verification is post-hoc evidence, not a runtime gate.
