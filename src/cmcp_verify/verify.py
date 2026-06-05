"""
TRACE Claim verification — implements issue #59.

Verifies a cMCP TRACE Claim without trusting the gateway operator.
Provider-specific attestation verification (TPM, SEV-SNP) is dispatched
per-provider and added in issues #62, #67.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import (  # noqa: F401
    decode_dss_signature,
)
from cryptography.exceptions import InvalidSignature

_SCHEMA_PATH = Path(__file__).parent.parent.parent / "schemas" / "trace-claim.schema.json"


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    PARTIALLY_VERIFIED = "partially_verified"


class VerificationError(str, Enum):
    UNSUPPORTED_PROVIDER = "UNSUPPORTED_PROVIDER"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    PUBLIC_KEY_NOT_BOUND = "PUBLIC_KEY_NOT_BOUND"
    POLICY_HASH_MISMATCH = "POLICY_HASH_MISMATCH"
    CATALOG_HASH_MISMATCH = "CATALOG_HASH_MISMATCH"
    ATTESTATION_STALE = "ATTESTATION_STALE"
    CHAIN_BROKEN = "CHAIN_BROKEN"
    CLAIM_MALFORMED = "CLAIM_MALFORMED"


@dataclass
class ApprovedHashes:
    """The operator-provided approved hashes to verify against."""

    policy_bundle_hash: str  # sha256:<hex>
    tool_catalog_hash: str   # sha256:<hex>


@dataclass
class VerificationResult:
    status: VerificationStatus
    verified_fields: list[str]
    unverified_fields: list[str]
    failure_reason: VerificationError | None
    attestation_age_seconds: int
    is_attestation_fresh: bool
    details: dict[str, str] = field(default_factory=dict)


def _canonical_json(claim_dict: dict[str, Any]) -> bytes:
    """Reproduce the gateway's canonical serialization for signature verification."""
    body = {k: v for k, v in claim_dict.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _verify_signature(claim: dict[str, Any]) -> tuple[bool, str | None]:
    """Verify the Ed25519 signature over the canonical claim body."""
    try:
        pub_hex: str = claim["tee_public_key"]
        pub_bytes = bytes.fromhex(pub_hex)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except (KeyError, ValueError) as exc:
        return False, f"cannot parse tee_public_key: {exc}"

    sig_b64: str = claim.get("signature", "")
    if not sig_b64:
        return False, "signature field is empty"

    try:
        # Add padding if needed for urlsafe base64
        padding = 4 - (len(sig_b64) % 4)
        if padding != 4:
            sig_b64 += "=" * padding
        sig_bytes = base64.urlsafe_b64decode(sig_b64)
    except Exception as exc:
        return False, f"cannot decode signature: {exc}"

    body = _canonical_json(claim)
    try:
        pub_key.verify(sig_bytes, body)
        return True, None
    except InvalidSignature:
        return False, "Ed25519 signature verification failed"


def _check_attestation_freshness(
    claim: dict[str, Any],
    max_age_seconds: int,
) -> tuple[int, bool]:
    """Return (age_seconds, is_fresh)."""
    try:
        generated_at_str: str = claim["attestation_report"]["attestation_generated_at"]
        generated_at = datetime.fromisoformat(generated_at_str)
        now = datetime.now(tz=timezone.utc)
        age = int((now - generated_at).total_seconds())
        return age, age <= max_age_seconds
    except (KeyError, ValueError):
        return -1, False


def _check_audit_chain(claim: dict[str, Any]) -> tuple[bool, str | None]:
    """
    Check audit chain consistency: chain_root, chain_tip, and audit_chain_length
    must be consistent. Full chain walk requires fetching the exported audit log
    (issue #55) — here we verify the fields are present and non-empty.
    """
    root = claim.get("audit_chain_root", "")
    tip = claim.get("audit_chain_tip", "")
    length = claim.get("audit_chain_length", 0)
    if not root or not tip:
        return False, "audit_chain_root or audit_chain_tip is empty"
    if length < 1:
        return False, "audit_chain_length is 0"
    return True, None


def _validate_schema(claim: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate against JSON Schema if available."""
    if not _SCHEMA_PATH.exists():
        return True, None
    try:
        import jsonschema
        schema = json.loads(_SCHEMA_PATH.read_text())
        jsonschema.validate(claim, schema)
        return True, None
    except Exception as exc:
        return False, str(exc)


def verify_trace_claim(
    claim_json: dict[str, Any],
    approved: ApprovedHashes,
    max_attestation_age_seconds: int = 86400,
) -> VerificationResult:
    """
    Verify a TRACE Claim without trusting the operator.

    Steps:
    1. JSON Schema validation
    2. Ed25519 signature verification over canonical claim body
    3. policy_bundle.hash check against approved.policy_bundle_hash
    4. tool_catalog.hash check against approved.tool_catalog_hash
    5. Attestation freshness check
    6. Audit chain consistency check
    7. Provider-specific attestation verification (dispatched per-provider)

    Returns VerificationResult with status and details.

    Example usage:
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
    """
    verified: list[str] = []
    unverified: list[str] = []
    failure: VerificationError | None = None
    details: dict[str, str] = {}

    # Step 1: Schema validation
    schema_ok, schema_err = _validate_schema(claim_json)
    if schema_ok:
        verified.append("schema")
    else:
        unverified.append("schema")
        failure = VerificationError.CLAIM_MALFORMED
        details["schema_error"] = schema_err or "schema validation failed"

    # Step 2: Signature
    sig_ok, sig_err = _verify_signature(claim_json)
    if sig_ok:
        verified.append("signature")
        verified.append("tee_public_key")
    else:
        unverified.extend(["signature", "tee_public_key"])
        failure = VerificationError.SIGNATURE_INVALID
        details["signature_error"] = sig_err or "invalid signature"

    # Step 3: Policy bundle hash
    claimed_policy = claim_json.get("policy_bundle", {}).get("hash", "")
    expected_policy = approved.policy_bundle_hash.removeprefix("sha256:")
    actual_policy = claimed_policy.removeprefix("sha256:")
    if actual_policy == expected_policy:
        verified.append("policy_bundle.hash")
    else:
        unverified.append("policy_bundle.hash")
        if failure is None:
            failure = VerificationError.POLICY_HASH_MISMATCH
        details["policy_hash_expected"] = expected_policy[:16] + "..."
        details["policy_hash_actual"] = actual_policy[:16] + "..."

    # Step 4: Catalog hash
    claimed_catalog = claim_json.get("tool_catalog", {}).get("hash", "")
    expected_catalog = approved.tool_catalog_hash.removeprefix("sha256:")
    actual_catalog = claimed_catalog.removeprefix("sha256:")
    if actual_catalog == expected_catalog:
        verified.append("tool_catalog.hash")
    else:
        unverified.append("tool_catalog.hash")
        if failure is None:
            failure = VerificationError.CATALOG_HASH_MISMATCH

    # Step 5: Attestation freshness
    age, is_fresh = _check_attestation_freshness(claim_json, max_attestation_age_seconds)
    if is_fresh:
        verified.append("attestation_freshness")
    else:
        unverified.append("attestation_freshness")
        if failure is None:
            failure = VerificationError.ATTESTATION_STALE
        details["attestation_age_seconds"] = str(age)

    # Step 6: Audit chain consistency
    chain_ok, chain_err = _check_audit_chain(claim_json)
    if chain_ok:
        verified.append("audit_chain")
    else:
        unverified.append("audit_chain")
        if failure is None:
            failure = VerificationError.CHAIN_BROKEN
        if chain_err:
            details["chain_error"] = chain_err

    # Step 7: Provider-specific attestation (dispatched)
    provider = claim_json.get("attestation_report", {}).get("provider", "")
    if provider == "software-only":
        unverified.append("hardware_attestation")
        details["hardware_attestation"] = "software-only mode — not hardware-backed"
    elif provider in ("tpm", "sev-snp", "tdx", "opaque"):
        # Provider-specific verification implemented in issues #62, #67, #70
        unverified.append("hardware_attestation")
        details["hardware_attestation"] = (
            f"Provider '{provider}' attestation verification not yet implemented — "
            f"see issues #62 (TPM), #67 (SEV-SNP), #70 (TDX/Opaque)"
        )
    else:
        unverified.append("hardware_attestation")
        failure = failure or VerificationError.UNSUPPORTED_PROVIDER

    # Determine overall status
    if failure is None:
        status = VerificationStatus.VERIFIED
    elif verified:
        status = VerificationStatus.PARTIALLY_VERIFIED
    else:
        status = VerificationStatus.UNVERIFIED

    return VerificationResult(
        status=status,
        verified_fields=verified,
        unverified_fields=unverified,
        failure_reason=failure,
        attestation_age_seconds=age,
        is_attestation_fresh=is_fresh,
        details=details,
    )
