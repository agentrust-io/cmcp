"""
TRACE Claim verification — implements issue #59.

Verifies a cMCP TRACE Claim without trusting the gateway operator.
Provider-specific attestation verification (TPM, SEV-SNP) is dispatched
per-provider and added in issues #62, #67.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from cmcp_gateway.audit.trace_claim import GatewayClaim

_SW_ONLY_FIRMWARE = "software-only-dev-mode"

_KNOWN_PLATFORMS = {
    "amd-sev-snp",
    "intel-tdx",
    "tpm2",
    "nvidia-h100",
    "nvidia-blackwell",
    "aws-nitro",
    "arm-cca",
    "google-confidential-space",
}


class VerificationStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    PARTIALLY_VERIFIED = "partially_verified"


class VerificationError(StrEnum):
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


def _jwk_x_to_hex(x_b64: str) -> str | None:
    """Decode trace.cnf.jwk.x (base64url, no padding) to hex. Returns None on error."""
    try:
        padding = 4 - (len(x_b64) % 4)
        padded = x_b64 + ("=" * padding if padding != 4 else "")
        return base64.urlsafe_b64decode(padded).hex()
    except Exception:
        return None


def _verify_signature(claim: dict[str, Any]) -> tuple[bool, str | None]:
    """Verify the Ed25519 signature using the JWK public key in trace.cnf.jwk.x."""
    try:
        x_b64: str = claim["trace"]["cnf"]["jwk"]["x"]
        padding = 4 - (len(x_b64) % 4)
        if padding != 4:
            x_b64 += "=" * padding
        pub_bytes = base64.urlsafe_b64decode(x_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except (KeyError, ValueError) as exc:
        return False, f"cannot parse trace.cnf.jwk.x: {exc}"

    sig_b64: str = claim.get("signature", "")
    if not sig_b64:
        return False, "signature field is empty"

    try:
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
        generated_at_str: str = claim["gateway"]["attestation_generated_at"]
        generated_at = datetime.fromisoformat(generated_at_str)
        now = datetime.now(tz=UTC)
        age = int((now - generated_at).total_seconds())
        return age, age <= max_age_seconds
    except (KeyError, ValueError):
        return -1, False


def _check_audit_chain(claim: dict[str, Any]) -> tuple[bool, str | None]:
    """Check that audit_chain root, tip, and length are present and non-empty."""
    chain = claim.get("gateway", {}).get("audit_chain", {})
    root = chain.get("root", "")
    tip = chain.get("tip", "")
    length = chain.get("length", 0)
    if not root or not tip:
        return False, "gateway.audit_chain.root or .tip is empty"
    if length < 1:
        return False, "gateway.audit_chain.length is 0"
    return True, None


def _validate_schema(claim: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate claim structure using the GatewayClaim Pydantic model."""
    try:
        GatewayClaim.model_validate(claim)
        return True, None
    except ValidationError as exc:
        return False, str(exc)


def verify_trace_claim(
    claim_json: dict[str, Any],
    approved: ApprovedHashes,
    max_attestation_age_seconds: int = 86400,
    *,
    trusted_public_key_hex: str | None = None,
) -> VerificationResult:
    """
    Verify a TRACE Claim without trusting the operator.

    Steps:
    1. Pydantic schema validation (GatewayClaim)
    2. Ed25519 signature verification over canonical claim body
    3. trace.policy.bundle_hash check against approved.policy_bundle_hash
    4. gateway.catalog.hash check against approved.tool_catalog_hash
    5. Attestation freshness check
    6. Audit chain consistency check
    7. Platform-specific attestation verification (dispatched per-platform)

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
    else:
        unverified.append("signature")
        failure = VerificationError.SIGNATURE_INVALID
        details["signature_error"] = sig_err or "invalid signature"

    # Step 2b: Public key binding — verify JWK x matches an externally-trusted key.
    # Without this, a malicious gateway can sign with any key and embed it in the claim.
    _runtime = claim_json.get("trace", {}).get("runtime", {})
    _is_sw_only = (
        _runtime.get("platform") == "tpm2"
        and _runtime.get("firmware_version") == _SW_ONLY_FIRMWARE
    )
    _x_b64 = claim_json.get("trace", {}).get("cnf", {}).get("jwk", {}).get("x", "")
    if trusted_public_key_hex:
        actual_hex = _jwk_x_to_hex(_x_b64) if _x_b64 else None
        normalized = trusted_public_key_hex.lower().removeprefix("0x")
        if actual_hex == normalized:
            verified.append("public_key_binding")
        else:
            unverified.append("public_key_binding")
            failure = failure or VerificationError.PUBLIC_KEY_NOT_BOUND
            details["public_key_binding"] = "trace.cnf.jwk.x does not match trusted_public_key_hex"
    elif not _is_sw_only:
        unverified.append("public_key_binding")
        failure = failure or VerificationError.PUBLIC_KEY_NOT_BOUND
        details["public_key_binding"] = (
            "no trusted_public_key_hex provided — TEE key binding cannot be verified"
        )

    # Step 3: Policy bundle hash
    claimed_policy = claim_json.get("trace", {}).get("policy", {}).get("bundle_hash", "")
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
    claimed_catalog = claim_json.get("gateway", {}).get("catalog", {}).get("hash", "")
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

    # Step 7: Platform-specific attestation
    platform = _runtime.get("platform", "")
    firmware_version = _runtime.get("firmware_version", "")

    if platform == "tpm2" and firmware_version == _SW_ONLY_FIRMWARE:
        unverified.append("hardware_attestation")
        details["hardware_attestation"] = "software-only mode — not hardware-backed"
    elif platform == "tpm2" and firmware_version != _SW_ONLY_FIRMWARE:
        from cmcp_verify.tpm import verify_tpm_measurement

        raw_ev = _runtime.get("raw_evidence")
        raw_bytes = base64.b64decode(raw_ev) if raw_ev else None
        tpm_result = verify_tpm_measurement(
            measurement=_runtime.get("measurement", ""),
            raw_evidence=raw_bytes,
            tee_public_key_hex=claim_json.get("trace", {}).get("cnf", {}).get("jwk", {}).get("x"),
            session_id=claim_json.get("gateway", {}).get("session_id"),
        )
        if tpm_result.verified:
            verified.append("hardware_attestation")
            verified.extend(tpm_result.verified_fields)
        else:
            unverified.append("hardware_attestation")
            if tpm_result.failure_reason:
                details["tpm_failure"] = tpm_result.failure_reason
        unverified.extend(tpm_result.unverified_fields)
        details.update(tpm_result.details)
    elif platform == "sev-snp" and firmware_version != _SW_ONLY_FIRMWARE:
        from cmcp_verify.sev_snp import verify_sev_snp_measurement

        raw_ev = _runtime.get("raw_evidence")
        raw_bytes = base64.b64decode(raw_ev) if raw_ev else None
        report_data_hex = _runtime.get("report_data")
        snp_result = verify_sev_snp_measurement(
            measurement=_runtime.get("measurement", ""),
            raw_evidence=raw_bytes,
            report_data_hex=report_data_hex,
        )
        if snp_result.verified:
            verified.append("hardware_attestation")
            verified.extend(snp_result.verified_fields)
        else:
            unverified.append("hardware_attestation")
            if snp_result.failure_reason:
                details["sev_snp_failure"] = snp_result.failure_reason
        unverified.extend(snp_result.unverified_fields)
        details.update(snp_result.details)
    elif platform == "intel-tdx":
        from cmcp_verify.tdx import verify_tdx_measurement

        raw_ev = _runtime.get("raw_evidence")
        raw_bytes = base64.b64decode(raw_ev) if raw_ev else None
        report_data_hex = _runtime.get("report_data")
        tdx_result = verify_tdx_measurement(
            measurement=_runtime.get("measurement", ""),
            raw_evidence=raw_bytes,
            report_data_hex=report_data_hex,
        )
        if tdx_result.verified:
            verified.append("hardware_attestation")
            verified.extend(tdx_result.verified_fields)
        else:
            unverified.append("hardware_attestation")
            if tdx_result.failure_reason:
                details["tdx_failure"] = tdx_result.failure_reason
        unverified.extend(tdx_result.unverified_fields)
        details.update(tdx_result.details)
    elif platform in ("opaque", "opaque-managed"):
        from cmcp_verify.opaque import verify_opaque_measurement

        raw_ev = _runtime.get("raw_evidence")
        raw_bytes = base64.b64decode(raw_ev) if raw_ev else None
        opaque_result = verify_opaque_measurement(
            measurement=_runtime.get("measurement", ""),
            raw_evidence=raw_bytes,
        )
        if opaque_result.verified:
            verified.append("hardware_attestation")
            verified.extend(opaque_result.verified_fields)
        else:
            unverified.append("hardware_attestation")
            if opaque_result.failure_reason:
                details["opaque_failure"] = opaque_result.failure_reason
        unverified.extend(opaque_result.unverified_fields)
        details.update(opaque_result.details)
    elif platform in _KNOWN_PLATFORMS:
        unverified.append("hardware_attestation")
        failure = failure or VerificationError.UNSUPPORTED_PROVIDER
        details["hardware_attestation"] = (
            f"Platform '{platform}' attestation verification not yet implemented"
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
