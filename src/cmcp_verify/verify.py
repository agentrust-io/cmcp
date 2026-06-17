"""
TRACE Claim verification -- implements issue #59.

Verifies a cMCP TRACE Claim without trusting the gateway operator.
Provider-specific attestation verification (TPM, SEV-SNP) is dispatched
per-provider and added in issues #62, #67.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from cmcp_runtime.agent_manifest import verify_agent_manifest_binding
from cmcp_runtime.audit.trace_claim import RuntimeClaim
from cmcp_runtime.errors import ConfigError

logger = logging.getLogger(__name__)

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
    "software-only",
}


def _is_software_only(runtime: dict[str, Any]) -> bool:
    """True for dev-mode (non-attested) records.

    Current records use platform "software-only"; records produced before
    that value existed used platform "tpm2" with the dev firmware sentinel.
    """
    if runtime.get("platform") == "software-only":
        return True
    return (
        runtime.get("platform") == "tpm2"
        and runtime.get("firmware_version") == _SW_ONLY_FIRMWARE
    )


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
    HARDWARE_ATTESTATION_FAILED = "HARDWARE_ATTESTATION_FAILED"
    AGENT_MANIFEST_MISMATCH = "AGENT_MANIFEST_MISMATCH"


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


def _verify_key_binding(
    claim: dict[str, Any],
    *,
    is_sw_only: bool,
) -> tuple[bool | None, str | None]:
    """
    CRYPTO-001: verify that cnf.jwk public key fingerprint matches report_data[:32].

    The gateway embeds SHA-256(public_key_bytes) as the first 32 bytes of the nonce
    it submits to the TEE when requesting the attestation report.  The TEE hardware
    commits that nonce into the signed report_data field.  The nonce is stored as
    trace.runtime.nonce (base64url of the full 64-byte value).

    Verifiers re-derive SHA-256(cnf.jwk.x public key bytes) and compare it against
    nonce[:32].  A mismatch means the public key was substituted after attestation;
    the claim must be rejected with PUBLIC_KEY_NOT_BOUND.

    Returns:
        (True,  None)          -- fingerprint matches; binding verified
        (False, reason)        -- mismatch or missing data; binding rejected
        (None,  warning_msg)   -- software-only / Level-0 mode; binding not applicable
    """
    if is_sw_only:
        logger.warning(
            "CRYPTO-001: software-only (dev) mode -- TEE key binding cannot be verified; "
            "this claim provides no hardware provenance guarantee"
        )
        return None, "software-only mode -- TEE key binding not applicable"

    # Extract the public key bytes from cnf.jwk.x
    x_b64 = claim.get("trace", {}).get("cnf", {}).get("jwk", {}).get("x", "")
    if not x_b64:
        return False, "trace.cnf.jwk.x is missing -- cannot verify key binding"

    try:
        padding = 4 - (len(x_b64) % 4)
        padded = x_b64 + ("=" * padding if padding != 4 else "")
        pub_key_bytes = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        return False, f"cannot decode trace.cnf.jwk.x: {exc}"

    # Compute SHA-256(public_key_bytes) -- the expected fingerprint
    expected_fingerprint = hashlib.sha256(pub_key_bytes).digest()

    # Extract the nonce from trace.runtime.nonce (base64url, first 32 bytes = fingerprint)
    nonce_b64 = claim.get("trace", {}).get("runtime", {}).get("nonce", "")
    if not nonce_b64:
        return False, (
            "trace.runtime.nonce is absent -- attestation report_data does not "
            "bind this public key to TEE hardware"
        )

    try:
        padding = 4 - (len(nonce_b64) % 4)
        padded = nonce_b64 + ("=" * padding if padding != 4 else "")
        nonce_bytes = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        return False, f"cannot decode trace.runtime.nonce: {exc}"

    if len(nonce_bytes) < 32:
        return False, (
            f"trace.runtime.nonce is too short ({len(nonce_bytes)} bytes); "
            "expected at least 32 bytes for key fingerprint"
        )

    actual_fingerprint = nonce_bytes[:32]
    if actual_fingerprint != expected_fingerprint:
        return False, (
            "cnf.jwk public key fingerprint does not match report_data[:32] -- "
            "the public key was not bound to this TEE attestation report; "
            "possible key substitution attack"
        )

    return True, None


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
    """Validate claim structure using the RuntimeClaim Pydantic model."""
    try:
        RuntimeClaim.model_validate(claim)
        return True, None
    except ValidationError as exc:
        return False, str(exc)


@dataclass
class AuditBundleResult:
    """Outcome of verifying an exported audit bundle against a claim."""

    verified: bool
    entry_count: int
    failures: list[str] = field(default_factory=list)


def verify_audit_bundle(
    bundle_json: dict[str, Any],
    claim_json: dict[str, Any] | None = None,
) -> AuditBundleResult:
    """
    Verify an exported audit bundle (GET /audit/export):

    1. Recompute every entry hash from its canonical body and check the
       prev_entry_hash linkage from "genesis" to the tip.
    2. If a claim is provided, cross-check the bundle's root/tip/length
       against gateway.audit_chain and verify the bundle_signature with the
       claim's confirmation key (trace.cnf.jwk.x).
    """
    failures: list[str] = []
    entries = bundle_json.get("entries", [])
    if not entries:
        return AuditBundleResult(verified=False, entry_count=0, failures=["bundle has no entries"])

    prev = "genesis"
    for i, entry in enumerate(entries):
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        recomputed = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
        if recomputed != entry.get("entry_hash"):
            failures.append(f"entry {i}: hash mismatch (content altered)")
        if entry.get("prev_entry_hash") != prev:
            failures.append(f"entry {i}: chain link broken")
        prev = entry.get("entry_hash", "")

    if claim_json is not None:
        chain = claim_json.get("gateway", {}).get("audit_chain", {})
        if chain.get("root") != entries[0].get("entry_hash"):
            failures.append("bundle root does not match claim gateway.audit_chain.root")
        if chain.get("tip") != entries[-1].get("entry_hash"):
            failures.append("bundle tip does not match claim gateway.audit_chain.tip")
        if chain.get("length") != len(entries):
            failures.append(
                f"bundle has {len(entries)} entries, claim says {chain.get('length')}"
            )

        sig_b64 = bundle_json.get("bundle_signature", "")
        x_b64 = claim_json.get("trace", {}).get("cnf", {}).get("jwk", {}).get("x", "")
        if not sig_b64:
            failures.append("bundle_signature is missing")
        elif not x_b64:
            failures.append("claim has no confirmation key to check bundle_signature against")
        else:
            try:
                pad = 4 - (len(x_b64) % 4)
                pub = Ed25519PublicKey.from_public_bytes(
                    base64.urlsafe_b64decode(x_b64 + ("=" * pad if pad != 4 else ""))
                )
                pad = 4 - (len(sig_b64) % 4)
                sig = base64.urlsafe_b64decode(sig_b64 + ("=" * pad if pad != 4 else ""))
                digest = hashlib.sha256(
                    json.dumps(
                        entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                    ).encode()
                ).digest()
                pub.verify(sig, digest)
            except InvalidSignature:
                failures.append("bundle_signature is invalid")
            except Exception as exc:
                failures.append(f"bundle_signature could not be checked: {exc}")

    return AuditBundleResult(
        verified=not failures, entry_count=len(entries), failures=failures
    )


def verify_trace_claim(
    claim_json: dict[str, Any],
    approved: ApprovedHashes,
    max_attestation_age_seconds: int = 86400,
    *,
    trusted_public_key_hex: str | None = None,
    agent_manifest: dict[str, Any] | None = None,
    trusted_agent_manifest_keys: dict[str, bytes] | None = None,
) -> VerificationResult:
    """
    Verify a TRACE Claim without trusting the operator.

    Steps:
    1. Pydantic schema validation (RuntimeClaim)
    2. Ed25519 signature verification over canonical claim body
    2b. CRYPTO-001: TEE key binding -- verify cnf.jwk fingerprint matches report_data[:32]
    2c. Optional out-of-band trusted_public_key_hex cross-check
    3. trace.policy.bundle_hash check against approved.policy_bundle_hash
    4. gateway.catalog.hash check against approved.tool_catalog_hash
    5. Optional Agent Manifest binding check when agent_manifest and trusted
       issuer keys are provided.
    6. Attestation freshness check
    7. Audit chain consistency check
    8. Platform-specific attestation verification (dispatched per-platform)

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

    # Step 2b: CRYPTO-001 -- TEE key binding via report_data fingerprint.
    # The nonce submitted to the TEE at attestation time encodes SHA-256(public_key_bytes)
    # in its first 32 bytes.  Hardware commits this nonce into the signed report_data field.
    # Verifiers re-derive the fingerprint from cnf.jwk.x and compare to nonce[:32].
    # An attacker who substitutes their own keypair cannot forge the TEE-signed nonce,
    # so verification fails even when the Ed25519 signature is self-consistent.
    _runtime = claim_json.get("trace", {}).get("runtime", {})
    _is_sw_only = _is_software_only(_runtime)

    binding_result, binding_msg = _verify_key_binding(claim_json, is_sw_only=_is_sw_only)
    if binding_result is True:
        verified.append("public_key_binding")
    elif binding_result is False:
        unverified.append("public_key_binding")
        # Key binding failure is a higher-priority security signal than a signature failure:
        # a substituted key means the signing key itself cannot be trusted.
        failure = VerificationError.PUBLIC_KEY_NOT_BOUND
        details["public_key_binding"] = binding_msg or "TEE key binding verification failed"
    # binding_result is None: software-only mode -- skip (no penalty, no credit)

    # Step 2c: Optional out-of-band trusted_public_key_hex cross-check.
    # Callers may supply an externally-pinned public key hex to add an additional
    # cross-check independent of the in-claim nonce.  Recorded as "trusted_public_key"
    # so consumers can distinguish the two mechanisms.
    _x_b64 = claim_json.get("trace", {}).get("cnf", {}).get("jwk", {}).get("x", "")
    if trusted_public_key_hex:
        actual_hex = _jwk_x_to_hex(_x_b64) if _x_b64 else None
        normalized = trusted_public_key_hex.lower().removeprefix("0x")
        if actual_hex == normalized:
            verified.append("trusted_public_key")
        else:
            unverified.append("trusted_public_key")
            failure = failure or VerificationError.PUBLIC_KEY_NOT_BOUND
            details["trusted_public_key"] = "trace.cnf.jwk.x does not match trusted_public_key_hex"

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

    # Step 5: Optional Agent Manifest binding cross-check (#302).
    if agent_manifest is not None:
        agent_identity = claim_json.get("gateway", {}).get("agent_identity")
        if not isinstance(agent_identity, dict):
            unverified.append("agent_manifest.binding")
            failure = failure or VerificationError.AGENT_MANIFEST_MISMATCH
            details["agent_manifest"] = "claim has no gateway.agent_identity binding"
        elif not trusted_agent_manifest_keys:
            unverified.append("agent_manifest.binding")
            failure = failure or VerificationError.AGENT_MANIFEST_MISMATCH
            details["agent_manifest"] = "no trusted Agent Manifest issuer keys provided"
        else:
            try:
                binding = verify_agent_manifest_binding(
                    agent_manifest,
                    trusted_agent_manifest_keys,
                    authenticated_subject=agent_identity.get("authenticated_subject"),
                    authenticated_subject_source=agent_identity.get("subject_source"),
                    policy_bundle_hash=claimed_policy,
                    tool_catalog_hash=claimed_catalog,
                    allow_dev_subject_from_manifest=(
                        agent_identity.get("subject_source") == "manifest-dev"
                    ),
                )
                expected_identity = {
                    "manifest_id": binding.manifest_id,
                    "agent_id": binding.agent_id,
                    "authenticated_subject": binding.authenticated_subject,
                    "subject_source": binding.subject_source,
                    "issuer": binding.issuer,
                    "issuer_key_id": binding.issuer_key_id,
                    "policy_bundle_hash": binding.policy_bundle_hash,
                    "tool_catalog_hash": binding.tool_catalog_hash,
                }
                mismatched = [
                    key
                    for key, expected in expected_identity.items()
                    if agent_identity.get(key) != expected
                ]
                if mismatched:
                    unverified.append("agent_manifest.binding")
                    failure = failure or VerificationError.AGENT_MANIFEST_MISMATCH
                    details["agent_manifest"] = (
                        "gateway.agent_identity mismatch: " + ", ".join(mismatched)
                    )
                else:
                    verified.append("agent_manifest.binding")
            except ConfigError as exc:
                unverified.append("agent_manifest.binding")
                failure = failure or VerificationError.AGENT_MANIFEST_MISMATCH
                details["agent_manifest"] = str(exc)

    # Step 6: Attestation freshness
    age, is_fresh = _check_attestation_freshness(claim_json, max_attestation_age_seconds)
    if is_fresh:
        verified.append("attestation_freshness")
    else:
        unverified.append("attestation_freshness")
        if failure is None:
            failure = VerificationError.ATTESTATION_STALE
        details["attestation_age_seconds"] = str(age)

    # Step 7: Audit chain consistency
    chain_ok, chain_err = _check_audit_chain(claim_json)
    if chain_ok:
        verified.append("audit_chain")
    else:
        unverified.append("audit_chain")
        if failure is None:
            failure = VerificationError.CHAIN_BROKEN
        if chain_err:
            details["chain_error"] = chain_err

    # Step 8: Platform-specific attestation
    platform = _runtime.get("platform", "")

    if _is_sw_only:
        unverified.append("hardware_attestation")
        details["hardware_attestation"] = "software-only mode - not hardware-backed"
    elif platform == "tpm2":
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
            failure = failure or VerificationError.HARDWARE_ATTESTATION_FAILED
            if tpm_result.failure_reason:
                details["tpm_failure"] = tpm_result.failure_reason
        unverified.extend(tpm_result.unverified_fields)
        details.update(tpm_result.details)
    elif platform == "amd-sev-snp":
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
            failure = failure or VerificationError.HARDWARE_ATTESTATION_FAILED
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
            failure = failure or VerificationError.HARDWARE_ATTESTATION_FAILED
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
            failure = failure or VerificationError.HARDWARE_ATTESTATION_FAILED
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
