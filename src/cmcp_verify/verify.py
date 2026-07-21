"""
TRACE Claim verification -- implements issue #59.

Verifies a cMCP TRACE Claim without trusting the gateway operator.
Provider-specific attestation verification (TPM, SEV-SNP) is dispatched
per-provider and added in issues #62, #67.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
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


def _jwk_thumbprint_sha256(x_b64url: str) -> bytes:
    """RFC 7638 §3 JWK Thumbprint: SHA-256(UTF-8(JSON of sorted required OKP members))."""
    canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": x_b64url},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).digest()


_SW_ONLY_FIRMWARE = "software-only-dev-mode"
_EXTERNAL_EVIDENCE_ERROR = "EXTERNAL_EVIDENCE_VERIFICATION_FAILED"
_EXTERNAL_EVIDENCE_HASH_RE = re.compile(r"^sha(256|384):[0-9a-f]+$")
_ISSUER_KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_EXTERNAL_EVIDENCE_TYPES = frozenset({
    "controller-execution-receipt/v1",
    "tee-signed-receipt",
    "controller-jwt",
    "opaque-receipt",
})

_KNOWN_PLATFORMS = {
    "amd-sev-snp",
    "azure-cvm-sev-snp",
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
    CHAIN_ROOT_NOT_BOUND = "CHAIN_ROOT_NOT_BOUND"
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

    The gateway embeds the RFC 7638 JWK Thumbprint (SHA-256 of the JSON representation
    of required OKP key members, sorted lexicographically) as the first 32 bytes of the
    nonce it submits to the TEE when requesting the attestation report.  The TEE hardware
    commits that nonce into the signed report_data field.  The nonce is stored as
    trace.runtime.nonce (base64url of the full 64-byte value).

    Verifiers re-derive the RFC 7638 JWK Thumbprint from cnf.jwk.x and compare it against
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
        base64.urlsafe_b64decode(padded)  # validate encoding; bytes not needed
    except Exception as exc:
        return False, f"cannot decode trace.cnf.jwk.x: {exc}"

    # Compute RFC 7638 JWK Thumbprint -- the expected fingerprint
    expected_fingerprint = _jwk_thumbprint_sha256(x_b64)

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


def _check_audit_chain_binding(
    claim: dict[str, Any],
    *,
    is_sw_only: bool,
) -> tuple[bool | None, str | None]:
    """
    AUDIT-006: verify that the audit-chain root is committed to the hardware-signed
    report_data, not merely carried as an unauthenticated advisory field.

    The gateway submits a per-session attestation nonce of the form

        jwk_thumbprint(key) (32) || SHA-256(chain_root_bytes) (32)

    so the TEE commits SHA-256(chain_root) into report_data[32:64].  The nonce is
    surfaced as trace.runtime.nonce (base64url of the full 64-byte value).

    The verifier re-derives SHA-256(SHA-256-hex-decode(gateway.audit_chain.root))
    and compares it constant-time against nonce[32:64].  A mismatch means the chain
    root in the claim is NOT the one attested by the hardware: a rogue operator who
    rebuilt a fresh, internally-consistent chain (different root) re-signed the claim
    with the in-enclave key but could not forge the TEE-committed report_data.  This
    is FATAL.

    Returns:
        (True,  None)          -- chain root commitment matches report_data[32:64]
        (False, reason)        -- mismatch / missing commitment; reject (fail closed)
        (None,  warning_msg)   -- software-only / Level-0 mode; not hardware-backed
    """
    root = claim.get("gateway", {}).get("audit_chain", {}).get("root", "")
    if not root:
        # _check_audit_chain already reports the empty-root failure; nothing to bind.
        return False, "gateway.audit_chain.root is empty -- cannot verify chain-root binding"

    # The chain root may carry a "sha256:" prefix in some serializations; the bytes
    # committed to the TEE are those of the bare hex digest (the entry_hash).
    root_hex = root.removeprefix("sha256:").removeprefix("sha384:")
    try:
        root_bytes = bytes.fromhex(root_hex)
    except ValueError as exc:
        return False, f"gateway.audit_chain.root is not valid hex: {exc}"
    expected_commitment = hashlib.sha256(root_bytes).digest()

    nonce_b64 = claim.get("trace", {}).get("runtime", {}).get("nonce", "")
    if not nonce_b64:
        if is_sw_only:
            return None, "software-only mode -- chain-root binding not applicable"
        return False, (
            "trace.runtime.nonce is absent -- attestation report_data does not "
            "commit the audit-chain root"
        )

    try:
        padding = 4 - (len(nonce_b64) % 4)
        padded = nonce_b64 + ("=" * padding if padding != 4 else "")
        nonce_bytes = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        return False, f"cannot decode trace.runtime.nonce: {exc}"

    if len(nonce_bytes) < 64:
        if is_sw_only:
            return None, (
                "software-only mode -- report_data does not carry a chain-root "
                "commitment in bytes [32:64]"
            )
        return False, (
            f"trace.runtime.nonce is too short ({len(nonce_bytes)} bytes); "
            "expected 64 bytes (key fingerprint || chain-root commitment)"
        )

    actual_commitment = nonce_bytes[32:64]
    if not hmac.compare_digest(actual_commitment, expected_commitment):
        # A mismatch is always fatal, including in software-only mode: the chain
        # root presented in the claim is not the one bound into report_data.
        return False, (
            "gateway.audit_chain.root does not match report_data[32:64] -- the "
            "audit-chain root was not committed to this attestation report; the "
            "chain may have been substituted after attestation"
        )

    if is_sw_only:
        logger.warning(
            "AUDIT-006: software-only (dev) mode -- chain-root commitment matches "
            "but provides no hardware provenance guarantee"
        )
        return None, "software-only mode -- chain-root binding not hardware-backed"

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


def _external_evidence_failure(entry_index: int, reason: str) -> str:
    return f"entry {entry_index}: {_EXTERNAL_EVIDENCE_ERROR}: {reason}"


def verify_audit_bundle(
    bundle_json: dict[str, Any],
    claim_json: dict[str, Any] | None = None,
    *,
    external_evidence_keys: dict[str, bytes] | None = None,
) -> AuditBundleResult:
    """
    Verify an exported audit bundle (GET /audit/export):

    1. Recompute every entry hash from its canonical body and check the
       prev_entry_hash linkage from "genesis" to the tip.
    2. If a claim is provided, cross-check the bundle's root/tip/length
       against gateway.audit_chain and verify the bundle_signature with the
       claim's confirmation key (trace.cnf.jwk.x).
    3. #301: if external_evidence_keys is provided (issuer_key_id -> raw Ed25519
       public key bytes), verify any external_execution_evidence receipt bound to an
       entry: linked_call_id must equal the entry call_id, and the issuer
       signature must verify over the canonical receipt (all fields except
       signature). This is opt-in: receipt-less entries and callers that do not
       supply keys are unaffected, so existing evidence keeps verifying.
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

    # #301: verify independent execution receipts (opt-in via external_evidence_keys).
    if external_evidence_keys is not None:
        for i, entry in enumerate(entries):
            ev = entry.get("external_execution_evidence")
            if not ev:
                continue
            if not isinstance(ev, dict):
                failures.append(
                    _external_evidence_failure(i, "external_execution_evidence is not an object")
                )
                continue
            if ev.get("linked_call_id") != entry.get("call_id"):
                failures.append(
                    _external_evidence_failure(
                        i,
                        "external_execution_evidence linked_call_id does not match "
                        "the entry call_id",
                    )
                )
                # Fail closed: a receipt bound to a different call_id must never
                # also be reported as signature-valid. Stop processing this entry.
                continue
            key_id = ev.get("issuer_key_id", "")
            if not isinstance(key_id, str) or not _ISSUER_KEY_ID_RE.match(key_id):
                failures.append(
                    _external_evidence_failure(
                        i,
                        "issuer_key_id must be lowercase hex SHA-256 of the issuer public key",
                    )
                )
                continue
            evidence_hash = ev.get("evidence_hash", "")
            if not isinstance(evidence_hash, str) or not _EXTERNAL_EVIDENCE_HASH_RE.match(evidence_hash):
                failures.append(
                    _external_evidence_failure(
                        i, "evidence_hash must be sha256:<hex> or sha384:<hex>"
                    )
                )
                continue
            evidence_type = ev.get("evidence_type", "")
            if evidence_type not in _EXTERNAL_EVIDENCE_TYPES:
                failures.append(
                    _external_evidence_failure(i, f"unsupported evidence_type '{evidence_type}'")
                )
                continue
            pub_bytes = external_evidence_keys.get(key_id)
            if not pub_bytes:
                failures.append(
                    _external_evidence_failure(
                        i, f"no trusted key for external evidence issuer_key_id '{key_id}'"
                    )
                )
                continue
            try:
                if len(pub_bytes) != 32:
                    raise ValueError("trusted issuer key must be 32 raw Ed25519 public key bytes")
                if hashlib.sha256(pub_bytes).hexdigest() != key_id:
                    raise ValueError("issuer_key_id does not match trusted issuer public key")
                pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
                signing_input = json.dumps(
                    {k: v for k, v in ev.items() if k != "signature"},
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode()
                sig_b64 = ev.get("signature", "")
                pad = 4 - (len(sig_b64) % 4)
                sig = base64.urlsafe_b64decode(sig_b64 + ("=" * pad if pad != 4 else ""))
                pub.verify(sig, signing_input)
            except InvalidSignature:
                failures.append(
                    _external_evidence_failure(i, "external_execution_evidence signature is invalid")
                )
            except Exception as exc:
                failures.append(
                    _external_evidence_failure(
                        i, f"external_execution_evidence could not be verified: {exc}"
                    )
                )

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
    trusted_ark_pem: bytes | None = None,
    trusted_intel_root_pem: bytes | None = None,
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
    7b. AUDIT-006: audit-chain root binding -- report_data[32:64] commits SHA-256(chain_root)
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

    # Step 7b: AUDIT-006 -- audit-chain root binding into report_data.
    # The chain root must be committed to the hardware-signed report_data
    # (report_data[32:64] == SHA-256(chain_root)), not merely asserted in the
    # advisory gateway.audit_chain.root field.  A mismatch is FATAL: it means a
    # rogue operator rebuilt the chain and re-signed the claim but could not forge
    # the TEE-committed commitment.  Only attempted when the chain is well-formed.
    if chain_ok:
        root_binding, root_binding_msg = _check_audit_chain_binding(
            claim_json, is_sw_only=_is_sw_only
        )
        if root_binding is True:
            verified.append("audit_chain_binding")
        elif root_binding is False:
            unverified.append("audit_chain_binding")
            failure = failure or VerificationError.CHAIN_ROOT_NOT_BOUND
            details["audit_chain_binding"] = (
                root_binding_msg or "audit-chain root binding verification failed"
            )
        else:
            # software-only / Level-0 mode: not hardware-backed, no penalty/credit.
            if root_binding_msg:
                details["audit_chain_binding"] = root_binding_msg

    # Step 8: Platform-specific attestation
    platform = _runtime.get("platform", "")

    if _is_sw_only:
        unverified.append("hardware_attestation")
        details["hardware_attestation"] = "software-only mode - not hardware-backed"
    elif platform == "tpm2":
        from cmcp_verify.tpm import verify_tpm_measurement

        raw_ev = _runtime.get("raw_evidence")
        raw_bytes = base64.b64decode(raw_ev) if raw_ev else None
        # The TPM quote commits the attestation nonce's first 32 bytes -- the RFC 7638
        # JWK Thumbprint of the TEE key -- as qualifying_data (§3.3). Re-derive it from
        # cnf.jwk.x so a substituted key is detected.
        _tpm_jwk_x = claim_json.get("trace", {}).get("cnf", {}).get("jwk", {}).get("x")
        _expected_qd = _jwk_thumbprint_sha256(_tpm_jwk_x) if _tpm_jwk_x else None
        tpm_result = verify_tpm_measurement(
            measurement=_runtime.get("measurement", ""),
            raw_evidence=raw_bytes,
            expected_qualifying_data=_expected_qd,
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
    elif platform == "azure-cvm-sev-snp":
        # Azure confidential VM: SEV-SNP behind a Hyper-V paravisor, vTPM-rooted.
        # The guest cannot control SNP REPORT_DATA (the paravisor binds the vTPM AK
        # there), so cMCP's nonce is committed into an AK-signed TPM quote's extraData
        # and the AK is rooted in silicon by the SNP report (REPORT_DATA ==
        # sha256(runtime_data)). The VCEK chain travels in the JSON evidence envelope;
        # the ARK is pinned out of band. Hardware-validated on live Azure SEV-SNP.
        from cmcp_verify.azure_cvm import verify_azure_cvm_measurement

        raw_bytes = base64.b64decode(_runtime["raw_evidence"])
        azure_result = verify_azure_cvm_measurement(
            measurement=_runtime.get("measurement", ""),
            raw_evidence=raw_bytes,
            report_data_hex=_runtime.get("report_data"),
            trusted_ark_pem=trusted_ark_pem,
        )
        chain_ok = "vcek_cert_chain" not in azure_result.unverified_fields
        if azure_result.verified and chain_ok:
            verified.append("hardware_attestation")
            verified.extend(azure_result.verified_fields)
        elif azure_result.verified and not chain_ok:
            verified.extend(azure_result.verified_fields)
            unverified.append("hardware_attestation")
            details["hardware_attestation"] = (
                "Azure CVM quote checked but VCEK chain/signature not verified"
            )
        else:
            unverified.append("hardware_attestation")
            failure = failure or VerificationError.HARDWARE_ATTESTATION_FAILED
            if azure_result.failure_reason:
                details["azure_cvm_failure"] = azure_result.failure_reason
        unverified.extend(azure_result.unverified_fields)
        details.update(azure_result.details)
    elif platform == "amd-sev-snp":
        from cmcp_verify.sev_snp import verify_sev_snp_measurement

        raw_ev = _runtime.get("raw_evidence")
        raw_bytes = base64.b64decode(raw_ev) if raw_ev else None
        report_data_hex = _runtime.get("report_data")
        # VCEK/ASK/ARK chain travels with the claim (passport model); the ARK is
        # pinned by the operator out of band. Both are needed for issue #370
        # report-signature + chain verification; absent either, it stays unverified.
        _chain_b64 = _runtime.get("cert_chain")
        cert_chain_pem = base64.b64decode(_chain_b64) if _chain_b64 else None
        snp_result = verify_sev_snp_measurement(
            measurement=_runtime.get("measurement", ""),
            raw_evidence=raw_bytes,
            report_data_hex=report_data_hex,
            cert_chain_pem=cert_chain_pem,
            trusted_ark_pem=trusted_ark_pem,
        )
        # The VCEK chain is the SNP hardware root of trust. Even when the report
        # parses and the measurement matches, a claim whose chain is unverified
        # must never be reported as fully VERIFIED (issues #370/#372) -- it stays
        # PARTIALLY_VERIFIED.
        chain_ok = "vcek_cert_chain" not in snp_result.unverified_fields
        if snp_result.verified and chain_ok:
            verified.append("hardware_attestation")
            verified.extend(snp_result.verified_fields)
        elif snp_result.verified and not chain_ok:
            verified.extend(snp_result.verified_fields)
            unverified.append("hardware_attestation")
            details["hardware_attestation"] = (
                "SNP report checked but VCEK chain/signature not verified"
            )
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
        # The DCAP quote (with its embedded PCK cert chain) travels with the claim
        # (passport model); the Intel SGX/TDX root CA is pinned by the operator out
        # of band. Both are needed for issue #370 quote-signature verification;
        # absent either, quote verification stays unverified.
        _quote_b64 = _runtime.get("raw_quote")
        raw_quote = base64.b64decode(_quote_b64) if _quote_b64 else None
        tdx_result = verify_tdx_measurement(
            measurement=_runtime.get("measurement", ""),
            raw_evidence=raw_bytes,
            report_data_hex=report_data_hex,
            raw_quote=raw_quote,
            trusted_intel_root_pem=trusted_intel_root_pem,
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
        # Fail closed: a claim with no hardware-backed attestation (software-only
        # or any non-hardware-backed path) is never fully VERIFIED, even when it is
        # otherwise self-consistent. See LIMITATIONS.md. A real failure below still
        # takes precedence and is not downgraded to partial.
        if "hardware_attestation" in unverified:
            status = VerificationStatus.PARTIALLY_VERIFIED
        else:
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
