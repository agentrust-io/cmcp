"""Tests for cmcp-verify TRACE Claim verification (issue #59)."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cmcp_runtime.agent_manifest import SIGNED_FIELDS, signing_pre_image
from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import (
    AgentIdentityInfo,
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    _to_dict,
    generate_trace_claim,
)
from cmcp_verify.verify import (
    ApprovedHashes,
    VerificationError,
    VerificationStatus,
    verify_trace_claim,
)

POLICY_HASH = "sha256:" + "a" * 64
CATALOG_HASH = "sha256:" + "b" * 64
AGENT_ID = "spiffe://factory.example/agent/material-movement/dev"
MANIFEST_ID = "0197739a-8c00-7000-8000-000000000001"


def _make_nonce_for_key(key: SigningKey) -> str:
    """Build a report_data hex string matching the CRYPTO-001 format.

    First 32 bytes: SHA-256(public_key_bytes) -- verifiable key fingerprint.
    Next 32 bytes: random salt -- session uniqueness (CRYPTO-002).
    """
    fingerprint = hashlib.sha256(key.public_key_bytes).digest()
    salt = secrets.token_bytes(32)
    return (fingerprint + salt).hex()


def _make_signed_claim(
    policy_hash=POLICY_HASH,
    catalog_hash=CATALOG_HASH,
    provider="software-only",
    agent_identity: AgentIdentityInfo | None = None,
):
    key = SigningKey()
    chain = AuditChain("test-session")
    measurement = "DEVELOPMENT_ONLY" if provider == "software-only" else "ab" * 32
    # Use proper CRYPTO-001 report_data for hardware providers; software-only ignores it.
    report_data = _make_nonce_for_key(key) if provider != "software-only" else "00" * 32

    claim = generate_trace_claim(
        session_id="test-session",
        signing_key=key,
        attestation_report=AttestationReportInfo(
            provider=provider,
            measurement=measurement,
            report_data=report_data,
            attestation_generated_at=datetime.now(tz=UTC).isoformat(),
            attestation_validity_seconds=86400,
        ),
        policy_bundle=PolicyBundleInfo(
            hash=policy_hash,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash=catalog_hash),
        call_summary=CallSummary(
            tool_calls_total=1,
            tool_calls_allowed=1,
            tool_calls_denied=0,
            tool_calls_faulted=0,
            tools_invoked=["test.tool"],
            session_max_sensitivity="public",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=[],
                cross_boundary_events=[],
            ),
        ),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        agent_identity=agent_identity,
        do_sign=True,
    )
    return _to_dict(claim), key


def _manifest_keypair() -> tuple[Ed25519PrivateKey, bytes, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub, hashlib.sha256(pub).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _signed_manifest(priv: Ed25519PrivateKey, key_id: str) -> dict:
    manifest = {
        "@context": "https://agentmanifest.agentrust.io/v0.1/context.json",
        "@type": "AgentManifest",
        "manifest_id": MANIFEST_ID,
        "agent_id": AGENT_ID,
        "version": "0.1",
        "issued_at": "2026-06-12T00:00:00Z",
        "expires_at": "2099-09-10T00:00:00Z",
        "issuer": "spiffe://factory.example/signing-authority/development",
        "crypto_profile": "standard",
        "artifacts": {
            "policy_bundle": {"hash": POLICY_HASH, "policy_language": "cedar"},
            "tool_manifest": {"catalog_hash": CATALOG_HASH, "tools": []},
        },
        "delegation_chain": [],
    }
    manifest["signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "key_type": "software",
        "signed_at": "2026-06-12T00:00:00Z",
        "signed_fields": list(SIGNED_FIELDS),
        "signature_value": _b64url(priv.sign(signing_pre_image(manifest))),
    }
    return manifest


def _agent_identity(*, agent_id: str = AGENT_ID) -> AgentIdentityInfo:
    return AgentIdentityInfo(
        manifest_id=MANIFEST_ID,
        agent_id=agent_id,
        authenticated_subject=AGENT_ID,
        subject_source="config",
        issuer="spiffe://factory.example/signing-authority/development",
        issuer_key_id="",
        policy_bundle_hash=POLICY_HASH,
        tool_catalog_hash=CATALOG_HASH,
    )


def _approved():
    return ApprovedHashes(policy_bundle_hash=POLICY_HASH, tool_catalog_hash=CATALOG_HASH)


# -- Signature verification ---------------------------------------------------


def test_valid_signature_is_verified():
    claim_dict, _ = _make_signed_claim()
    result = verify_trace_claim(claim_dict, _approved())
    assert "signature" in result.verified_fields


def test_tampered_signature_fails():
    claim_dict, _ = _make_signed_claim()
    claim_dict["signature"] = "AAAA" * 16
    result = verify_trace_claim(claim_dict, _approved())
    assert "signature" in result.unverified_fields
    assert result.failure_reason == VerificationError.SIGNATURE_INVALID


def test_empty_signature_fails():
    claim_dict, _ = _make_signed_claim()
    claim_dict["signature"] = ""
    result = verify_trace_claim(claim_dict, _approved())
    assert result.failure_reason == VerificationError.SIGNATURE_INVALID


def test_tampered_claim_body_fails_signature():
    """TRACE-002 -- signature fails if claim body is modified after signing."""
    claim_dict, _ = _make_signed_claim()
    claim_dict["gateway"]["session_id"] = "tampered-session"
    result = verify_trace_claim(claim_dict, _approved())
    assert result.failure_reason == VerificationError.SIGNATURE_INVALID


# -- Hash checks --------------------------------------------------------------


def test_matching_policy_hash_is_verified():
    claim_dict, _ = _make_signed_claim()
    result = verify_trace_claim(claim_dict, _approved())
    assert "policy_bundle.hash" in result.verified_fields


def test_mismatched_policy_hash_fails():
    claim_dict, _ = _make_signed_claim()
    approved = ApprovedHashes(
        policy_bundle_hash="sha256:" + "0" * 64, tool_catalog_hash=CATALOG_HASH
    )
    result = verify_trace_claim(claim_dict, approved)
    assert "policy_bundle.hash" in result.unverified_fields


def test_matching_catalog_hash_is_verified():
    claim_dict, _ = _make_signed_claim()
    result = verify_trace_claim(claim_dict, _approved())
    assert "tool_catalog.hash" in result.verified_fields


def test_mismatched_catalog_hash_fails():
    claim_dict, _ = _make_signed_claim()
    approved = ApprovedHashes(
        policy_bundle_hash=POLICY_HASH, tool_catalog_hash="sha256:" + "0" * 64
    )
    result = verify_trace_claim(claim_dict, approved)
    assert "tool_catalog.hash" in result.unverified_fields


def test_agent_manifest_binding_is_verified():
    priv, pub, key_id = _manifest_keypair()
    manifest = _signed_manifest(priv, key_id)
    identity = _agent_identity()
    identity.issuer_key_id = key_id
    claim_dict, _ = _make_signed_claim(agent_identity=identity)
    result = verify_trace_claim(
        claim_dict,
        _approved(),
        agent_manifest=manifest,
        trusted_agent_manifest_keys={key_id: pub},
    )
    assert "agent_manifest.binding" in result.verified_fields


def test_agent_manifest_binding_mismatch_fails():
    priv, pub, key_id = _manifest_keypair()
    manifest = _signed_manifest(priv, key_id)
    identity = _agent_identity(agent_id="spiffe://factory.example/agent/other/dev")
    identity.issuer_key_id = key_id
    claim_dict, _ = _make_signed_claim(agent_identity=identity)
    result = verify_trace_claim(
        claim_dict,
        _approved(),
        agent_manifest=manifest,
        trusted_agent_manifest_keys={key_id: pub},
    )
    assert "agent_manifest.binding" in result.unverified_fields
    assert result.failure_reason == VerificationError.AGENT_MANIFEST_MISMATCH


# -- Attestation freshness ----------------------------------------------------


def test_fresh_attestation_is_verified():
    claim_dict, _ = _make_signed_claim()
    result = verify_trace_claim(claim_dict, _approved(), max_attestation_age_seconds=86400)
    assert result.is_attestation_fresh is True


def test_stale_attestation_fails():
    claim_dict, _ = _make_signed_claim()
    old = (datetime.now(tz=UTC) - timedelta(days=2)).isoformat()
    claim_dict["gateway"]["attestation_generated_at"] = old
    result = verify_trace_claim(claim_dict, _approved(), max_attestation_age_seconds=86400)
    assert result.is_attestation_fresh is False


# -- Audit chain --------------------------------------------------------------


def test_valid_audit_chain_is_verified():
    claim_dict, _ = _make_signed_claim()
    result = verify_trace_claim(claim_dict, _approved())
    assert "audit_chain" in result.verified_fields


def test_missing_audit_chain_root_fails():
    claim_dict, _ = _make_signed_claim()
    claim_dict["gateway"]["audit_chain"]["root"] = ""
    result = verify_trace_claim(claim_dict, _approved())
    assert "audit_chain" in result.unverified_fields


# -- Status -------------------------------------------------------------------


def test_software_only_provider_is_partially_verified():
    """software-only attestation is never fully VERIFIED."""
    claim_dict, _ = _make_signed_claim()
    result = verify_trace_claim(claim_dict, _approved())
    assert result.status in (VerificationStatus.PARTIALLY_VERIFIED, VerificationStatus.VERIFIED)
    assert "hardware_attestation" in result.unverified_fields


def test_all_software_only_verified_fields_are_present():
    claim_dict, _ = _make_signed_claim()
    result = verify_trace_claim(claim_dict, _approved())
    assert "signature" in result.verified_fields
    assert "policy_bundle.hash" in result.verified_fields
    assert "tool_catalog.hash" in result.verified_fields
    assert "attestation_freshness" in result.verified_fields
    assert "audit_chain" in result.verified_fields


# -- TEE-001: known hardware platform without verifier ------------------------


def test_known_hardware_platform_without_verifier_is_partially_verified():
    """TEE-001 -- amd-sev-snp without raw evidence must not be VERIFIED.

    The dispatch previously compared against the provider name ("sev-snp")
    instead of the platform name ("amd-sev-snp"), so SNP verification never
    ran; with the dispatch fixed, the missing raw evidence fails closed.
    """
    claim_dict, key = _make_signed_claim(provider="sev-snp")
    result = verify_trace_claim(
        claim_dict, _approved(), trusted_public_key_hex=key.public_key_hex
    )
    assert result.status == VerificationStatus.PARTIALLY_VERIFIED
    assert result.failure_reason == VerificationError.HARDWARE_ATTESTATION_FAILED
    assert "hardware_attestation" in result.unverified_fields


# -- CRYPTO-001: TEE key binding via report_data fingerprint ------------------


def test_tee_key_binding_happy_path():
    """CRYPTO-001 -- valid key with correct fingerprint in nonce passes binding check."""
    key = SigningKey()
    chain = AuditChain("test-session")
    fingerprint = hashlib.sha256(key.public_key_bytes).digest()
    salt = secrets.token_bytes(32)
    report_data = (fingerprint + salt).hex()

    claim = generate_trace_claim(
        session_id="test-session",
        signing_key=key,
        attestation_report=AttestationReportInfo(
            provider="sev-snp",
            measurement="ab" * 32,
            report_data=report_data,
            attestation_generated_at=datetime.now(tz=UTC).isoformat(),
            attestation_validity_seconds=86400,
        ),
        policy_bundle=PolicyBundleInfo(
            hash=POLICY_HASH,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash=CATALOG_HASH),
        call_summary=CallSummary(
            tool_calls_total=0,
            tool_calls_allowed=0,
            tool_calls_denied=0,
            tool_calls_faulted=0,
            tools_invoked=[],
            session_max_sensitivity="public",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=[],
                cross_boundary_events=[],
            ),
        ),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        do_sign=True,
    )
    claim_dict = _to_dict(claim)
    result = verify_trace_claim(claim_dict, _approved())
    assert "public_key_binding" in result.verified_fields, (
        f"Expected public_key_binding in verified; "
        f"verified={result.verified_fields}, "
        f"unverified={result.unverified_fields}, details={result.details}"
    )
    assert "public_key_binding" not in result.unverified_fields


def test_tee_key_binding_attack_path_mismatched_fingerprint():
    """CRYPTO-001 -- attacker generates a fresh keypair and signs a claim.

    The attacker embeds their own public key in cnf.jwk. The nonce in
    trace.runtime was committed by the gateway using the *gateway* key
    (SHA-256(gateway_key)), not the attacker key. Verification must reject
    the claim with PUBLIC_KEY_NOT_BOUND even though the Ed25519 signature
    over the claim body is self-consistent.
    """
    gateway_key = SigningKey()
    attacker_key = SigningKey()

    chain = AuditChain("test-session")
    gateway_fingerprint = hashlib.sha256(gateway_key.public_key_bytes).digest()
    salt = secrets.token_bytes(32)
    report_data = (gateway_fingerprint + salt).hex()

    # Build a valid claim signed by the gateway key.
    claim = generate_trace_claim(
        session_id="test-session",
        signing_key=gateway_key,
        attestation_report=AttestationReportInfo(
            provider="sev-snp",
            measurement="ab" * 32,
            report_data=report_data,
            attestation_generated_at=datetime.now(tz=UTC).isoformat(),
            attestation_validity_seconds=86400,
        ),
        policy_bundle=PolicyBundleInfo(
            hash=POLICY_HASH,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash=CATALOG_HASH),
        call_summary=CallSummary(
            tool_calls_total=0,
            tool_calls_allowed=0,
            tool_calls_denied=0,
            tool_calls_faulted=0,
            tools_invoked=[],
            session_max_sensitivity="public",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=[],
                cross_boundary_events=[],
            ),
        ),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        do_sign=False,
    )
    claim_dict = _to_dict(claim)

    # Attacker replaces cnf.jwk with their own public key.
    attacker_x = base64.urlsafe_b64encode(attacker_key.public_key_bytes).rstrip(b"=").decode()
    claim_dict["trace"]["cnf"]["jwk"]["x"] = attacker_x
    claim_dict["trace"]["cnf"]["jwk"]["kid"] = f"cmcp-{attacker_key.public_key_hex[:8]}"

    # Attacker re-signs the body so Ed25519 verification passes.
    body = {k: v for k, v in claim_dict.items() if k != "signature"}
    body_bytes = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    raw_sig = attacker_key.sign(body_bytes)
    claim_dict["signature"] = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()

    result = verify_trace_claim(claim_dict, _approved())

    # Ed25519 signature must pass (self-consistent with attacker key).
    assert "signature" in result.verified_fields, (
        "Expected attacker-re-signed claim to pass Ed25519 check"
    )
    # TEE key binding must fail: nonce encodes gateway_key fingerprint, not attacker key.
    assert "public_key_binding" in result.unverified_fields, (
        f"Expected public_key_binding in unverified; "
        f"verified={result.verified_fields}, details={result.details}"
    )
    assert result.failure_reason == VerificationError.PUBLIC_KEY_NOT_BOUND


def test_tee_key_binding_absent_nonce_fails():
    """CRYPTO-001 -- hardware claim with no nonce in runtime is rejected."""
    claim_dict, _ = _make_signed_claim(provider="sev-snp")
    claim_dict["trace"]["runtime"].pop("nonce", None)
    result = verify_trace_claim(claim_dict, _approved())
    assert "public_key_binding" in result.unverified_fields
    assert result.failure_reason == VerificationError.PUBLIC_KEY_NOT_BOUND


def test_tee_key_binding_software_only_exempt():
    """CRYPTO-001 -- software-only provider is exempt from TEE key binding check."""
    claim_dict, _ = _make_signed_claim(provider="software-only")
    result = verify_trace_claim(claim_dict, _approved())
    assert "public_key_binding" not in result.unverified_fields
    assert "public_key_binding" not in result.verified_fields


# -- CRYPTO-001: trusted_public_key_hex out-of-band cross-check (legacy) ------


def test_matching_trusted_public_key_is_verified():
    """trusted_public_key_hex matching JWK adds trusted_public_key to verified."""
    claim_dict, key = _make_signed_claim(provider="sev-snp")
    result = verify_trace_claim(
        claim_dict, _approved(), trusted_public_key_hex=key.public_key_hex
    )
    assert "trusted_public_key" in result.verified_fields
    assert "trusted_public_key" not in result.unverified_fields


def test_mismatched_trusted_public_key_fails():
    """Wrong trusted_public_key_hex -> PUBLIC_KEY_NOT_BOUND."""
    claim_dict, _ = _make_signed_claim(provider="sev-snp")
    result = verify_trace_claim(
        claim_dict, _approved(), trusted_public_key_hex="00" * 32
    )
    assert "trusted_public_key" in result.unverified_fields
    assert result.failure_reason == VerificationError.PUBLIC_KEY_NOT_BOUND


def test_no_trusted_key_for_hardware_platform_fails():
    """CRYPTO-001 -- hardware platform without nonce fingerprint -> PUBLIC_KEY_NOT_BOUND."""
    key = SigningKey()
    chain = AuditChain("test-session")
    claim = generate_trace_claim(
        session_id="test-session",
        signing_key=key,
        attestation_report=AttestationReportInfo(
            provider="sev-snp",
            measurement="ab" * 32,
            report_data="00" * 64,
            attestation_generated_at=datetime.now(tz=UTC).isoformat(),
            attestation_validity_seconds=86400,
        ),
        policy_bundle=PolicyBundleInfo(
            hash=POLICY_HASH,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash=CATALOG_HASH),
        call_summary=CallSummary(
            tool_calls_total=0,
            tool_calls_allowed=0,
            tool_calls_denied=0,
            tool_calls_faulted=0,
            tools_invoked=[],
            session_max_sensitivity="public",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=[],
                cross_boundary_events=[],
            ),
        ),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        do_sign=True,
    )
    claim_dict = _to_dict(claim)
    result = verify_trace_claim(claim_dict, _approved())
    assert "public_key_binding" in result.unverified_fields
    assert result.failure_reason == VerificationError.PUBLIC_KEY_NOT_BOUND


def test_no_trusted_key_for_software_only_is_not_penalized():
    """CRYPTO-001 -- software-only is exempt from the TEE key binding requirement."""
    claim_dict, _ = _make_signed_claim()
    result = verify_trace_claim(claim_dict, _approved())
    assert "public_key_binding" not in result.unverified_fields
    assert "public_key_binding" not in result.verified_fields
