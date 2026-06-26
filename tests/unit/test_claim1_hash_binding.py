"""Tests for Claim 1: policy bundle hash binding properties.

These tests assert invariants the claim1 experiment demonstrates. They run
in CI against every bundle change and catch regressions in hash determinism,
avalanche behaviour, mismatch enforcement, and TRACE Claim signature coverage.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    generate_trace_claim,
)
from cmcp_runtime.errors import PolicyHashMismatch
from cmcp_runtime.policy.bundle import load_policy_bundle

FIXTURES = (
    Path(__file__).parent.parent.parent
    / "experiments"
    / "claim1-policy-hash-binding"
    / "fixtures"
)
BUNDLE_V1 = FIXTURES / "bundle-v1"
BUNDLE_V2 = FIXTURES / "bundle-v2"


def _verify_sig(claim_dict: dict, pub_hex: str) -> bool:
    sig_b64 = claim_dict.get("signature", "")
    # urlsafe_b64decode requires padding; add "==" which is idempotent if already padded
    sig = base64.urlsafe_b64decode(sig_b64 + "==")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    body = {k: v for k, v in claim_dict.items() if k != "signature"}
    body_bytes = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    try:
        pub.verify(sig, body_bytes)
        return True
    except Exception:
        return False


def _stub_claim(bundle_hash: str, signing_key: SigningKey):
    report = AttestationReportInfo(
        provider="software-only",
        measurement="DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION",
        report_data="aa" * 32,
        attestation_generated_at="2026-06-25T00:00:00Z",
        attestation_validity_seconds=86400,
    )
    policy = PolicyBundleInfo(
        hash=bundle_hash,
        enforcement_mode="enforcing",
        policy_version="1.0.0",
    )
    catalog = ToolCatalogInfo(hash="sha256:" + "0" * 64)
    summary = CallSummary(
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
    )
    return generate_trace_claim(
        session_id="test-session",
        signing_key=signing_key,
        attestation_report=report,
        policy_bundle=policy,
        tool_catalog=catalog,
        call_summary=summary,
        audit_chain_root="sha256:" + "0" * 64,
        audit_chain_tip="sha256:" + "0" * 64,
        audit_chain_length=0,
    )


def test_hash_determinism():
    """Same bundle loaded twice produces the same hash."""
    b1 = load_policy_bundle(str(BUNDLE_V1))
    b2 = load_policy_bundle(str(BUNDLE_V1))
    assert b1.bundle_hash == b2.bundle_hash


def test_avalanche_one_char_change():
    """A single-character change in a policy file changes at least 64 of 256 hash bits."""
    b1 = load_policy_bundle(str(BUNDLE_V1))
    b2 = load_policy_bundle(str(BUNDLE_V2))
    assert b1.bundle_hash != b2.bundle_hash
    h1 = bytes.fromhex(b1.bundle_hash.removeprefix("sha256:"))
    h2 = bytes.fromhex(b2.bundle_hash.removeprefix("sha256:"))
    bits_diff = sum(bin(a ^ b).count("1") for a, b in zip(h1, h2))
    assert bits_diff > 64, f"Expected >64 bits to change on single-char delta, got {bits_diff}"


def test_mismatch_raises_on_wrong_expected_hash():
    """load_policy_bundle raises PolicyHashMismatch when expected_hash does not match disk."""
    b1 = load_policy_bundle(str(BUNDLE_V1))
    with pytest.raises(PolicyHashMismatch):
        load_policy_bundle(str(BUNDLE_V2), expected_hash=b1.bundle_hash)


def test_correct_hash_passes():
    """load_policy_bundle succeeds when expected_hash matches the loaded bundle."""
    b1 = load_policy_bundle(str(BUNDLE_V1))
    result = load_policy_bundle(str(BUNDLE_V1), expected_hash=b1.bundle_hash)
    assert result.bundle_hash == b1.bundle_hash


def test_trace_claim_signature_valid():
    """A freshly generated TRACE Claim signature verifies against the embedded public key."""
    b1 = load_policy_bundle(str(BUNDLE_V1))
    key = SigningKey()
    claim = _stub_claim(b1.bundle_hash, key)
    claim_dict = json.loads(claim.model_dump_json(exclude_none=True))
    assert _verify_sig(claim_dict, key.public_key_hex)


def test_trace_claim_signature_broken_by_hash_tamper():
    """Replacing the bundle_hash field in a signed TRACE Claim breaks signature verification."""
    b1 = load_policy_bundle(str(BUNDLE_V1))
    b2 = load_policy_bundle(str(BUNDLE_V2))
    key = SigningKey()
    claim = _stub_claim(b1.bundle_hash, key)
    claim_dict = json.loads(claim.model_dump_json(exclude_none=True))
    claim_dict["trace"]["policy"]["bundle_hash"] = b2.bundle_hash
    assert not _verify_sig(claim_dict, key.public_key_hex)
