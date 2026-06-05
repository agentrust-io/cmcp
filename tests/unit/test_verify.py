"""Tests for cmcp-verify TRACE Claim verification (issue #59)."""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta

import pytest

from cmcp_gateway.audit.chain import AuditChain
from cmcp_gateway.audit.keys import SigningKey
from cmcp_gateway.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    generate_trace_claim,
    _to_dict,
)
from cmcp_verify.verify import (
    ApprovedHashes,
    VerificationError,
    VerificationStatus,
    verify_trace_claim,
)


POLICY_HASH = "sha256:" + "a" * 64
CATALOG_HASH = "sha256:" + "b" * 64


def _make_signed_claim(policy_hash=POLICY_HASH, catalog_hash=CATALOG_HASH):
    key = SigningKey()
    chain = AuditChain("test-session")

    claim = generate_trace_claim(
        session_id="test-session",
        signing_key=key,
        attestation_report=AttestationReportInfo(
            provider="software-only",
            measurement="DEVELOPMENT_ONLY",
            report_data="00" * 32,
            attestation_generated_at=datetime.now(tz=timezone.utc).isoformat(),
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
        do_sign=True,
    )
    return _to_dict(claim), key


def _approved():
    return ApprovedHashes(policy_bundle_hash=POLICY_HASH, tool_catalog_hash=CATALOG_HASH)


# ── Signature verification ────────────────────────────────────────────────────


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
    """TRACE-002 — signature fails if claim body is modified after signing."""
    claim_dict, _ = _make_signed_claim()
    claim_dict["gateway"]["session_id"] = "tampered-session"
    result = verify_trace_claim(claim_dict, _approved())
    assert result.failure_reason == VerificationError.SIGNATURE_INVALID


# ── Hash checks ───────────────────────────────────────────────────────────────


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


# ── Attestation freshness ─────────────────────────────────────────────────────


def test_fresh_attestation_is_verified():
    claim_dict, _ = _make_signed_claim()
    result = verify_trace_claim(claim_dict, _approved(), max_attestation_age_seconds=86400)
    assert result.is_attestation_fresh is True


def test_stale_attestation_fails():
    claim_dict, _ = _make_signed_claim()
    old = (datetime.now(tz=timezone.utc) - timedelta(days=2)).isoformat()
    claim_dict["gateway"]["attestation_generated_at"] = old
    result = verify_trace_claim(claim_dict, _approved(), max_attestation_age_seconds=86400)
    assert result.is_attestation_fresh is False


# ── Audit chain ───────────────────────────────────────────────────────────────


def test_valid_audit_chain_is_verified():
    claim_dict, _ = _make_signed_claim()
    result = verify_trace_claim(claim_dict, _approved())
    assert "audit_chain" in result.verified_fields


def test_missing_audit_chain_root_fails():
    claim_dict, _ = _make_signed_claim()
    claim_dict["gateway"]["audit_chain"]["root"] = ""
    result = verify_trace_claim(claim_dict, _approved())
    assert "audit_chain" in result.unverified_fields


# ── Status ────────────────────────────────────────────────────────────────────


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
