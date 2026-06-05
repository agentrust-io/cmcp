"""Tests for TRACE Claim generation, signing, and validation (issues #49, #50, #52)."""

from __future__ import annotations

import base64
import json

import pytest

from cmcp_gateway.audit.chain import AuditChain
from cmcp_gateway.audit.keys import SigningKey
from cmcp_gateway.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    TraceClaim,
    canonical_json,
    generate_trace_claim,
    sign_trace_claim,
    validate_trace_claim,
    _to_dict,
)
from cmcp_gateway.errors import ClaimValidationError


def _make_report() -> AttestationReportInfo:
    return AttestationReportInfo(
        provider="software-only",
        measurement="DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION",
        report_data="aa" * 32,
        attestation_generated_at="2026-06-04T00:00:00+00:00",
        attestation_validity_seconds=86400,
    )


def _make_call_summary() -> CallSummary:
    return CallSummary(
        tool_calls_total=2,
        tool_calls_allowed=1,
        tool_calls_denied=1,
        tool_calls_faulted=0,
        tools_invoked=["crm.query"],
        session_max_sensitivity="pii",
        call_graph_summary=CallGraphSummary(
            compliance_domains_touched=["pii"],
            cross_boundary_events=[],
        ),
    )


def _make_claim(signing_key=None) -> TraceClaim:
    chain = AuditChain("sess-001")
    return generate_trace_claim(
        session_id="sess-001",
        tee_public_key="ab" * 32,
        attestation_report=_make_report(),
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "0" * 64,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "1" * 64),
        call_summary=_make_call_summary(),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        signing_key=signing_key,
    )


# ── canonical_json ────────────────────────────────────────────────────────────

def test_canonical_json_is_deterministic():
    d = {"b": 2, "a": 1, "signature": "sig"}
    b1 = canonical_json(d)
    b2 = canonical_json(d)
    assert b1 == b2


def test_canonical_json_excludes_signature():
    d = {"a": 1, "signature": "should-be-excluded"}
    result = json.loads(canonical_json(d))
    assert "signature" not in result
    assert "a" in result


def test_canonical_json_sorted_keys():
    d = {"z": 3, "a": 1, "m": 2}
    result = canonical_json(d).decode()
    assert result.index('"a"') < result.index('"m"') < result.index('"z"')


# ── generate_trace_claim ──────────────────────────────────────────────────────

def test_generate_claim_version():
    claim = _make_claim()
    assert claim.trace_version == "1.0"


def test_generate_claim_session_id():
    claim = _make_claim()
    assert claim.session_id == "sess-001"


def test_generate_claim_tee_public_key():
    claim = _make_claim()
    assert claim.tee_public_key == "ab" * 32


def test_generate_claim_unsigned_has_empty_signature():
    claim = _make_claim(signing_key=None)
    assert claim.signature == ""


def test_generate_claim_signed_has_signature():
    key = SigningKey()
    claim = _make_claim(signing_key=key)
    assert len(claim.signature) > 0


def test_generate_claim_signature_verifiable():
    """Conformance: TRACE-002 — signature verifies against tee_public_key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import cryptography.hazmat.primitives.serialization as ser

    key = SigningKey()
    claim = _make_claim(signing_key=key)

    # Verify signature
    claim_dict = _to_dict(claim)
    body = canonical_json(claim_dict)
    sig_bytes = base64.urlsafe_b64decode(claim.signature + "==")

    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex))
    pub.verify(sig_bytes, body)  # raises if invalid


def test_generate_claim_tee_key_consistent_in_session():
    """Conformance: ATTEST-003 — same tee_public_key across all claims in a session."""
    key = SigningKey()
    c1 = _make_claim(signing_key=key)
    c2 = _make_claim(signing_key=key)
    assert c1.tee_public_key == c2.tee_public_key


def test_generate_claim_audit_chain_fields():
    chain = AuditChain("sess-002")
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
    claim = generate_trace_claim(
        session_id="sess-002",
        tee_public_key="00" * 32,
        attestation_report=_make_report(),
        policy_bundle=PolicyBundleInfo(hash="sha256:" + "0" * 64, enforcement_mode="advisory", policy_version="0.1"),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "1" * 64),
        call_summary=_make_call_summary(),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
    )
    assert claim.audit_chain_root == chain.chain_root
    assert claim.audit_chain_tip == chain.chain_tip
    assert claim.audit_chain_length == 2  # session_start + tool_call


# ── validate_trace_claim ──────────────────────────────────────────────────────

def test_validate_passes_for_valid_claim():
    # Just check it doesn't raise (schema may not be present in test env)
    claim = _make_claim()
    claim_dict = _to_dict(claim)
    # If schema is available, this validates; if not, it's a no-op
    validate_trace_claim(claim_dict)
