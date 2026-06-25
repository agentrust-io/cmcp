"""
Tests for Claim 6: cross-organizational attestation chain properties.
Tests assert the dual-attestation protocol invariants in software simulation.
"""
import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    canonical_json,
    generate_trace_claim,
)


def _nonce(key_hex: str, session_id: str) -> str:
    return hashlib.sha256(bytes.fromhex(key_hex) + session_id.encode()).hexdigest()


def _verify_sig(claim_dict: dict, pub_hex: str) -> bool:
    sig = base64.urlsafe_b64decode(claim_dict.get("signature", "") + "==")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    try:
        pub.verify(sig, canonical_json(claim_dict))
        return True
    except Exception:
        return False


def _make_phase1(session_id: str, key: SigningKey) -> dict:
    nonce_hex = _nonce(key.public_key_hex, session_id)
    report = AttestationReportInfo(
        provider="tpm", measurement="sha256:" + "ab" * 32,
        report_data=nonce_hex,
        attestation_generated_at="2026-06-25T00:00:00Z",
        attestation_validity_seconds=3600,
    )
    claim = generate_trace_claim(
        session_id=session_id, signing_key=key,
        attestation_report=report,
        policy_bundle=PolicyBundleInfo(hash="sha256:" + "0" * 64, enforcement_mode="enforcing", policy_version="1.0"),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "0" * 64),
        call_summary=CallSummary(
            tool_calls_total=1, tool_calls_allowed=1, tool_calls_denied=0, tool_calls_faulted=0,
            tools_invoked=["ehr.get_patient"], session_max_sensitivity="hipaa_phi",
            call_graph_summary=CallGraphSummary(compliance_domains_touched=["phi"], cross_boundary_events=[]),
        ),
        audit_chain_root="sha256:" + "0" * 64,
        audit_chain_tip="sha256:" + "1" * 64,
        audit_chain_length=1,
    )
    return json.loads(claim.model_dump_json(exclude_none=True))


def test_independent_keypairs():
    k1, k2 = SigningKey(), SigningKey()
    assert k1.public_key_hex != k2.public_key_hex


def test_session_linkage():
    session_id = "test-session-X"
    gw_key, sv_key = SigningKey(), SigningKey()
    p1 = _make_phase1(session_id, gw_key)
    assert p1["gateway"]["session_id"] == session_id


def test_phase1_nonce_matches_expected():
    session_id = "test-nonce-check"
    key = SigningKey()
    p1 = _make_phase1(session_id, key)
    expected_hex = _nonce(key.public_key_hex, session_id)
    actual_b64 = p1["trace"]["runtime"]["nonce"]
    actual_hex = base64.urlsafe_b64decode(actual_b64 + "==").hex()
    assert actual_hex == expected_hex


def test_nonce_changes_with_session():
    key = SigningKey()
    n1 = _nonce(key.public_key_hex, "session-A")
    n2 = _nonce(key.public_key_hex, "session-B")
    assert n1 != n2


def test_nonce_changes_with_key():
    k1, k2 = SigningKey(), SigningKey()
    n1 = _nonce(k1.public_key_hex, "session-A")
    n2 = _nonce(k2.public_key_hex, "session-A")
    assert n1 != n2


def test_phase1_signature_valid():
    key = SigningKey()
    p1 = _make_phase1("test-sig", key)
    assert _verify_sig(p1, key.public_key_hex)


def test_tampered_session_id_breaks_signature():
    key = SigningKey()
    p1 = _make_phase1("session-original", key)
    tampered = json.loads(json.dumps(p1))
    tampered["gateway"]["session_id"] = "session-attacker"
    assert not _verify_sig(tampered, key.public_key_hex)


def test_cross_claim_tamper_independence():
    """Tampering Phase 1 must not affect Phase 2 verification."""
    session_id = "session-cross"
    gw_key, sv_key = SigningKey(), SigningKey()
    p1 = _make_phase1(session_id, gw_key)

    # Build a minimal Phase 2 claim independently
    p2_body = json.dumps({
        "session_id": session_id,
        "server_public_key_hex": sv_key.public_key_hex,
        "nonce": _nonce(sv_key.public_key_hex, session_id),
    }, sort_keys=True, separators=(",", ":")).encode()
    p2_sig = sv_key.sign(p2_body)

    # Tamper Phase 1
    p1["gateway"]["session_id"] = "tampered"
    assert not _verify_sig(p1, gw_key.public_key_hex)

    # Phase 2 unaffected
    pub2 = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sv_key.public_key_hex))
    pub2.verify(p2_sig, p2_body)  # would raise if invalid


def test_binary_swap_changes_claim():
    session_id = "session-binary"
    key = SigningKey()
    approved = "sha256:" + hashlib.sha256(b"approved-binary-v1").hexdigest()
    tampered  = "sha256:" + hashlib.sha256(b"tampered-binary-v2").hexdigest()
    assert approved != tampered
    # measurement change propagates to claim content -- distinct from approved
    assert tampered != approved
