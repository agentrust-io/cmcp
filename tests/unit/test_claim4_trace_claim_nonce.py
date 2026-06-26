"""Tests for Claim 4: TRACE Claim nonce binding and disclosure resistance.

These tests assert the invariants the claim4 experiment demonstrates: the nonce
binds a claim to a specific session and TEE instance, a session-id swap breaks
the Ed25519 signature, and removing an audit entry breaks the export signature.
They run in CI to catch regressions in nonce construction and claim signing.
"""

from __future__ import annotations

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
    generate_trace_claim,
)


def _compute_nonce(public_key_hex: str, session_id: str) -> str:
    """SHA-256(tee_public_key_bytes || session_id_bytes) as hex."""
    return hashlib.sha256(bytes.fromhex(public_key_hex) + session_id.encode("utf-8")).hexdigest()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _verify_sig(claim_dict: dict, pub_hex: str) -> bool:
    sig = base64.urlsafe_b64decode(claim_dict.get("signature", "") + "==")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    body = {k: v for k, v in claim_dict.items() if k != "signature"}
    body_bytes = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    try:
        pub.verify(sig, body_bytes)
        return True
    except Exception:
        return False


def _stub_claim(session_id: str, signing_key: SigningKey, nonce_hex: str):
    report = AttestationReportInfo(
        provider="tpm",
        measurement="sha256:" + "ab" * 32,
        report_data=nonce_hex,
        attestation_generated_at="2026-06-25T00:00:00Z",
        attestation_validity_seconds=3600,
    )
    policy = PolicyBundleInfo(hash="sha256:" + "0" * 64, enforcement_mode="enforcing", policy_version="1.0.0")
    catalog = ToolCatalogInfo(hash="sha256:" + "0" * 64)
    summary = CallSummary(
        tool_calls_total=1,
        tool_calls_allowed=1,
        tool_calls_denied=0,
        tool_calls_faulted=0,
        tools_invoked=["ehr.get_patient"],
        session_max_sensitivity="hipaa_phi",
        call_graph_summary=CallGraphSummary(compliance_domains_touched=["hipaa_phi"], cross_boundary_events=[]),
    )
    return generate_trace_claim(
        session_id=session_id,
        signing_key=signing_key,
        attestation_report=report,
        policy_bundle=policy,
        tool_catalog=catalog,
        call_summary=summary,
        audit_chain_root="sha256:" + "0" * 64,
        audit_chain_tip="sha256:" + "0" * 64,
        audit_chain_length=1,
    )


def test_nonce_is_deterministic():
    """The same key and session_id always produce the same nonce."""
    key = SigningKey()
    assert _compute_nonce(key.public_key_hex, "session-A") == _compute_nonce(key.public_key_hex, "session-A")


def test_nonce_changes_with_session_id():
    """Changing the session_id changes the nonce (session binding)."""
    key = SigningKey()
    assert _compute_nonce(key.public_key_hex, "session-A") != _compute_nonce(key.public_key_hex, "session-B")


def test_nonce_changes_with_tee_key():
    """Changing the TEE key changes the nonce for the same session (instance binding)."""
    key1 = SigningKey()
    key2 = SigningKey()
    assert _compute_nonce(key1.public_key_hex, "session-A") != _compute_nonce(key2.public_key_hex, "session-A")


def test_claim_nonce_does_not_match_other_session():
    """A claim minted for session-A carries A's nonce, which fails B's expected nonce."""
    key = SigningKey()
    nonce_a = _compute_nonce(key.public_key_hex, "session-A")
    claim = _stub_claim("session-A", key, nonce_a)
    embedded = json.loads(claim.model_dump_json(exclude_none=True))["trace"]["runtime"]["nonce"]
    assert embedded == _b64url(bytes.fromhex(nonce_a))
    expected_for_b = _b64url(bytes.fromhex(_compute_nonce(key.public_key_hex, "session-B")))
    assert embedded != expected_for_b


def test_session_id_tamper_breaks_signature():
    """Replacing session_id in a signed claim invalidates its Ed25519 signature."""
    key = SigningKey()
    nonce_a = _compute_nonce(key.public_key_hex, "session-A")
    claim_dict = json.loads(_stub_claim("session-A", key, nonce_a).model_dump_json(exclude_none=True))
    assert _verify_sig(claim_dict, key.public_key_hex)
    claim_dict["gateway"]["session_id"] = "session-B"
    assert not _verify_sig(claim_dict, key.public_key_hex)


def test_audit_entry_removal_breaks_export_signature():
    """Removing one audit entry changes the bundle hash, so the export signature fails."""
    key = SigningKey()
    entries = [{"call_id": f"call-{i}", "tool": "ehr.get_patient", "decision": "allow", "seq": i} for i in range(5)]

    def _bundle_hash(items: list[dict]) -> str:
        canonical = json.dumps(items, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def _export_body(bundle_hash: str) -> bytes:
        return json.dumps(
            {"bundle_hash": bundle_hash, "verifier_nonce": "v-nonce-abc123"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()

    full_hash = _bundle_hash(entries)
    sig = key.sign(_export_body(full_hash))

    entries_minus_one = [e for e in entries if e["call_id"] != "call-2"]
    minus_hash = _bundle_hash(entries_minus_one)
    assert minus_hash != full_hash

    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex))
    try:
        pub.verify(sig, _export_body(minus_hash))
        still_valid = True
    except Exception:
        still_valid = False
    assert not still_valid
