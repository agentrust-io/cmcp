"""Tests for Claim 4: TRACE Claim key binding and disclosure resistance.

Asserts the invariants the claim4 experiment demonstrates under the implemented
nonce construction (docs/spec/attestation.md §3.3):

    nonce = JWK_thumbprint(tee_public_key) (32) || random_salt (32)

The nonce binds the report to the gateway key (report_data[:32] is the RFC 7638
thumbprint, re-derivable from cnf.jwk.x); the session is bound through the signed
claim body, not the nonce. These run in CI to catch regressions in nonce
construction and claim signing.
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
from cmcp_runtime.tee.base import jwk_thumbprint, make_nonce

_SALT_A = b"\x11" * 32
_SALT_B = b"\x22" * 32


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


def _stub_claim(session_id: str, signing_key: SigningKey, nonce: bytes):
    report = AttestationReportInfo(
        provider="tpm",
        measurement="sha256:" + "ab" * 32,
        report_data=nonce.hex(),
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


def test_thumbprint_is_deterministic():
    """The JWK thumbprint is deterministic for a given key."""
    key = SigningKey()
    assert jwk_thumbprint(key.public_key_bytes) == jwk_thumbprint(key.public_key_bytes)


def test_report_data_binds_key():
    """nonce[:32] equals the JWK thumbprint, so report_data is bound to the key."""
    key = SigningKey()
    nonce = make_nonce(key.public_key_bytes, _SALT_A)
    assert len(nonce) == 64
    assert nonce[:32] == jwk_thumbprint(key.public_key_bytes)
    assert nonce[32:] == _SALT_A


def test_thumbprint_changes_with_key():
    """Different TEE keys produce different thumbprints (instance binding)."""
    assert jwk_thumbprint(SigningKey().public_key_bytes) != jwk_thumbprint(SigningKey().public_key_bytes)


def test_salt_makes_nonce_fresh():
    """A different salt yields a different nonce for the same key (freshness)."""
    key = SigningKey()
    assert make_nonce(key.public_key_bytes, _SALT_A) != make_nonce(key.public_key_bytes, _SALT_B)


def test_session_id_tamper_breaks_signature():
    """Replacing session_id in a signed claim invalidates its Ed25519 signature."""
    key = SigningKey()
    nonce = make_nonce(key.public_key_bytes, _SALT_A)
    claim_dict = json.loads(_stub_claim("session-A", key, nonce).model_dump_json(exclude_none=True))
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
