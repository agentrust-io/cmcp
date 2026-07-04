"""
Claim 4: Operator-trust-free governance proof artifact with key-bound nonce.

The TRACE Claim nonce binds each attestation report to the gateway's TEE key, and
the session is bound through the signed claim body. An operator cannot replay a
valid TRACE Claim under a different session or forge one for a different TEE key.

Nonce construction (hardware mode), per docs/spec/attestation.md §3.3:
    nonce = JWK_thumbprint(tee_public_key) (32 bytes) || random_salt (32 bytes)

The first 32 bytes are the RFC 7638 JWK Thumbprint of the gateway public key, so a
verifier re-derives them from cnf.jwk.x and confirms they equal report_data[:32]
(key / instance binding). The remaining 32 bytes are a per-startup random salt so
every enclave instance produces a distinct, fresh nonce. Session linkage is NOT in
the nonce: it is carried by gateway.session_id inside the Ed25519-signed claim body.

Properties demonstrated (software simulation):

P1  The JWK thumbprint is deterministic for a given key, and a verifier can
    re-derive it from cnf.jwk.x.
P2  report_data[:32] equals the thumbprint -> the report is bound to this key.
P3  A different TEE key yields a different thumbprint (instance binding).
P4  A different salt yields a different nonce (freshness across startups).
P5  Session binding: replacing session_id in a signed claim breaks the Ed25519
    signature -- an attacker cannot present a claim under a different session.
P6  Removing one audit entry from the export changes the bundle hash, which
    invalidates the gateway's signature over the export (selective disclosure
    resistance).

Running:
  pip install -e .
  python experiments/claim4-trace-claim-nonce/run.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys

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
from cmcp_runtime.tee.base import jwk_thumbprint, make_nonce


def _verify_sig(claim_dict: dict, pub_hex: str) -> bool:
    sig_b64 = claim_dict.get("signature", "")
    sig = base64.urlsafe_b64decode(sig_b64 + "==")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    body = canonical_json(claim_dict)
    try:
        pub.verify(sig, body)
        return True
    except Exception:
        return False


def _stub_claim(session_id: str, signing_key: SigningKey, nonce: bytes):
    """Generate a minimal TRACE Claim with an explicit nonce in report_data."""
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
        tool_calls_total=1, tool_calls_allowed=1, tool_calls_denied=0, tool_calls_faulted=0,
        tools_invoked=["ehr.get_patient"], session_max_sensitivity="hipaa_phi",
        call_graph_summary=CallGraphSummary(compliance_domains_touched=["hipaa_phi"], cross_boundary_events=[]),
    )
    return generate_trace_claim(
        session_id=session_id, signing_key=signing_key, attestation_report=report,
        policy_bundle=policy, tool_catalog=catalog, call_summary=summary,
        audit_chain_root="sha256:" + "0" * 64,
        audit_chain_tip="sha256:" + "0" * 64,
        audit_chain_length=1,
    )


def _result(label: str, value: str) -> None:
    print(f"  {label}: {value}")


def main() -> int:
    print()
    print("Claim 4 | TRACE Claim key binding and disclosure resistance")
    print("=" * 72)

    # --- P1: thumbprint determinism + verifier re-derivation ---
    print()
    print("P1  JWK thumbprint determinism")
    key = SigningKey()
    salt = b"\x11" * 32
    tp1 = jwk_thumbprint(key.public_key_bytes)
    tp2 = jwk_thumbprint(key.public_key_bytes)
    _result("thumbprint run 1", tp1.hex())
    _result("thumbprint run 2", tp2.hex())
    if tp1 != tp2:
        print("  FAIL: thumbprint not deterministic")
        return 1
    print("  PASS: thumbprint is deterministic and re-derivable from cnf.jwk.x")

    # --- P2: report_data binds the key ---
    print()
    print("P2  report_data[:32] equals the thumbprint (key binding)")
    nonce = make_nonce(key.public_key_bytes, salt)
    _result("nonce", nonce.hex())
    _result("report_data[:32]", nonce[:32].hex())
    if nonce[:32] != tp1:
        print("  FAIL: report_data[:32] does not match the thumbprint")
        return 1
    print("  PASS: report is bound to this gateway key")

    # --- P3: instance binding (different key) ---
    print()
    print("P3  Instance binding -- different TEE key -> different thumbprint")
    key2 = SigningKey()
    tp_key2 = jwk_thumbprint(key2.public_key_bytes)
    _result("key 1 thumbprint", tp1.hex())
    _result("key 2 thumbprint", tp_key2.hex())
    if tp1 == tp_key2:
        print("  FAIL: different keys produced the same thumbprint")
        return 1
    print("  PASS: nonce[:32] changes with the TEE key")

    # --- P4: freshness (different salt) ---
    print()
    print("P4  Freshness -- different salt -> different nonce")
    nonce_b = make_nonce(key.public_key_bytes, b"\x22" * 32)
    _result("nonce (salt A)", nonce.hex())
    _result("nonce (salt B)", nonce_b.hex())
    if nonce == nonce_b:
        print("  FAIL: different salts produced the same nonce")
        return 1
    print("  PASS: per-startup salt makes each instance nonce distinct")

    # --- P5: session binding via signed claim body ---
    print()
    print("P5  Session binding -- session_id tamper breaks the Ed25519 signature")
    claim = _stub_claim("session-A", key, nonce)
    claim_dict = json.loads(claim.model_dump_json(exclude_none=True))
    sig_valid_original = _verify_sig(claim_dict, key.public_key_hex)
    tampered = json.loads(json.dumps(claim_dict))
    tampered["gateway"]["session_id"] = "session-B"
    sig_valid_tampered = _verify_sig(tampered, key.public_key_hex)
    _result("signature on original claim (session-A)", "VALID" if sig_valid_original else "INVALID")
    _result("signature after replacing session_id", "VALID" if sig_valid_tampered else "INVALID")
    if not sig_valid_original:
        print("  FAIL: original claim signature invalid")
        return 1
    if sig_valid_tampered:
        print("  FAIL: tampered claim signature still valid")
        return 1
    print("  PASS: a claim cannot be presented under a different session")

    # --- P6: selective disclosure resistance ---
    print()
    print("P6  Selective disclosure resistance -- removing one audit entry breaks export hash")
    verifier_nonce = "v-nonce-abc123"
    audit_entries = [
        {"call_id": f"call-{i}", "tool": "ehr.get_patient", "decision": "allow", "seq": i}
        for i in range(5)
    ]
    canonical_full = json.dumps(audit_entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    bundle_hash_full = "sha256:" + hashlib.sha256(canonical_full).hexdigest()
    export_body = json.dumps(
        {"bundle_hash": bundle_hash_full, "verifier_nonce": verifier_nonce},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    export_sig_raw = key.sign(export_body)

    entries_minus_one = [e for e in audit_entries if e["call_id"] != "call-2"]
    canonical_minus = json.dumps(entries_minus_one, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    bundle_hash_minus = "sha256:" + hashlib.sha256(canonical_minus).hexdigest()

    _result("Full audit (5 entries) bundle_hash", bundle_hash_full)
    _result("After removing call-2 (4 entries)", bundle_hash_minus)
    _result("Hashes match?", str(bundle_hash_full == bundle_hash_minus))

    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex))
    modified_body = json.dumps(
        {"bundle_hash": bundle_hash_minus, "verifier_nonce": verifier_nonce},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    try:
        pub.verify(export_sig_raw, modified_body)
        sig_still_valid = True
    except Exception:
        sig_still_valid = False
    _result("Export signature valid on modified bundle?", str(sig_still_valid))
    if sig_still_valid:
        print("  FAIL: signature still valid after entry removal")
        return 1
    print("  PASS: removing one audit entry changes bundle_hash, signature fails")

    # --- Summary ---
    print()
    print("Summary:")
    print("  P1: Thumbprint deterministic / re-derivable     PASS")
    print("  P2: report_data[:32] binds the TEE key          PASS")
    print("  P3: Thumbprint changes with TEE key             PASS")
    print("  P4: Salt makes each instance nonce fresh        PASS")
    print("  P5: session_id tamper breaks Ed25519 sig        PASS")
    print("  P6: Entry removal breaks export signature       PASS")
    print()
    print("In hardware TEE mode, the nonce is committed into the hardware-signed")
    print("report_data field. The operator cannot forge a thumbprint for a different")
    print("key without compromising the TEE.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
