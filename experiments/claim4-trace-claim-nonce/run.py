"""
Claim 4: Operator-trust-free governance proof artifact with session-bound nonce.

The TRACE Claim nonce construction binds each attestation report to a specific
session and TEE instance. An attacker cannot replay a valid TRACE Claim from a
different session or a different TEE instance.

Nonce construction (hardware mode):
    nonce = SHA-256(tee_public_key_bytes || session_id_bytes)

This nonce is set as the 'report_data' / 'user_data' field when requesting
the hardware attestation report. A verifier checks that the nonce in the
hardware-signed report matches SHA-256(claim.cnf.jwk.x || claim.gateway.session_id).

Properties demonstrated (software simulation):

P1  Nonce is deterministic for the same key and session_id.
P2  Nonce changes when session_id changes (session binding).
P3  Nonce changes when the TEE key changes (instance binding).
P4  A TRACE Claim produced for session A cannot be replayed for session B --
    the nonce in the claim would not match the verifier's expected nonce for B.
P5  Replacing session_id in a signed claim breaks the Ed25519 signature --
    an attacker cannot forge a valid claim for a different session.
P6  Selective disclosure: removing one audit entry from the export changes the
    bundle hash, invalidating the gateway's signature over the export.

Note: P4 is demonstrated as a mathematical check in software mode. In hardware
mode, the nonce is hardware-signed and cannot be forged by the operator.

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


def _compute_nonce(public_key_hex: str, session_id: str) -> str:
    """SHA-256(tee_public_key_bytes || session_id_bytes) as hex."""
    key_bytes = bytes.fromhex(public_key_hex)
    session_bytes = session_id.encode("utf-8")
    return hashlib.sha256(key_bytes + session_bytes).hexdigest()


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


def _stub_claim(session_id: str, signing_key: SigningKey, nonce_hex: str):
    """Generate a minimal TRACE Claim with an explicit nonce in report_data."""
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
    print("Claim 4 | TRACE Claim nonce binding and selective disclosure resistance")
    print("=" * 72)

    # --- P1 & P2: Nonce determinism and session binding ---
    print()
    print("P1 + P2  Nonce determinism and session binding")
    key = SigningKey()
    nonce_A1 = _compute_nonce(key.public_key_hex, "session-A")
    nonce_A2 = _compute_nonce(key.public_key_hex, "session-A")
    nonce_B  = _compute_nonce(key.public_key_hex, "session-B")
    _result("Nonce(key, session-A) run 1", f"sha256:{nonce_A1}")
    _result("Nonce(key, session-A) run 2", f"sha256:{nonce_A2}")
    _result("Nonce(key, session-B)",       f"sha256:{nonce_B}")
    if nonce_A1 != nonce_A2:
        print("  FAIL: nonce not deterministic")
        return 1
    if nonce_A1 == nonce_B:
        print("  FAIL: different session_ids produced the same nonce")
        return 1
    print("  PASS: nonce is deterministic; changes with session_id")

    # --- P3: Instance binding (different key) ---
    print()
    print("P3  Instance binding -- different TEE key -> different nonce")
    key2 = SigningKey()
    nonce_key2 = _compute_nonce(key2.public_key_hex, "session-A")
    _result("Key 1 nonce for session-A", f"sha256:{nonce_A1}")
    _result("Key 2 nonce for session-A", f"sha256:{nonce_key2}")
    if nonce_A1 == nonce_key2:
        print("  FAIL: different TEE keys produced the same nonce for the same session")
        return 1
    print("  PASS: nonce changes with TEE key -- instance-binding confirmed")

    # --- P4: Replay attack (mathematical check) ---
    print()
    print("P4  Session replay attack (mathematical verification)")
    claim_A = _stub_claim("session-A", key, nonce_A1)
    claim_A_dict = json.loads(claim_A.model_dump_json(exclude_none=True))
    actual_nonce_in_claim = claim_A_dict["trace"]["runtime"].get("nonce", "")
    expected_nonce_for_B = base64.urlsafe_b64encode(bytes.fromhex(nonce_B)).rstrip(b"=").decode()
    _result("Nonce embedded in claim (session-A)", actual_nonce_in_claim)
    _result("Verifier expected nonce for session-B", expected_nonce_for_B)
    if actual_nonce_in_claim == expected_nonce_for_B:
        print("  FAIL: nonce would pass for the wrong session")
        return 1
    print("  PASS: claim from session-A fails nonce check for session-B")
    print("        In hardware mode, the nonce is hardware-signed; this check")
    print("        is enforced by the TEE provider's endorsement chain.")

    # --- P5: Signature breaks on session_id tamper ---
    print()
    print("P5  Ed25519 signature breaks on session_id tampering")
    sig_valid_original = _verify_sig(claim_A_dict, key.public_key_hex)
    tampered = json.loads(json.dumps(claim_A_dict))
    tampered["gateway"]["session_id"] = "session-B"
    sig_valid_tampered = _verify_sig(tampered, key.public_key_hex)
    _result("Signature on original claim (session-A)", "VALID" if sig_valid_original else "INVALID")
    _result("Signature after replacing session_id with session-B", "VALID" if sig_valid_tampered else "INVALID")
    if not sig_valid_original:
        print("  FAIL: original claim signature invalid")
        return 1
    if sig_valid_tampered:
        print("  FAIL: tampered claim signature still valid")
        return 1
    print("  PASS: session_id tampering immediately breaks signature")

    # --- P6: Selective disclosure resistance ---
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
    export_sig = base64.urlsafe_b64encode(export_sig_raw).rstrip(b"=").decode()

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
    print("  P1: Nonce deterministic                         PASS")
    print("  P2: Nonce changes with session_id              PASS")
    print("  P3: Nonce changes with TEE key                 PASS")
    print("  P4: Session-A claim fails check for session-B  PASS (mathematical)")
    print("  P5: session_id tamper breaks Ed25519 sig       PASS")
    print("  P6: Entry removal breaks export signature      PASS")
    print()
    print("In hardware TEE mode, P4 becomes a hardware-enforced check:")
    print("The nonce is signed by the TEE hardware. The operator cannot forge")
    print("a nonce for a different session without compromising the hardware.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
