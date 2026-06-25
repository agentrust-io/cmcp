"""
Claim 6: Cross-organizational attestation chains for B2B AI tool access.

In B2B AI tool access, party A (enterprise) runs a Phase 1 cMCP gateway and
party B (SaaS vendor) runs a Phase 2 cMCP server. Each operates a separate TEE
with a separate keypair. A third-party verifier can confirm both sides
independently by checking each attestation against its hardware endorsement chain,
without trusting either operator.

This experiment simulates the dual-attestation protocol in software:
- Phase 1: existing cMCP gateway claim (already in production)
- Phase 2: stub server claim with the same structure (Phase 2 not yet deployed)

Phase 2 stub attestable fields:
  - server_binary_measurement: SHA-256 of the server binary (TEE PCR)
  - tool_catalog_hash:          SHA-256 of the server's approved tool definitions
  - egress_policy_hash:         SHA-256 of the server's egress policy
  - session_id:                 shared with Phase 1 (linkage key)
  - nonce:                      SHA-256(server_key_bytes || session_id_bytes)
  - signature:                  Ed25519 over canonical claim body

Properties demonstrated:

P1  Each side has an independent keypair. Phase 1 and Phase 2 public keys differ.
P2  Both claims carry the same session_id. Linkage established.
P3  Phase 1 nonce = SHA-256(gateway_key || session_id). Binds claim to session.
P4  Phase 2 nonce = SHA-256(server_key  || session_id). Different nonce, same session.
P5  Verifier independently checks each claim against its own public key.
P6  Tampering with Phase 1 claim does not affect Phase 2 validity (independent keys).
P7  Server binary swap detection: different binary measurement -> different Phase 2 claim.

Note: In hardware TEE mode, nonces are hardware-signed. A verifier holding the TEE
provider's endorsement certificate can confirm neither operator forged their nonce.
In software mode (this experiment), nonces are mathematically checked.

Running:
  pip install -e .
  python experiments/claim6-cross-org-attestation/run.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from dataclasses import dataclass

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


# ── Phase 2 stub claim structure ─────────────────────────────────────────────

@dataclass
class Phase2Claim:
    """
    Minimal stub representing a Phase 2 cMCP server TRACE Claim.
    In production, this would mirror the full RuntimeClaim structure but
    attest server-side properties: binary measurement, egress policy, tool catalog.
    """
    session_id: str
    server_public_key_hex: str
    server_binary_measurement: str
    tool_catalog_hash: str
    egress_policy_hash: str
    nonce: str             # SHA-256(server_key_bytes || session_id_bytes), hex
    signature: str         # Ed25519 over canonical body, base64url


def _compute_nonce(key_hex: str, session_id: str) -> str:
    return hashlib.sha256(bytes.fromhex(key_hex) + session_id.encode()).hexdigest()


def _canonical_phase2(claim: Phase2Claim, exclude_sig: bool = True) -> bytes:
    d = {
        "session_id": claim.session_id,
        "server_public_key_hex": claim.server_public_key_hex,
        "server_binary_measurement": claim.server_binary_measurement,
        "tool_catalog_hash": claim.tool_catalog_hash,
        "egress_policy_hash": claim.egress_policy_hash,
        "nonce": claim.nonce,
    }
    if not exclude_sig:
        d["signature"] = claim.signature
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _make_phase2_claim(session_id: str, server_key: SigningKey,
                       binary_hash: str, catalog_hash: str, egress_hash: str) -> Phase2Claim:
    nonce = _compute_nonce(server_key.public_key_hex, session_id)
    stub = Phase2Claim(
        session_id=session_id,
        server_public_key_hex=server_key.public_key_hex,
        server_binary_measurement=binary_hash,
        tool_catalog_hash=catalog_hash,
        egress_policy_hash=egress_hash,
        nonce=nonce,
        signature="",
    )
    body = _canonical_phase2(stub)
    sig_raw = server_key.sign(body)
    stub.signature = base64.urlsafe_b64encode(sig_raw).rstrip(b"=").decode()
    return stub


def _verify_phase2(claim: Phase2Claim) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(claim.server_public_key_hex))
    sig = base64.urlsafe_b64decode(claim.signature + "==")
    try:
        pub.verify(sig, _canonical_phase2(claim))
        return True
    except Exception:
        return False


def _verify_phase1(claim_dict: dict, pub_hex: str) -> bool:
    sig = base64.urlsafe_b64decode(claim_dict.get("signature", "") + "==")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    try:
        pub.verify(sig, canonical_json(claim_dict))
        return True
    except Exception:
        return False


def _result(label: str, value: str) -> None:
    print(f"  {label}: {value}")


def main() -> int:
    print()
    print("Claim 6 | Cross-organizational attestation chains for B2B AI tool access")
    print("=" * 74)

    SESSION_ID = "session-cross-org-abc123"
    APPROVED_BINARY = "sha256:" + hashlib.sha256(b"approved-server-v1.0-binary").hexdigest()
    TAMPERED_BINARY = "sha256:" + hashlib.sha256(b"tampered-server-v1.1-binary").hexdigest()
    SERVER_CATALOG_HASH = "sha256:" + hashlib.sha256(b"approved-tool-catalog-v1").hexdigest()
    EGRESS_POLICY_HASH  = "sha256:" + hashlib.sha256(b"approved-egress-policy-v1").hexdigest()

    gateway_key = SigningKey()
    server_key  = SigningKey()

    # --- P1: Independent keypairs ---
    print()
    print("P1  Independent keypairs -- Phase 1 (gateway) and Phase 2 (server) have different keys")
    _result("Gateway key (first 16)", gateway_key.public_key_hex[:16] + "...")
    _result("Server  key (first 16)", server_key.public_key_hex[:16] + "...")
    if gateway_key.public_key_hex == server_key.public_key_hex:
        print("  FAIL: gateway and server have the same key")
        return 1
    print("  PASS: independent keypairs confirmed")

    # --- Generate both claims ---
    nonce_hex = _compute_nonce(gateway_key.public_key_hex, SESSION_ID)
    report = AttestationReportInfo(
        provider="tpm",
        measurement="sha256:" + "ab" * 32,
        report_data=nonce_hex,
        attestation_generated_at="2026-06-25T00:00:00Z",
        attestation_validity_seconds=3600,
    )
    policy = PolicyBundleInfo(hash="sha256:" + "c1" * 32, enforcement_mode="enforcing", policy_version="1.0.0")
    catalog = ToolCatalogInfo(hash="sha256:" + "d2" * 32)
    summary = CallSummary(
        tool_calls_total=3, tool_calls_allowed=2, tool_calls_denied=1, tool_calls_faulted=0,
        tools_invoked=["ehr.get_patient", "slack.post_message"],
        session_max_sensitivity="hipaa_phi",
        call_graph_summary=CallGraphSummary(
            compliance_domains_touched=["phi", "external"],
            cross_boundary_events=[{"from_domain": "phi", "to_domain": "external", "call_id": "c2"}],
        ),
    )
    phase1_claim = generate_trace_claim(
        session_id=SESSION_ID, signing_key=gateway_key, attestation_report=report,
        policy_bundle=policy, tool_catalog=catalog, call_summary=summary,
        audit_chain_root="sha256:" + "0" * 64,
        audit_chain_tip="sha256:" + "1" * 64,
        audit_chain_length=3,
    )
    phase1_dict = json.loads(phase1_claim.model_dump_json(exclude_none=True))

    phase2_claim = _make_phase2_claim(
        SESSION_ID, server_key, APPROVED_BINARY, SERVER_CATALOG_HASH, EGRESS_POLICY_HASH
    )

    # --- P2: Session linkage ---
    print()
    print("P2  Same session_id in both claims -- linkage established")
    p1_session = phase1_dict["gateway"]["session_id"]
    p2_session = phase2_claim.session_id
    _result("Phase 1 session_id", p1_session)
    _result("Phase 2 session_id", p2_session)
    if p1_session != p2_session:
        print("  FAIL: session_ids differ")
        return 1
    print("  PASS: both claims carry the same session_id")

    # --- P3 & P4: Independent nonce bindings ---
    print()
    print("P3 + P4  Independent nonces, each bound to its own key + the shared session_id")
    p1_nonce_expected = _compute_nonce(gateway_key.public_key_hex, SESSION_ID)
    p2_nonce_expected = _compute_nonce(server_key.public_key_hex, SESSION_ID)
    p1_nonce_in_claim = base64.urlsafe_b64decode(
        phase1_dict["trace"]["runtime"].get("nonce", "") + "=="
    ).hex()
    _result("Phase 1 nonce (expected)", f"sha256:{p1_nonce_expected[:16]}...")
    _result("Phase 1 nonce (in claim)", f"sha256:{p1_nonce_in_claim[:16]}...")
    _result("Phase 2 nonce (expected)", f"sha256:{p2_nonce_expected[:16]}...")
    _result("Phase 2 nonce (in claim)", f"sha256:{phase2_claim.nonce[:16]}...")
    if p1_nonce_in_claim != p1_nonce_expected:
        print("  FAIL: Phase 1 nonce mismatch")
        return 1
    if phase2_claim.nonce != p2_nonce_expected:
        print("  FAIL: Phase 2 nonce mismatch")
        return 1
    if p1_nonce_expected == p2_nonce_expected:
        print("  FAIL: Phase 1 and Phase 2 nonces should differ (different keys)")
        return 1
    print("  PASS: each nonce binds its claim to (own_key, shared_session_id)")

    # --- P5: Independent verification ---
    print()
    print("P5  Verifier independently checks each claim against its own key")
    p1_valid = _verify_phase1(phase1_dict, gateway_key.public_key_hex)
    p2_valid = _verify_phase2(phase2_claim)
    _result("Phase 1 signature valid?", "yes" if p1_valid else "NO")
    _result("Phase 2 signature valid?", "yes" if p2_valid else "NO")
    if not p1_valid or not p2_valid:
        print("  FAIL: one or both signatures invalid")
        return 1
    print("  PASS: each claim independently verifiable against its own TEE public key")

    # --- P6: Cross-claim tamper independence ---
    print()
    print("P6  Tampering with Phase 1 does not affect Phase 2 validity (independent keys)")
    tampered_p1 = json.loads(json.dumps(phase1_dict))
    tampered_p1["gateway"]["session_id"] = "session-TAMPERED"
    p1_tampered_valid = _verify_phase1(tampered_p1, gateway_key.public_key_hex)
    p2_still_valid = _verify_phase2(phase2_claim)
    _result("Phase 1 signature after tamper", "VALID" if p1_tampered_valid else "invalid")
    _result("Phase 2 signature unchanged?",   "yes" if p2_still_valid else "NO")
    if p1_tampered_valid:
        print("  FAIL: tampered Phase 1 still verifies")
        return 1
    if not p2_still_valid:
        print("  FAIL: Phase 2 affected by Phase 1 tamper (keys should be independent)")
        return 1
    print("  PASS: Phase 1 tamper invalidates only Phase 1; Phase 2 unaffected")

    # --- P7: Binary swap detection ---
    print()
    print("P7  Server binary swap detection -- different measurement -> different Phase 2 claim")
    phase2_tampered = _make_phase2_claim(
        SESSION_ID, server_key, TAMPERED_BINARY, SERVER_CATALOG_HASH, EGRESS_POLICY_HASH
    )
    _result("Approved binary measurement", APPROVED_BINARY[:40] + "...")
    _result("Tampered binary measurement", TAMPERED_BINARY[:40] + "...")
    _result("Phase 2 (approved) measurement", phase2_claim.server_binary_measurement[:40] + "...")
    _result("Phase 2 (tampered) measurement", phase2_tampered.server_binary_measurement[:40] + "...")
    if phase2_claim.server_binary_measurement == phase2_tampered.server_binary_measurement:
        print("  FAIL: measurements should differ")
        return 1
    if phase2_claim.signature == phase2_tampered.signature:
        print("  FAIL: signatures should differ for different measurements")
        return 1
    print("  PASS: binary change produces different measurement and different signature")
    print("        A verifier holding the approved measurement sha256 would reject the tampered claim.")

    # --- Summary ---
    print()
    print("Cross-org verification protocol:")
    print("  1. Enterprise (party A) receives tool call result from SaaS vendor (party B).")
    print("  2. Enterprise requests party B's Phase 2 TRACE Claim for the session.")
    print("  3. Enterprise verifies:")
    print("     a. Phase 1 claim (own gateway): sig valid, nonce = SHA-256(gateway_key || session_id)")
    print("     b. Phase 2 claim (vendor server): sig valid, nonce = SHA-256(server_key || session_id)")
    print("     c. Both session_ids match.")
    print("     d. Phase 2 measurement = pre-approved server binary hash.")
    print("     e. Phase 2 tool_catalog_hash = independently-reviewed catalog hash.")
    print("  Neither party needs to trust the other's infrastructure.")
    print("  In hardware mode, each nonce is hardware-signed by the TEE provider.")
    print()
    print("All properties: PASS")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
