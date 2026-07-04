"""
Experiment: Policy Bundle Hash Binding
Claim 1: Hardware-attested policy enforcement at the AI agent tool boundary

Proves four properties:
  1. Bundle hash is deterministic (same content → same hash, always)
  2. Avalanche effect: one character change → completely different hash
  3. PolicyHashMismatch raised when disk bundle differs from expected hash
  4. TRACE Claim signature covers bundle_hash (tamper breaks verification)

Run from repo root:
  pip install -e .
  python experiments/claim1-policy-hash-binding/run.py
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

# Allow running from repo root without install
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

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
from cmcp_runtime.errors import PolicyHashMismatch
from cmcp_runtime.policy.bundle import load_policy_bundle

FIXTURES = Path(__file__).parent / "fixtures"
BUNDLE_V1 = FIXTURES / "bundle-v1"
BUNDLE_V2 = FIXTURES / "bundle-v2"


def _bits_different(h1: str, h2: str) -> int:
    """Count differing bits between two hex-encoded SHA-256 digests."""
    b1 = bytes.fromhex(h1.removeprefix("sha256:"))
    b2 = bytes.fromhex(h2.removeprefix("sha256:"))
    return sum(bin(a ^ b).count("1") for a, b in zip(b1, b2))


def _verify_claim_signature(claim_json: dict, public_key_hex: str) -> bool:
    """Verify Ed25519 signature on a RuntimeClaim dict."""
    sig_b64 = claim_json.get("signature", "")
    if not sig_b64:
        return False
    try:
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "==")
        pub_raw = bytes.fromhex(public_key_hex)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_raw)
        body = {k: v for k, v in claim_json.items() if k != "signature"}
        body_bytes = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        pub_key.verify(sig_bytes, body_bytes)
        return True
    except Exception:
        return False


def _make_stub_claim(bundle_hash: str, signing_key: SigningKey):
    """Build a minimal signed RuntimeClaim for signature tamper testing."""
    report = AttestationReportInfo(
        provider="software-only",
        measurement="DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION",
        report_data="",
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
        session_id="exp1-session",
        signing_key=signing_key,
        attestation_report=report,
        policy_bundle=policy,
        tool_catalog=catalog,
        call_summary=summary,
        audit_chain_root="sha256:" + "0" * 64,
        audit_chain_tip="sha256:" + "0" * 64,
        audit_chain_length=0,
    )


def section(title: str) -> None:
    print(f"\n[{title}]")


def result(label: str, value: str, ok: bool | None = None) -> None:
    if ok is None:
        print(f"    {label}: {value}")
    elif ok:
        print(f"    {label}: {value}  OK")
    else:
        print(f"    {label}: {value}  FAIL")


def main() -> int:
    print("=" * 60)
    print("Experiment: Policy Bundle Hash Binding")
    print("Claim 1: cMCP TEE-measured policy enforcement")
    print("=" * 60)

    failures = 0

    # ------------------------------------------------------------------
    # Property 1: Determinism
    # ------------------------------------------------------------------
    section("1. Hash determinism: same bundle, same hash across loads")

    b1_load1 = load_policy_bundle(str(BUNDLE_V1))
    b1_load2 = load_policy_bundle(str(BUNDLE_V1))

    h1 = b1_load1.bundle_hash
    h1_reload = b1_load2.bundle_hash
    deterministic = h1 == h1_reload

    result("bundle-v1 hash (load 1)", h1)
    result("bundle-v1 hash (load 2)", h1_reload)
    result("Deterministic", "YES" if deterministic else "NO", deterministic)
    if not deterministic:
        failures += 1

    # ------------------------------------------------------------------
    # Property 2: Avalanche effect
    # ------------------------------------------------------------------
    section("2. Avalanche effect: one character changed in cedar comment")

    b2_load = load_policy_bundle(str(BUNDLE_V2))
    h2 = b2_load.bundle_hash

    bits_diff = _bits_different(h1, h2)
    chars_diff = sum(a != b for a, b in zip(h1[7:], h2[7:]))  # skip "sha256:" prefix
    hashes_differ = h1 != h2

    # Read the actual diff so we can report what changed
    cedar_v1 = (BUNDLE_V1 / "allow_ehr_tools.cedar").read_text().splitlines()[0]
    cedar_v2 = (BUNDLE_V2 / "allow_ehr_tools.cedar").read_text().splitlines()[0]

    result("bundle-v1 hash", h1)
    result("bundle-v2 hash", h2)
    result("Change", f"line 1 of cedar file: {repr(cedar_v1)} -> {repr(cedar_v2)}")
    result("Bits changed (of 256)", f"{bits_diff} ({100 * bits_diff // 256}%)")
    result("Hex chars changed (of 64)", f"{chars_diff}")
    result("Hashes differ", "YES: tamper detectable" if hashes_differ else "NO: NOT detectable", hashes_differ)
    if not hashes_differ:
        failures += 1

    # ------------------------------------------------------------------
    # Property 3: PolicyHashMismatch on disk/expected mismatch
    # ------------------------------------------------------------------
    section("3. Tamper detection: load bundle-v2 with expected_hash of bundle-v1")
    print(f"    (simulates an admin swapping the bundle after approval)")

    mismatch_raised = False
    try:
        load_policy_bundle(str(BUNDLE_V2), expected_hash=h1)
    except PolicyHashMismatch as exc:
        mismatch_raised = True
        result("PolicyHashMismatch raised", "YES", True)
        result("Error detail", str(exc)[:80] + "...")
    if not mismatch_raised:
        result("PolicyHashMismatch raised", "NO: bundle substitution NOT caught", False)
        failures += 1

    # Positive control: correct hash passes
    try:
        load_policy_bundle(str(BUNDLE_V1), expected_hash=h1)
        result("Correct hash (bundle-v1 / h1)", "passes without error", True)
    except PolicyHashMismatch:
        result("Correct hash (bundle-v1 / h1)", "incorrectly raised mismatch", False)
        failures += 1

    # ------------------------------------------------------------------
    # Property 4: TRACE Claim signature covers bundle_hash
    # ------------------------------------------------------------------
    section("4. TRACE Claim signature tamper detection")
    print("    (TRACE Claim is signed with TEE-sealed key; any field change breaks the sig)")

    signing_key = SigningKey()
    pub_hex = signing_key.public_key_hex

    claim = _make_stub_claim(h1, signing_key)
    claim_dict = json.loads(claim.model_dump_json(exclude_none=True))

    # Verify original
    orig_valid = _verify_claim_signature(claim_dict, pub_hex)
    result("Original claim signature", "VALID" if orig_valid else "INVALID", orig_valid)
    if not orig_valid:
        failures += 1

    # Tamper: swap bundle_hash in the claim to bundle-v2's hash
    tampered = json.loads(json.dumps(claim_dict))
    tampered["trace"]["policy"]["bundle_hash"] = h2
    tampered_valid = _verify_claim_signature(tampered, pub_hex)
    result("Claim with tampered bundle_hash", "VALID" if tampered_valid else "INVALID (rejected)", not tampered_valid)
    if tampered_valid:
        failures += 1

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    if failures == 0:
        print("Result: ALL 4 PROPERTIES CONFIRMED")
        print()
        print("Interpretation:")
        print("  A policy bundle substitution attack is detectable because:")
        print(f"  - bundle-v1 (approved) hash: {h1}")
        print(f"  - bundle-v2 (tampered) hash: {h2}")
        print(f"  - {bits_diff}/256 bits differ from one character change")
        print("  - load_policy_bundle raises PolicyHashMismatch on mismatch")
        print("  - TRACE Claim signature is invalidated by any hash field change")
        return 0
    else:
        print(f"Result: {failures} PROPERTIES FAILED: see output above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
