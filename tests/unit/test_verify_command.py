"""End-to-end tests for `cmcp verify`: real claim, real tampering."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from starlette.testclient import TestClient

from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.cli import build_server, main
from cmcp_runtime.config import AttestationConfig, Config
from cmcp_runtime.policy.bundle import PolicyStore
from cmcp_runtime.startup import RuntimeContext


@pytest.fixture
def claim_and_bundle(tmp_path):
    """Spin up a real server, close a session, export claim + audit bundle."""
    config = Config(attestation=AttestationConfig(), dev_mode=True)

    attestation_report = MagicMock()
    attestation_report.provider = "software-only"
    attestation_report.attestation_generated_at = datetime.now(UTC)
    attestation_report.attestation_validity_seconds = 86400
    attestation_report.measurement = "0" * 64
    attestation_report.report_data = "0" * 64
    attestation_report.measurement_note = None
    attestation_report.raw_evidence = None

    bundle_mock = MagicMock()
    bundle_mock.bundle_hash = "sha256:" + "0" * 64
    bundle_mock.policy_files = {"allow.cedar": "permit (principal, action, resource);"}
    bundle_mock.manifest = MagicMock()
    bundle_mock.manifest.version = "test-v1"
    policy_store = MagicMock(spec=PolicyStore)
    policy_store.bundle = bundle_mock

    catalog = MagicMock()
    catalog.entries = {}
    catalog.catalog_hash = "sha256:" + "1" * 64
    catalog.exceptions = []

    ctx = RuntimeContext(
        config=config,
        tee_provider=MagicMock(),
        attestation_report=attestation_report,
        signing_key=SigningKey(),
        policy_bundle=policy_store,
        catalog=catalog,
    )
    server = build_server(ctx)
    client = TestClient(server.app)
    session_id = server._session.session_id
    claim = client.post(f"/sessions/{session_id}/close").json()
    bundle = client.get(f"/audit/export?session_id={session_id}").json()

    claim_file = tmp_path / "claim.json"
    bundle_file = tmp_path / "bundle.json"
    claim_file.write_text(json.dumps(claim))
    bundle_file.write_text(json.dumps(bundle))
    return claim_file, bundle_file, claim, bundle


def test_verify_software_only_is_partially_verified(claim_and_bundle):
    # The fixture is a software-only (dev mode) claim: every cryptographic check
    # passes, but with no hardware-backed attestation the verifier fails closed
    # to partially_verified, so the CLI reports FAIL and exits non-zero.
    claim_file, _, _, _ = claim_and_bundle
    result = CliRunner().invoke(main, ["verify", str(claim_file)])
    assert result.exit_code == 1, result.output
    assert "RESULT: FAIL (partially_verified)" in result.output
    assert "signature                PASS" in result.output
    assert "hardware_attestation     FAIL" in result.output
    assert "not pinned" in result.output  # hashes unpinned by default


def test_verify_pinned_hashes_still_partial_without_hardware(claim_and_bundle):
    # Pinning the hashes does not grant a software-only claim a full pass; it is
    # still partially_verified because hardware attestation is absent.
    claim_file, _, claim, _ = claim_and_bundle
    result = CliRunner().invoke(main, [
        "verify", str(claim_file),
        "--policy-hash", claim["trace"]["policy"]["bundle_hash"],
        "--catalog-hash", claim["gateway"]["catalog"]["hash"],
    ])
    assert result.exit_code == 1, result.output
    assert "RESULT: FAIL (partially_verified)" in result.output


def test_verify_fails_with_wrong_pinned_hash(claim_and_bundle):
    claim_file, _, _, _ = claim_and_bundle
    result = CliRunner().invoke(main, [
        "verify", str(claim_file), "--policy-hash", "sha256:" + "f" * 64,
    ])
    assert result.exit_code == 1
    assert "RESULT: FAIL" in result.output


def test_verify_fails_on_tampered_claim(claim_and_bundle, tmp_path):
    """The tamper demo: change one field, signature verification fails."""
    _, _, claim, _ = claim_and_bundle
    claim["gateway"]["call_summary"]["tool_calls_total"] += 7
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(claim))
    result = CliRunner().invoke(main, ["verify", str(tampered)])
    assert result.exit_code == 1
    assert "RESULT: FAIL" in result.output
    assert "signature" in result.output


def test_verify_audit_bundle_passes(claim_and_bundle):
    # The audit bundle itself verifies (PASS), but the software-only claim is
    # only partially_verified, so the overall CLI result is still FAIL.
    claim_file, bundle_file, _, _ = claim_and_bundle
    result = CliRunner().invoke(main, [
        "verify", str(claim_file), "--audit-bundle", str(bundle_file),
    ])
    assert result.exit_code == 1, result.output
    assert "audit_bundle             PASS" in result.output
    assert "RESULT: FAIL (partially_verified)" in result.output


def test_verify_fails_on_tampered_audit_bundle(claim_and_bundle, tmp_path):
    """Mutating one audit entry breaks the hash chain and the bundle signature."""
    claim_file, _, _, bundle = claim_and_bundle
    bundle["entries"][0]["entry_type"] = "tool_call"
    tampered = tmp_path / "tampered-bundle.json"
    tampered.write_text(json.dumps(bundle))
    result = CliRunner().invoke(main, [
        "verify", str(claim_file), "--audit-bundle", str(tampered),
    ])
    assert result.exit_code == 1
    assert "RESULT: FAIL" in result.output
