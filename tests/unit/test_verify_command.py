"""End-to-end tests for `cmcp verify`: real claim, real tampering."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from starlette.testclient import TestClient

import cmcp_verify
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.cli import build_server, main
from cmcp_runtime.config import AttestationConfig, Config
from cmcp_runtime.policy.bundle import PolicyStore
from cmcp_runtime.startup import RuntimeContext
from cmcp_verify.tpm_roots import AZURE_VTPM_ROOT_2023_PEM


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
    signing_key = SigningKey()
    ctx = RuntimeContext(
        config=config,
        tee_provider=MagicMock(),
        attestation_report=attestation_report,
        signing_key=signing_key,
        policy_bundle=policy_store,
        catalog=catalog,
    )
    server = build_server(ctx)
    client = TestClient(server.app)
    session_id = server._session.session_id
    # Produce real tool-call evidence so removing tool_transcript cannot be
    # confused with a legitimately transcript-less claim.
    server._audit_chain.append(
        "tool_call",
        call_id="fixture-call",
        tool_name="fixture-tool",
        policy_decision="allow",
    )
    claim = client.post(f"/sessions/{session_id}/close").json()
    bundle = client.get(f"/audit/export?session_id={session_id}").json()

    claim_file = tmp_path / "claim.json"
    bundle_file = tmp_path / "bundle.json"
    claim_file.write_text(json.dumps(claim))
    bundle_file.write_text(json.dumps(bundle))
    return claim_file, bundle_file, claim, bundle, signing_key


def test_verify_software_only_is_partially_verified(claim_and_bundle):
    # The fixture is a software-only (dev mode) claim: every cryptographic check
    # passes, but with no hardware-backed attestation the verifier fails closed
    # to partially_verified, so the CLI reports FAIL and exits non-zero.
    claim_file, _, _, _, _ = claim_and_bundle
    result = CliRunner().invoke(main, ["verify", str(claim_file)])
    assert result.exit_code == 1, result.output
    assert "RESULT: FAIL (partially_verified)" in result.output
    assert "signature                PASS" in result.output
    assert "hardware_attestation     FAIL" in result.output
    assert "not pinned" in result.output  # hashes unpinned by default


def test_verify_pinned_hashes_still_partial_without_hardware(claim_and_bundle):
    # Pinning the hashes does not grant a software-only claim a full pass; it is
    # still partially_verified because hardware attestation is absent.
    claim_file, _, claim, _, _ = claim_and_bundle
    result = CliRunner().invoke(main, [
        "verify", str(claim_file),
        "--policy-hash", claim["trace"]["policy"]["bundle_hash"],
        "--catalog-hash", claim["gateway"]["catalog"]["hash"],
    ])
    assert result.exit_code == 1, result.output
    assert "RESULT: FAIL (partially_verified)" in result.output


def test_verify_fails_with_wrong_pinned_hash(claim_and_bundle):
    claim_file, _, _, _, _ = claim_and_bundle
    result = CliRunner().invoke(main, [
        "verify", str(claim_file), "--policy-hash", "sha256:" + "f" * 64,
    ])
    assert result.exit_code == 1
    assert "RESULT: FAIL" in result.output


def test_verify_fails_on_tampered_claim(claim_and_bundle, tmp_path):
    """The tamper demo: change one field, signature verification fails."""
    _, _, claim, _, _ = claim_and_bundle
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
    claim_file, bundle_file, claim, _, _ = claim_and_bundle
    assert claim["trace"]["tool_transcript"]["call_count"] == 1
    call_summary = claim["gateway"]["call_summary"]
    assert {
        field: call_summary[field]
        for field in (
            "tool_calls_total",
            "tool_calls_allowed",
            "tool_calls_denied",
            "tool_cals_faulted",
            "tools_invoked",
        )
    } == {
        "tool_calls_total": 1,
        "tool_calls_allowed": 1,
        "tool_calls_denied": 0,
        "tool_calls_faulted": 0,
        "tools_invoked": ["fixture-tool"],
    }
    result = CliRunner().invoke(main, [
        "verify", str(claim_file), "--audit-bundle", str(bundle_file),
    ])
    assert result.exit_code == 1, result.output
    assert "audit_bundle             PASS" in result.output
    assert "RESULT: FAIL (partially_verified)" in result.output

def test_verify_rejects_tool_transcript_hash_mismatch(claim_and_bundle, tmp_path):
    """A re-signed claim must still bind tool_transcript.hash to audit_chain.tip."""
    _, bundle_file, claim, _, signing_key = claim_and_bundle

    claim["trace"]["tool_transcript"]["hash"] = "sha256:" + "0" * 64

    body = {k: v for k, v in claim.items() if k != "signature"}
    body_bytes = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    raw_sig = signing_key.sign(body_bytes)
    claim["signature"] = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()

    tampered_claim = tmp_path / "tool-transcript-mismatch.json"
    tampered_claim.write_text(json.dumps(claim))

    result = CliRunner().invoke(main, [
        "verify", str(tampered_claim), "--audit-bundle", str(bundle_file),
    ])

    assert result.exit_code == 1, result.output
    assert "signature                PASS" in result.output
    assert "audit_bundle             FAIL" in result.output
    assert "tool_transcript.hash does not match gateway.audit_chain.tip" in result.output
def test_verify_rejects_removed_tool_transcript(claim_and_bundle, tmp_path):
    """Check whether a re-signed claim can drop the transcript binding."""
    _, bundle_file, claim, _, signing_key = claim_and_bundle

    claim["trace"].pop("tool_transcript")

    body = {k: v for k, v in claim.items() if k != "signature"}
    body_bytes = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()

    raw_sig = signing_key.sign(body_bytes)
    claim["signature"] = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()

    stripped_claim = tmp_path / "tool-transcript-removed.json"
    stripped_claim.write_text(json.dumps(claim))

    result = CliRunner().invoke(
        main,
        ["verify", str(stripped_claim), "--audit-bundle", str(bundle_file)],
    )

    assert result.exit_code == 1, result.output
    assert "signature                PASS" in result.output
    assert "audit_bundle             FAIL" in result.output
    assert "tool_transcript.hash is missing for a bundle with tool calls" in result.output


@pytest.mark.parametrize(
    ("section", "field_name", "tampered_value", "expected_error"),
    [
        (
            "tool_transcript",
            "call_count",
            7,
            "trace.tool_transcript.call_count does not match audit bundle tool calls",
        ),
        (
            "call_summary",
            "tool_calls_total",
            7,
            "gateway.call_summary.tool_calls_total does not match audit bundle tool calls",
        ),
        (
            "call_summary",
            "tool_calls_allowed",
            0,
            "gateway.call_summary.tool_calls_allowed does not match audit bundle tool calls",
        ),
        (
            "call_summary",
            "tool_calls_denied",
            1,
            "gateway.call_summary.tool_calls_denied does not match audit bundle tool calls",
        ),
        (
            "call_summary",
            "tool_calls_faulted",
            1,
            "gateway.call_summary.tool_calls_faulted does not match audit bundle tool calls",
        ),
        (
            "call_summary",
            "tools_invoked",
            ["substituted.tool"],
            "gateway.call_summary.tools_invoked does not match audit bundle tool calls",
        ),
        (
            "call_summary",
            "tool_calls_total",
            True,
            "gateway.call_summary.tool_calls_total does not match audit bundle tool calls",
        ),
        (
            "call_summary",
            "tool_calls_denied",
            False,
            "gateway.call_summary.tool_cals_denied does not match audit bundle tool calls",
        ),
    ],
)
def test_verify_rejects_call_summary_mismatch(
    claim_and_bundle,
    tmp_path,
    section,
    field_name,
    tampered_value,
    expected_error,
):
    """A re-signed claim must bind audit-derived call metadata to the bundle."""
    _, bundle_file, claim, _, signing_key = claim_and_bundle

    if section == "tool_transcript":
        claim["trace"][section][field_name] = tampered_value
    else:
        claim["gateway"][section][field_name] = tampered_value

    body = {k: v for k, v in claim.items() if k != "signature"}
    body_bytes = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    raw_sig = signing_key.sign(body_bytes)
    claim["signature"] = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()

    tampered_claim = tmp_path / f"{field_name}-mismatch.json"
    tampered_claim.write_text(json.dumps(claim))

    result = CliRunner().invoke(main, [
        "verify", str(tampered_claim), "--audit-bundle", str(bundle_file),
    ])

    assert result.exit_code == 1, result.output
    assert "signature                PASS" in result.output
    assert "audit_bundle             FAIL" in result.output
    assert expected_error in result.output


def test_verify_fails_on_tampered_audit_bundle(claim_and_bundle, tmp_path):
    """Mutating one audit entry breaks the hash chain and the bundle signature."""
    claim_file, _, _, bundle, _ = claim_and_bundle
    bundle["entries"][0]["entry_type"] = "tool_call"
    tampered = tmp_path / "tampered-bundle.json"
    tampered.write_text(json.dumps(bundle))
    result = CliRunner().invoke(main, [
        "verify", str(claim_file), "--audit-bundle", str(tampered),
    ])
    assert result.exit_code == 1
    assert "RESULT: FAIL" in result.output


def test_verify_threads_only_the_tpm_ca_bundle(claim_and_bundle, tmp_path, monkeypatch):
    claim_file, _, _, _, _ = claim_and_bundle
    ca_path = tmp_path / "tpm-ca.pem"
    ca_path.write_bytes(AZURE_VTPM_ROOT_2023_PEM)

    captured: dict[str, object] = {}
    real_verify = cmcp_verify.verify_trace_claim

    def capture_verify(*args, **kwargs):
        captured.update(kwargs)
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(cmcp_verify, "verify_trace_claim", capture_verify)

    result = CliRunner().invoke(
        main,
        ["verify", str(claim_file), "--trusted-tpm-ca", str(ca_path)],
    )

    assert result.exit_code == 1, result.output
    assert result.output.endswith("RESULT: FAIL (partially_verified)\n")
    assert captured["trusted_tpm_ca_pem"] == AZURE_VTPM_ROOT_2023_PEM
    assert "trusted_ark_pem" not in captured
    assert "trusted_intel_root_pem" not in captured


def test_verify_rejects_invalid_tpm_ca_bundle(claim_and_bundle, tmp_path, monkeypatch):
    claim_file, _, _, _, _ = claim_and_bundle
    ca_path = tmp_path / "not-a-certificate.pem"
    ca_path.write_text("this is not a PEM certificate")

    def must_not_verify(*args, **kwargs):
        pytest.fail("verify_trace_claim must not run with an invalid TPM CA bundle")

    monkeypatch.setattr(cmcp_verify, "verify_trace_claim", must_not_verify)

    result = CliRunner().invoke(
        main,
        ["verify", str(claim_file), "--trusted-tpm-ca", str(ca_path)],
    )

    assert result.exit_code == 1, result.output
    assert "TPM CA bundle must contain PEM-encoded X.509 certificates" in result.output


def test_verify_help_keeps_the_new_trust_anchor_tpm_only():
    result = CliRunner().invoke(main, ["verify", "--help"])

    assert result.exit_code == 0, result.output
    assert "--trusted-tpm-ca" in result.output
    assert "TPM 2.0 claims only" in result.output
    assert "--trusted-amd" not in result.output
    assert "--trusted-intel" not in result.output
