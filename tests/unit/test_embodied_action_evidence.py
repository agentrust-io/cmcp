"""Tests for embodied action evidence profile verification."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cmcp_verify import (
    ReceiptState,
    hash_embodied_action_payload,
    verify_embodied_action_evidence,
)

_FIXTURE = (
    Path(__file__).parent.parent
    / "fixtures"
    / "embodied-action-evidence"
    / "ros2-fibonacci-aborted.json"
)


def _fixture() -> dict:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _rebind_payload_hash(fixture: dict) -> None:
    """Keep fixture mutations focused on profile checks, not stale evidence hashes."""

    payload = fixture["detached_payload"]
    fixture["audit_entry"]["external_execution_evidence"]["evidence_hash"] = (
        hash_embodied_action_payload(payload)
    )


def test_ros2_fibonacci_aborted_fixture_verifies():
    fixture = _fixture()

    result = verify_embodied_action_evidence(
        fixture["audit_entry"],
        fixture["detached_payload"],
        fixture["trace_claim"],
        require_receipt=True,
    )

    assert result.verified, result.failures
    assert result.receipt_state == ReceiptState.REJECTED
    assert "external_execution_evidence.evidence_hash" in result.verified_fields
    assert "action_ref" in result.verified_fields
    assert "receipt.goal_uuid" in result.verified_fields
    assert "receipt.goal_preimage_hash" in result.verified_fields
    assert "receipt.physical_completion_claim" in result.verified_fields


def test_ros2_fixture_external_evidence_signature_is_valid():
    fixture = _fixture()
    evidence = fixture["audit_entry"]["external_execution_evidence"]
    signature = evidence["signature"]
    padding = 4 - (len(signature) % 4)
    signature_bytes = base64.urlsafe_b64decode(
        signature + ("=" * padding if padding != 4 else "")
    )
    signing_input = json.dumps(
        {k: v for k, v in evidence.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(fixture["trusted_issuer_public_key_hex"])
    )

    public_key.verify(signature_bytes, signing_input)


def test_action_ref_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    payload = fixture["detached_payload"]
    payload["action_ref"] = "sha256:" + "0" * 64
    payload["receipt"]["action_ref"] = payload["action_ref"]
    _rebind_payload_hash(fixture)

    result = verify_embodied_action_evidence(
        fixture["audit_entry"],
        payload,
        fixture["trace_claim"],
    )

    assert not result.verified
    assert any("action_ref" in failure for failure in result.failures)


def test_ros2_goal_uuid_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    payload = fixture["detached_payload"]
    payload["receipt"]["goal_uuid"] = "00000000000000000000000000000000"
    _rebind_payload_hash(fixture)

    result = verify_embodied_action_evidence(
        fixture["audit_entry"],
        payload,
        fixture["trace_claim"],
    )

    assert not result.verified
    assert any("receipt.goal_uuid" in failure for failure in result.failures)


def test_ros2_goal_preimage_hash_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    payload = fixture["detached_payload"]
    payload["receipt"]["goal_preimage_hash"] = "sha256:" + "0" * 64
    _rebind_payload_hash(fixture)

    result = verify_embodied_action_evidence(
        fixture["audit_entry"],
        payload,
        fixture["trace_claim"],
    )

    assert not result.verified
    assert any("receipt.goal_preimage_hash" in failure for failure in result.failures)


def test_missing_receipt_is_absent_unless_policy_requires_it():
    fixture = copy.deepcopy(_fixture())
    payload = fixture["detached_payload"]
    payload.pop("receipt")
    _rebind_payload_hash(fixture)

    optional_result = verify_embodied_action_evidence(
        fixture["audit_entry"],
        payload,
        fixture["trace_claim"],
    )
    required_result = verify_embodied_action_evidence(
        fixture["audit_entry"],
        payload,
        fixture["trace_claim"],
        require_receipt=True,
    )

    assert optional_result.verified, optional_result.failures
    assert optional_result.receipt_state == ReceiptState.ABSENT
    assert not required_result.verified
    assert required_result.receipt_state == ReceiptState.ABSENT
    assert any("receipt is required" in failure for failure in required_result.failures)


def test_physical_completion_claim_fails_closed():
    fixture = copy.deepcopy(_fixture())
    payload = fixture["detached_payload"]
    payload["receipt"]["physical_completion_claim"] = "completed"
    _rebind_payload_hash(fixture)

    result = verify_embodied_action_evidence(
        fixture["audit_entry"],
        payload,
        fixture["trace_claim"],
    )

    assert not result.verified
    assert any("physical completion" in failure for failure in result.failures)


def test_gateway_self_report_is_verified_but_warned():
    fixture = copy.deepcopy(_fixture())
    payload = fixture["detached_payload"]
    payload["receipt"]["issuer_independence"] = "gateway_self_report"
    _rebind_payload_hash(fixture)

    result = verify_embodied_action_evidence(
        fixture["audit_entry"],
        payload,
        fixture["trace_claim"],
    )

    assert result.verified, result.failures
    assert any("self-report" in warning for warning in result.warnings)
