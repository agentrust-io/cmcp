"""Tests for embodied action evidence profile verification."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cmcp_verify import (
    ReceiptState,
    hash_embodied_action_payload,
    verify_embodied_action_evidence,
)
from cmcp_verify.embodied_action import canonical_json_bytes

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


def _verify_fixture(fixture: dict):
    return verify_embodied_action_evidence(
        fixture["audit_entry"],
        fixture["detached_payload"],
        fixture["trace_claim"],
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


def test_payload_hash_helper_supports_sha384_and_rejects_unknown_algorithm():
    fixture = _fixture()
    payload = fixture["detached_payload"]

    assert hash_embodied_action_payload(payload, algorithm="sha384").startswith("sha384:")
    with pytest.raises(ValueError, match="algorithm must be sha256 or sha384"):
        hash_embodied_action_payload(payload, algorithm="sha512")


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


def test_missing_external_execution_evidence_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["audit_entry"]["external_execution_evidence"] = None

    result = _verify_fixture(fixture)

    assert not result.verified
    assert result.receipt_state == ReceiptState.INVALID
    assert any("no external_execution_evidence" in failure for failure in result.failures)


def test_accepted_receipt_classifies_as_accepted():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["receipt"]["verdict"] = "accepted"
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert result.verified, result.failures
    assert result.receipt_state == ReceiptState.ACCEPTED


def test_invalid_receipt_verdict_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["receipt"]["verdict"] = "pending"
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert result.receipt_state == ReceiptState.INVALID
    assert any("receipt.verdict" in failure for failure in result.failures)


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


def test_missing_required_payload_field_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"].pop("controller_target")
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("missing required fields" in failure for failure in result.failures)


def test_wrong_profile_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["profile"] = "cmcp.other_profile.v0"
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("profile must be" in failure for failure in result.failures)


def test_payload_call_id_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["call_id"] = "01986d7c-6b2f-7c68-9ff8-000000000000"
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("payload call_id" in failure for failure in result.failures)


def test_evidence_linked_call_id_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["audit_entry"]["external_execution_evidence"]["linked_call_id"] = (
        "01986d7c-6b2f-7c68-9ff8-000000000000"
    )

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("linked_call_id" in failure for failure in result.failures)


def test_evidence_hash_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["audit_entry"]["external_execution_evidence"]["evidence_hash"] = "sha256:" + "0" * 64

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("evidence_hash" in failure for failure in result.failures)


def test_malformed_evidence_hash_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["audit_entry"]["external_execution_evidence"]["evidence_hash"] = "sha512:not-a-digest"

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("evidence_hash" in failure for failure in result.failures)


def test_non_string_action_ref_preimage_field_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["action_timestamp"] = 123
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("preimage fields must be strings" in failure for failure in result.failures)


def test_governance_decision_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["governance_decision"] = "deny"
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("governance_decision" in failure for failure in result.failures)


def test_policy_bundle_hash_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["policy_bundle_hash"] = "sha256:" + "0" * 64
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("policy_bundle_hash" in failure for failure in result.failures)


def test_tool_catalog_hash_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["tool_catalog_hash"] = "sha256:" + "0" * 64
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("tool_catalog_hash" in failure for failure in result.failures)


def test_agent_identity_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["trace_claim"]["gateway"]["agent_identity"]["agent_id"] = (
        "spiffe://factory.example/agent/other/dev"
    )

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("agent_id" in failure for failure in result.failures)


def test_non_object_agent_identity_is_ignored():
    fixture = copy.deepcopy(_fixture())
    fixture["trace_claim"]["gateway"]["agent_identity"] = "not-an-object"

    result = _verify_fixture(fixture)

    assert result.verified, result.failures


def test_ros2_must_be_object_when_present():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["ros2"] = "not-an-object"
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("ros2 must be an object" in failure for failure in result.failures)


def test_ros2_missing_required_field_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["ros2"].pop("action_name")
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("ros2 missing required fields" in failure for failure in result.failures)


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


def test_receipt_must_be_object_when_present():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["receipt"] = "not-an-object"
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert result.receipt_state == ReceiptState.INVALID
    assert any("receipt must be an object" in failure for failure in result.failures)


def test_receipt_type_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["receipt"]["receipt_type"] = "other-receipt/v1"
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("receipt.receipt_type" in failure for failure in result.failures)


def test_receipt_call_id_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["receipt"]["call_id"] = "01986d7c-6b2f-7c68-9ff8-000000000000"
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("receipt.call_id" in failure for failure in result.failures)


def test_receipt_action_ref_mismatch_fails():
    fixture = copy.deepcopy(_fixture())
    fixture["detached_payload"]["receipt"]["action_ref"] = "sha256:" + "0" * 64
    _rebind_payload_hash(fixture)

    result = _verify_fixture(fixture)

    assert not result.verified
    assert any("receipt.action_ref" in failure for failure in result.failures)


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


# -- canonical_json_bytes: RFC 8785/JCS compliance (agentrust-io/cmcp#588) ------


def test_canonical_json_bytes_emits_utf8_not_ascii_escapes():
    # RFC 8785 requires UTF-8 output; \uXXXX-escaping non-ASCII characters (the
    # old behavior) gives a different byte string -- and a different hash --
    # than a JCS-compliant producer would emit for the identical value.
    result = canonical_json_bytes({"action_scope": "robot-cell-caf\u00e9"})
    assert "robot-cell-caf\u00e9".encode("utf-8") in result
    assert b"\\u00e9" not in result


def test_canonical_json_bytes_orders_keys_by_utf16_code_unit():
    # A supplementary-plane character's UTF-16 lead surrogate can sort before a
    # high-BMP character that is nonetheless a larger Unicode code point --
    # Python's default `sorted()` (code-point order) gets this backwards.
    result = canonical_json_bytes({"\U0001f600": 1, "\uffff": 2})
    assert result.index("\U0001f600".encode()) < result.index("\uffff".encode())


def test_canonical_json_bytes_rejects_float_fields():
    # Every required field in the embodied-action profile is a string (spec
    # explicitly steers producers away from numeric timestamps); a float
    # reaching the preimage is refused rather than silently serialized in a
    # way a JCS-compliant verifier might not reproduce byte-for-byte.
    with pytest.raises(ValueError, match="floating point"):
        canonical_json_bytes({"action_timestamp": 1750868200.0})


def test_action_ref_matches_independent_jcs_reference_hash():
    # A hand-computed RFC 8785 reference for the exact v0.1 action_ref preimage
    # shape, so this fails if the JCS wiring silently regresses even when
    # every existing fixture-based test still passes (they don't cover
    # non-ASCII field values). Keys are written here in the RFC 8785 §3.2.3
    # (UTF-16 code-unit) order by hand, and the value is UTF-8-encoded
    # directly, rather than calling the function under test.
    import hashlib

    preimage_text = (
        '{"action_scope":"cell-7","action_timestamp":'
        '"2026-06-25T16:30:00Z","action_type":"m\u00e9tro",'
        '"agent_id":"agent-1"}'
    )
    expected = "sha256:" + hashlib.sha256(preimage_text.encode("utf-8")).hexdigest()

    from cmcp_verify.embodied_action import compute_action_ref

    actual = compute_action_ref({
        "agent_id": "agent-1",
        "action_type": "m\u00e9tro",
        "action_scope": "cell-7",
        "action_timestamp": "2026-06-25T16:30:00Z",
    })
    assert actual == expected


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
