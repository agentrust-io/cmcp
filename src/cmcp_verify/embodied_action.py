"""Profile-aware verification for embodied action evidence payloads."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

EMBODIED_ACTION_PROFILE = "cmcp.embodied_action_evidence.v0"

_HASH_RE = re.compile(r"^sha(256|384):([0-9a-f]+)$")
_ACTION_REF_FIELDS = ("agent_id", "action_type", "action_scope", "action_timestamp")
_REQUIRED_PAYLOAD_FIELDS = (
    "profile",
    "call_id",
    "action_ref",
    "agent_id",
    "action_type",
    "action_scope",
    "action_timestamp",
    "governance_decision",
    "policy_bundle_hash",
    "tool_catalog_hash",
    "controller_target",
    "handoff_timestamp",
)
_ROS2_REQUIRED_FIELDS = (
    "distribution",
    "action_name",
    "action_type",
    "goal_uuid",
    "goal_preimage_hash",
    "goal_preimage_method",
)


class ReceiptState(StrEnum):
    """Detached payload receipt classification."""

    ABSENT = "absent"
    UNTRUSTED = "untrusted"
    INVALID = "invalid"
    STALE = "stale"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass
class EmbodiedActionEvidenceResult:
    """Result of verifying a detached embodied-action evidence payload."""

    verified: bool
    receipt_state: ReceiptState
    verified_fields: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    """Return the canonical JSON byte form used by cMCP evidence hashes."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def hash_embodied_action_payload(payload: dict[str, Any], *, algorithm: str = "sha256") -> str:
    """Hash a detached embodied-action evidence payload."""

    if algorithm == "sha256":
        digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    elif algorithm == "sha384":
        digest = hashlib.sha384(canonical_json_bytes(payload)).hexdigest()
    else:
        raise ValueError("algorithm must be sha256 or sha384")
    return f"{algorithm}:{digest}"


def compute_action_ref(payload: dict[str, Any]) -> str:
    """Compute the profile action_ref from the v0.1 canonical action preimage."""

    preimage = {field: payload[field] for field in _ACTION_REF_FIELDS}
    return "sha256:" + hashlib.sha256(canonical_json_bytes(preimage)).hexdigest()


def _claim_policy_hash(claim_json: dict[str, Any]) -> str | None:
    policy = claim_json.get("trace", {}).get("policy", {})
    value = policy.get("bundle_hash")
    return value if isinstance(value, str) else None


def _claim_catalog_hash(claim_json: dict[str, Any]) -> str | None:
    catalog = claim_json.get("gateway", {}).get("catalog", {})
    value = catalog.get("hash")
    return value if isinstance(value, str) else None


def _claim_agent_id(claim_json: dict[str, Any]) -> str | None:
    identity = claim_json.get("gateway", {}).get("agent_identity")
    if not isinstance(identity, dict):
        return None
    value = identity.get("agent_id")
    return value if isinstance(value, str) else None


def _verify_hash_value(hash_value: str, payload: dict[str, Any]) -> bool:
    match = _HASH_RE.match(hash_value)
    if not match:
        return False
    algorithm = f"sha{match.group(1)}"
    return hmac.compare_digest(hash_value, hash_embodied_action_payload(payload, algorithm=algorithm))


def _record_receipt_state(
    receipt: dict[str, Any] | None,
    failures: list[str],
) -> ReceiptState:
    if receipt is None:
        return ReceiptState.ABSENT
    verdict = receipt.get("verdict")
    if verdict == "accepted":
        return ReceiptState.ACCEPTED
    if verdict == "rejected":
        return ReceiptState.REJECTED
    failures.append("receipt.verdict must be accepted or rejected")
    return ReceiptState.INVALID


def verify_embodied_action_evidence(
    audit_entry: dict[str, Any],
    detached_payload: dict[str, Any],
    claim_json: dict[str, Any] | None = None,
    *,
    require_receipt: bool = False,
) -> EmbodiedActionEvidenceResult:
    """Verify the detached payload for the embodied action evidence profile.

    This helper assumes the caller has already run ``verify_audit_bundle`` when
    issuer signature verification is required. It checks the profile-specific
    binding between an audit entry, the detached evidence payload, and optional
    TRACE Claim context.
    """

    verified_fields: list[str] = []
    failures: list[str] = []
    warnings: list[str] = []

    evidence = audit_entry.get("external_execution_evidence")
    if not isinstance(evidence, dict):
        failures.append("audit entry has no external_execution_evidence object")
        return EmbodiedActionEvidenceResult(
            verified=False,
            receipt_state=ReceiptState.INVALID,
            verified_fields=verified_fields,
            failures=failures,
            warnings=warnings,
        )

    missing = [field for field in _REQUIRED_PAYLOAD_FIELDS if field not in detached_payload]
    if missing:
        failures.append(f"detached payload missing required fields: {', '.join(missing)}")

    if detached_payload.get("profile") != EMBODIED_ACTION_PROFILE:
        failures.append(f"detached payload profile must be {EMBODIED_ACTION_PROFILE}")
    else:
        verified_fields.append("profile")

    call_id = audit_entry.get("call_id")
    if detached_payload.get("call_id") != call_id:
        failures.append("detached payload call_id does not match audit entry call_id")
    else:
        verified_fields.append("call_id")

    if evidence.get("linked_call_id") != call_id:
        failures.append("external_execution_evidence linked_call_id does not match audit entry call_id")
    else:
        verified_fields.append("external_execution_evidence.linked_call_id")

    evidence_hash = evidence.get("evidence_hash")
    if not isinstance(evidence_hash, str) or not _verify_hash_value(evidence_hash, detached_payload):
        failures.append("external_execution_evidence evidence_hash does not match detached payload")
    else:
        verified_fields.append("external_execution_evidence.evidence_hash")

    if all(isinstance(detached_payload.get(field), str) for field in _ACTION_REF_FIELDS):
        expected_action_ref = compute_action_ref(detached_payload)
        if detached_payload.get("action_ref") != expected_action_ref:
            failures.append("action_ref does not match canonical action preimage")
        else:
            verified_fields.append("action_ref")
    else:
        failures.append("action_ref preimage fields must be strings")

    policy_decision = audit_entry.get("policy_decision")
    if policy_decision is not None:
        if detached_payload.get("governance_decision") != policy_decision:
            failures.append("governance_decision does not match audit entry policy_decision")
        else:
            verified_fields.append("governance_decision")

    if claim_json is not None:
        policy_hash = _claim_policy_hash(claim_json)
        if policy_hash is not None:
            if detached_payload.get("policy_bundle_hash") != policy_hash:
                failures.append("policy_bundle_hash does not match TRACE Claim policy hash")
            else:
                verified_fields.append("policy_bundle_hash")

        catalog_hash = _claim_catalog_hash(claim_json)
        if catalog_hash is not None:
            if detached_payload.get("tool_catalog_hash") != catalog_hash:
                failures.append("tool_catalog_hash does not match TRACE Claim catalog hash")
            else:
                verified_fields.append("tool_catalog_hash")

        agent_id = _claim_agent_id(claim_json)
        if agent_id is not None:
            if detached_payload.get("agent_id") != agent_id:
                failures.append("agent_id does not match TRACE Claim agent identity")
            else:
                verified_fields.append("agent_id")

    ros2 = detached_payload.get("ros2")
    if ros2 is not None:
        if not isinstance(ros2, dict):
            failures.append("ros2 must be an object when present")
        else:
            ros_missing = [field for field in _ROS2_REQUIRED_FIELDS if field not in ros2]
            if ros_missing:
                failures.append(f"ros2 missing required fields: {', '.join(ros_missing)}")
            else:
                verified_fields.append("ros2.goal_preimage_hash")
                verified_fields.append("ros2.goal_uuid")

    receipt = detached_payload.get("receipt")
    if receipt is not None and not isinstance(receipt, dict):
        failures.append("receipt must be an object when present")
        receipt_state = ReceiptState.INVALID
    else:
        receipt_state = _record_receipt_state(receipt, failures)

    if require_receipt and receipt_state == ReceiptState.ABSENT:
        failures.append("receipt is required by verifier policy")

    if isinstance(receipt, dict):
        if receipt.get("receipt_type") != evidence.get("evidence_type"):
            failures.append("receipt.receipt_type does not match evidence_type")
        else:
            verified_fields.append("receipt.receipt_type")

        if receipt.get("call_id") is not None:
            if receipt.get("call_id") != detached_payload.get("call_id"):
                failures.append("receipt.call_id does not match detached payload call_id")
            else:
                verified_fields.append("receipt.call_id")

        if receipt.get("action_ref") is not None:
            if receipt.get("action_ref") != detached_payload.get("action_ref"):
                failures.append("receipt.action_ref does not match detached payload action_ref")
            else:
                verified_fields.append("receipt.action_ref")

        if isinstance(ros2, dict):
            if receipt.get("goal_uuid") is not None:
                if receipt.get("goal_uuid") != ros2.get("goal_uuid"):
                    failures.append("receipt.goal_uuid does not match ros2.goal_uuid")
                else:
                    verified_fields.append("receipt.goal_uuid")
            if receipt.get("goal_preimage_hash") is not None:
                if receipt.get("goal_preimage_hash") != ros2.get("goal_preimage_hash"):
                    failures.append(
                        "receipt.goal_preimage_hash does not match ros2.goal_preimage_hash"
                    )
                else:
                    verified_fields.append("receipt.goal_preimage_hash")

        physical_claim = receipt.get("physical_completion_claim")
        if physical_claim is not None:
            if physical_claim != "none":
                failures.append("physical completion claims are not verified by this profile")
            else:
                verified_fields.append("receipt.physical_completion_claim")

        if receipt.get("issuer_independence") == "gateway_self_report":
            warnings.append("receipt is same-party gateway self-report evidence")

    return EmbodiedActionEvidenceResult(
        verified=not failures,
        receipt_state=receipt_state,
        verified_fields=verified_fields,
        failures=failures,
        warnings=warnings,
    )
