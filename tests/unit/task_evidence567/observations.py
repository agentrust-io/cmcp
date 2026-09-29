"""Conditional fixture oracle for settled #567 observation/relation boundaries.

The fixture trusts separately pinned witness and creation-source keys, plus
the exact, complete exchange/event scope. Signed witness statements are TEST
EVIDENCE, not a new callback-authentication protocol. No Tasks runtime or
terminal verifier exists here. SHA/signature validity binds bytes, not
real-world authority; that authority is an explicit synthetic-world premise
described in README.md.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ESTABLISHED = "ESTABLISHED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"
CONTRADICTED = "VERIFIED_CONTRADICTION"
PROTOCOL_PROFILE = "io.modelcontextprotocol/tasks@2026-07-28"
CREATION_CONTRACT = "CreateTaskResult:durable-and-resolvable-at-return"
TASK_STATUSES = frozenset({"working", "input_required", "completed", "failed", "cancelled"})


def canonical(value: Any) -> bytes:
    return rfc8785.dumps(value)


@dataclass(frozen=True)
class Observation:
    occurrence: str
    kind: str
    payload: bytes
    ingest_index: int

    @property
    def data(self) -> dict[str, Any]:
        return json.loads(self.payload)

    @property
    def commitment(self) -> str:
        # Receiver arrival is deliberately not a producer/source identity.
        body = [self.occurrence, self.kind, self.payload.hex()]
        return hashlib.sha256(canonical(body)).hexdigest()


@dataclass(frozen=True)
class Witness:
    body: bytes
    signature: bytes


@dataclass(frozen=True)
class FixtureProfile:
    witness_key: bytes
    request_scope: tuple[Observation, ...]
    creation_source_key: bytes | None = None
    creation_source_id: str | None = None

    @property
    def scope_commitment(self) -> str:
        return hashlib.sha256(canonical([r.commitment for r in self.request_scope])).hexdigest()

    def read(self, witness: Witness | None, boundary: str) -> dict[str, Any] | None:
        if witness is None:
            return None
        try:
            Ed25519PublicKey.from_public_bytes(self.witness_key).verify(
                witness.signature, witness.body
            )
            body = json.loads(witness.body)
            if canonical(body) != witness.body or body.get("boundary") != boundary:
                return None
        except (InvalidSignature, ValueError, TypeError, AttributeError):
            return None
        return body


@dataclass(frozen=True)
class Assessment:
    disposition: str
    reason: str
    operation: str | None = None


def typed_id(data: dict[str, Any]) -> tuple[type, int | str] | None:
    value = data.get("id")
    return (type(value), value) if type(value) in (str, int) else None


def bind_exchange(
    profile: FixtureProfile,
    request: Observation,
    response: Observation,
    witness: Witness | None,
) -> Assessment:
    if request.kind != "request_observed":
        return Assessment(NOT_ESTABLISHED, "not_a_typed_request_observation")
    response_id = typed_id(response.data)
    if response_id is None:
        return Assessment(NOT_ESTABLISHED, "no_usable_typed_response_id")
    if request not in profile.request_scope or typed_id(request.data) != response_id:
        return Assessment(NOT_ESTABLISHED, "request_not_in_scope_or_typed_id_mismatch")
    body = profile.read(witness, "exchange")
    if body is None or any(
        body.get(key) != value
        for key, value in {
            "scope": profile.scope_commitment,
            "request": request.commitment,
            "response": response.commitment,
        }.items()
    ):
        return Assessment(NOT_ESTABLISHED, "independent_occurrence_binding_missing")
    return Assessment(ESTABLISHED, "exact_exchange_bound", request.data["method"])


def _creation_source_premise_bound(
    profile: FixtureProfile, response: Observation, source_witness: Witness | None
) -> bool:
    """Check exact stipulated source bytes, separately from the contract receipt.

    Signature validity authenticates fixture premise bytes, not external source
    truth. The optional legacy type label is diagnostic and never decides type.
    """
    if (
        source_witness is None
        or profile.creation_source_key is None
        or profile.creation_source_id is None
    ):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(profile.creation_source_key).verify(
            source_witness.signature, source_witness.body
        )
        source = json.loads(source_witness.body)
        if not isinstance(source, dict) or canonical(source) != source_witness.body:
            return False
    except (InvalidSignature, ValueError, TypeError, AttributeError):
        return False
    return {key: value for key, value in source.items() if key != "result_type"} == {
        "boundary": "creation_source_type",
        "response": response.commitment,
        "source": profile.creation_source_id,
        "source_bytes": response.payload.hex(),
        "protocol_profile": PROTOCOL_PROFILE,
    }


def _sep2663_creation_discriminator_guard(payload: bytes) -> bool:
    """Fixture-only 2026 task discriminator and required flat task fields.

    This is not a full MCP Tasks validator. The legacy SDK CreateTaskResult
    parser models 2025-11-25 and is not authority for this type decision.
    """
    try:
        result = json.loads(payload)
    except (ValueError, TypeError, UnicodeDecodeError):
        return False
    return (
        isinstance(result, dict)
        and result.get("resultType") == "task"
        and isinstance(result.get("taskId"), str)
        and bool(result["taskId"])
        and isinstance(result.get("status"), str)
        and result.get("status") in TASK_STATUSES
        and isinstance(result.get("createdAt"), str)
        and bool(result["createdAt"])
        and isinstance(result.get("lastUpdatedAt"), str)
        and bool(result["lastUpdatedAt"])
        and "ttlMs" in result
        and (result["ttlMs"] is None or type(result["ttlMs"]) is int)
    )


def creation_claims(
    profile: FixtureProfile,
    response: Observation,
    witness: Witness | None,
    source_witness: Witness | None,
) -> frozenset[str]:
    body = profile.read(witness, "trusted_creation_contract")
    if (
        response.kind != "task_creation_result_observed"
        or body is None
        or body.get("response") != response.commitment
        or body.get("contract") != CREATION_CONTRACT
        or body.get("protocol_profile") != PROTOCOL_PROFILE
        or not _creation_source_premise_bound(profile, response, source_witness)
        or not _sep2663_creation_discriminator_guard(response.payload)
    ):
        return frozenset()
    return frozenset({"durable_creation_at_return", "get_resolvable_at_return"})


def acknowledgement_claims(
    profile: FixtureProfile,
    request: Observation,
    response: Observation,
    witness: Witness | None,
) -> tuple[Assessment, frozenset[str]]:
    binding = bind_exchange(profile, request, response, witness)
    if (
        binding.disposition != ESTABLISHED
        or response.kind != "protocol_acknowledgement_observed"
        or "error" in response.data
    ):
        return binding, frozenset()
    result = response.data.get("result")
    if not isinstance(result, dict) or result.get("resultType") != "complete":
        return binding, frozenset()
    if binding.operation == "tasks/update":
        return binding, frozenset({"accepted_for_processing"})
    if binding.operation == "tasks/cancel":
        return binding, frozenset({"cancellation_intent_acknowledged"})
    return binding, frozenset()


def producer_event(
    profile: FixtureProfile, observation: Observation, witness: Witness | None
) -> tuple[str, str] | None:
    body = profile.read(witness, "producer_event")
    if body is None or body.get("observation") != observation.commitment:
        return None
    source, event = body.get("source"), body.get("event")
    if not isinstance(source, str) or not isinstance(event, str):
        return None
    return source, event


def delivery_relation(
    profile: FixtureProfile,
    observations: tuple[Observation, Observation],
    witnesses: tuple[Witness | None, Witness | None],
) -> tuple[tuple[Observation, Observation], str]:
    events = [producer_event(profile, obs, proof) for obs, proof in zip(observations, witnesses, strict=True)]
    if None in events:
        relation = NOT_ESTABLISHED
    else:
        relation = "duplicate_delivery" if events[0] == events[1] else "distinct_events"
    return observations, relation


def source_order(
    profile: FixtureProfile, observations: tuple[Observation, ...], witness: Witness | None
) -> tuple[tuple[Observation, ...], tuple[str, ...] | None]:
    body = profile.read(witness, "source_order")
    by_commitment = {obs.commitment: obs for obs in observations}
    if body is None or not isinstance(body.get("domain"), str):
        return observations, None
    order = body.get("order")
    if not isinstance(order, list) or len(order) != len(observations) or set(order) != set(by_commitment):
        return observations, None
    return observations, tuple(by_commitment[item].occurrence for item in order)


def requested_condition(
    profile: FixtureProfile,
    request: Observation,
    acknowledgement: Observation,
    exchange: Witness | None,
    snapshot: Observation | None,
    comparison: Witness | None,
) -> Assessment:
    binding, claims = acknowledgement_claims(profile, request, acknowledgement, exchange)
    if "cancellation_intent_acknowledged" not in claims or binding.operation != "tasks/cancel":
        return Assessment(NOT_ESTABLISHED, "bound_cancellation_ack_missing")
    if snapshot is None:
        return Assessment(NOT_ESTABLISHED, "later_observation_absent_not_failure")
    if snapshot.kind != "task_state_observed":
        return Assessment(NOT_ESTABLISHED, "not_a_task_state_observation")
    body = profile.read(comparison, "later_same_task_observation")
    if body is None or any(
        body.get(key) != value for key, value in {
            "request": request.commitment, "ack": acknowledgement.commitment,
            "snapshot": snapshot.commitment, "task": request.data["params"]["taskId"],
        }.items()
    ) or snapshot.data.get("taskId") != body["task"]:
        return Assessment(NOT_ESTABLISHED, "later_same_task_binding_missing")
    status = snapshot.data.get("status")
    if status == "cancelled":
        return Assessment(ESTABLISHED, "requested_condition_at_exact_compared_observation")
    if status == "completed":
        return Assessment(CONTRADICTED, "requested_condition_at_exact_compared_observation")
    return Assessment(NOT_ESTABLISHED, "outside_bounded_comparison")


def retained_terminal_view(observations: tuple[Observation, ...]) -> dict[str, Any]:
    # This is preservation only; no terminal verification/resolution is adopted.
    return {
        "observations": observations,
        "terminal_assessments": tuple(
            (obs.occurrence, NOT_ESTABLISHED) for obs in observations
        ),
        "selected_terminal": None,
        "business_success": NOT_ESTABLISHED,
        "external_effect": NOT_ESTABLISHED,
    }


def protocol_error_binding(
    profile: FixtureProfile, request: Observation, response: Observation, witness: Witness | None
) -> tuple[Observation, Assessment]:
    if "error" not in response.data:
        return response, Assessment(NOT_ESTABLISHED, "not_a_protocol_error_observation")
    return response, bind_exchange(profile, request, response, witness)
