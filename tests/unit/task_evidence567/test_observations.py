"""AM-01/02/04–09/11 fixture differentials, not a Tasks runtime conformance claim.

EXACT EVIDENCE is constructed per case below; EXPECTED results occur only in
assertions. TRUST ASSUMPTIONS: the fixed test witness and separate creation-source
keys have the stated scope, with the entire eligible request scope fixed before
evaluation. This is an independent-input seam within one synthetic fixture,
not an independently administered authority or deployed callback verifier.
BOUNDARIES and CLAIM LIMITS are named by tests and detailed in README.md.
No terminal truth, causal outcome, external effect or final schema is adopted.
"""

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.types import CallToolResult, CreateTaskResult, Result

from .observations import (
    CONTRADICTED,
    ESTABLISHED,
    NOT_ESTABLISHED,
    PROTOCOL_PROFILE,
    FixtureProfile,
    Observation,
    Witness,
    acknowledgement_claims,
    bind_exchange,
    canonical,
    creation_claims,
    delivery_relation,
    producer_event,
    protocol_error_binding,
    requested_condition,
    retained_terminal_view,
    source_order,
)

# Publicly disclosed synthetic test seed; never a production identity/key.
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC = KEY.public_key().public_bytes_raw()
SOURCE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
SOURCE_PUBLIC = SOURCE_KEY.public_key().public_bytes_raw()
CREATION_SOURCE_ID = "fixture-task-create-return-1"

# These exact source bytes are fixed before any receiving Observation. The
# source/type and creation-contract premises are STIPULATED/TRUSTED, not
# SOURCE_PROVEN. The 2026 discriminator is read from the bound response bytes.
CREATION_SOURCE_BYTES = canonical({
    "resultType": "task",
    "taskId": "task-1",
    "status": "working",
    "createdAt": "2026-09-26T00:00:00Z",
    "lastUpdatedAt": "2026-09-26T00:00:00Z",
    "ttlMs": 60000,
})
GENERIC_SOURCE_BYTES = canonical({
    "resultType": "complete",
    "content": [{"type": "text", "text": "accepted"}],
    "isError": False,
})


def observation(name, kind, data, arrival=0):
    return Observation(name, kind, canonical(data), arrival)


def request(name="request-1", method="tasks/cancel", request_id=7):
    return observation(name, "request_observed", {
        "jsonrpc": "2.0", "id": request_id, "method": method,
        "params": {"taskId": "task-1"},
    })


def response(name="response-1", request_id=7):
    return observation(name, "protocol_acknowledgement_observed", {
        "jsonrpc": "2.0", "id": request_id, "result": {"resultType": "complete"},
    }, 1)


def attest(boundary, **facts):
    body = canonical({"boundary": boundary, **facts})
    return Witness(body, KEY.sign(body))


def exchange(profile, req, resp):
    return attest("exchange", scope=profile.scope_commitment,
                  request=req.commitment, response=resp.commitment)


def creation_profile():
    return FixtureProfile(PUBLIC, (), SOURCE_PUBLIC, CREATION_SOURCE_ID)


def creation_contract(obs):
    return attest("trusted_creation_contract", response=obs.commitment,
                  contract="CreateTaskResult:durable-and-resolvable-at-return",
                  protocol_profile=PROTOCOL_PROFILE)


def creation_source_witness(
    obs, source_bytes, result_type=None, source=CREATION_SOURCE_ID,
    protocol_profile=PROTOCOL_PROFILE,
):
    statement = {
        "boundary": "creation_source_type",
        "response": obs.commitment,
        "source": source,
        "source_bytes": source_bytes.hex(),
        "protocol_profile": protocol_profile,
    }
    if result_type is not None:
        # Legacy diagnostic label: signed fixture text, never type authority.
        statement["result_type"] = result_type
    body = canonical(statement)
    return Witness(body, SOURCE_KEY.sign(body))


def test_am01_exact_create_task_result_source_at_return_only():
    obs = Observation("creation", "task_creation_result_observed", CREATION_SOURCE_BYTES, 0)
    profile = creation_profile()
    contract = creation_contract(obs)
    source = creation_source_witness(obs, CREATION_SOURCE_BYTES)
    claims = {"durable_creation_at_return", "get_resolvable_at_return"}
    assert obs.data["resultType"] == "task"
    assert obs.data["taskId"] == "task-1"
    assert creation_claims(profile, obs, contract, source) == claims
    assert not creation_claims(profile, obs, None, source)
    assert not creation_claims(profile, obs, replace(contract, signature=bytes(64)), source)
    assert not creation_claims(profile, obs, contract, None)
    assert not creation_claims(profile, obs, contract, replace(source, signature=bytes(64)))
    assert not ({"completion", "external_effect"} & creation_claims(profile, obs, contract, source))


def test_am01_generic_successful_call_result_is_not_create_task_result():
    assert not CallToolResult.model_validate_json(GENERIC_SOURCE_BYTES).is_error
    obs = Observation("creation", "task_creation_result_observed", GENERIC_SOURCE_BYTES, 0)
    source = creation_source_witness(obs, GENERIC_SOURCE_BYTES)
    assert obs.data["resultType"] == "complete"
    assert not creation_claims(creation_profile(), obs, creation_contract(obs), source)


def test_am01_spoofed_creation_kind_with_unrelated_payload_is_not_create_task_result():
    obs = observation("creation", "task_creation_result_observed", {"unrelated": True})
    # A source record for different bytes does not match. A fresh valid fixture
    # signature over these bytes cannot replace the 2026 discriminator.
    for source_bytes in (CREATION_SOURCE_BYTES, obs.payload):
        source = creation_source_witness(obs, source_bytes, "CreateTaskResult")
        assert not creation_claims(creation_profile(), obs, creation_contract(obs), source)


def test_am01_changed_payload_after_source_type_witness_is_not_creation():
    original = Observation("creation", "task_creation_result_observed", CREATION_SOURCE_BYTES, 0)
    source = creation_source_witness(original, CREATION_SOURCE_BYTES)
    changed = replace(original, payload=canonical({**original.data, "taskId": "task-2"}))
    assert changed.data["resultType"] == "task"
    assert not creation_claims(creation_profile(), changed, creation_contract(changed), source)


def test_am01_wrong_discriminator_is_not_promoted_by_signed_type_label():
    payload = canonical({**Observation("creation", "task_creation_result_observed",
                                   CREATION_SOURCE_BYTES, 0).data, "resultType": "complete"})
    obs = Observation("creation", "task_creation_result_observed", payload, 0)
    source = creation_source_witness(obs, payload, "CreateTaskResult")
    assert not creation_claims(creation_profile(), obs, creation_contract(obs), source)


def test_am01_missing_required_discriminator_is_not_creation():
    data = Observation("creation", "task_creation_result_observed", CREATION_SOURCE_BYTES, 0).data
    payload = canonical({key: value for key, value in data.items() if key != "resultType"})
    obs = Observation("creation", "task_creation_result_observed", payload, 0)
    source = creation_source_witness(obs, payload, "CreateTaskResult")
    assert not creation_claims(creation_profile(), obs, creation_contract(obs), source)


def test_am01_legacy_dual_shape_diagnostic_cannot_override_target_bytes():
    legacy = canonical({
        "resultType": "complete",
        "task": {
            "taskId": "legacy-task", "status": "working",
            "createdAt": "2026-09-26T00:00:00Z",
            "lastUpdatedAt": "2026-09-26T00:00:00Z", "ttl": 60,
        },
        "content": [{"type": "text", "text": "accepted"}],
        "isError": False,
    })
    assert CreateTaskResult.model_validate_json(legacy).task.task_id == "legacy-task"
    assert not CallToolResult.model_validate_json(legacy).is_error
    obs = Observation("creation", "task_creation_result_observed", legacy, 0)
    for diagnostic_label in ("CreateTaskResult", "CallToolResult"):
        source = creation_source_witness(obs, legacy, diagnostic_label)
        assert not creation_claims(creation_profile(), obs, creation_contract(obs), source)


def test_am01_diagnostic_label_cannot_demote_target_task_bytes():
    obs = Observation("creation", "task_creation_result_observed", CREATION_SOURCE_BYTES, 0)
    for diagnostic_label in ("CreateTaskResult", "CallToolResult"):
        source = creation_source_witness(obs, CREATION_SOURCE_BYTES, diagnostic_label)
        assert creation_claims(creation_profile(), obs, creation_contract(obs), source) == {
            "durable_creation_at_return", "get_resolvable_at_return",
        }


def test_am01_wrong_protocol_profile_is_not_promoted():
    obs = Observation("creation", "task_creation_result_observed", CREATION_SOURCE_BYTES, 0)
    source = creation_source_witness(obs, CREATION_SOURCE_BYTES,
                                     protocol_profile="io.modelcontextprotocol/tasks@2025-11-25")
    assert not creation_claims(creation_profile(), obs, creation_contract(obs), source)


def test_am01_wrong_independently_bound_source_is_not_promoted():
    obs = Observation("creation", "task_creation_result_observed", CREATION_SOURCE_BYTES, 0)
    wrong_source = creation_source_witness(
        obs, CREATION_SOURCE_BYTES, source="another-return"
    )
    assert not creation_claims(creation_profile(), obs, creation_contract(obs), wrong_source)


def test_ack_operation_comes_from_bound_request_not_identical_response_bytes():
    """AM02-UPDATE/CANCEL: shared result bytes, independently signed exchange joins."""
    update, cancel = request("update", "tasks/update"), request("cancel")
    resp = response()
    profile = FixtureProfile(PUBLIC, (update, cancel))
    update_binding, update_claims = acknowledgement_claims(profile, update, resp, exchange(profile, update, resp))
    cancel_binding, cancel_claims = acknowledgement_claims(profile, cancel, resp, exchange(profile, cancel, resp))
    assert update_binding.operation == "tasks/update"
    assert cancel_binding.operation == "tasks/cancel"
    assert update_claims == {"accepted_for_processing"}
    assert cancel_claims == {"cancellation_intent_acknowledged"}
    assert acknowledgement_claims(profile, cancel, resp, None)[1] == set()
    # A response/request-ID match does not repair a witness for the other occurrence.
    wrong = acknowledgement_claims(profile, cancel, resp, exchange(profile, update, resp))
    assert wrong[0].disposition == NOT_ESTABLISHED
    assert wrong[1] == set()
    assert resp.payload == response().payload


def test_ack_preserves_legitimate_response_detail():
    """AM02-DETAIL: accounting must not succeed by narrowing observed bytes."""
    req = request()
    resp = response()
    detailed = replace(resp, payload=canonical({**resp.data, "_meta": {"trace": "detail-retained"}}))
    profile = FixtureProfile(PUBLIC, (req,))
    binding, claims = acknowledgement_claims(profile, req, detailed, exchange(profile, req, detailed))
    assert binding.disposition == ESTABLISHED
    assert claims == {"cancellation_intent_acknowledged"}
    assert detailed.data["_meta"] == {"trace": "detail-retained"}
    assert bind_exchange(profile, req, detailed, exchange(profile, req, resp)).disposition == NOT_ESTABLISHED


def test_result_metadata_is_preserved_under_exact_exchange_binding():
    """AM02-RESULT-META: the pinned SDK Result admits metadata INSIDE the result."""
    req, resp = request(), response()
    result = {"resultType": "complete", "_meta": {"trace": "do-not-discard"}}
    assert Result.model_validate(result).meta == {"trace": "do-not-discard"}
    detailed = replace(resp, payload=canonical({**resp.data, "result": result}))
    profile = FixtureProfile(PUBLIC, (req,))
    binding, claims = acknowledgement_claims(profile, req, detailed, exchange(profile, req, detailed))
    assert binding.disposition == ESTABLISHED
    assert claims == {"cancellation_intent_acknowledged"}
    assert detailed.data["result"] == result
    assert bind_exchange(profile, req, detailed, exchange(profile, req, resp)).disposition == NOT_ESTABLISHED


@pytest.mark.parametrize("proof_kind,expected", [
    ("none", NOT_ESTABLISHED), ("exact", ESTABLISHED),
    ("other_occurrence", NOT_ESTABLISHED), ("narrowed_scope", NOT_ESTABLISHED),
    ("invalid_signature", NOT_ESTABLISHED),
], ids=["AM04-NO-BINDING", "AM04-EXACT", "AM04-REUSED-ID", "AM04-SCOPE", "AM04-UNTRUSTED"])
def test_reused_id_requires_independently_bound_occurrence(proof_kind, expected):
    first, second, resp = request("occurrence-A"), request("occurrence-B"), response()
    profile = FixtureProfile(PUBLIC, (first, second))
    proofs = {
        "none": None,
        "exact": exchange(profile, second, resp),
        "other_occurrence": exchange(profile, first, resp),
        "narrowed_scope": exchange(FixtureProfile(PUBLIC, (second,)), second, resp),
        "invalid_signature": replace(exchange(profile, second, resp), signature=bytes(64)),
    }
    assert first.payload == second.payload
    result = bind_exchange(profile, second, resp, proofs[proof_kind])
    assert result.disposition == expected
    assert result.operation == ("tasks/cancel" if expected == ESTABLISHED else None)


@pytest.mark.parametrize("request_id,response_id", [(7, "7"), (True, 1), (1, True)])
def test_typed_ids_are_not_coerced(request_id, response_id):
    """AM04-TYPED: even a fixture witness does not change the typed ID prerequisite."""
    req, resp = request(request_id=request_id), response(request_id=response_id)
    profile = FixtureProfile(PUBLIC, (req,))
    assert bind_exchange(profile, req, resp, exchange(profile, req, resp)).disposition == NOT_ESTABLISHED


@pytest.mark.parametrize("event_ids,expected", [
    (("event-1", "event-2"), "distinct_events"),
    (("event-1", "event-1"), "duplicate_delivery"),
    ((None, None), NOT_ESTABLISHED),
], ids=["AM05-DISTINCT", "AM05-DUPLICATE", "AM05-NO-EVIDENCE"])
def test_equal_payloads_do_not_determine_event_identity(event_ids, expected):
    profile = FixtureProfile(PUBLIC, ())
    observations = (
        observation("receipt-A", "task_state_observed", {"taskId": "task-1", "status": "working"}, 0),
        observation("receipt-B", "task_state_observed", {"taskId": "task-1", "status": "working"}, 1),
    )
    witnesses = tuple(
        attest("producer_event", observation=obs.commitment, source="producer", event=event)
        if event else None for obs, event in zip(observations, event_ids, strict=True)
    )
    preserved, relation = delivery_relation(profile, observations, witnesses)
    assert preserved == observations and len(preserved) == 2
    assert observations[0].payload == observations[1].payload
    assert relation == expected
    assert relation != "another_task_transition"
    if witnesses[0] is not None:
        assert producer_event(profile, observations[1], witnesses[0]) is None


@pytest.mark.parametrize("reverse", [False, True], ids=["AM06-AGREES", "AM06-REVERSED"])
def test_source_order_is_bound_separately_from_fixed_ingest(reverse):
    profile = FixtureProfile(PUBLIC, ())
    observations = (response("receipt-A"), replace(response("receipt-B"), ingest_index=2))
    ordered = observations[::-1] if reverse else observations
    proof = attest("source_order", domain="source-sequence-A", order=[obs.commitment for obs in ordered])
    preserved, order = source_order(profile, observations, proof)
    assert preserved == observations
    assert tuple(obs.ingest_index for obs in preserved) == (1, 2)
    assert order == tuple(obs.occurrence for obs in ordered)
    assert source_order(profile, observations, None) == (observations, None)
    assert delivery_relation(profile, observations, (None, None))[1] == NOT_ESTABLISHED
    assert retained_terminal_view(preserved)["selected_terminal"] is None


@pytest.mark.parametrize("status,expected", [
    ("cancelled", ESTABLISHED), ("completed", CONTRADICTED), (None, NOT_ESTABLISHED),
], ids=["AM07-CANCELLED", "AM07-COMPLETED", "AM07-NO-LATER-OBSERVATION"])
def test_requested_condition_is_scoped_to_exact_later_observation(status, expected):
    req, ack = request(), response()
    profile = FixtureProfile(PUBLIC, (req,))
    obs = observation("later", "task_state_observed", {"taskId": "task-1", "status": status}, 2) if status else None
    proof = attest("later_same_task_observation", request=req.commitment, ack=ack.commitment,
                   snapshot=obs.commitment, task="task-1") if obs else None
    result = requested_condition(profile, req, ack, exchange(profile, req, ack), obs, proof)
    assert result.disposition == expected
    assert "causality" not in result.reason
    assert retained_terminal_view((obs,) if obs else ())["external_effect"] == NOT_ESTABLISHED
    if obs:
        assert retained_terminal_view((obs,))["terminal_assessments"] == (("later", NOT_ESTABLISHED),)
        assert requested_condition(profile, req, ack, exchange(profile, req, ack), obs, None).disposition == NOT_ESTABLISHED
        wrong = replace(obs, payload=canonical({"taskId": "different-task", "status": status}))
        assert requested_condition(profile, req, ack, exchange(profile, req, ack), wrong, proof).disposition == NOT_ESTABLISHED
    else:
        assert result.reason == "later_observation_absent_not_failure"


@pytest.mark.parametrize("kind,task,expected", [
    ("task_state_observed", "task-1", ESTABLISHED),
    ("generic_call_result_observed", "task-1", NOT_ESTABLISHED),
    ("task_state_observed", "different-task", NOT_ESTABLISHED),
], ids=["AM07-ELIGIBLE-TWIN", "AM07-WRONG-KIND", "AM07-WRONG-TASK"])
def test_comparison_requires_eligible_state_even_with_valid_fresh_witness(kind, task, expected):
    req, ack = request(), response()
    profile = FixtureProfile(PUBLIC, (req,))
    obs = observation("later", kind, {"taskId": task, "status": "cancelled"}, 2)
    proof = attest("later_same_task_observation", request=req.commitment, ack=ack.commitment,
                   snapshot=obs.commitment, task="task-1")
    assert profile.read(proof, "later_same_task_observation") is not None
    result = requested_condition(profile, req, ack, exchange(profile, req, ack), obs, proof)
    assert result.disposition == expected


@pytest.mark.parametrize("is_error", [False, True], ids=["AM08-FALSE", "AM08-TRUE"])
def test_tool_result_flag_does_not_change_observed_task_state(is_error):
    obs = observation("completed", "task_state_observed", {
        "taskId": "task-1", "status": "completed", "result": {"isError": is_error},
    })
    view = retained_terminal_view((obs,))
    assert view["observations"][0].data["status"] == "completed"
    assert view["observations"][0].data["result"]["isError"] is is_error
    assert view["terminal_assessments"] == (("completed", NOT_ESTABLISHED),)
    assert view["business_success"] == view["external_effect"] == NOT_ESTABLISHED


def test_conflicting_terminal_observations_survive_both_ingest_orders():
    """AM09-CONFLICT: source observations are premises, no resolution authority exists."""
    completed = observation("source-A", "task_state_observed", {"taskId": "task-1", "status": "completed"}, 0)
    failed = observation("source-B", "task_state_observed", {"taskId": "task-1", "status": "failed"}, 1)
    for observations in ((completed, failed), (replace(failed, ingest_index=0), replace(completed, ingest_index=1))):
        result = retained_terminal_view(observations)
        assert result["observations"] == observations
        assert len(result["observations"]) == len(result["terminal_assessments"]) == 2
        assert {obs.data["status"] for obs in result["observations"]} == {"completed", "failed"}
        assert all(disposition == NOT_ESTABLISHED for _, disposition in result["terminal_assessments"])
        assert result["selected_terminal"] is None
        assert result["external_effect"] == NOT_ESTABLISHED


@pytest.mark.parametrize("mode,expected,reason", [
    ("exact", ESTABLISHED, "exact_exchange_bound"),
    ("no_id", NOT_ESTABLISHED, "no_usable_typed_response_id"),
    ("unbound_id", NOT_ESTABLISHED, "independent_occurrence_binding_missing"),
], ids=["AM11-BOUND", "AM11-NO-ID", "AM11-ID-ONLY"])
def test_error_binding_preserves_exact_outer_error_without_task_outcome(mode, expected, reason):
    req = request()
    resp = observation("error", "protocol_error_response_observed", {
        "jsonrpc": "2.0", "id": None if mode == "no_id" else 7,
        "error": {"code": -32602, "message": "exact outer error", "data": {"detail": 17}},
    })
    profile = FixtureProfile(PUBLIC, (req,))
    proof = exchange(profile, req, resp) if mode == "exact" else None
    preserved, result = protocol_error_binding(profile, req, resp, proof)
    assert preserved is resp and preserved.payload == resp.payload
    assert result.disposition == expected and result.reason == reason
    assert result.operation == ("tasks/cancel" if mode == "exact" else None)
    assert acknowledgement_claims(profile, req, resp, proof)[1] == set()
    assert retained_terminal_view((resp,))["selected_terminal"] is None
    assert retained_terminal_view((resp,))["external_effect"] == NOT_ESTABLISHED
