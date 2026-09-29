"""AM-03 / AM-10: test-only conditional evidence; never a gateway execution.

Every AM-03 world preserves the same exact acknowledgement and holds requester
authentication, request occurrence, and policy authority/applicability as stated
synthetic premises. Only Cedar operand matching is verified here.

Every AM-10 world uses exact AuditEntry commitments and a test-key-signed scope
receipt. The source of the commitments and the signer's authenticated-scope
authority are synthetic trusted premises, NOT live credential verification.
The separately signed A↔B statement authenticates stipulated premise bytes;
it does not establish external provenance or a final wire representation.
The expected result is asserted after evaluation and never fed to the oracle.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cmcp_runtime.audit.chain import AuditEntry
from cmcp_runtime.execution import valid_execution_id

from .authority_origin import (
    CONTRADICTION,
    ESTABLISHED,
    EXCLUSION_POLICY,
    INCLUSION_POLICY,
    NOT_ESTABLISHED,
    TRUSTED_CREATION_SOURCE_PUBLIC_KEY,
    TRUSTED_EXCLUDE_SHA256,
    TRUSTED_INCLUDE_SHA256,
    TRUSTED_ORIGIN_HASHES,
    TRUSTED_RELATED_HASHES,
    TRUSTED_SCOPE_PUBLIC_KEY,
    AuthorityEvidence,
    CorrelationReceipt,
    CreationSourceReceipt,
    OriginEvidence,
    ScopeReceipt,
    correlation_statement,
    creation_source_statement,
    evaluate_authority,
    evaluate_origin,
    fixture_bytes,
    scope_statement,
)

ACK = b'{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete"}}'
EXECUTION_ID = "fixture-execution-1"
INVALID_EXECUTION_ID = "invalid execution id"
# Publicly known, deterministic test-only key material; no credentials involved.
SCOPE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
CREATION_SOURCE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
ORIGIN_REQUEST = fixture_bytes({"fixture_request": "origin-call", "task": "task-1"})
RELATED_REQUEST = fixture_bytes({"fixture_request": "related-call", "task": "task-1"})


def creation_record(
    *, task: str = "task-1", call_id: str = "call-origin-1",
    request: bytes = ORIGIN_REQUEST, execution_id: str | None = EXECUTION_ID,
    server_identity: str = "fixture-server", tool_name: str = "fixture-tool",
) -> bytes:
    """Separate fixture source bytes; external production provenance is stipulated."""
    return fixture_bytes({
        "record_id": "creation-1",
        "kind": "task_creation_result_observed",
        "task": task,
        "source": {"server_identity": server_identity, "tool_name": tool_name},
        "origin_call_id": call_id,
        "origin_request_sha256": hashlib.sha256(request).hexdigest(),
        "execution_id": execution_id,
    })


def origin_entry(execution_id: str | None = EXECUTION_ID) -> AuditEntry:
    entry = AuditEntry(
        entry_id="origin-entry-1", sequence_number=1,
        timestamp_utc="2026-09-25T00:00:00Z", session_id="fixture-session",
        call_id="call-origin-1", entry_type="tool_call", tool_name="fixture-tool",
        server_identity="fixture-server", policy_decision="allow",
        policy_rule_matched="fixture-rule", latency_us=1,
        request_payload_hash=hashlib.sha256(ORIGIN_REQUEST).hexdigest(),
        response_payload_hash=None, response_inspection_result=None,
        session_sensitivity_before=None, session_sensitivity_after=None,
        detail=None, workflow_id="fixture-workflow", prev_entry_hash="fixture-prior",
        execution_id=execution_id,
    )
    entry.entry_hash = entry.compute_hash()
    return entry


def related_entry() -> AuditEntry:
    """Actual second committed call; relevance is a stipulated pair premise."""
    entry = AuditEntry(
        entry_id="related-entry-2", sequence_number=3,
        timestamp_utc="2026-09-25T00:00:02Z", session_id="fixture-session",
        call_id="call-related-2", entry_type="tool_call", tool_name="fixture-tool",
        server_identity="fixture-server", policy_decision="allow",
        policy_rule_matched="fixture-rule", latency_us=2,
        request_payload_hash=hashlib.sha256(RELATED_REQUEST).hexdigest(),
        response_payload_hash=None, response_inspection_result=None,
        session_sensitivity_before=None, session_sensitivity_after=None,
        detail=None, workflow_id="fixture-workflow", prev_entry_hash="fixture-intervening",
        execution_id=EXECUTION_ID,
    )
    entry.entry_hash = entry.compute_hash()
    return entry


def origin_world(execution_id: str | None = EXECUTION_ID) -> OriginEvidence:
    creation = creation_record(execution_id=execution_id)
    source_statement = creation_source_statement(creation, ORIGIN_REQUEST)
    source_receipt = CreationSourceReceipt(
        source_statement, CREATION_SOURCE_KEY.sign(source_statement),
    )
    entry = origin_entry(execution_id)
    entry_b = related_entry()
    statement = scope_statement(creation, entry.entry_hash)
    pair_statement = correlation_statement(entry.entry_hash, entry_b.entry_hash)
    return OriginEvidence(
        creation_observation=creation, originating_request=ORIGIN_REQUEST,
        creation_source_receipt=source_receipt,
        entry=entry, entry_commitment=entry.entry_hash,
        scope_receipt=ScopeReceipt(statement, SCOPE_KEY.sign(statement)),
        entry_b=entry_b, entry_b_commitment=entry_b.entry_hash,
        correlation_receipt=CorrelationReceipt(
            pair_statement, SCOPE_KEY.sign(pair_statement),
        ),
    )


def with_creation_source(
    world: OriginEvidence, observation: bytes, request: bytes = ORIGIN_REQUEST,
) -> OriginEvidence:
    """Sign source and scope anew; source projections never come from the entry."""
    source_statement = creation_source_statement(observation, request)
    scope = scope_statement(observation, world.entry_commitment)
    return replace(
        world, creation_observation=observation, originating_request=request,
        creation_source_receipt=CreationSourceReceipt(
            source_statement, CREATION_SOURCE_KEY.sign(source_statement),
        ),
        scope_receipt=ScopeReceipt(scope, SCOPE_KEY.sign(scope)),
    )


@pytest.mark.parametrize("policy,expected,reason", [
    pytest.param(INCLUSION_POLICY, ESTABLISHED, "trusted_policy_includes_exact_request", id="AM03-positive"),
    pytest.param(None, NOT_ESTABLISHED, "authority_evidence_absent_or_unusable", id="AM03-authentication-only-no-authority"),
    pytest.param("permit(principal, action, resource);", NOT_ESTABLISHED, "policy_not_bound_to_fixture_authority", id="AM03-untrusted-policy-insufficient"),
    pytest.param(EXCLUSION_POLICY, CONTRADICTION, "trusted_explicit_forbid_matches_exact_request", id="AM03-verified-explicit-exclusion"),
])
def test_am03_authority_worlds_preserve_ack(policy, expected, reason):
    """Boundary: cancellation authority only; no state/effect/causality inference."""
    world = AuthorityEvidence(policy, ACK)
    result = evaluate_authority(world)
    assert result.authority.disposition == expected
    assert result.authority.reason == reason
    assert result.acknowledgement == ACK
    assert world.acknowledgement == ACK


def test_am03_exact_policy_pins_are_not_recomputed_from_submitted_evidence():
    assert hashlib.sha256(INCLUSION_POLICY.encode()).hexdigest() == TRUSTED_INCLUDE_SHA256
    assert hashlib.sha256(EXCLUSION_POLICY.encode()).hexdigest() == TRUSTED_EXCLUDE_SHA256
    world = AuthorityEvidence(INCLUSION_POLICY + "\n", ACK)
    assert evaluate_authority(world).authority.disposition == NOT_ESTABLISHED


@pytest.mark.parametrize("field,value", [
    ("requester", "another-requester"), ("task", "another-task"),
    ("scope", "different-scope"), ("instant", 123457), ("method", "tasks/update"),
])
@pytest.mark.parametrize("policy", [INCLUSION_POLICY, EXCLUSION_POLICY])
def test_am03_nonmatching_policy_is_ne_not_verified_contradiction(field, value, policy):
    """Inclusion/exclusion needs actual applicability, not mere policy presence."""
    world = replace(AuthorityEvidence(policy, ACK), **{field: value})
    result = evaluate_authority(world)
    assert result.authority.disposition == NOT_ESTABLISHED
    assert result.acknowledgement == ACK


@pytest.mark.parametrize("policy", [INCLUSION_POLICY, EXCLUSION_POLICY])
def test_am03_engine_error_does_not_become_verified_exclusion(policy):
    with patch("cmcp_runtime.policy.cedar.cedarpy.is_authorized", side_effect=RuntimeError("unavailable")):
        result = evaluate_authority(AuthorityEvidence(policy, ACK))
    assert result.authority.disposition == NOT_ESTABLISHED
    assert result.authority.reason == "authority_evaluation_error"
    assert result.acknowledgement == ACK


def test_am03_removing_only_authority_evidence_kills_positive_relation():
    positive = AuthorityEvidence(INCLUSION_POLICY, ACK)
    removed = replace(positive, policy=None)
    assert evaluate_authority(positive).authority.disposition == ESTABLISHED
    assert evaluate_authority(removed).authority.disposition == NOT_ESTABLISHED
    assert replace(positive, policy=None) == removed
    assert evaluate_authority(positive).acknowledgement == evaluate_authority(removed).acknowledgement


def test_am10_trusted_fixture_pins_match_exact_entry_and_scope_key():
    """Pins are fixture authority premises, not a proof of gateway provenance."""
    assert {
        origin_entry().entry_hash,
        origin_entry(None).entry_hash,
        origin_entry(INVALID_EXECUTION_ID).entry_hash,
    } == TRUSTED_ORIGIN_HASHES
    assert {related_entry().entry_hash} == TRUSTED_RELATED_HASHES
    assert SCOPE_KEY.public_key().public_bytes_raw() == TRUSTED_SCOPE_PUBLIC_KEY
    assert CREATION_SOURCE_KEY.public_key().public_bytes_raw() == TRUSTED_CREATION_SOURCE_PUBLIC_KEY


def test_am10_positive_committed_origin_and_execution_are_established():
    """AM10-A: exact A and B, stipulated source/scope/pair; no live effect."""
    world = origin_world()
    assert world.creation_source_receipt is not None
    assert world.originating_request is not None
    assert world.creation_source_receipt.statement == creation_source_statement(
        world.creation_observation, world.originating_request,
    )
    assert world.entry_commitment.encode() not in world.creation_source_receipt.statement
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == ESTABLISHED
    assert result.execution_binding.disposition == ESTABLISHED
    assert result.entry_to_entry_correlation.disposition == ESTABLISHED
    assert result.evidence is world


def test_am10_m17_wrong_origin_call_preserves_entry_to_entry_correlation():
    """Only the task-origin call claim changes; A↔B support must survive."""
    baseline = origin_world()
    world = with_creation_source(
        baseline, creation_record(call_id="provably-other-call"),
    )
    assert world.entry is baseline.entry
    assert world.entry_b is baseline.entry_b
    assert world.entry_commitment == baseline.entry_commitment
    assert world.entry_b_commitment == baseline.entry_b_commitment
    assert world.correlation_receipt is baseline.correlation_receipt
    assert world.originating_request == baseline.originating_request
    assert world.creation_observation == creation_record(call_id="provably-other-call")
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == CONTRADICTION
    assert result.execution_binding.disposition == NOT_ESTABLISHED
    assert result.entry_to_entry_correlation.disposition == ESTABLISHED


def test_am10_ab_support_removed_drops_only_entry_to_entry_correlation():
    """Equal execution IDs alone cannot replace the stipulated pair support."""
    baseline = origin_world()
    world = replace(baseline, correlation_receipt=None)
    assert world.entry is baseline.entry
    assert world.entry_b is baseline.entry_b
    assert world.scope_receipt is baseline.scope_receipt
    assert world.creation_source_receipt is baseline.creation_source_receipt
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == ESTABLISHED
    assert result.execution_binding.disposition == ESTABLISHED
    assert result.entry_to_entry_correlation.disposition == NOT_ESTABLISHED


@pytest.mark.parametrize("rehash", [False, True])
def test_am10_related_entry_substitution_cannot_reuse_pair_premise(rehash):
    world = origin_world()
    changed = replace(world.entry_b, call_id="substituted-related-call")
    if rehash:
        changed.entry_hash = changed.compute_hash()
    result = evaluate_origin(replace(world, entry_b=changed, entry_b_commitment=changed.entry_hash))
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == ESTABLISHED
    assert result.execution_binding.disposition == ESTABLISHED
    assert result.entry_to_entry_correlation.disposition == NOT_ESTABLISHED


@pytest.mark.parametrize("world,expected_pair", [
    (origin_world(None), NOT_ESTABLISHED),
    (with_creation_source(origin_world(), creation_record(execution_id=None)), ESTABLISHED),
])
def test_am10_null_execution_preserves_origin_and_never_synthesizes_id(world, expected_pair):
    """AM10-B: absent entry ID or absent source ID; not no execution."""
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.reason == "execution_unavailable_no_identifier_synthesized"
    assert result.entry_to_entry_correlation.disposition == expected_pair
    assert b'"execution_id":null' in result.evidence.creation_observation


def test_am10_wrong_call_projection_contradicts_origin_not_entry_or_execution():
    """AM10-C: source-signed wrong call is comparable to the exact entry."""
    world = with_creation_source(origin_world(), creation_record(call_id="provably-other-call"))
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == CONTRADICTION
    assert result.origin_binding.reason == "origin_projection_disagrees_with_committed_entry"
    assert result.execution_binding.disposition == NOT_ESTABLISHED
    assert result.evidence is world


def test_am10_missing_same_agent_scope_is_ne_not_another_agent():
    """AM10-D: source and entry match, but no independent scope receipt."""
    world = replace(origin_world(), scope_receipt=None)
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED
    assert result.origin_binding.reason == "same_agent_scope_not_bound_to_exact_evidence"
    assert result.evidence is world


def test_am10_scope_receipt_for_another_observation_cannot_discharge_this_one():
    world = replace(origin_world(), creation_observation=b"another observation with the same IDs")
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_scope_receipt_for_other_committed_entry_does_not_transfer():
    world = replace(origin_world(None), scope_receipt=origin_world().scope_receipt)
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED


def test_am10_faithful_scope_statement_without_valid_signature_is_insufficient():
    world = origin_world()
    assert world.scope_receipt is not None
    signature = bytes([world.scope_receipt.signature[0] ^ 1]) + world.scope_receipt.signature[1:]
    world = replace(world, scope_receipt=replace(world.scope_receipt, signature=signature))
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_untrusted_scope_signer_cannot_promote_equal_ids():
    world = origin_world()
    assert world.scope_receipt is not None
    other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    receipt = replace(world.scope_receipt, signature=other_key.sign(world.scope_receipt.statement))
    result = evaluate_origin(replace(world, scope_receipt=receipt))
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


@pytest.mark.parametrize("rehash", [False, True])
def test_am10_modified_entry_cannot_self_establish_its_commitment(rehash):
    world = origin_world()
    changed = replace(world.entry, call_id="different-call")
    if rehash:
        changed.entry_hash = changed.compute_hash()
    result = evaluate_origin(replace(world, entry=changed, entry_commitment=changed.entry_hash))
    assert result.entry_binding.disposition == NOT_ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_wrong_request_projection_is_not_hidden_by_equal_call_and_execution():
    wrong_request = fixture_bytes({"fixture_request": "different-origin-call", "task": "task-1"})
    world = with_creation_source(
        origin_world(), creation_record(request=wrong_request), wrong_request,
    )
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == CONTRADICTION
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_different_execution_projection_does_not_erase_supported_origin():
    world = with_creation_source(origin_world(), creation_record(execution_id="other-execution"))
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_invalid_execution_id_uses_real_validator_without_erasing_origin():
    """Both exact projections match; only the real ID validator blocks execution."""
    assert not valid_execution_id(INVALID_EXECUTION_ID)
    world = origin_world(INVALID_EXECUTION_ID)
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.reason == "execution_projection_not_established"
    with patch(f"{evaluate_origin.__module__}.valid_execution_id", return_value=True):
        bypassed = evaluate_origin(world)
    assert bypassed.execution_binding.disposition == ESTABLISHED


def test_am10_different_task_with_fresh_source_and_scope_cannot_join_entry():
    """A genuinely different task changes the signed request and its entry hash join."""
    other_request = fixture_bytes({"fixture_request": "origin-call", "task": "different-task"})
    world = with_creation_source(
        origin_world(), creation_record(task="different-task", request=other_request),
        other_request,
    )
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == CONTRADICTION
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_unrelated_minimal_record_with_fresh_signatures_does_not_join():
    """The independent review's different-task shape lacks origin projection."""
    unrelated = fixture_bytes({
        "record_id": "creation-x", "kind": "task_creation_result_observed",
        "task": "different-task",
    })
    world = with_creation_source(origin_world(), unrelated)
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_source_signed_task_must_match_its_bound_request():
    world = with_creation_source(origin_world(), creation_record(task="different-task"))
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_source_identity_mismatch_is_independently_comparable():
    world = with_creation_source(origin_world(), creation_record(server_identity="different-server"))
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == CONTRADICTION
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_missing_creation_source_receipt_is_ne_despite_equal_fields():
    world = replace(origin_world(), creation_source_receipt=None)
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_changed_creation_bytes_after_source_receipt_cannot_join():
    world = origin_world()
    changed = creation_record(call_id="changed-after-source-receipt")
    scope = scope_statement(changed, world.entry_commitment)
    world = replace(
        world, creation_observation=changed,
        scope_receipt=ScopeReceipt(scope, SCOPE_KEY.sign(scope)),
    )
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_changed_request_bytes_after_source_receipt_cannot_join():
    world = replace(
        origin_world(),
        originating_request=fixture_bytes({"fixture_request": "changed", "task": "task-1"}),
    )
    result = evaluate_origin(world)
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_tampered_creation_source_signature_cannot_promote_equal_fields():
    world = origin_world()
    assert world.creation_source_receipt is not None
    signature = world.creation_source_receipt.signature
    receipt = replace(world.creation_source_receipt, signature=bytes([signature[0] ^ 1]) + signature[1:])
    result = evaluate_origin(replace(world, creation_source_receipt=receipt))
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_untrusted_creation_source_signer_cannot_promote_equal_fields():
    world = origin_world()
    assert world.creation_source_receipt is not None
    other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    receipt = replace(
        world.creation_source_receipt,
        signature=other_key.sign(world.creation_source_receipt.statement),
    )
    result = evaluate_origin(replace(world, creation_source_receipt=receipt))
    assert result.entry_binding.disposition == ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


def test_am10_real_audit_hash_is_load_bearing():
    with patch.object(AuditEntry, "compute_hash", return_value="0" * 64):
        # Construct before mutation so the patch cannot manufacture its own pin.
        result = evaluate_origin(POSITIVE_WORLD)
    assert result.entry_binding.disposition == NOT_ESTABLISHED
    assert result.origin_binding.disposition == NOT_ESTABLISHED
    assert result.execution_binding.disposition == NOT_ESTABLISHED


POSITIVE_WORLD = origin_world()
