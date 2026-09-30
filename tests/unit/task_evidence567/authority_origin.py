"""Conditional AM-03/AM-10 oracles, ONLY for the local #567 test world.

These are not runtime Tasks support, wire fields, or credential verification.
AM-03 trusts two exact synthetic authority documents for the stated action;
their hashes bind bytes, not authority. Real Cedar evaluates their applicability.
AM-10 trusts exact A and B audit-entry commitments, a synthetic creation-source
signer, and a separate synthetic scope-asserting key. The A↔B receipt is a
distinct stipulated fixture premise over exact operands. Neither key proves
that a real gateway authenticated an agent, admitted an execution, or ran a task.
The real AuditEntry hash function is used; no ExecutionRegistry is activated.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cmcp_runtime.audit.chain import AuditEntry
from cmcp_runtime.execution import valid_execution_id
from cmcp_runtime.policy.cedar import CedarBackend

ESTABLISHED = "ESTABLISHED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"
CONTRADICTION = "VERIFIED_CONTRADICTION"

INCLUSION_POLICY = '''permit (
    principal == Agent::"fixture-requester",
    action == Action::"TaskCancel",
    resource == Resource::"fixture-task"
) when {
    context.scope == "cancel-this-task" && context.instant == 123456
};
'''
EXCLUSION_POLICY = INCLUSION_POLICY.replace("permit (", "forbid (", 1)

# Pins are written independently of policy evidence supplied to evaluate_authority.
# In each alternate fixture world, only the supplied exact document governs.
TRUSTED_INCLUDE_SHA256 = "ded107c0cf63bed83cc10d7656c033a2f0269e2469dc3bb15e6315c90a4d4dec"
TRUSTED_EXCLUDE_SHA256 = "43179ec750a2d959fca1bbe4431e64e9f62d06a0df2c5a519ada0681f73fac64"


@dataclass(frozen=True)
class Boundary:
    disposition: str
    reason: str


@dataclass(frozen=True)
class AuthorityEvidence:
    """Authentication/request/ack provenance are held valid as fixture premises."""

    policy: str | None
    acknowledgement: bytes
    requester: str = "fixture-requester"
    method: str = "tasks/cancel"
    task: str = "fixture-task"
    scope: str = "cancel-this-task"
    instant: int = 123456


@dataclass(frozen=True)
class AuthorityResult:
    authority: Boundary
    acknowledgement: bytes


def evaluate_authority(evidence: AuthorityEvidence) -> AuthorityResult:
    """No inference about cancellation taking effect follows from this relation."""
    boundary = _authority_boundary(evidence)
    return AuthorityResult(boundary, evidence.acknowledgement)


def _authority_boundary(evidence: AuthorityEvidence) -> Boundary:
    if not isinstance(evidence.policy, str):
        return Boundary(NOT_ESTABLISHED, "authority_evidence_absent_or_unusable")
    digest = hashlib.sha256(evidence.policy.encode()).hexdigest()
    if digest not in (TRUSTED_INCLUDE_SHA256, TRUSTED_EXCLUDE_SHA256):
        return Boundary(NOT_ESTABLISHED, "policy_not_bound_to_fixture_authority")
    if evidence.method != "tasks/cancel":
        return Boundary(NOT_ESTABLISHED, "outside_fixture_action_scope")
    decision = CedarBackend(policy_content=evidence.policy).evaluate({
        "agent_id": evidence.requester,
        "tool_name": "task_cancel",
        "resource": evidence.task,
        "scope": evidence.scope,
        "instant": evidence.instant,
    })
    if decision.error is not None:
        return Boundary(NOT_ESTABLISHED, "authority_evaluation_error")
    if decision.allowed:
        return Boundary(ESTABLISHED, "trusted_policy_includes_exact_request")
    # A nonmatching permit, default deny, or engine error is not exclusion proof.
    # This pin contains exactly one forbid; Cedar must actually match that rule.
    if digest == TRUSTED_EXCLUDE_SHA256 and decision.policy_ids == ("policy0",):
        return Boundary(CONTRADICTION, "trusted_explicit_forbid_matches_exact_request")
    return Boundary(NOT_ESTABLISHED, "no_verified_exclusion_or_inclusion")


def fixture_bytes(value: dict[str, Any]) -> bytes:
    """Stable test notation, not adoption of a production canonicalization rule."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


# These fixed commitments are accepted authority inputs of the synthetic worlds.
# A self-consistent hash on any other submitted entry does not earn trust.
TRUSTED_ORIGIN_HASHES = frozenset({
    "9895b24b17b7692dac6e59e23f4b46aeff023cdd81529e10524f14b3e98303bb",
    "2d85016a8a071fdc222328ac5b7a9936fea7ad51611b784c42cc20d4ab68d64d",
    "dc076f836a849f9452a5b7947c3e96e3bbf7ece0d2a84fe199f4bd2c85544eb2",
})
TRUSTED_RELATED_HASHES = frozenset({
    # Exact B commitment is pinned independently of submitted fixture evidence.
    "18e129ea89b4d0fd6a7378073a0aa039382358b3d35eff28ec2bcdd8042188fc",
})
TRUSTED_SCOPE_PUBLIC_KEY = bytes.fromhex(
    "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
)
TRUSTED_CREATION_SOURCE_PUBLIC_KEY = bytes.fromhex(
    "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
)
SCOPE_DOMAIN = "AM10-fixture-same-authenticated-agent-scope-not-production"
CORRELATION_DOMAIN = "AM10-fixture-entry-pair-correlation-not-production"
CREATION_SOURCE_DOMAIN = "AM10-fixture-creation-source-not-production"
FIXTURE_AGENT_SCOPE = "fixture-agent-scope"


@dataclass(frozen=True)
class ScopeReceipt:
    """The issuing authority's scope is a trust premise, not asserted by a bool."""

    statement: bytes
    signature: bytes


@dataclass(frozen=True)
class CreationSourceReceipt:
    """Synthetic source authority for exact creation and request bytes only."""

    statement: bytes
    signature: bytes


@dataclass(frozen=True)
class CorrelationReceipt:
    """Stipulated A↔B premise bytes, not proof of external provenance."""

    statement: bytes
    signature: bytes


@dataclass(frozen=True)
class OriginEvidence:
    creation_observation: bytes
    originating_request: bytes | None
    creation_source_receipt: CreationSourceReceipt | None
    entry: AuditEntry
    entry_commitment: str
    scope_receipt: ScopeReceipt | None
    entry_b: AuditEntry
    entry_b_commitment: str
    correlation_receipt: CorrelationReceipt | None


@dataclass(frozen=True)
class OriginResult:
    """Fixture-only assessments; these are not proposed production wire fields."""

    entry_binding: Boundary
    origin_binding: Boundary
    execution_binding: Boundary
    entry_to_entry_correlation: Boundary
    evidence: OriginEvidence


@dataclass(frozen=True)
class CreationProjection:
    task: str
    call_id: str
    request_hash: str
    server_identity: str
    tool_name: str
    execution_id: str | None


def creation_source_statement(observation: bytes, request: bytes) -> bytes:
    """Bind separate fixture source bytes without including the comparator A."""
    return fixture_bytes({
        "domain": CREATION_SOURCE_DOMAIN,
        "creation_observation_sha256": hashlib.sha256(observation).hexdigest(),
        "originating_request_sha256": hashlib.sha256(request).hexdigest(),
    })


def scope_statement(observation: bytes, entry_commitment: str) -> bytes:
    """Exact creation/A pair stipulated to share the fixture agent scope."""
    return fixture_bytes({
        "domain": SCOPE_DOMAIN,
        "authenticated_agent_scope": FIXTURE_AGENT_SCOPE,
        "creation_observation_sha256": hashlib.sha256(observation).hexdigest(),
        "origin_entry_commitment": entry_commitment,
    })


def correlation_statement(entry_commitment: str, entry_b_commitment: str) -> bytes:
    """Bind the stipulated same-scope correlation claim to exact A and B."""
    return fixture_bytes({
        "domain": CORRELATION_DOMAIN,
        "authenticated_agent_scope": FIXTURE_AGENT_SCOPE,
        "claim": "same_execution_for_exact_entry_pair",
        "origin_entry_commitment": entry_commitment,
        "related_entry_commitment": entry_b_commitment,
    })


def _scope_is_bound(evidence: OriginEvidence) -> bool:
    receipt = evidence.scope_receipt
    if receipt is None:
        return False
    expected = scope_statement(evidence.creation_observation, evidence.entry_commitment)
    if receipt.statement != expected:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(TRUSTED_SCOPE_PUBLIC_KEY).verify(
            receipt.signature, receipt.statement,
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def _entry_to_entry_correlation(evidence: OriginEvidence, scope_bound: bool) -> Boundary:
    """Assess the separately stipulated A↔B relation, independent of task origin."""
    entry_b = evidence.entry_b
    if (
        evidence.entry_b_commitment not in TRUSTED_RELATED_HASHES
        or entry_b.entry_hash != evidence.entry_b_commitment
        or entry_b.compute_hash() != evidence.entry_b_commitment
    ):
        return Boundary(NOT_ESTABLISHED, "exact_trusted_related_entry_not_bound")
    receipt = evidence.correlation_receipt
    if not scope_bound or receipt is None:
        return Boundary(NOT_ESTABLISHED, "entry_pair_scope_or_correlation_support_absent")
    expected = correlation_statement(evidence.entry_commitment, evidence.entry_b_commitment)
    if receipt.statement != expected:
        return Boundary(NOT_ESTABLISHED, "entry_pair_correlation_premise_not_bound")
    try:
        Ed25519PublicKey.from_public_bytes(TRUSTED_SCOPE_PUBLIC_KEY).verify(
            receipt.signature, receipt.statement,
        )
    except (InvalidSignature, ValueError):
        return Boundary(NOT_ESTABLISHED, "entry_pair_correlation_premise_not_bound")
    execution_a = evidence.entry.execution_id
    execution_b = entry_b.execution_id
    if (
        evidence.entry.call_id == entry_b.call_id
        or execution_a is None or execution_b is None
        or not valid_execution_id(execution_a)
        or not valid_execution_id(execution_b)
        or execution_a != execution_b
    ):
        return Boundary(NOT_ESTABLISHED, "entry_pair_execution_correlation_not_established")
    return Boundary(ESTABLISHED, "exact_entry_pair_correlation_in_stipulated_scope")


def _creation_source_projection(evidence: OriginEvidence) -> CreationProjection | None:
    """Decode only a source-signed fixture projection, never entry fields.

    This JSON is local test notation, not a proposed MCP Tasks wire shape.
    The signer's creation-source authority is a conditional fixture premise.
    """
    request_bytes = evidence.originating_request
    receipt = evidence.creation_source_receipt
    if request_bytes is None or receipt is None:
        return None
    expected = creation_source_statement(evidence.creation_observation, request_bytes)
    if receipt.statement != expected:
        return None
    try:
        Ed25519PublicKey.from_public_bytes(TRUSTED_CREATION_SOURCE_PUBLIC_KEY).verify(
            receipt.signature, receipt.statement,
        )
        record = json.loads(evidence.creation_observation)
        request = json.loads(request_bytes)
    except (InvalidSignature, ValueError, UnicodeDecodeError, TypeError):
        return None
    if not isinstance(record, dict) or not isinstance(request, dict):
        return None
    if set(record) != {
        "record_id", "kind", "task", "source", "origin_call_id",
        "origin_request_sha256", "execution_id",
    }:
        return None
    source = record["source"]
    if not isinstance(source, dict) or set(source) != {"server_identity", "tool_name"}:
        return None
    if (
        not isinstance(record["record_id"], str) or not record["record_id"]
        or record["kind"] != "task_creation_result_observed"
        or not isinstance(record["task"], str) or not record["task"]
        or not isinstance(record["origin_call_id"], str) or not record["origin_call_id"]
        or not isinstance(source["server_identity"], str) or not source["server_identity"]
        or not isinstance(source["tool_name"], str) or not source["tool_name"]
        or not isinstance(request.get("task"), str)
        or request["task"] != record["task"]
        or record["origin_request_sha256"] != hashlib.sha256(request_bytes).hexdigest()
        or (record["execution_id"] is not None and not isinstance(record["execution_id"], str))
    ):
        return None
    return CreationProjection(
        task=record["task"],
        call_id=record["origin_call_id"],
        request_hash=record["origin_request_sha256"],
        server_identity=source["server_identity"],
        tool_name=source["tool_name"],
        execution_id=record["execution_id"],
    )


def evaluate_origin(evidence: OriginEvidence) -> OriginResult:
    """Conditional fixture joins only, never actual execution/operation/effect."""
    entry = evidence.entry
    if (
        evidence.entry_commitment not in TRUSTED_ORIGIN_HASHES
        or entry.entry_hash != evidence.entry_commitment
        or entry.compute_hash() != evidence.entry_commitment
    ):
        unknown = Boundary(NOT_ESTABLISHED, "exact_trusted_entry_not_bound")
        return OriginResult(unknown, unknown, unknown, unknown, evidence)
    entry_binding = Boundary(ESTABLISHED, "exact_trusted_entry_commitment_verified")
    scope_bound = _scope_is_bound(evidence)
    correlation = _entry_to_entry_correlation(evidence, scope_bound)
    if not scope_bound:
        unknown = Boundary(NOT_ESTABLISHED, "same_agent_scope_not_bound_to_exact_evidence")
        return OriginResult(entry_binding, unknown, unknown, correlation, evidence)
    creation_projection = _creation_source_projection(evidence)
    if creation_projection is None:
        unknown = Boundary(NOT_ESTABLISHED, "creation_source_projection_not_bound")
        return OriginResult(entry_binding, unknown, unknown, correlation, evidence)
    origin_projection = creation_projection
    if (
        origin_projection.call_id != entry.call_id
        or origin_projection.request_hash != entry.request_payload_hash
        or origin_projection.server_identity != entry.server_identity
        or origin_projection.tool_name != entry.tool_name
    ):
        return OriginResult(
            entry_binding,
            Boundary(CONTRADICTION, "origin_projection_disagrees_with_committed_entry"),
            Boundary(NOT_ESTABLISHED, "dependent_execution_join_lacks_supported_origin"),
            correlation,
            evidence,
        )
    origin = Boundary(ESTABLISHED, "origin_projections_faithful_in_same_agent_scope")
    execution = creation_projection.execution_id
    if execution is None or entry.execution_id is None:
        relation = Boundary(NOT_ESTABLISHED, "execution_unavailable_no_identifier_synthesized")
    elif not valid_execution_id(execution) or execution != entry.execution_id:
        relation = Boundary(NOT_ESTABLISHED, "execution_projection_not_established")
    else:
        relation = Boundary(ESTABLISHED, "execution_projection_matches_supported_origin")
    return OriginResult(entry_binding, origin, relation, correlation, evidence)
