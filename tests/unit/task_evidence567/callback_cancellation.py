"""Conditional CB/CAN fixture oracles; no runtime or proposed wire protocol.

Role/key authority and the complete occurrence population are independent
synthetic premises. Signatures authenticate those premises, not live clients.
Native supporting messages follow ext-tasks 7b8e2bd. Nothing here verifies a
terminal result, an external effect, replay ordering or production credentials.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .accounting import Accounting, Submission, _account
from .authority_origin import (
    CONTRADICTION,
    ESTABLISHED,
    NOT_ESTABLISHED,
    AuthorityEvidence,
    Boundary,
    evaluate_authority,
)
from .observations import FixtureProfile, Observation, Witness, canonical

CB_BOUNDARIES = tuple(f"CB-{index:02d}" for index in range(1, 8))
OPERANDS = ("principal", "action", "resource", "scope", "instant")
CAN_BOUNDARIES = tuple(f"CAN-01/{name}" for name in OPERANDS) + (
    "CAN-02", "cancellation_authority",
)


@dataclass(frozen=True)
class Trust:
    """Fixed outside witnesses. Keys grant only the named fixture role."""

    keys: tuple[tuple[str, bytes], ...]
    source: str = "fixture-source"
    client: str = "fixture-requester"
    task: str = "fixture-task"
    scope: str = "cancel-this-task"
    evaluation: str = "evaluation-1"
    instant: int = 123456
    exclusive_task: bool = True

    def read(self, role: str, witness: Witness | None) -> dict[str, Any] | None:
        keys = dict(self.keys)
        key = keys.get(role)
        if key is None:
            return None
        # Reuse #701's exact signature/canonical-byte verification.
        return FixtureProfile(key, ()).read(witness, role)


def _subject(
    profile: Trust, role: str, subject: Observation, witness: Witness | None,
) -> dict[str, Any] | None:
    body = profile.read(role, witness)
    if body is None or body.get("subject") != subject.commitment:
        return None
    return body


def _result(disposition: str, reason: str) -> Boundary:
    return Boundary(disposition, reason)


def delivery_source(profile: Trust, delivery: Observation, witness: Witness | None) -> Boundary:
    body = _subject(profile, "CB-01", delivery, witness)
    if body is None or not isinstance(body.get("source"), str) or not body["source"]:
        return _result(NOT_ESTABLISHED, "delivery_source_not_bound")
    if body["source"] != profile.source:
        return _result(CONTRADICTION, "eligible_same_delivery_incompatible_source")
    return _result(ESTABLISHED, "exact_delivery_source_bound")


def delivery_bytes(profile: Trust, delivery: Observation, witness: Witness | None) -> Boundary:
    body = _subject(profile, "CB-02", delivery, witness)
    digest = None if body is None else body.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        return _result(NOT_ESTABLISHED, "comparable_delivery_commitment_missing")
    try:
        committed = bytes.fromhex(digest)
    except ValueError:
        return _result(NOT_ESTABLISHED, "malformed_delivery_commitment")
    if len(committed) != hashlib.sha256().digest_size:
        return _result(NOT_ESTABLISHED, "malformed_delivery_commitment")
    if committed != hashlib.sha256(delivery.payload).digest():
        return _result(CONTRADICTION, "eligible_same_delivery_bytes_disagree")
    return _result(ESTABLISHED, "exact_delivery_bytes_bound")


def delivery_task(profile: Trust, delivery: Observation, witness: Witness | None) -> Boundary:
    body = _subject(profile, "CB-03", delivery, witness)
    if body is None or not isinstance(body.get("task"), str) or not body["task"]:
        return _result(NOT_ESTABLISHED, "independent_task_membership_missing")
    if body["task"] == profile.task:
        return _result(ESTABLISHED, "exact_delivery_task_bound")
    if profile.exclusive_task:
        return _result(CONTRADICTION, "incompatible_exclusive_task_membership")
    return _result(NOT_ESTABLISHED, "other_membership_does_not_exclude_selected_task")


def _identity(
    profile: Trust, role: str, subject: Observation, witness: Witness | None,
) -> Boundary:
    body = _subject(profile, role, subject, witness)
    if body is None or body.get("client") != profile.client:
        return _result(NOT_ESTABLISHED, "authenticated_client_not_bound")
    return _result(ESTABLISHED, "authenticated_fixture_client_bound")


def _permission(
    profile: Trust, role: str, subject: Observation, witness: Witness | None, actor: str,
) -> Boundary:
    body = _subject(profile, role, subject, witness)
    if body is None or any(body.get(key) != value for key, value in {
        "actor": actor, "task": profile.task, "scope": profile.scope,
        "evaluation": profile.evaluation,
    }.items()):
        return _result(NOT_ESTABLISHED, "applicable_authority_missing")
    start, end = body.get("valid_from"), body.get("valid_until")
    if type(start) is not int or type(end) is not int or not start <= profile.instant <= end:
        return _result(NOT_ESTABLISHED, "authority_does_not_cover_selected_instant")
    if body.get("decision") == "forbid":
        return _result(CONTRADICTION, "applicable_explicit_exclusion")
    if body.get("decision") == "allow":
        return _result(ESTABLISHED, "applicable_permission")
    return _result(NOT_ESTABLISHED, "no_explicit_authority_decision")


def reporting_authority(
    profile: Trust, delivery: Observation, source: Witness | None, permission: Witness | None,
) -> Boundary:
    authenticated = delivery_source(profile, delivery, source)
    if authenticated.disposition != ESTABLISHED:
        return _result(NOT_ESTABLISHED, "expected_reporting_actor_not_authenticated")
    return _permission(profile, "CB-04", delivery, permission, profile.source)


def subscription_acceptance(
    profile: Trust, listen: Observation, acknowledged: Observation, witness: Witness | None,
) -> Boundary:
    body = _subject(profile, "CB-05", acknowledged, witness)
    if body is None or body.get("listen") != listen.commitment or body.get("complete") is not True:
        return _result(NOT_ESTABLISHED, "complete_exact_ack_exchange_binding_missing")
    request, notification = listen.data, acknowledged.data
    if (request.get("method") != "subscriptions/listen"
            or "id" not in request
            or notification.get("method") != "notifications/subscriptions/acknowledged"
            or "id" in notification):
        return _result(NOT_ESTABLISHED, "not_native_listen_and_acknowledged_notification")
    params = notification.get("params")
    notifications = params.get("notifications") if isinstance(params, dict) else None
    tasks = notifications.get("taskIds") if isinstance(notifications, dict) else None
    if not isinstance(tasks, list) or not all(isinstance(task, str) for task in tasks):
        return _result(NOT_ESTABLISHED, "no_complete_accepted_task_list")
    if profile.task not in tasks:
        return _result(CONTRADICTION, "task_absent_from_this_complete_ack_only")
    return _result(ESTABLISHED, "task_accepted_in_this_exact_ack_only")


def subscriber_authority(
    profile: Trust, listen: Observation, identity: Witness | None, permission: Witness | None,
) -> Boundary:
    authenticated = _identity(profile, "listen-client", listen, identity)
    if authenticated.disposition != ESTABLISHED:
        return _result(NOT_ESTABLISHED, "subscriber_authentication_missing")
    return _permission(profile, "CB-06", listen, permission, profile.client)


def delivery_context(
    profile: Trust, delivery: Observation, listen: Observation, witness: Witness | None,
) -> Boundary:
    body = _subject(profile, "CB-07", delivery, witness)
    if body is None or body.get("listen") != listen.commitment or body.get("client") != profile.client:
        return _result(NOT_ESTABLISHED, "delivery_not_bound_to_selected_listen_and_subscriber")
    return _result(ESTABLISHED, "exact_delivery_listen_subscriber_bound")


@dataclass(frozen=True)
class Cancellation:
    """Exact captured request plus independently selected evaluation operands."""

    request: Observation
    policy: str | None
    client: Witness | None
    bindings: tuple[tuple[str, Witness | None], ...]
    joint: Witness | None = None


@dataclass(frozen=True)
class CancellationResult:
    authentication: Boundary
    policy: Boundary
    bindings: tuple[tuple[str, Boundary], ...]
    joint: Boundary
    authority: Boundary


def cancellation(profile: Trust, evidence: Cancellation) -> CancellationResult:
    data = evidence.request.data
    params = data.get("params")
    task = params.get("taskId") if isinstance(params, dict) else None
    task = task if isinstance(task, str) else ""
    method = data.get("method")
    method = method if isinstance(method, str) else ""
    policy = evaluate_authority(AuthorityEvidence(
        evidence.policy, b"fixture-ack-kept-separate", requester=profile.client,
        method=method, task=task, scope=profile.scope, instant=profile.instant,
    )).authority
    authentication = _identity(profile, "cancel-client", evidence.request, evidence.client)
    values = {"principal": profile.client, "action": "tasks/cancel", "resource": task,
              "scope": profile.scope, "instant": profile.instant}
    supplied = dict(evidence.bindings)
    bindings = []
    for name in OPERANDS:
        body = _subject(profile, f"CAN-01/{name}", evidence.request, supplied.get(name))
        value = None if body is None else body.get("value")
        if (body is None or type(value) is not type(values[name]) or value != values[name]
                or body.get("client") != profile.client):
            boundary = _result(NOT_ESTABLISHED, "independent_operand_binding_missing")
        else:
            boundary = _result(ESTABLISHED, "individual_exact_operand_bound")
        bindings.append((name, boundary))
    # This authority attests context coverage of exact statement bytes ONLY.
    # It cannot establish the separate operand signer's provenance/value claim.
    # Retaining body bytes but omitting one operand signature must leave this
    # independently supported relation E, exposing the composite prerequisite.
    context = _subject(profile, "CAN-02", evidence.request, evidence.joint)
    commitments = None if context is None else context.get("bindings")
    applicable = (context is not None and context.get("evaluation") == profile.evaluation
                  and isinstance(commitments, dict))
    for name in OPERANDS:
        witness = supplied.get(name)
        body = None
        if witness is not None and isinstance(commitments, dict):
            try:
                candidate = json.loads(witness.body)
                if (isinstance(candidate, dict) and canonical(candidate) == witness.body
                        and commitments.get(name) == hashlib.sha256(witness.body).hexdigest()):
                    body = candidate
            except (ValueError, TypeError):
                pass
        contexts = None if body is None else body.get("evaluations")
        start = None if body is None else body.get("valid_from")
        end = None if body is None else body.get("valid_until")
        if (not isinstance(contexts, list) or profile.evaluation not in contexts
                or type(start) is not int or type(end) is not int
                or not start <= profile.instant <= end):
            applicable = False
    joint = _result(ESTABLISHED if applicable else NOT_ESTABLISHED,
                    "joint_scope_and_time_coverage" if applicable else "joint_applicability_missing")
    required = (authentication, policy, joint, *(boundary for _, boundary in bindings))
    if any(boundary.disposition == CONTRADICTION for boundary in required):
        authority = _result(CONTRADICTION, "applicable_cancellation_exclusion")
    elif any(boundary.disposition != ESTABLISHED for boundary in required):
        authority = _result(NOT_ESTABLISHED, "required_cancellation_relation_missing")
    else:
        authority = _result(ESTABLISHED, "all_required_cancellation_relations_established")
    return CancellationResult(authentication, policy, tuple(bindings), joint, authority)


def account_slice(submission: Submission) -> tuple[Accounting, ...]:
    """Fixed source kinds trigger even when authentication/relations fail.

    Reuse AM-12 counting and attempt preservation, not its creation trigger.
    Supporting listen/ack records are never delivery/request subjects here.
    """
    deliveries = tuple(r for r in submission.observations if r.kind == "callback_delivery_observed")
    cancellations = tuple(r for r in submission.observations if r.kind == "cancellation_request_observed")
    return tuple(_account(submission, deliveries, boundary) for boundary in CB_BOUNDARIES) + tuple(
        _account(submission, cancellations, boundary) for boundary in CAN_BOUNDARIES
    )
