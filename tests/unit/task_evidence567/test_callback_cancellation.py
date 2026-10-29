"""Approved CB-01..07 / CAN-01..02, synthetic and conditional only.

Each negative keeps the other world premises fixed and has an E twin. Keys
and their narrowly scoped roles, complete occurrence scopes, actor/task and
evaluation context are stipulated independently of submitted witness bytes.
No live client authentication, effect, terminal result or wire format is earned.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .accounting import Assessment, Submission
from .accounting import Observation as AccountingObservation
from .authority_origin import (
    CONTRADICTION as C,
)
from .authority_origin import (
    ESTABLISHED as E,
)
from .authority_origin import (
    EXCLUSION_POLICY,
    INCLUSION_POLICY,
)
from .authority_origin import (
    NOT_ESTABLISHED as N,
)
from .callback_cancellation import (
    CB_BOUNDARIES,
    OPERANDS,
    Cancellation,
    Trust,
    account_slice,
    cancellation,
    delivery_bytes,
    delivery_context,
    delivery_source,
    delivery_task,
    reporting_authority,
    subscriber_authority,
    subscription_acceptance,
)
from .observations import Observation, Witness, canonical

# Public deterministic test-only seeds. Keys' role authority is a premise,
# never inferred from a self-consistent signature or the message's own key.
ROLES = CB_BOUNDARIES + ("listen-client", "cancel-client", "CAN-02") + tuple(
    f"CAN-01/{name}" for name in OPERANDS
)
KEYS = {role: Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(f"cmcp567-public-test-seed:{role}".encode()).digest()
) for role in ROLES}
PROFILE = Trust(tuple((role, key.public_key().public_bytes_raw()) for role, key in KEYS.items()))


def observation(occurrence, kind, data):
    return Observation(occurrence, kind, canonical(data), 0)


def signed(role, subject, **fields):
    body = canonical({"boundary": role, "subject": subject.commitment, **fields})
    return Witness(body, KEYS[role].sign(body))


def corrupted(witness):
    return replace(witness, signature=bytes([witness.signature[0] ^ 1]) + witness.signature[1:])


@dataclass(frozen=True)
class World:
    delivery: Observation
    listen: Observation
    ack: Observation
    request: Observation


@pytest.fixture
def world():
    return World(
        observation("delivery-1", "callback_delivery_observed", {
            "jsonrpc": "2.0", "method": "notifications/tasks",
            "params": {"taskId": PROFILE.task, "status": "working"},
        }),
        observation("listen-1", "request_observed", {
            "jsonrpc": "2.0", "id": 10, "method": "subscriptions/listen",
            "params": {"notifications": {"taskIds": [PROFILE.task]}},
        }),
        observation("ack-1", "notification_observed", {
            "jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
            "params": {"notifications": {"taskIds": [PROFILE.task]}},
        }),
        observation("cancel-1", "cancellation_request_observed", {
            "jsonrpc": "2.0", "id": 11, "method": "tasks/cancel",
            "params": {"taskId": PROFILE.task},
        }),
    )


def source(world):
    return signed("CB-01", world.delivery, source=PROFILE.source)


def permission(role, subject, expected_actor, **changes):
    fields = {"actor": expected_actor, "task": PROFILE.task, "scope": PROFILE.scope,
              "evaluation": PROFILE.evaluation, "valid_from": 123400,
              "valid_until": 123500, "decision": "allow", **changes}
    return signed(role, subject, **fields)


def client(role, subject):
    return signed(role, subject, client=PROFILE.client)


def acknowledgement(world, **changes):
    return signed("CB-05", world.ack, listen=world.listen.commitment, complete=True, **changes)


def cancel_evidence(world, **changes):
    values = {"principal": PROFILE.client, "action": "tasks/cancel", "resource": PROFILE.task,
              "scope": PROFILE.scope, "instant": PROFILE.instant}
    bindings = tuple((name, signed(
        f"CAN-01/{name}", world.request, client=PROFILE.client, value=values[name],
        evaluations=[PROFILE.evaluation], valid_from=123400, valid_until=123500,
    )) for name in OPERANDS)
    joint = joint_context(world, bindings)
    return replace(Cancellation(world.request, INCLUSION_POLICY,
                                client("cancel-client", world.request), bindings, joint), **changes)


def joint_context(world, bindings):
    return signed("CAN-02", world.request, evaluation=PROFILE.evaluation, bindings={
        name: hashlib.sha256(witness.body).hexdigest() for name, witness in bindings
        if witness is not None
    })


@pytest.mark.parametrize("case,expected", [
    ("positive", E), ("missing", N), ("signature", N), ("wrong-subject", N),
    ("incompatible", C), ("wrong-role", N),
])
def test_cb01_delivery_source(world, case, expected):
    evidence = source(world)
    if case == "missing":
        evidence = None
    elif case == "signature":
        evidence = corrupted(evidence)
    elif case == "wrong-subject":
        evidence = signed("CB-01", replace(world.delivery, occurrence="delivery-2"), source=PROFILE.source)
    elif case == "incompatible":
        evidence = signed("CB-01", world.delivery, source="other-authenticated-source")
    elif case == "wrong-role":
        body = evidence.body
        evidence = Witness(body, KEYS["CB-02"].sign(body))
    assert delivery_source(PROFILE, world.delivery, evidence).disposition == expected


@pytest.mark.parametrize("case,expected", [
    ("positive", E), ("missing", N), ("signature", N), ("wrong-subject", N),
    ("mismatch", C), ("malformed", N), ("whitespace", N), ("uppercase", E),
])
def test_cb02_delivered_bytes(world, case, expected):
    digest = hashlib.sha256(world.delivery.payload).hexdigest()
    subject = world.delivery
    if case == "wrong-subject":
        subject = replace(subject, occurrence="delivery-2")
    if case == "mismatch":
        digest = hashlib.sha256(b"different delivered bytes").hexdigest()
    if case == "malformed":
        digest = "not a digest"
    if case == "whitespace":
        digest = " " * 64
    if case == "uppercase":
        digest = digest.upper()
    evidence = signed("CB-02", subject, sha256=digest)
    if case == "missing":
        evidence = None
    if case == "signature":
        evidence = corrupted(evidence)
    assert delivery_bytes(PROFILE, world.delivery, evidence).disposition == expected


@pytest.mark.parametrize("case,expected", [
    ("positive", E), ("id-text-only", N), ("wrong-subject", N),
    ("exclusive-other-task", C), ("nonexclusive-other-task", N), ("signature", N),
])
def test_cb03_task_membership(world, case, expected):
    profile = replace(PROFILE, exclusive_task=case != "nonexclusive-other-task")
    subject = replace(world.delivery, occurrence="delivery-2") if case == "wrong-subject" else world.delivery
    task = "other-task" if "other-task" in case else PROFILE.task
    evidence = signed("CB-03", subject, task=task)
    if case == "id-text-only":
        evidence = None
    if case == "signature":
        evidence = corrupted(evidence)
    assert world.delivery.data["params"]["taskId"] == PROFILE.task
    assert delivery_task(profile, world.delivery, evidence).disposition == expected


@pytest.mark.parametrize("role", ["CB-04", "CB-06"])
@pytest.mark.parametrize("case,expected", [
    ("positive", E), ("missing", N), ("wrong-task", N), ("wrong-context", N),
    ("wrong-actor", N), ("expired", N), ("forbid", C), ("signature", N),
])
def test_cb04_cb06_authority_is_separate(world, role, case, expected):
    subject = world.delivery if role == "CB-04" else world.listen
    actor = PROFILE.source if role == "CB-04" else PROFILE.client
    changes = {"wrong-task": {"task": "other-task"}, "wrong-context": {"evaluation": "other-evaluation"},
               "wrong-actor": {"actor": "other-actor"}, "expired": {"valid_until": 123455},
               "forbid": {"decision": "forbid"}}.get(case, {})
    evidence = permission(role, subject, actor, **changes)
    if case == "missing":
        evidence = None
    if case == "signature":
        evidence = corrupted(evidence)
    assert delivery_source(PROFILE, world.delivery, source(world)).disposition == E
    assert subscription_acceptance(PROFILE, world.listen, world.ack, acknowledgement(world)).disposition == E
    if role == "CB-04":
        result = reporting_authority(PROFILE, subject, source(world), evidence)
    else:
        result = subscriber_authority(PROFILE, subject, client("listen-client", subject), evidence)
    assert result.disposition == expected


def test_cb04_authentication_is_not_reporting_permission(world):
    assert delivery_source(PROFILE, world.delivery, source(world)).disposition == E
    assert reporting_authority(PROFILE, world.delivery, source(world), None).disposition == N
    allow = permission("CB-04", world.delivery, PROFILE.source)
    assert reporting_authority(PROFILE, world.delivery, None, allow).disposition == N


@pytest.mark.parametrize("case,expected", [
    ("positive", E), ("missing", N), ("wrong-listen", N), ("wrong-ack", N),
    ("requested-not-accepted", C), ("partial", N), ("response-not-notification", N),
    ("signature", N),
])
def test_cb05_exact_native_ack_only(world, case, expected):
    if case == "requested-not-accepted":
        data = world.ack.data
        data["params"]["notifications"]["taskIds"] = []
        world = replace(world, ack=replace(world.ack, payload=canonical(data)))
    if case == "response-not-notification":
        world = replace(world, ack=observation("ack-1", "response_observed", {
            "jsonrpc": "2.0", "id": 10, "result": {"notifications": {"taskIds": [PROFILE.task]}},
        }))
    evidence = signed("CB-05", world.ack,
                      listen=(replace(world.listen, occurrence="listen-2").commitment
                              if case == "wrong-listen" else world.listen.commitment),
                      complete=case != "partial")
    if case == "wrong-ack":
        evidence = signed("CB-05", replace(world.ack, occurrence="ack-2"),
                          listen=world.listen.commitment, complete=True)
    if case == "missing":
        evidence = None
    if case == "signature":
        evidence = corrupted(evidence)
    assert world.listen.data["params"]["notifications"]["taskIds"] == [PROFILE.task]
    assert subscription_acceptance(PROFILE, world.listen, world.ack, evidence).disposition == expected


def test_cb06_acceptance_and_permission_do_not_authenticate_subscriber(world):
    allow = permission("CB-06", world.listen, PROFILE.client)
    assert subscription_acceptance(PROFILE, world.listen, world.ack, acknowledgement(world)).disposition == E
    assert subscriber_authority(PROFILE, world.listen, None, allow).disposition == N


@pytest.mark.parametrize("case,expected", [
    ("positive", E), ("missing", N), ("wrong-listen", N),
    ("wrong-client", N), ("wrong-delivery", N), ("signature", N),
])
def test_cb07_delivery_context_does_not_inherit_listen_evidence(world, case, expected):
    subject = replace(world.delivery, occurrence="delivery-2") if case == "wrong-delivery" else world.delivery
    listen = replace(world.listen, occurrence="listen-2") if case == "wrong-listen" else world.listen
    subscriber = "other-client" if case == "wrong-client" else PROFILE.client
    evidence = signed("CB-07", subject, listen=listen.commitment, client=subscriber)
    if case == "missing":
        evidence = None
    if case == "signature":
        evidence = corrupted(evidence)
    assert subscription_acceptance(PROFILE, world.listen, world.ack, acknowledgement(world)).disposition == E
    allow = permission("CB-06", world.listen, PROFILE.client)
    assert subscriber_authority(PROFILE, world.listen, client("listen-client", world.listen), allow).disposition == E
    assert delivery_context(PROFILE, world.delivery, world.listen, evidence).disposition == expected


@pytest.mark.parametrize("name", OPERANDS)
def test_can01_one_missing_binding_defeats_composite_despite_same_permit(world, name):
    positive = cancel_evidence(world)
    negative = replace(positive, bindings=tuple(
        (key, replace(value, signature=b"") if key == name else value)
        for key, value in positive.bindings
    ))
    before, after = cancellation(PROFILE, positive), cancellation(PROFILE, negative)
    assert before.policy == after.policy
    assert before.policy.disposition == E
    assert before.authentication == after.authentication
    assert after.authentication.disposition == E
    assert all(boundary.disposition == E for _, boundary in before.bindings)
    assert dict(after.bindings)[name].disposition == N
    assert all(boundary.disposition == E for key, boundary in after.bindings if key != name)
    assert before.joint == after.joint
    assert after.joint.disposition == E
    assert before.authority.disposition == E
    assert after.authority.disposition == N


@pytest.mark.parametrize("name", OPERANDS)
@pytest.mark.parametrize("case", ["wrong-subject", "wrong-value", "wrong-client", "signature"])
def test_can01_inapplicable_operand_is_not_authority(world, name, case):
    evidence = cancel_evidence(world)
    old = dict(evidence.bindings)[name]
    fields = json.loads(old.body)
    fields.pop("boundary")
    fields.pop("subject")
    subject = world.request
    if case == "wrong-subject":
        subject = replace(subject, occurrence="cancel-2")
    if case == "wrong-value":
        fields["value"] = "other-value"
    if case == "wrong-client":
        fields["client"] = "other-client"
    changed = signed(f"CAN-01/{name}", subject, **fields)
    if case == "signature":
        changed = corrupted(changed)
    changed_bindings = tuple(
        (key, changed if key == name else value) for key, value in evidence.bindings
    )
    result = cancellation(PROFILE, replace(evidence, bindings=changed_bindings,
                                          joint=joint_context(world, changed_bindings)))
    assert result.policy.disposition == E
    assert result.authentication.disposition == result.joint.disposition == E
    assert dict(result.bindings)[name].disposition == N
    assert all(boundary.disposition == E for key, boundary in result.bindings if key != name)
    assert result.authority.disposition == N


@pytest.mark.parametrize("case", ["split-context", "expired", "future", "no-context"])
def test_can02_individually_valid_not_jointly_applicable(world, case):
    positive = cancel_evidence(world)
    changed = []
    for index, (name, witness) in enumerate(positive.bindings):
        fields = json.loads(witness.body)
        fields.pop("boundary")
        fields.pop("subject")
        if case == "split-context":
            fields["evaluations"] = [f"other-evaluation-{index}"]
        elif case == "expired":
            fields["valid_until"] = PROFILE.instant - 1
        elif case == "future":
            fields["valid_from"] = PROFILE.instant + 1
        else:
            fields["evaluations"] = []
        changed.append((name, signed(f"CAN-01/{name}", world.request, **fields)))
    before = cancellation(PROFILE, positive)
    after = cancellation(PROFILE, replace(positive, bindings=tuple(changed),
                                         joint=joint_context(world, changed)))
    assert before.policy == after.policy
    assert before.authentication == after.authentication
    assert all(boundary.disposition == E for _, boundary in after.bindings)
    assert before.joint.disposition == before.authority.disposition == E
    assert after.joint.disposition == after.authority.disposition == N


def test_can02_older_evidence_still_covering_selected_context_is_usable(world):
    evidence = cancel_evidence(world)
    changed = []
    for name, witness in evidence.bindings:
        fields = json.loads(witness.body)
        fields.pop("boundary")
        fields.pop("subject")
        fields.update(issued_at=1, valid_from=0, valid_until=999999,
                      evaluations=["older-evaluation", PROFILE.evaluation])
        changed.append((name, signed(f"CAN-01/{name}", world.request, **fields)))
    result = cancellation(PROFILE, replace(evidence, bindings=tuple(changed),
                                          joint=joint_context(world, changed)))
    assert result.joint.disposition == result.authority.disposition == E


@pytest.mark.parametrize("case,expected", [
    ("positive", E), ("missing", N), ("signature", N),
    ("wrong-subject", N), ("wrong-context", N), ("wrong-hash", N),
])
def test_can02_independent_joint_receipt_is_required(world, case, expected):
    evidence = cancel_evidence(world)
    joint = evidence.joint
    fields = json.loads(joint.body)
    fields.pop("boundary")
    fields.pop("subject")
    subject = world.request
    if case == "wrong-subject":
        subject = replace(subject, occurrence="cancel-2")
    if case == "wrong-context":
        fields["evaluation"] = "evaluation-2"
    if case == "wrong-hash":
        fields["bindings"]["principal"] = "0" * 64
    joint = signed("CAN-02", subject, **fields)
    if case == "missing":
        joint = None
    if case == "signature":
        joint = corrupted(joint)
    result = cancellation(PROFILE, replace(evidence, joint=joint))
    assert result.authentication.disposition == result.policy.disposition == E
    assert all(boundary.disposition == E for _, boundary in result.bindings)
    assert result.joint.disposition == result.authority.disposition == expected


@pytest.mark.parametrize("exclusive", [False, True])
def test_cb03_selected_membership_has_a_twin_in_each_profile(world, exclusive):
    profile = replace(PROFILE, exclusive_task=exclusive)
    matching = signed("CB-03", world.delivery, task=profile.task)
    other = signed("CB-03", world.delivery, task="other-task")
    assert delivery_task(profile, world.delivery, matching).disposition == E
    assert delivery_task(profile, world.delivery, other).disposition == (C if exclusive else N)


@pytest.mark.parametrize("case", ["task-id-only", "no-client", "bad-client-signature",
                                    "no-policy", "explicit-forbid", "other-task"])
def test_can_task_id_possession_never_suffices(world, case):
    evidence = cancel_evidence(world)
    expected = N
    if case == "task-id-only":
        evidence = replace(evidence, client=None, bindings=())
    elif case == "no-client":
        evidence = replace(evidence, client=None)
    elif case == "bad-client-signature":
        evidence = replace(evidence, client=corrupted(evidence.client))
    elif case == "no-policy":
        evidence = replace(evidence, policy=None)
    elif case == "explicit-forbid":
        evidence = replace(evidence, policy=EXCLUSION_POLICY)
        expected = C
    else:
        data = world.request.data
        data["params"]["taskId"] = "other-task"
        world = replace(world, request=replace(world.request, payload=canonical(data)))
        evidence = cancel_evidence(world)
    result = cancellation(PROFILE, evidence)
    assert result.authority.disposition == expected
    if case in {"task-id-only", "no-client", "bad-client-signature"}:
        assert result.policy.disposition == E
        assert result.authentication.disposition == N
    if case == "other-task":
        assert result.policy.disposition == N  # Inapplicable permit is not C.


def test_positive_relations_are_nonvacuous(world):
    """An always-N helper must lose the established positive twins."""
    assert delivery_source(PROFILE, world.delivery, source(world)).disposition == E
    assert delivery_bytes(PROFILE, world.delivery, signed(
        "CB-02", world.delivery, sha256=hashlib.sha256(world.delivery.payload).hexdigest(),
    )).disposition == E
    assert delivery_task(PROFILE, world.delivery, signed("CB-03", world.delivery, task=PROFILE.task)).disposition == E
    assert reporting_authority(PROFILE, world.delivery, source(world),
                               permission("CB-04", world.delivery, PROFILE.source)).disposition == E
    assert subscription_acceptance(PROFILE, world.listen, world.ack, acknowledgement(world)).disposition == E
    assert subscriber_authority(PROFILE, world.listen, client("listen-client", world.listen),
                                permission("CB-06", world.listen, PROFILE.client)).disposition == E
    assert delivery_context(PROFILE, world.delivery, world.listen, signed(
        "CB-07", world.delivery, listen=world.listen.commitment, client=PROFILE.client,
    )).disposition == E
    result = cancellation(PROFILE, cancel_evidence(world))
    assert result.joint.disposition == result.authority.disposition == E


def test_evaluated_unknown_is_accounted_but_never_upgraded_to_authority(world):
    # Fixed source handle is selected BEFORE either evaluation or assessments.
    subject = AccountingObservation(world.request.commitment, "cancellation_request_observed", PROFILE.task)
    population = (subject,)
    evidence = cancel_evidence(world)
    absent_principal = replace(evidence, bindings=tuple(
        (name, replace(witness, signature=b"") if name == "principal" else witness)
        for name, witness in evidence.bindings
    ))
    result = cancellation(PROFILE, absent_principal)
    assert result.joint.disposition == E
    assert result.authority.disposition == N
    values = tuple((f"CAN-01/{name}", boundary.disposition) for name, boundary in result.bindings)
    values += (("CAN-02", result.joint.disposition), ("cancellation_authority", result.authority.disposition))
    rows = tuple(Assessment(f"assessment-{name}", subject, name, disposition)
                 for name, disposition in values)
    submission = Submission(population, rows)
    selected = [item for item in account_slice(submission) if item.obligations]
    assert len(selected) == 7
    assert all(item.status == "PASS" for item in selected)
    assert selected[0].obligations[0].submitted_disposition == N
    assert selected[-1].obligations[0].submitted_disposition == N
    omitted = Submission(population, rows[:-1])
    assert account_slice(omitted)[-1].obligations[0].status == "UNACCOUNTED"
    assert result.authority.disposition == N  # Accounting cannot repair the relation.
