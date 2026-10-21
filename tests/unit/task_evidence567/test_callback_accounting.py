"""Conditional CB/CAN accounting over a predeclared occurrence population.

SOURCE_DECLARED: the frozen local contract requires seven callback and seven
cancellation boundaries, independent of authentication or submitted outcomes.
EXACT EVIDENCE is constructed below; CASE_IDs are pytest parameter IDs.
TRUST ASSUMPTIONS: these accounting.Observation handles identify distinct
already-selected fixture records; assessment eligibility is local shape only.
CLAIM LIMIT: accounting does not establish a callback/cancellation relation,
runtime completeness, credentials, a wire schema, or an external effect.
"""

from dataclasses import FrozenInstanceError, replace

import pytest

from .accounting import Assessment, Observation, Submission
from .callback_cancellation import CAN_BOUNDARIES, CB_BOUNDARIES, account_slice

_FAMILIES = (
    ("callback_delivery_observed", CB_BOUNDARIES),
    ("cancellation_request_observed", CAN_BOUNDARIES),
)
_BOUNDARY_CASES = [
    pytest.param(kind, boundaries, boundary, id=boundary)
    for kind, boundaries in _FAMILIES
    for boundary in boundaries
]
_FAMILY_CASES = [
    pytest.param(kind, boundaries, id=boundaries[0].split("-")[0])
    for kind, boundaries in _FAMILIES
]


def _observation(kind, record_id="occurrence-1"):
    return Observation(record_id, kind, "same-task")


def _assessment(subject, boundary, disposition="ESTABLISHED", **changes):
    return replace(
        Assessment(f"assessment-{boundary}", subject, boundary, disposition),
        **changes,
    )


def _rows(subject, boundaries, disposition="ESTABLISHED"):
    return tuple(_assessment(subject, boundary, disposition) for boundary in boundaries)


def _accounting(submission, boundary):
    return account_slice(submission)[(CB_BOUNDARIES + CAN_BOUNDARIES).index(boundary)]


def test_boundary_population_matches_the_frozen_local_contract():
    """CB-CAN-FIXED-BOUNDARIES: outcomes do not select the required relation set."""
    assert CB_BOUNDARIES == (
        "CB-01", "CB-02", "CB-03", "CB-04", "CB-05", "CB-06", "CB-07",
    )
    assert CAN_BOUNDARIES == (
        "CAN-01/principal", "CAN-01/action", "CAN-01/resource", "CAN-01/scope",
        "CAN-01/instant", "CAN-02", "cancellation_authority",
    )
    assert len(account_slice(Submission((), ()))) == 14


def test_source_kinds_separate_delivery_request_and_supporting_occurrences():
    """CB-CAN-SOURCE-KINDS: a shared task does not merge source populations."""
    delivery = _observation("callback_delivery_observed", "delivery")
    request = _observation("cancellation_request_observed", "cancel")
    listen = _observation("subscription_listen_request_observed", "listen")
    acknowledged = _observation("subscription_acknowledged_notification_observed", "ack")
    rows = _rows(delivery, CB_BOUNDARIES) + _rows(request, CAN_BOUNDARIES) + (
        _assessment(listen, "CB-01"),
        _assessment(acknowledged, "CAN-02"),
    )
    submission = Submission((delivery, request, listen, acknowledged), rows)
    results = account_slice(submission)
    assert len(results) == 14
    for boundary, result in zip(CB_BOUNDARIES + CAN_BOUNDARIES, results, strict=True):
        obligation, = result.obligations
        assert result.status == "PASS"
        assert obligation.subject is (delivery if boundary in CB_BOUNDARIES else request)
        assert obligation.boundary == boundary
        assert obligation.status == "ACCOUNTED"
        assert result.submission is submission
        assert result.submission.assessments == rows
    assert results[0].obligations[0].wrong_subject_positions == (14,)
    assert results[12].obligations[0].wrong_subject_positions == (15,)


@pytest.mark.parametrize("kind,boundaries,boundary", _BOUNDARY_CASES)
@pytest.mark.parametrize(
    "disposition", ["ESTABLISHED", "NOT_ESTABLISHED"], ids=["E", "N"],
)
def test_every_required_boundary_accounts_an_explicit_disposition(
    kind, boundaries, boundary, disposition,
):
    subject = _observation(kind)
    rows = tuple(
        _assessment(subject, name, disposition if name == boundary else "ESTABLISHED")
        for name in boundaries
    )
    submission = Submission((subject,), rows)
    result = _accounting(submission, boundary)
    obligation, = result.obligations
    assert result.status == "PASS"
    assert obligation.subject is subject
    assert obligation.boundary == boundary
    assert obligation.status == "ACCOUNTED"
    assert obligation.attempt_positions == (boundaries.index(boundary),)
    assert obligation.malformed_positions == ()
    assert obligation.submitted_disposition == disposition
    assert result.submission is submission
    assert result.submission.assessments == rows
    assert all(_accounting(submission, name).status == "PASS" for name in boundaries)


@pytest.mark.parametrize("kind,boundaries,boundary", _BOUNDARY_CASES)
def test_omission_is_unaccounted_not_an_implicit_unknown(kind, boundaries, boundary):
    subject = _observation(kind)
    rows = tuple(row for row in _rows(subject, boundaries) if row.boundary != boundary)
    submission = Submission((subject,), rows)
    result = _accounting(submission, boundary)
    obligation, = result.obligations
    assert result.status == "FAIL"
    assert obligation.status == "UNACCOUNTED"
    assert obligation.attempt_positions == ()
    assert obligation.submitted_disposition is None
    assert result.submission.assessments == rows
    assert all(
        _accounting(submission, name).status == "PASS"
        for name in boundaries if name != boundary
    )


@pytest.mark.parametrize("kind,boundaries,boundary", _BOUNDARY_CASES)
@pytest.mark.parametrize("equal_fields", [False, True], ids=["SAME-TASK", "EQUAL-FIELDS"])
def test_another_occurrence_cannot_discharge_the_exact_subject(
    kind, boundaries, boundary, equal_fields,
):
    required = _observation(kind)
    other = _observation(kind, "occurrence-1" if equal_fields else "occurrence-2")
    assert other is not required
    assert other.task_id == required.task_id
    if equal_fields:
        assert vars(other) == vars(required)
    rows = _rows(other, boundaries)
    submission = Submission((required, other), rows)
    result = _accounting(submission, boundary)
    missing, accounted = result.obligations
    assert result.status == "FAIL"
    assert missing.subject is required
    assert missing.status == "UNACCOUNTED"
    assert missing.attempt_positions == ()
    assert missing.wrong_subject_positions == (boundaries.index(boundary),)
    assert missing.submitted_disposition is None
    assert accounted.subject is other
    assert accounted.status == "ACCOUNTED"
    assert accounted.attempt_positions == (boundaries.index(boundary),)
    assert result.submission.observations == (required, other)
    assert result.submission.assessments == rows


@pytest.mark.parametrize("kind,boundaries,boundary", _BOUNDARY_CASES)
def test_duplicate_attempts_remain_ambiguous(kind, boundaries, boundary):
    subject = _observation(kind)
    row = _assessment(subject, boundary)
    rows = (row, row)
    result = _accounting(Submission((subject,), rows), boundary)
    obligation, = result.obligations
    assert result.status == "FAIL"
    assert obligation.status == "AMBIGUOUS_ACCOUNTING"
    assert obligation.attempt_positions == (0, 1)
    assert obligation.malformed_positions == ()
    assert obligation.submitted_disposition is None
    assert result.submission.assessments == rows
    assert len(result.submission.assessments) == 2


@pytest.mark.parametrize("kind,boundaries,boundary", _BOUNDARY_CASES)
def test_malformed_targeted_attempt_remains_visible(kind, boundaries, boundary):
    subject = _observation(kind)
    row = _assessment(subject, boundary, disposition=None)
    result = _accounting(Submission((subject,), (row,)), boundary)
    obligation, = result.obligations
    assert result.status == "FAIL"
    assert obligation.status == "MALFORMED_ACCOUNTING"
    assert obligation.attempt_positions == (0,)
    assert obligation.malformed_positions == (0,)
    assert result.malformed_positions == (0,)
    assert obligation.submitted_disposition is None
    assert result.submission.assessments == (row,)


@pytest.mark.parametrize("kind,boundaries,boundary", _BOUNDARY_CASES)
@pytest.mark.parametrize("malformed_first", [False, True], ids=["VALID-FIRST", "MALFORMED-FIRST"])
def test_valid_and_malformed_duplicate_cannot_be_filtered_to_pass(
    kind, boundaries, boundary, malformed_first,
):
    subject = _observation(kind)
    valid = _assessment(subject, boundary)
    malformed = replace(valid, evidence_basis=None)
    rows = (malformed, valid) if malformed_first else (valid, malformed)
    result = _accounting(Submission((subject,), rows), boundary)
    obligation, = result.obligations
    assert result.status == "FAIL"
    assert obligation.status == "AMBIGUOUS_ACCOUNTING"
    assert obligation.attempt_positions == (0, 1)
    assert obligation.malformed_positions == ((0,) if malformed_first else (1,))
    assert result.malformed_positions == obligation.malformed_positions
    assert obligation.submitted_disposition is None
    assert result.submission.assessments == rows


@pytest.mark.parametrize("kind,boundaries,boundary", _BOUNDARY_CASES)
def test_wrong_boundary_and_unassignable_rows_are_retained(kind, boundaries, boundary):
    subject = _observation(kind)
    rows = (
        _assessment(subject, "authentication", "NOT_ESTABLISHED"),
        _assessment(None, boundary),
        _assessment(subject, None),
    )
    result = _accounting(Submission((subject,), rows), boundary)
    obligation, = result.obligations
    assert result.status == "FAIL"
    assert obligation.status == "UNACCOUNTED"
    assert obligation.attempt_positions == ()
    assert obligation.wrong_subject_positions == (1,)
    assert obligation.wrong_boundary_positions == (0, 2)
    assert obligation.malformed_positions == ()
    assert result.malformed_positions == (1, 2)
    assert obligation.submitted_disposition is None
    assert result.submission.assessments == rows


@pytest.mark.parametrize("kind,boundaries", _FAMILY_CASES)
def test_authentication_unknown_does_not_remove_source_obligations(kind, boundaries):
    subject = _observation(kind)
    authentication = _assessment(subject, "authentication", "NOT_ESTABLISHED")
    omitted = Submission((subject,), (authentication,))
    explicit_unknowns = Submission(
        (subject,), (authentication,) + _rows(subject, boundaries, "NOT_ESTABLISHED"),
    )
    for index, boundary in enumerate(boundaries):
        missing = _accounting(omitted, boundary)
        missing_obligation, = missing.obligations
        assert missing.status == "FAIL"
        assert missing_obligation.subject is subject
        assert missing_obligation.status == "UNACCOUNTED"
        assert missing_obligation.wrong_boundary_positions == (0,)
        accounted = _accounting(explicit_unknowns, boundary)
        accounted_obligation, = accounted.obligations
        assert accounted.status == "PASS"
        assert accounted_obligation.subject is subject
        assert accounted_obligation.status == "ACCOUNTED"
        assert accounted_obligation.attempt_positions == (index + 1,)
        assert accounted_obligation.submitted_disposition == "NOT_ESTABLISHED"
    assert omitted.observations == explicit_unknowns.observations == (subject,)
    assert explicit_unknowns.assessments[0] is authentication


@pytest.mark.parametrize("kind,boundaries", _FAMILY_CASES)
def test_source_population_and_attempt_membership_are_frozen_before_accounting(kind, boundaries):
    first, second = _observation(kind), _observation(kind, "occurrence-2")
    records = [first, second]
    rows = list(_rows(first, boundaries))
    submission = Submission(records, rows)
    records.clear()
    rows.extend(_rows(second, boundaries))
    assert submission.observations == (first, second)
    assert submission.assessments == _rows(first, boundaries)
    for boundary in boundaries:
        result = _accounting(submission, boundary)
        accounted, missing = result.obligations
        assert result.status == "FAIL"
        assert accounted.subject is first
        assert accounted.status == "ACCOUNTED"
        assert missing.subject is second
        assert missing.status == "UNACCOUNTED"
        assert missing.attempt_positions == ()
    with pytest.raises(FrozenInstanceError):
        submission.observations = ()
    with pytest.raises(FrozenInstanceError):
        submission.assessments = ()


@pytest.mark.parametrize("supporting", [False, True], ids=["EMPTY", "LISTEN-ACK"])
@pytest.mark.parametrize("with_rows", [False, True], ids=["NO-ROWS", "WITH-ROWS"])
def test_no_source_occurrence_is_outside_not_vacuous_pass(supporting, with_rows):
    listen = _observation("subscription_listen_request_observed", "listen")
    acknowledged = _observation("subscription_acknowledged_notification_observed", "ack")
    records = (listen, acknowledged) if supporting else ()
    rows = (
        _rows(listen, CB_BOUNDARIES) + _rows(acknowledged, CAN_BOUNDARIES)
        if with_rows else ()
    )
    submission = Submission(records, rows)
    results = account_slice(submission)
    assert len(results) == 14
    for result in results:
        assert result.status == "OUTSIDE_BOUNDED_CONTRACT"
        assert result.obligations == ()
        assert result.submission is submission
        assert result.submission.observations == records
        assert result.submission.assessments == rows
