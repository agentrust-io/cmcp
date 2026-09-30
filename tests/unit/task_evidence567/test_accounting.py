"""AM-12/13: frozen submission membership, exact subjects and honest unknowns.

CASE_IDs are pytest parameter IDs or named in test docstrings. EXACT EVIDENCE
is constructed in each test. TRUST ASSUMPTIONS throughout: the local frozen
observation handles faithfully represent distinct already-identified records;
row eligibility is fixture shape only. BOUNDARY: execution_correlation for
AM-12, profile-required protocol_error_binding for AM-13. EXPECTED results are
literal assertions, never passed into the accounting helper. CLAIM LIMIT:
accounting only, not verified execution/error binding, runtime completeness,
public schema, policy profile design, or historical supersession.
"""

from dataclasses import FrozenInstanceError, replace

import pytest

from .accounting import (
    Assessment,
    Observation,
    Submission,
    account_execution,
    account_protocol_error,
)


def creation(record_id="creation-1"):
    return Observation(record_id, "task_creation_result_observed", "same-task")


def assessment(subject, **changes):
    return replace(Assessment("assessment-1", subject, "execution_correlation", "ESTABLISHED"), **changes)


@pytest.mark.parametrize("disposition", ["ESTABLISHED", "NOT_ESTABLISHED"], ids=["AM12-POSITIVE", "AM12-NE"])
def test_exact_one_accounts_without_upgrading_disposition(disposition):
    subject = creation()
    row = assessment(subject, disposition=disposition)
    result = account_execution(Submission((subject,), (row,)))
    assert result.status == "PASS"
    assert result.obligations[0].status == "ACCOUNTED"
    assert result.obligations[0].attempt_positions == (0,)
    assert result.obligations[0].submitted_disposition == disposition
    assert result.submission.assessments == (row,)


def test_omitted_obligation_is_not_synthesized_as_unknown():
    """AM12-OMITTED: the creation, not a supplied row, triggers accounting."""
    subject = creation()
    result = account_execution(Submission((subject,), ()))
    assert result.status == "FAIL"
    assert result.obligations[0].status == "UNACCOUNTED"
    assert result.obligations[0].submitted_disposition is None
    assert result.submission.assessments == ()


def test_wrong_subject_does_not_discharge_another_creation():
    """AM12-WRONG-SUBJECT: both creation records share a task, not an occurrence."""
    required, other = creation(), creation("creation-2")
    row = assessment(other)
    result = account_execution(Submission((required, other), (row,)))
    assert result.status == "FAIL"
    missing, accounted = result.obligations
    assert missing.subject is required
    assert missing.status == "UNACCOUNTED"
    assert missing.wrong_subject_positions == (0,)
    assert missing.submitted_disposition is None
    assert accounted.subject is other
    assert accounted.status == "ACCOUNTED"
    assert result.submission.assessments == (row,)


def test_equal_record_fields_do_not_forge_an_exact_subject():
    """AM12-EXACT-HANDLE: copied ID/task/kind text is not the declared record."""
    required, different_instance = creation(), creation()
    row = assessment(different_instance)
    result = account_execution(Submission((required,), (row,)))
    assert result.status == "FAIL"
    assert result.obligations[0].status == "UNACCOUNTED"
    assert result.obligations[0].wrong_subject_positions == (0,)


@pytest.mark.parametrize("changes", [
    {},
    {"assessment_id": "other-id"},
    {"timestamp": "2030-01-02T00:00:00Z"},
    {"evaluator": "other-evaluator"},
    {"evidence_basis": ("other-basis",)},
], ids=["AM12-DUPLICATE-SAME", "AM12-DUPLICATE-ID", "AM12-DUPLICATE-TIME", "AM12-DUPLICATE-EVALUATOR", "AM12-DUPLICATE-BASIS"])
def test_duplicates_remain_ambiguous_in_one_submission(changes):
    subject = creation()
    row = assessment(subject)
    rows = (row, replace(row, **changes))
    result = account_execution(Submission((subject,), rows))
    assert result.status == "FAIL"
    assert result.obligations[0].status == "AMBIGUOUS_ACCOUNTING"
    assert result.obligations[0].attempt_positions == (0, 1)
    assert result.obligations[0].submitted_disposition is None
    assert result.submission.assessments == rows
    assert len(result.submission.assessments) == 2


@pytest.mark.parametrize("changes", [
    {"assessment_id": None},
    {"disposition": None},
    {"disposition": "MADE_UP"},
    {"evaluator": None},
    {"evidence_basis": None},
], ids=["AM12-MALFORMED-ID", "AM12-MALFORMED-MISSING-DISPOSITION", "AM12-MALFORMED-DISPOSITION", "AM12-MALFORMED-EVALUATOR", "AM12-MALFORMED-BASIS"])
def test_malformed_targeted_attempt_is_visible(changes):
    subject = creation()
    row = assessment(subject, **changes)
    result = account_execution(Submission((subject,), (row,)))
    assert result.status == "FAIL"
    assert result.obligations[0].status == "MALFORMED_ACCOUNTING"
    assert result.obligations[0].attempt_positions == (0,)
    assert result.obligations[0].malformed_positions == (0,)
    assert result.malformed_positions == (0,)
    assert result.submission.assessments == (row,)


@pytest.mark.parametrize("malformed_first", [False, True], ids=["AM12-VALID-PLUS-MALFORMED-DUPLICATE", "AM12-MALFORMED-PLUS-VALID-DUPLICATE"])
def test_valid_plus_malformed_duplicate_cannot_be_filtered_to_pass(malformed_first):
    subject = creation()
    valid = assessment(subject)
    malformed = replace(valid, disposition=None)
    rows = (malformed, valid) if malformed_first else (valid, malformed)
    result = account_execution(Submission((subject,), rows))
    assert result.status == "FAIL"
    assert result.obligations[0].status == "AMBIGUOUS_ACCOUNTING"
    assert result.obligations[0].attempt_positions == (0, 1)
    assert result.obligations[0].malformed_positions == ((0,) if malformed_first else (1,))
    assert result.submission.assessments == rows
    assert result.obligations[0].submitted_disposition is None


def test_wrong_boundary_does_not_discharge_execution_accounting():
    """AM12-WRONG-BOUNDARY: exact subject with authentication is insufficient."""
    subject = creation()
    wrong = assessment(subject, boundary="authentication")
    result = account_execution(Submission((subject,), (wrong,)))
    assert result.status == "FAIL"
    assert result.obligations[0].status == "UNACCOUNTED"
    assert result.obligations[0].wrong_boundary_positions == (0,)
    assert result.submission.assessments == (wrong,)


def test_other_boundary_does_not_duplicate_an_accounted_obligation():
    """AM12-BOUNDARY-TWIN: preserve unrelated assessment without conflating it."""
    subject = creation()
    rows = (assessment(subject), assessment(subject, boundary="authentication"))
    result = account_execution(Submission((subject,), rows))
    assert result.status == "PASS"
    assert result.obligations[0].attempt_positions == (0,)
    assert result.obligations[0].wrong_boundary_positions == (1,)
    assert result.submission.assessments == rows


def test_history_outside_submission_is_not_silently_merged_or_superseded():
    """AM12-EXPLICIT-VIEW: membership, not timestamp, separates submitted history."""
    subject = creation()
    historical = assessment(subject, timestamp="2040-01-01T00:00:00Z")
    current = assessment(subject, timestamp="2030-01-01T00:00:00Z")
    history = Submission((subject,), (historical,))
    view = Submission((subject,), (current,))
    assert account_execution(view).status == "PASS"
    assert history.assessments == (historical,)
    assert view.assessments == (current,)
    both = account_execution(Submission((subject,), (historical, current)))
    assert both.status == "FAIL"
    assert both.obligations[0].status == "AMBIGUOUS_ACCOUNTING"


def test_submission_membership_is_frozen_before_check():
    """AM12-PREDECLARED: later edits to authoring lists cannot change the view."""
    subject = creation()
    records, rows = [subject], [assessment(subject)]
    submission = Submission(records, rows)
    records.clear()
    rows.append(replace(rows[0], disposition=None))
    first = account_execution(submission)
    assert first.status == "PASS"
    assert len(submission.observations) == len(submission.assessments) == 1
    with pytest.raises(FrozenInstanceError):
        submission.assessments = ()
    assert account_execution(submission) == first


@pytest.mark.parametrize("with_assessment", [False, True], ids=["AM12-OUTSIDE-EMPTY", "AM12-OUTSIDE-WITH-ROW"])
def test_no_creation_observation_is_outside_not_vacuous_pass(with_assessment):
    subject = Observation("ack", "protocol_acknowledgement_observed", "same-task")
    rows = (assessment(subject),) if with_assessment else ()
    result = account_execution(Submission((subject,), rows))
    assert result.status == "OUTSIDE_BOUNDED_CONTRACT"
    assert result.obligations == ()
    assert result.submission.assessments == rows


def test_every_creation_triggers_even_when_assessments_cover_only_one():
    """AM12-ALL-TRIGGERS: a supplied assessment cannot determine population."""
    first, second = creation(), creation("creation-2")
    result = account_execution(Submission((first, second), (assessment(first),)))
    assert result.status == "FAIL"
    assert [item.status for item in result.obligations] == ["ACCOUNTED", "UNACCOUNTED"]


def test_am13_explicit_unknown_is_accounted_but_omission_is_incomplete():
    """AM13-NE/OMITTED: same error record, fixed required profile, one-row delta."""
    subject = Observation("error", "protocol_error_response_observed", "same-task", True)
    row = assessment(subject, boundary="protocol_error_binding", disposition="NOT_ESTABLISHED")
    accounted = account_protocol_error(Submission((subject,), (row,)))
    omitted = account_protocol_error(Submission((subject,), ()))
    assert accounted.status == "PASS"
    assert accounted.obligations[0].submitted_disposition == "NOT_ESTABLISHED"
    assert omitted.status == "FAIL"
    assert omitted.obligations[0].status == "UNACCOUNTED"
    assert omitted.obligations[0].submitted_disposition is None
    assert accounted.submission.observations == omitted.submission.observations == (subject,)


def test_am13_other_boundary_or_subject_cannot_discharge_required_error():
    """AM13-BOUND-TWIN: exact profile obligation is not another record/boundary."""
    subject = Observation("error", "protocol_error_response_observed", "same-task", True)
    other = replace(subject, record_id="other-error")
    for row in (
        assessment(subject, boundary="authentication", disposition="NOT_ESTABLISHED"),
        assessment(other, boundary="protocol_error_binding", disposition="NOT_ESTABLISHED"),
    ):
        result = account_protocol_error(Submission((subject,), (row,)))
        assert result.status == "FAIL"
        assert result.obligations[0].status == "UNACCOUNTED"
        assert result.submission.assessments == (row,)


def test_am13_does_not_invent_a_profile_requirement():
    """AM13-OUTSIDE: no profile requirement, so no runtime completeness claim."""
    subject = Observation("error", "protocol_error_response_observed", "same-task", False)
    result = account_protocol_error(Submission((subject,), ()))
    assert result.status == "OUTSIDE_BOUNDED_CONTRACT"
    assert result.obligations == ()
