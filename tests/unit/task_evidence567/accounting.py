"""Non-normative, test-only AM-12/13 submission accounting for cMCP #567.

These local containers are not wire schemas or runtime evidence verifiers.
Record references are exact in-memory observation handles: neither task ID nor
equal field text binds an assessment to an occurrence. A declared tuple fixes
membership before accounting; no history selector or supersession is implied.
An eligible submitted disposition is counted, not independently verified here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, eq=False)
class Observation:
    """An already identified record instance, conditional on fixture provenance."""

    record_id: str
    kind: str
    task_id: str
    requires_error_binding: bool = False


@dataclass(frozen=True)
class Assessment:
    """A submitted attempt, including malformed attempts; never deduplicated."""

    assessment_id: str | None
    subject: Observation | None
    boundary: str | None
    disposition: str | None
    evaluator: str | None = "fixture-evaluator"
    timestamp: str | None = "2030-01-01T00:00:00Z"
    evidence_basis: tuple[str, ...] | None = ("fixture-evidence",)


@dataclass(frozen=True)
class Submission:
    """Complete, predeclared local evaluation view, not computed from outcomes."""

    observations: tuple[Observation, ...]
    assessments: tuple[Assessment, ...]

    def __post_init__(self) -> None:
        # Copy membership even when callers supplied mutable input sequences.
        object.__setattr__(self, "observations", tuple(self.observations))
        object.__setattr__(self, "assessments", tuple(self.assessments))


@dataclass(frozen=True)
class ObligationAccounting:
    subject: Observation
    boundary: str
    status: str
    attempt_positions: tuple[int, ...]
    malformed_positions: tuple[int, ...]
    wrong_subject_positions: tuple[int, ...]
    wrong_boundary_positions: tuple[int, ...]
    submitted_disposition: str | None


@dataclass(frozen=True)
class Accounting:
    status: str
    submission: Submission
    obligations: tuple[ObligationAccounting, ...]
    malformed_positions: tuple[int, ...]


def eligible_assessment(row: Assessment) -> bool:
    """Only local shape eligibility, not proof of the row's relation claim."""
    return (
        isinstance(row.assessment_id, str)
        and bool(row.assessment_id)
        and isinstance(row.subject, Observation)
        and isinstance(row.boundary, str)
        and bool(row.boundary)
        and isinstance(row.disposition, str)
        and row.disposition in {"ESTABLISHED", "NOT_ESTABLISHED", "VERIFIED_CONTRADICTION"}
        and isinstance(row.evaluator, str)
        and bool(row.evaluator)
        and isinstance(row.evidence_basis, tuple)
        and all(isinstance(item, str) for item in row.evidence_basis)
    )


def _account(
    submission: Submission, subjects: tuple[Observation, ...], boundary: str
) -> Accounting:
    malformed = tuple(
        index for index, row in enumerate(submission.assessments)
        if not eligible_assessment(row)
    )
    obligations = []
    for subject in subjects:
        # Count every targeted attempt BEFORE testing shape eligibility.
        positions = tuple(
            index for index, row in enumerate(submission.assessments)
            if row.subject is subject and row.boundary == boundary
        )
        malformed_here = tuple(index for index in positions if index in malformed)
        if len(positions) == 0:
            status = "UNACCOUNTED"
        elif len(positions) > 1:
            status = "AMBIGUOUS_ACCOUNTING"
        elif malformed_here:
            status = "MALFORMED_ACCOUNTING"
        else:
            status = "ACCOUNTED"
        obligations.append(ObligationAccounting(
            subject=subject,
            boundary=boundary,
            status=status,
            attempt_positions=positions,
            malformed_positions=malformed_here,
            wrong_subject_positions=tuple(
                index for index, row in enumerate(submission.assessments)
                if row.boundary == boundary and row.subject is not subject
            ),
            wrong_boundary_positions=tuple(
                index for index, row in enumerate(submission.assessments)
                if row.subject is subject and row.boundary != boundary
            ),
            submitted_disposition=(
                submission.assessments[positions[0]].disposition
                if status == "ACCOUNTED" else None
            ),
        ))
    if not subjects:
        status = "OUTSIDE_BOUNDED_CONTRACT"
    else:
        status = "PASS" if all(item.status == "ACCOUNTED" for item in obligations) else "FAIL"
    return Accounting(status, submission, tuple(obligations), malformed)


def account_execution(submission: Submission) -> Accounting:
    """AM-12: every creation observation triggers, irrespective of assessments."""
    subjects = tuple(
        record for record in submission.observations
        if record.kind == "task_creation_result_observed"
    )
    return _account(submission, subjects, "execution_correlation")


def account_protocol_error(submission: Submission) -> Accounting:
    """AM-13: only observations whose applicable profile requires the relation."""
    subjects = tuple(
        record for record in submission.observations
        if record.kind == "protocol_error_response_observed" and record.requires_error_binding
    )
    return _account(submission, subjects, "protocol_error_binding")
