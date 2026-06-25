"""Tests for Claim 2: session sensitivity state machine properties.

Asserts the compliance gap invariant (per-call policy misses cross-boundary
violations that session-level policy catches) and the monotonic state machine
that produces that gap.
"""

from __future__ import annotations

import pytest

from cmcp_runtime.session.state import SENSITIVITY_ORDER, SessionState

_PHI_LEVEL = SENSITIVITY_ORDER["hipaa_phi"]

# Synthetic 5-call trace: call 1 retrieves PHI; calls 2 and 5 are the
# true violations (external non-BAA after PHI); call 3 is internal (correctly
# permitted); call 4 is a second PHI retrieval (permitted, BAA covered).
_TRACE = [
    # (tool, compliance_domain, requires_baa, response_tags, is_true_violation)
    ("ehr.get_patient",       "hipaa_phi", True,  ["hipaa_phi", "pii"], False),
    ("slack.post_message",    "external",  False, [],                   True),
    ("analytics.run_query",   "internal",  False, ["confidential"],     False),
    ("ehr.get_patient",       "hipaa_phi", True,  ["hipaa_phi", "pii"], False),
    ("external_webhook.post", "external",  False, [],                   True),
]


def _per_call_verdict(compliance_domain: str, requires_baa: bool) -> str:
    """Per-call policy: no session context, all catalog tools individually permitted."""
    return "ALLOW"


def _session_verdict(compliance_domain: str, requires_baa: bool, session_max: str) -> str:
    """Session policy: block external non-BAA calls once session is PHI-contaminated."""
    if SENSITIVITY_ORDER.get(session_max, 0) >= _PHI_LEVEL:
        if compliance_domain == "external" and not requires_baa:
            return "DENY"
    return "ALLOW"


def test_per_call_misses_all_violations():
    """Per-call policy catches 0 of 2 cross-boundary PHI violations."""
    session = SessionState(session_id="test-per-call")
    missed = 0
    for _tool, domain, baa, tags, is_violation in _TRACE:
        verdict = _per_call_verdict(domain, baa)
        if is_violation and verdict == "ALLOW":
            missed += 1
        session.update_from_inspection("c", tags, False, True)
    assert missed == 2, f"Expected per-call to miss 2 violations, missed {missed}"


def test_session_catches_all_violations():
    """Session policy catches 2 of 2 cross-boundary PHI violations."""
    session = SessionState(session_id="test-session")
    caught = 0
    for _tool, domain, baa, tags, is_violation in _TRACE:
        verdict = _session_verdict(domain, baa, session.max_sensitivity)
        if is_violation and verdict == "DENY":
            caught += 1
        session.update_from_inspection("c", tags, False, True)
    assert caught == 2, f"Expected session to catch 2 violations, caught {caught}"


def test_session_max_sensitivity_is_monotonic():
    """session_max_sensitivity must never decrease across any call sequence."""
    session = SessionState(session_id="test-monotonic")
    seen = []
    for _tool, _domain, _baa, tags, _violation in _TRACE:
        session.update_from_inspection("c", tags, False, True)
        seen.append(SENSITIVITY_ORDER.get(session.max_sensitivity, 0))
    for i in range(len(seen) - 1):
        assert seen[i] <= seen[i + 1], (
            f"session_max_sensitivity decreased at step {i + 1}: "
            f"{seen[i]} -> {seen[i + 1]}"
        )


def test_denied_response_still_raises_sensitivity():
    """A denied PHI response still raises session_max_sensitivity (agent knows PHI was touched)."""
    session = SessionState(session_id="test-denied")
    assert session.max_sensitivity == "public"
    session.update_from_inspection("c1", ["hipaa_phi"], False, response_allowed=False)
    assert session.max_sensitivity == "hipaa_phi"


def test_sensitivity_raised_by_call_recorded():
    """sensitivity_raised_by_call records the first call that raised session sensitivity."""
    session = SessionState(session_id="test-raised-by")
    session.update_from_inspection("call-phi-1", ["hipaa_phi"], False, True)
    assert session.sensitivity_raised_by_call == "call-phi-1"
    # A subsequent lower-sensitivity call must NOT overwrite the field.
    session.update_from_inspection("call-clean-2", ["public"], False, True)
    assert session.sensitivity_raised_by_call == "call-phi-1"


def test_operator_reset_clears_sensitivity():
    """operator reset() returns session to 'public' and increments reset_count."""
    session = SessionState(session_id="test-reset")
    session.update_from_inspection("c1", ["hipaa_phi"], False, True)
    assert session.max_sensitivity == "hipaa_phi"
    old_id, new_id = session.reset(reason="test reset", authorized_by="operator@example.com")
    assert session.max_sensitivity == "public"
    assert old_id != new_id
    assert session.reset_count == 1
