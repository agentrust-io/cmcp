"""Tests for session sensitivity state machine (issue #84)."""

from __future__ import annotations

import asyncio

import pytest

from cmcp_runtime.session.state import SENSITIVITY_ORDER, SessionState, _max_sensitivity

# ── _max_sensitivity ──────────────────────────────────────────────────────────

def test_max_sensitivity_prefers_higher():
    assert _max_sensitivity("public", "pii") == "pii"
    assert _max_sensitivity("pii", "public") == "pii"
    assert _max_sensitivity("pii", "confidential") == "confidential"
    assert _max_sensitivity("confidential", "hipaa_phi") == "hipaa_phi"


def test_max_sensitivity_equal_returns_first():
    # hipaa_phi and mnpi are equal level
    assert _max_sensitivity("hipaa_phi", "mnpi") == "hipaa_phi"


def test_sensitivity_order_monotonic():
    levels = ["public", "pii", "confidential"]
    for i in range(len(levels) - 1):
        assert SENSITIVITY_ORDER[levels[i]] < SENSITIVITY_ORDER[levels[i + 1]]


# ── SessionState ──────────────────────────────────────────────────────────────

def test_initial_sensitivity_is_public():
    state = SessionState(session_id="s1")
    assert state.max_sensitivity == "public"


def test_update_raises_sensitivity():
    state = SessionState(session_id="s1")
    state.update_from_inspection("c1", sensitivity_tags=["pii"], injection_detected=False, response_allowed=True)
    assert state.max_sensitivity == "pii"


def test_update_is_monotonically_increasing():
    """Sensitivity never decreases automatically."""
    state = SessionState(session_id="s1")
    state.update_from_inspection("c1", ["hipaa_phi"], False, True)
    state.update_from_inspection("c2", ["public"], False, True)
    assert state.max_sensitivity == "hipaa_phi"


def test_update_records_raising_call():
    state = SessionState(session_id="s1")
    state.update_from_inspection("c1", ["pii"], False, True)
    assert state.sensitivity_raised_by_call == "c1"
    assert state.sensitivity_raised_at is not None


def test_update_no_raise_keeps_none():
    state = SessionState(session_id="s1")
    state.update_from_inspection("c1", [], False, True)
    assert state.sensitivity_raised_by_call is None


def test_update_records_injection_event():
    state = SessionState(session_id="s1")
    state.update_from_inspection("c1", [], injection_detected=True, response_allowed=False)
    assert len(state.injection_events) == 1
    assert state.injection_events[0].call_id == "c1"


def test_update_raises_sensitivity_on_denied_response():
    """Denied high-sensitivity response still raises session sensitivity."""
    state = SessionState(session_id="s1")
    state.update_from_inspection("c1", ["mnpi"], injection_detected=False, response_allowed=False)
    assert state.max_sensitivity == "mnpi"


def test_multiple_updates_accumulate_injection_events():
    state = SessionState(session_id="s1")
    state.update_from_inspection("c1", [], True, False)
    state.update_from_inspection("c2", [], True, False)
    assert len(state.injection_events) == 2


def test_reset_lowers_sensitivity():
    state = SessionState(session_id="s1")
    state.update_from_inspection("c1", ["hipaa_phi"], False, True)
    assert state.max_sensitivity == "hipaa_phi"
    state.reset(reason="task switch", authorized_by="operator@example.com")
    assert state.max_sensitivity == "public"


def test_reset_generates_new_session_id():
    state = SessionState(session_id="s1")
    prev, new = state.reset(reason="test", authorized_by="op")
    assert prev == "s1"
    assert new != "s1"
    assert state.session_id == new


def test_reset_increments_reset_count():
    state = SessionState(session_id="s1")
    state.reset(reason="r1", authorized_by="op")
    state.reset(reason="r2", authorized_by="op")
    assert state.reset_count == 2


def test_update_highest_tag_wins_per_update():
    state = SessionState(session_id="s1")
    state.update_from_inspection("c1", ["pii", "mnpi", "confidential"], False, True)
    assert state.max_sensitivity in ("mnpi", "hipaa_phi", "trade_secret")
    assert SENSITIVITY_ORDER[state.max_sensitivity] == 3


# ── AUTH-002: asyncio.Lock guards concurrent mutations ────────────────────────

def test_session_state_has_mutation_lock():
    """AUTH-002: SessionState must expose an asyncio.Lock for concurrent-mutation protection."""
    import asyncio
    state = SessionState(session_id="s-lock")
    assert isinstance(state.mutation_lock, asyncio.Lock)


@pytest.mark.asyncio
async def test_concurrent_update_and_reset_do_not_corrupt_state():
    """AUTH-002: concurrent update_from_inspection and reset must not leave state inconsistent."""
    state = SessionState(session_id="s-concurrent")

    async def _update():
        async with state.mutation_lock:
            state.update_from_inspection("c1", ["pii"], False, True)

    async def _reset():
        async with state.mutation_lock:
            state.reset(reason="concurrent reset", authorized_by="test")

    # Run 10 interleaved updates and resets; state must be valid throughout.
    tasks = [_update() for _ in range(5)] + [_reset() for _ in range(5)]
    await asyncio.gather(*tasks)
    assert state.max_sensitivity in SENSITIVITY_ORDER


# ── AUTH-001: attestation upgrade rotates session token ───────────────────────

def test_upgrade_attestation_rotates_session_id():
    """AUTH-001: session token (session_id) must be rotated on attestation upgrade."""
    state = SessionState(session_id="s1")
    old_id, new_id = state.upgrade_attestation()
    assert old_id == "s1"
    assert new_id != "s1"
    assert state.session_id == new_id


def test_upgrade_attestation_clears_stale_flag():
    state = SessionState(session_id="s1", attestation_stale=True)
    state.upgrade_attestation()
    assert state.attestation_stale is False


def test_upgrade_attestation_preserves_sensitivity():
    """Unlike reset(), upgrade_attestation() preserves accumulated session sensitivity."""
    state = SessionState(session_id="s1")
    state.update_from_inspection("c1", ["hipaa_phi"], False, True)
    assert state.max_sensitivity == "hipaa_phi"
    state.upgrade_attestation()
    assert state.max_sensitivity == "hipaa_phi"


def test_upgrade_attestation_preserves_injection_events():
    state = SessionState(session_id="s1")
    state.update_from_inspection("c1", [], injection_detected=True, response_allowed=False)
    state.upgrade_attestation()
    assert len(state.injection_events) == 1


def test_upgrade_attestation_does_not_increment_reset_count():
    state = SessionState(session_id="s1")
    state.upgrade_attestation()
    assert state.reset_count == 0
