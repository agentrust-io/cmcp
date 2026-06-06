"""Tests for CallLog and temporal adjacency tracking (issue #94)."""

from __future__ import annotations

from datetime import UTC, datetime

from cmcp_gateway.session.call_log import CallLog, CallRecord


def _rec(tool: str) -> CallRecord:
    return CallRecord(
        tool_name=tool,
        called_at=datetime.now(UTC),
        duration_ms=1.0,
        allowed=True,
        sensitivity_raised=False,
        stage_results={"policy": "allow"},
    )


# ── empty log ─────────────────────────────────────────────────────────────────

def test_empty_adjacent_pairs():
    log = CallLog(session_id="s1")
    assert log.adjacent_pairs() == []


def test_empty_suspicious_sequence():
    log = CallLog(session_id="s1")
    assert log.suspicious_sequence() is False


# ── single entry ──────────────────────────────────────────────────────────────

def test_single_entry_tools_called():
    log = CallLog(session_id="s1")
    log.record(_rec("tool.a"))
    assert log.tools_called() == ["tool.a"]


def test_single_entry_not_suspicious():
    log = CallLog(session_id="s1")
    log.record(_rec("tool.a"))
    assert log.suspicious_sequence() is False


# ── alternating tools ─────────────────────────────────────────────────────────

def test_alternating_not_suspicious():
    log = CallLog(session_id="s1")
    for tool in ["a", "b", "a", "b", "a", "b"]:
        log.record(_rec(tool))
    assert log.suspicious_sequence() is False


# ── same tool 4x (threshold=3): suspicious ────────────────────────────────────

def test_same_tool_four_times_suspicious():
    log = CallLog(session_id="s1")
    for _ in range(4):
        log.record(_rec("tool.x"))
    assert log.suspicious_sequence(threshold=3) is True


# ── same tool exactly 3x then different: not suspicious ───────────────────────

def test_same_tool_three_then_different_not_suspicious():
    log = CallLog(session_id="s1")
    for _ in range(3):
        log.record(_rec("tool.x"))
    log.record(_rec("tool.y"))
    assert log.suspicious_sequence(threshold=3) is False


# ── recent(n) returns last n ──────────────────────────────────────────────────

def test_recent_returns_last_n():
    log = CallLog(session_id="s1")
    tools = [f"tool.{i}" for i in range(10)]
    for t in tools:
        log.record(_rec(t))
    recent = log.recent(5)
    assert len(recent) == 5
    assert [r.tool_name for r in recent] == tools[-5:]


def test_recent_fewer_than_n():
    log = CallLog(session_id="s1")
    log.record(_rec("tool.a"))
    log.record(_rec("tool.b"))
    assert len(log.recent(10)) == 2


# ── tools_called preserves first-seen order ───────────────────────────────────

def test_tools_called_first_seen_order():
    log = CallLog(session_id="s1")
    for tool in ["c", "a", "b", "a", "c", "d"]:
        log.record(_rec(tool))
    assert log.tools_called() == ["c", "a", "b", "d"]


# ── adjacent_pairs ────────────────────────────────────────────────────────────

def test_adjacent_pairs_single():
    log = CallLog(session_id="s1")
    log.record(_rec("a"))
    assert log.adjacent_pairs() == []


def test_adjacent_pairs_multiple():
    log = CallLog(session_id="s1")
    for t in ["a", "b", "c"]:
        log.record(_rec(t))
    assert log.adjacent_pairs() == [("a", "b"), ("b", "c")]


# ── suspicious resets after different tool breaks run ─────────────────────────

def test_suspicious_reset_mid_sequence():
    log = CallLog(session_id="s1")
    for _ in range(4):
        log.record(_rec("x"))   # suspicious after 4th
    assert log.suspicious_sequence(threshold=3) is True
    log.record(_rec("y"))       # breaks run
    log.record(_rec("x"))
    # now x has run of 1 — still overall suspicious because earlier 4-run is in history
    assert log.suspicious_sequence(threshold=3) is True
