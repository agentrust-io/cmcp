"""Registry-level gates for durable execution correlation (issue #565)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from cmcp_runtime.execution import (
    AdmissionStatus,
    Disposition,
    ExecutionStateError,
    valid_execution_id,
)
from cmcp_runtime.execution.registry import ExecutionRegistry


@pytest.mark.parametrize(
    "value,ok",
    [
        ("exec-1", True),
        ("exec-café", False),  # non-ASCII
        ("a" * 200, True),
        ("a" * 201, False),
        ("", False),
        ("has space", False),
        ("line\nbreak", False),
        ("tab\tsep", False),
        ("urn:example:execution:42", True),
    ],
)
def test_valid_execution_id_bounds(value, ok):
    assert valid_execution_id(value) is ok

AGENT = "spiffe://example.org/agent-a"
OTHER_AGENT = "spiffe://example.org/agent-b"
BINDING_A = "sha256:aaaa"
BINDING_B = "sha256:bbbb"


def _registry(tmp_path: Path, name: str = "executions.db") -> ExecutionRegistry:
    return ExecutionRegistry(tmp_path / name)


def _admit(reg: ExecutionRegistry, *, agent: str = AGENT, execution_id: str = "exec-1",
           binding: str = BINDING_A, call_id: str = "call-1"):
    return reg.admit(
        agent_identity=agent,
        execution_id=execution_id,
        action_binding=binding,
        call_id=call_id,
    )


def test_first_admit_reserves_and_returns_binding(tmp_path):
    reg = _registry(tmp_path)
    result = _admit(reg)
    assert result.status is AdmissionStatus.ADMITTED
    assert result.admitted
    assert result.action_binding == BINDING_A


def test_same_identity_same_binding_is_replay_not_a_second_reservation(tmp_path):
    reg = _registry(tmp_path)
    first = _admit(reg, call_id="call-1")
    second = _admit(reg, call_id="call-2")
    assert first.admitted
    assert not second.admitted
    assert second.status is AdmissionStatus.REPLAY_IN_FLIGHT
    # The binding still resolves so the refusal can be audited under it.
    assert second.action_binding == first.action_binding


def test_changed_binding_same_execution_id_is_a_collision(tmp_path):
    reg = _registry(tmp_path)
    _admit(reg, binding=BINDING_A)
    collided = _admit(reg, binding=BINDING_B)
    assert collided.status is AdmissionStatus.COLLISION_CHANGED_BINDING
    assert not collided.admitted


def test_different_identities_do_not_collide(tmp_path):
    reg = _registry(tmp_path)
    a = _admit(reg, agent=AGENT)
    b = _admit(reg, agent=OTHER_AGENT)
    assert a.admitted and b.admitted


def test_terminal_completed_is_not_replayable(tmp_path):
    reg = _registry(tmp_path)
    first = _admit(reg)
    reg.finalize(
        agent_identity=AGENT, execution_id="exec-1",
        disposition=Disposition.COMPLETED, terminal_audit_entry_hash="hash-1",
    )
    replay = _admit(reg, call_id="call-2")
    assert replay.status is AdmissionStatus.REPLAY_TERMINAL
    assert not replay.admitted
    assert replay.action_binding == first.action_binding


def test_outcome_unknown_is_not_replayable(tmp_path):
    reg = _registry(tmp_path)
    _admit(reg)
    reg.finalize(
        agent_identity=AGENT, execution_id="exec-1",
        disposition=Disposition.OUTCOME_UNKNOWN, terminal_audit_entry_hash="hash-1",
    )
    replay = _admit(reg, call_id="call-2")
    assert replay.status is AdmissionStatus.REPLAY_OUTCOME_UNKNOWN
    assert not replay.admitted


def test_finalize_before_admit_raises(tmp_path):
    reg = _registry(tmp_path)
    with pytest.raises(ExecutionStateError):
        reg.finalize(
            agent_identity=AGENT, execution_id="ghost",
            disposition=Disposition.COMPLETED, terminal_audit_entry_hash="h",
        )


def test_double_finalize_is_ignored(tmp_path):
    reg = _registry(tmp_path)
    _admit(reg)
    reg.finalize(
        agent_identity=AGENT, execution_id="exec-1",
        disposition=Disposition.COMPLETED, terminal_audit_entry_hash="hash-1",
    )
    # A retry of the caller's terminal path must not raise after the effect.
    reg.finalize(
        agent_identity=AGENT, execution_id="exec-1",
        disposition=Disposition.OUTCOME_UNKNOWN, terminal_audit_entry_hash="hash-2",
    )
    row = reg._conn.execute(
        "SELECT state, terminal_audit_entry_hash FROM executions "
        "WHERE agent_identity=? AND execution_id=?",
        (AGENT, "exec-1"),
    ).fetchone()
    assert row == ("completed", "hash-1")


def test_restart_recovery_seals_in_flight_as_outcome_unknown(tmp_path):
    reg = _registry(tmp_path)
    _admit(reg, execution_id="exec-live")
    _admit(reg, execution_id="exec-done", call_id="c2")
    reg.finalize(
        agent_identity=AGENT, execution_id="exec-done",
        disposition=Disposition.COMPLETED, terminal_audit_entry_hash="h",
    )
    reg.close()

    restarted = _registry(tmp_path)
    sealed = restarted.recover()
    assert sealed == 1
    replay_live = restarted.admit(
        agent_identity=AGENT, execution_id="exec-live",
        action_binding=BINDING_A, call_id="c3",
    )
    assert replay_live.status is AdmissionStatus.REPLAY_OUTCOME_UNKNOWN
    assert not replay_live.admitted


class _InterceptConn:
    """Forwards to a real sqlite3.Connection, letting a test intervene per statement."""

    def __init__(self, real: sqlite3.Connection, on_execute) -> None:
        self._real = real
        self._on_execute = on_execute

    def execute(self, sql: str, *args):
        self._on_execute(self._real, sql, args)
        return self._real.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_injected_persistence_failure_during_finalize_fails_closed(tmp_path):
    reg = _registry(tmp_path)
    _admit(reg, execution_id="exec-x")

    def fail_the_update(_real, sql, _args):
        if sql.startswith("UPDATE executions SET state="):
            raise sqlite3.OperationalError("disk I/O error (injected)")

    reg._conn = _InterceptConn(reg._conn, fail_the_update)
    with pytest.raises(sqlite3.OperationalError):
        reg.finalize(
            agent_identity=AGENT, execution_id="exec-x",
            disposition=Disposition.COMPLETED, terminal_audit_entry_hash="h",
        )
    reg._conn = reg._conn._real
    reg.close()

    # The row is still in_flight on disk; recovery seals it and it never
    # admits another invocation.
    restarted = _registry(tmp_path)
    assert restarted.recover() == 1
    replay = restarted.admit(
        agent_identity=AGENT, execution_id="exec-x",
        action_binding=BINDING_A, call_id="c9",
    )
    assert replay.status is AdmissionStatus.REPLAY_OUTCOME_UNKNOWN


def test_injected_persistence_failure_during_recovery_rolls_back(tmp_path):
    reg = _registry(tmp_path)
    _admit(reg, execution_id="exec-recover")

    def fail_the_recovery_update(_real, sql, _args):
        if sql.startswith("UPDATE executions SET state='outcome_unknown'"):
            raise sqlite3.OperationalError("disk I/O error (injected)")

    reg._conn = _InterceptConn(reg._conn, fail_the_recovery_update)
    with pytest.raises(sqlite3.OperationalError):
        reg.recover()
    reg._conn = reg._conn._real

    row = reg._conn.execute(
        "SELECT state FROM executions WHERE execution_id='exec-recover'"
    ).fetchone()
    assert row == ("in_flight",)
    reg.close()


def test_injected_persistence_failure_during_admission_rolls_back(tmp_path):
    reg = _registry(tmp_path)

    def fail_the_insert(_real, sql, _args):
        if sql.startswith("INSERT INTO executions"):
            raise sqlite3.OperationalError("disk I/O error (injected)")

    reg._conn = _InterceptConn(reg._conn, fail_the_insert)
    with pytest.raises(sqlite3.OperationalError):
        _admit(reg, execution_id="exec-admit")
    reg._conn = reg._conn._real

    assert reg._conn.execute("SELECT COUNT(*) FROM executions").fetchone() == (0,)
    assert _admit(reg, execution_id="exec-admit").status is AdmissionStatus.ADMITTED
    reg.close()


def test_concurrent_admits_of_one_key_reserve_exactly_once(tmp_path):
    """Two threads racing to admit the same key: exactly one is ADMITTED, the
    other is classified as a replay. No double reservation, no exception."""
    import threading

    reg = _registry(tmp_path)
    barrier = threading.Barrier(8)
    results: list = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        barrier.wait()
        r = reg.admit(
            agent_identity=AGENT, execution_id="exec-hot",
            action_binding=BINDING_A, call_id=f"c{i}",
        )
        with lock:
            results.append(r.status)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(AdmissionStatus.ADMITTED) == 1
    assert all(
        s in (AdmissionStatus.ADMITTED, AdmissionStatus.REPLAY_IN_FLIGHT) for s in results
    )
    rows = reg._conn.execute(
        "SELECT COUNT(*) FROM executions WHERE execution_id='exec-hot'"
    ).fetchone()
    assert rows == (1,)


def test_separate_registry_connections_serialize_same_key(tmp_path):
    """BEGIN IMMEDIATE serializes two registry instances on one database file."""
    import threading

    first = _registry(tmp_path)
    second = _registry(tmp_path)
    barrier = threading.Barrier(2)
    results: list = []
    lock = threading.Lock()

    def worker(reg: ExecutionRegistry, call_id: str) -> None:
        barrier.wait()
        result = _admit(reg, execution_id="exec-shared", call_id=call_id)
        with lock:
            results.append(result.status)

    threads = [
        threading.Thread(target=worker, args=(first, "call-a")),
        threading.Thread(target=worker, args=(second, "call-b")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(AdmissionStatus.ADMITTED) == 1
    assert results.count(AdmissionStatus.REPLAY_IN_FLIGHT) == 1
    first.close()
    second.close()
