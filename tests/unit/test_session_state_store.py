"""Shared, persistent session-sensitivity state.

Covers the two properties that separate a shared store from the in-process
default: the accumulated value survives a restart, and the read-modify-write is
serialised across gateway instances rather than only across coroutines in one.
"""

from __future__ import annotations

import multiprocessing as mp
import sqlite3
import time
from pathlib import Path

import pytest

from cmcp_runtime.session.state import SENSITIVITY_ORDER, SessionState
from cmcp_runtime.session.store import (
    InMemorySessionStateStore,
    SessionStateStore,
    SqliteSessionStateStore,
    StoredSensitivity,
)

# ── Protocol conformance ──────────────────────────────────────────────────────


def test_both_stores_satisfy_the_protocol(tmp_path: Path):
    assert isinstance(InMemorySessionStateStore(), SessionStateStore)
    assert isinstance(SqliteSessionStateStore(tmp_path / "s.db"), SessionStateStore)


def test_only_the_sqlite_store_claims_to_be_shared(tmp_path: Path):
    """A caller must be able to tell, because it cannot from the outside."""
    assert InMemorySessionStateStore().is_shared() is False
    assert SqliteSessionStateStore(tmp_path / "s.db").is_shared() is True


# ── Persistence across a restart ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_accumulated_value_survives_a_restart(tmp_path: Path):
    """The session identifier outlives the process; the value must too."""
    db = tmp_path / "session_state.db"

    store = SqliteSessionStateStore(db)
    state = SessionState(session_id="s-restart", state_store=store)
    await state.hydrate()
    await state.apply_inspection("call-A", ["hipaa_phi"], False, True)
    assert state.max_sensitivity == "hipaa_phi"
    store.close()

    # A new process would open a new store over the same file.
    revived_store = SqliteSessionStateStore(db)
    revived = SessionState(session_id="s-restart", state_store=revived_store)
    assert revived.max_sensitivity == "public"
    adopted = await revived.hydrate()

    assert adopted is True
    assert revived.max_sensitivity == "hipaa_phi"
    assert revived.sensitivity_raised_by_call == "call-A"


@pytest.mark.asyncio
async def test_hydrate_seeds_a_session_the_store_has_not_seen(tmp_path: Path):
    store = SqliteSessionStateStore(tmp_path / "s.db")
    state = SessionState(session_id="s-new", state_store=store)

    assert await state.hydrate() is False
    assert store.load("s-new") == StoredSensitivity("public", None, None, 0)


# ── Sharing across instances ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_second_instance_enforces_what_the_first_accumulated(tmp_path: Path):
    """The ratchet must hold per session, not per gateway instance.

    Without a shared store, an agent that reads sensitive data through instance A
    and egresses through instance B is evaluated by an instance that never saw
    the read.
    """
    store = SqliteSessionStateStore(tmp_path / "s.db")
    a = SessionState(session_id="s-shared", state_store=store)
    b = SessionState(session_id="s-shared", state_store=store)

    await a.apply_inspection("call-read", ["hipaa_phi"], False, True)
    await b.hydrate()

    assert b.max_sensitivity == "hipaa_phi"


@pytest.mark.asyncio
async def test_the_stored_value_only_rises(tmp_path: Path):
    """An instance holding a lower value must not lower the shared one."""
    store = SqliteSessionStateStore(tmp_path / "s.db")
    high = SessionState(session_id="s-mono", state_store=store)
    await high.apply_inspection("call-1", ["hipaa_phi"], False, True)

    low = SessionState(session_id="s-mono", state_store=store)
    await low.apply_inspection("call-2", ["public"], False, True)

    assert store.load("s-mono").max_sensitivity == "hipaa_phi"
    assert low.max_sensitivity == "hipaa_phi"


@pytest.mark.asyncio
async def test_a_reset_on_one_instance_closes_the_session_for_another(tmp_path: Path):
    """A response on instance B must not raise the successor A opened."""
    store = SqliteSessionStateStore(tmp_path / "s.db")
    a = SessionState(session_id="s-reset", state_store=store)
    b = SessionState(session_id="s-reset", state_store=store)
    await a.hydrate()
    await b.hydrate()
    await a.apply_inspection("call-A", ["pii"], False, True)

    generation = b.reset_count            # B's view, taken before the reset
    old_id, new_id, closed = await a.apply_reset(reason="op", authorized_by="operator")

    applied = await b.apply_inspection(
        "call-B", ["confidential"], False, True, for_reset_count=generation
    )

    assert applied is False
    assert closed.session_id == old_id
    assert closed.max_sensitivity == "pii"
    assert store.closed(old_id)["max_sensitivity"] == "pii"
    assert store.load(new_id).max_sensitivity == "public"


# ── Cross-process serialisation ───────────────────────────────────────────────


def _hold_reserved_lock(db_path: str, held_for_s: float, ready, done) -> None:
    """Another gateway instance holding the store's write lock."""
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("BEGIN IMMEDIATE")
    ready.set()
    time.sleep(held_for_s)
    conn.execute("COMMIT")
    conn.close()
    done.set()


@pytest.mark.asyncio
async def test_the_write_lock_serialises_across_processes(tmp_path: Path):
    """An asyncio.Lock cannot do this: it is invisible to another process.

    A real second process takes the store's RESERVED lock. This process must wait
    for it rather than interleave, which is what makes the serialisation span
    gateway instances instead of only coroutines.
    """
    db = tmp_path / "s.db"
    store = SqliteSessionStateStore(db, busy_timeout_ms=10_000)
    state = SessionState(session_id="s-xproc", state_store=store)
    await state.hydrate()

    ctx = mp.get_context("spawn")
    ready, done = ctx.Event(), ctx.Event()
    holder = ctx.Process(
        target=_hold_reserved_lock, args=(str(db), 1.5, ready, done), daemon=True
    )
    holder.start()
    try:
        assert ready.wait(timeout=15), "helper process never took the lock"
        assert not done.is_set()

        started = time.monotonic()
        await state.apply_inspection("call-x", ["pii"], False, True)
        waited = time.monotonic() - started

        # The write could only land once the other process committed.
        assert done.is_set()
        assert waited > 0.5, f"did not wait for the other instance (waited {waited:.2f}s)"
        assert store.load("s-xproc").max_sensitivity == "pii"
    finally:
        holder.join(timeout=15)


# ── The in-process default is unchanged ───────────────────────────────────────


@pytest.mark.asyncio
async def test_no_store_configured_keeps_the_previous_behaviour():
    state = SessionState(session_id="s-plain")
    assert state.state_store is None

    assert await state.hydrate() is False
    assert await state.apply_inspection("call-A", ["pii"], False, True) is True
    assert state.max_sensitivity == "pii"

    _, _, closed = await state.apply_reset(reason="op", authorized_by="test")
    assert closed.max_sensitivity == "pii"
    assert state.max_sensitivity == "public"
    assert state.max_sensitivity in SENSITIVITY_ORDER


@pytest.mark.asyncio
async def test_in_memory_store_serialises_but_does_not_persist():
    store = InMemorySessionStateStore()
    state = SessionState(session_id="s-mem", state_store=store)
    await state.apply_inspection("call-A", ["pii"], False, True)

    assert store.load("s-mem").max_sensitivity == "pii"
    # A different store instance stands for a restart: nothing carried over.
    assert InMemorySessionStateStore().load("s-mem") is None
