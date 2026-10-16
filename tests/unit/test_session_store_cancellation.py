"""Cancellation must not abandon an in-flight SQLite operation or its locks."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from contextlib import suppress
from pathlib import Path

import pytest

from cmcp_runtime.session.store import SqliteSessionStateStore, StoredSensitivity

VALUE = StoredSensitivity("restricted", None, "call", 0)


async def _assert_reusable(store: SqliteSessionStateStore, path: Path) -> None:
    assert not store._thread_lock.locked()
    assert not store._conn.in_transaction
    async with store.exclusive("after-cancellation"):
        store.save("after-cancellation", VALUE)
    other = SqliteSessionStateStore(path, busy_timeout_ms=100)
    try:
        async with other.exclusive("second-connection"):
            other.save("second-connection", VALUE)
        assert other.load("after-cancellation") == VALUE
    finally:
        other.close()


@pytest.mark.asyncio
async def test_cancelled_acquisition_waits_for_sqlite_and_rolls_back(tmp_path: Path):
    path = tmp_path / "state.db"
    store = SqliteSessionStateStore(path, busy_timeout_ms=2000)
    blocker = sqlite3.connect(path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    started, finished = threading.Event(), threading.Event()
    begin = store._begin_immediate

    def observed_begin():
        started.set()
        try:
            begin()
        finally:
            finished.set()

    store._begin_immediate = observed_begin
    body_entered = False

    async def operation():
        nonlocal body_entered
        async with store.exclusive("cancelled"):
            body_entered = True
            store.save("cancelled", VALUE)

    task = asyncio.create_task(operation())
    try:
        assert await asyncio.to_thread(started.wait, 1)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()  # A second cancellation must not cancel the worker future.
        await asyncio.sleep(0)
        blocker.execute("ROLLBACK")
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await asyncio.to_thread(finished.wait, 1)
        assert not body_entered
        assert store.load("cancelled") is None
        await _assert_reusable(store, path)
    finally:
        if blocker.in_transaction:
            blocker.rollback()
        blocker.close()
        assert await asyncio.to_thread(finished.wait, 3)
        with suppress(asyncio.CancelledError):
            await task
        # Also makes the regression safe when exercised against the old code.
        if store._thread_lock.locked():
            store._rollback()
        store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["commit", "rollback"])
async def test_cancellation_waits_for_transaction_finalization(tmp_path: Path, stage: str):
    path = tmp_path / "state.db"
    store = SqliteSessionStateStore(path)
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = getattr(store, f"_{stage}")

    def gated_finalization():
        started.set()
        try:
            assert release.wait(3), "test did not release SQLite finalization"
            original()
        finally:
            finished.set()

    setattr(store, f"_{stage}", gated_finalization)

    async def operation():
        async with store.exclusive("during-finalization"):
            store.save("during-finalization", VALUE)
            if stage == "rollback":
                raise LookupError("body failed")

    task = asyncio.create_task(operation())
    try:
        assert await asyncio.to_thread(started.wait, 1)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        completed_before_cleanup = task.done()
        release.set()
        if stage == "commit":
            with pytest.raises(asyncio.CancelledError):
                await task
            assert store.load("during-finalization") == VALUE
        else:
            with pytest.raises(LookupError, match="body failed"):
                await task
            assert store.load("during-finalization") is None
        assert not completed_before_cleanup
        await _assert_reusable(store, path)
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 3)
        with suppress(asyncio.CancelledError, LookupError):
            await task
        if store._thread_lock.locked():
            store._rollback()
        store.close()


@pytest.mark.asyncio
async def test_cancellation_in_body_rolls_back(tmp_path: Path):
    path = tmp_path / "state.db"
    store = SqliteSessionStateStore(path)
    entered = asyncio.Event()

    async def operation():
        async with store.exclusive("cancelled-body"):
            store.save("cancelled-body", VALUE)
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(operation())
    try:
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert store.load("cancelled-body") is None
        await _assert_reusable(store, path)
    finally:
        store.close()


@pytest.mark.asyncio
async def test_cancellation_before_start_does_not_acquire_a_transaction(tmp_path: Path):
    path = tmp_path / "state.db"
    store = SqliteSessionStateStore(path)

    async def operation():
        async with store.exclusive("never-started"):
            pytest.fail("cancelled task entered the transaction")

    task = asyncio.create_task(operation())
    task.cancel()
    try:
        with pytest.raises(asyncio.CancelledError):
            await task
        await _assert_reusable(store, path)
    finally:
        store.close()


@pytest.mark.asyncio
async def test_failed_acquisition_does_not_retain_locks(tmp_path: Path):
    path = tmp_path / "state.db"
    store = SqliteSessionStateStore(path, busy_timeout_ms=25)
    blocker = sqlite3.connect(path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            async with store.exclusive("failed-acquisition"):
                pytest.fail("failed acquisition entered the transaction")
        blocker.rollback()
        await _assert_reusable(store, path)
    finally:
        blocker.close()
        store.close()
