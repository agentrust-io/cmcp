"""
Persistent, shared session-sensitivity state.

The accumulated session-sensitivity value is the one piece of session state that
enforcement depends on: a gateway that loses it stops being able to say what the
session already handled, and a gateway that keeps it privately cannot enforce
across more than one instance. Two consequences follow, and this module holds
both.

**Persistence.** An in-memory value does not survive a restart. A session that
had reached ``restricted`` comes back at ``public`` after a process bounce, and
the sensitivity that was accumulated over the whole session is gone while the
session identifier the agent host holds is still live.

**Sharing.** Where several gateway instances serve one agent session, each
holding its own value means the ratchet holds per instance and not per session.
An agent that reads sensitive data through one instance and then egresses
through another is evaluated by an instance that never saw the read.

Both are answered by keeping the value in one store and serialising the
read-modify-write against it. The mechanism has to serialise *across processes*,
not merely across coroutines in one of them, so an ``asyncio.Lock`` is not
sufficient: it is invisible to every other instance.

``SqliteSessionStateStore`` uses ``BEGIN IMMEDIATE``, which takes SQLite's
database-level RESERVED lock. Two processes cannot hold it at once, so the
critical section spans instances on a shared filesystem volume. This follows the
audit chain, which already takes its durability from SQLite in WAL mode, so a
deployment gains no new infrastructure by turning it on.

``InMemorySessionStateStore`` is the default and preserves the single-instance
behaviour exactly: no file, no cross-process guarantee, and the same
``asyncio.Lock`` semantics as before.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS session_state (
    session_id                  TEXT PRIMARY KEY,
    max_sensitivity             TEXT NOT NULL,
    sensitivity_raised_at       TEXT,
    sensitivity_raised_by_call  TEXT,
    reset_count                 INTEGER NOT NULL DEFAULT 0,
    updated_at                  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS closed_sessions (
    session_id  TEXT PRIMARY KEY,
    payload     TEXT NOT NULL,
    closed_at   TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class StoredSensitivity:
    """The subset of session state that is shared and must survive a restart.

    Deliberately narrow. Injection events, drift lists and the kill switch are
    per-instance observations, and copying them between instances would present
    one instance's observations as another's.
    """

    max_sensitivity: str
    sensitivity_raised_at: str | None
    sensitivity_raised_by_call: str | None
    reset_count: int


@runtime_checkable
class SessionStateStore(Protocol):
    """Where the accumulated session-sensitivity value lives.

    ``exclusive`` must serialise every operation that modifies the value for one
    session, across all instances sharing the store. Implementations that cannot
    do that across processes must say so in their docstring, because a caller
    cannot tell the difference from the outside until it is enforcing wrongly.
    """

    def exclusive(self, session_id: str) -> AbstractAsyncContextManager[None]:
        """Hold the session's write lock for the duration of the context."""
        ...

    def load(self, session_id: str) -> StoredSensitivity | None:
        """Return the stored value, or None when the session is not yet stored."""
        ...

    def save(self, session_id: str, value: StoredSensitivity) -> None:
        """Write the value. Called inside ``exclusive``."""
        ...

    def record_closed(self, session_id: str, record: object) -> None:
        """Preserve the final state of a session closed by a reset."""
        ...

    def is_shared(self) -> bool:
        """True when the store serialises across gateway instances."""
        ...


class InMemorySessionStateStore:
    """Single-instance store. The default, and the previous behaviour exactly.

    Serialises with an ``asyncio.Lock``, which is confined to one event loop in
    one process: it is not visible to another gateway instance and does not
    survive a restart. ``is_shared()`` returns False so a caller can tell.
    """

    def __init__(self) -> None:
        self._values: dict[str, StoredSensitivity] = {}
        self._closed: dict[str, object] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    @asynccontextmanager
    async def exclusive(self, session_id: str) -> AsyncIterator[None]:
        lock = self._locks.setdefault(session_id, asyncio.Lock())
        async with lock:
            yield

    def load(self, session_id: str) -> StoredSensitivity | None:
        return self._values.get(session_id)

    def save(self, session_id: str, value: StoredSensitivity) -> None:
        self._values[session_id] = value

    def record_closed(self, session_id: str, record: object) -> None:
        self._closed[session_id] = record

    def closed(self, session_id: str) -> object | None:
        return self._closed.get(session_id)

    def is_shared(self) -> bool:
        return False


class SqliteSessionStateStore:
    """Shared, persistent store serialised across gateway instances.

    ``exclusive`` opens a ``BEGIN IMMEDIATE`` transaction, which takes SQLite's
    RESERVED lock on the database. Only one connection can hold it, so the
    critical section covers every instance pointed at the same file, and the
    read-modify-write of the accumulated value cannot interleave with another
    instance's. ``busy_timeout`` makes a contending instance wait rather than
    fail, and the transaction commits on exit so the value is on disk before the
    lock is released.

    The lock is database-wide rather than per session. For the write path this
    is a correct-but-coarse choice: sensitivity writes are short, and a
    per-session lock in SQLite would need its own lease table with expiry, which
    is a failure mode (a crashed holder blocking a session until its lease ages
    out) in exchange for concurrency this workload does not need.
    """

    def __init__(self, db_path: Path, *, busy_timeout_ms: int = 5000) -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(
            str(db_path), check_same_thread=False, isolation_level=None
        )
        self._thread_lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        self._conn.executescript(_CREATE_TABLES)
        logger.info("Session state store opened: path=%s", db_path)

    @asynccontextmanager
    async def exclusive(self, session_id: str) -> AsyncIterator[None]:
        # Taken in a worker thread: sqlite3 blocks, and blocking the event loop
        # while another instance holds the lock would stall every other call.
        await asyncio.to_thread(self._begin_immediate)
        try:
            yield
        except BaseException:
            await asyncio.to_thread(self._rollback)
            raise
        else:
            await asyncio.to_thread(self._commit)

    def _begin_immediate(self) -> None:
        self._thread_lock.acquire()
        try:
            self._conn.execute("BEGIN IMMEDIATE")
        except BaseException:
            self._thread_lock.release()
            raise

    def _commit(self) -> None:
        try:
            self._conn.execute("COMMIT")
        finally:
            self._thread_lock.release()

    def _rollback(self) -> None:
        try:
            self._conn.execute("ROLLBACK")
        finally:
            self._thread_lock.release()

    def load(self, session_id: str) -> StoredSensitivity | None:
        cur = self._conn.execute(
            "SELECT max_sensitivity, sensitivity_raised_at, "
            "sensitivity_raised_by_call, reset_count "
            "FROM session_state WHERE session_id = ?",
            (session_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return StoredSensitivity(
            max_sensitivity=row[0],
            sensitivity_raised_at=row[1],
            sensitivity_raised_by_call=row[2],
            reset_count=int(row[3]),
        )

    def save(self, session_id: str, value: StoredSensitivity) -> None:
        self._conn.execute(
            "INSERT INTO session_state "
            "(session_id, max_sensitivity, sensitivity_raised_at, "
            " sensitivity_raised_by_call, reset_count, updated_at) "
            "VALUES (?, ?, ?, ?, ?, datetime('now')) "
            "ON CONFLICT(session_id) DO UPDATE SET "
            " max_sensitivity=excluded.max_sensitivity, "
            " sensitivity_raised_at=excluded.sensitivity_raised_at, "
            " sensitivity_raised_by_call=excluded.sensitivity_raised_by_call, "
            " reset_count=excluded.reset_count, "
            " updated_at=excluded.updated_at",
            (
                session_id,
                value.max_sensitivity,
                value.sensitivity_raised_at,
                value.sensitivity_raised_by_call,
                value.reset_count,
            ),
        )

    def record_closed(self, session_id: str, record: object) -> None:
        payload = json.dumps(asdict(record), sort_keys=True)  # type: ignore[call-overload]
        self._conn.execute(
            "INSERT INTO closed_sessions (session_id, payload, closed_at) "
            "VALUES (?, ?, datetime('now')) "
            "ON CONFLICT(session_id) DO UPDATE SET payload=excluded.payload",
            (session_id, payload),
        )

    def closed(self, session_id: str) -> dict[str, object] | None:
        cur = self._conn.execute(
            "SELECT payload FROM closed_sessions WHERE session_id = ?", (session_id,)
        )
        row = cur.fetchone()
        return None if row is None else json.loads(row[0])

    def is_shared(self) -> bool:
        return True

    def close(self) -> None:
        self._conn.close()
