"""AGT SRE kill switch evaluator: implements issue #341."""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cmcp_runtime.config import KillSwitchConfig

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS kill_switch_blocks (
    agent_id    TEXT PRIMARY KEY,
    blocked_at  TEXT NOT NULL,
    reason      TEXT NOT NULL
);
"""


class KillSwitchBlockStore:
    """Durable record of which agent identities are blocked.

    A block is the one kill switch fact that must outlive the process. Held in
    memory, it was lifted by any restart: the identity that tripped the switch
    came back with a clean slate, and the operator had no way to tell that a
    restart and not a decision had unblocked it.

    Kept in the audit database file, which startup already opens and refuses to
    run without, so a deployment gains no new file and no new way to start
    without its blocks. Reads go to the database every time rather than to a
    cache, so an instance sharing the file sees a block another instance wrote.

    The rolling deny window is not stored. After a restart the window starts
    empty, which can delay a trip but can never lift one.
    """

    def __init__(self, db_path: Path) -> None:
        # check_same_thread=False plus one lock, matching SqliteAuditStore:
        # callers are async handlers and worker threads, every access is short.
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_CREATE_TABLE)
        self._conn.commit()
        logger.info("Kill switch block store opened: path=%s", db_path)

    def block(self, agent_id: str, *, reason: str) -> None:
        """Record a block. Blocking an identity that is already blocked keeps the first record."""
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO kill_switch_blocks (agent_id, blocked_at, reason) "
                "VALUES (?, ?, ?)",
                (agent_id, datetime.now(UTC).isoformat(), reason),
            )
            self._conn.commit()

    def unblock(self, agent_id: str) -> bool:
        """Remove a block. Returns False when the identity was not blocked."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM kill_switch_blocks WHERE agent_id = ?", (agent_id,)
            )
            self._conn.commit()
        return cur.rowcount > 0

    def is_blocked(self, agent_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM kill_switch_blocks WHERE agent_id = ?", (agent_id,)
            ).fetchone()
        return row is not None

    def blocked_at(self, agent_id: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT blocked_at FROM kill_switch_blocks WHERE agent_id = ?", (agent_id,)
            ).fetchone()
        return None if row is None else str(row[0])


class KillSwitchEvaluator:
    """Rolling-window deny-rate evaluator for per-agent-identity enforcement.

    When a registered agent identity exceeds `deny_rate_threshold` policy
    denies over the rolling `window_seconds` window (with at least `min_calls`
    events), the identity is flagged. The TRACE claim for the session that
    trips the threshold carries `kill_switch_triggered=true`: hardware-attested
    evidence of automated enforcement. Subsequent `create_session()` calls for
    the same agent identity raise `KillSwitchTripped`.

    Blocks are held in a `KillSwitchBlockStore` when one is supplied, which is
    how the running gateway is wired, so a block survives a restart and lasts
    until an operator lifts it. Without a store they are held in memory, which
    is only suitable for tests.

    Thread-safety: this evaluator is not thread-safe by itself. The caller
    (SessionManager) must serialise calls if sessions are closed concurrently.
    In practice the gateway processes sessions on an asyncio event loop and
    close_session() is called synchronously, so no lock is needed.
    """

    def __init__(
        self, config: KillSwitchConfig, *, store: KillSwitchBlockStore | None = None
    ) -> None:
        self._config = config
        self._store = store
        # agent_id -> deque of (monotonic_time, is_deny: bool)
        self._events: dict[str, deque[tuple[float, bool]]] = defaultdict(deque)
        self._blocked: set[str] = set()

    def record_calls(self, agent_id: str, *, allowed: int, denied: int) -> None:
        """Record call outcomes from a just-closed session into the rolling window."""
        now = time.monotonic()
        q = self._events[agent_id]
        for _ in range(allowed):
            q.append((now, False))
        for _ in range(denied):
            q.append((now, True))
        self._prune(agent_id)

    def evaluate(self, agent_id: str) -> bool:
        """Return True and flag the agent if the kill switch threshold is exceeded."""
        if not self._config.enabled:
            return False
        self._prune(agent_id)
        q = self._events[agent_id]
        total = len(q)
        if total < self._config.min_calls:
            return False
        deny_count = sum(1 for _, is_deny in q if is_deny)
        rate = deny_count / total
        if rate >= self._config.deny_rate_threshold:
            self._block(agent_id, reason="deny_rate_threshold")
            return True
        return False

    def is_blocked(self, agent_id: str) -> bool:
        """Return True if this agent identity has previously tripped the kill switch."""
        if self._store is not None:
            return self._store.is_blocked(agent_id)
        return agent_id in self._blocked

    def unblock(self, agent_id: str) -> bool:
        """Lift a block and clear the identity's event history.

        Returns False when the identity was not blocked, so an operator action
        that changed nothing is distinguishable from one that did.
        """
        self._events.pop(agent_id, None)
        if self._store is not None:
            return self._store.unblock(agent_id)
        was_blocked = agent_id in self._blocked
        self._blocked.discard(agent_id)
        return was_blocked

    def _block(self, agent_id: str, *, reason: str) -> None:
        if self._store is not None:
            self._store.block(agent_id, reason=reason)
        else:
            self._blocked.add(agent_id)

    def _prune(self, agent_id: str) -> None:
        cutoff = time.monotonic() - self._config.window_seconds
        q = self._events[agent_id]
        while q and q[0][0] < cutoff:
            q.popleft()
