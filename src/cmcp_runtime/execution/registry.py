"""Standalone execution-state foundation for #565; not wired into the gateway.

Reservations are keyed by (agent_identity, execution_id). Admission atomically
stores or compares an opaque binding. Completed and outcome_unknown rows are
terminal, while recovery marks abandoned in_flight rows outcome_unknown.
Identifiers never expire and repeat reservations never authorize invocation.

These are storage primitives, not production execution enforcement. The binding
preimage is unresolved in #588. finalize() commits only the registry row: it
cannot atomically publish a terminal audit entry. Integrating this module requires
an adopted binding contract and a shared durable terminal/audit boundary, with
crash and recovery tests. The gateway refuses supplied execution IDs until both
requirements are met; there is no runtime activation option.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

logger = logging.getLogger(__name__)

_IN_FLIGHT = "in_flight"

# #574 says the gateway validates execution_id, not just scopes it. This is the
# durable primary key: an empty string or a multi-megabyte value must never
# reach it. 1 to 200 printable, non-space ASCII characters covers UUIDs, ULIDs,
# and URN-style identifiers without opening the key to control characters or
# unbounded length.
_EXECUTION_ID_RE = re.compile(r"[\x21-\x7e]{1,200}\Z")


def valid_execution_id(value: str) -> bool:
    """True when `value` is well-formed enough to be a durable correlation key."""
    return _EXECUTION_ID_RE.match(value) is not None

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS executions (
    agent_identity            TEXT NOT NULL,
    execution_id              TEXT NOT NULL,
    action_binding            TEXT NOT NULL,
    state                     TEXT NOT NULL,
    call_id                   TEXT,
    terminal_audit_entry_hash TEXT,
    created_utc               TEXT NOT NULL,
    updated_utc               TEXT NOT NULL,
    PRIMARY KEY (agent_identity, execution_id)
);
"""


class AdmissionStatus(StrEnum):
    """Classification of an `admit()` request. Only ADMITTED may invoke upstream."""

    ADMITTED = "admitted"
    REPLAY_IN_FLIGHT = "replay_in_flight"
    REPLAY_TERMINAL = "replay_terminal"
    REPLAY_OUTCOME_UNKNOWN = "replay_outcome_unknown"
    COLLISION_CHANGED_BINDING = "collision_changed_binding"


class Disposition(StrEnum):
    """Terminal disposition supplied to `finalize()`. Both are non-replayable."""

    COMPLETED = "completed"
    OUTCOME_UNKNOWN = "outcome_unknown"


class ExecutionStateError(RuntimeError):
    """A caller finalized an execution that was never admitted."""


@dataclass(frozen=True)
class Admission:
    """
    Outcome of `admit()`.

    `action_binding` is the opaque digest the caller supplied, echoed back so it
    can be recorded on the audit entry whether the request was admitted or
    refused.
    """

    status: AdmissionStatus
    action_binding: str

    @property
    def admitted(self) -> bool:
        return self.status is AdmissionStatus.ADMITTED

    @property
    def audit_rule(self) -> str:
        """Stable `policy_rule_matched` value for a refused admission."""
        return f"execution:{self.status.value}"


class ExecutionRegistry:
    """Durable owner of execution-correlation state. One instance per process."""

    def __init__(self, db_path: Path) -> None:
        # check_same_thread=False plus one lock: the proxy calls this from async
        # handlers and worker threads, and every write is a short serialized
        # transaction. busy_timeout covers a second gateway process sharing the
        # file behind BEGIN IMMEDIATE's reserved lock.
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_CREATE_TABLE)
        self._conn.commit()
        logger.info("Execution registry opened: path=%s", db_path)

    def recover(self) -> int:
        """
        Fail closed over crash ambiguity. Every execution still `in_flight` is
        moved to `outcome_unknown`: the gateway stopped between reserving the
        identifier and recording a terminal, so the external effect is unknown
        and the identifier must never admit another invocation. Returns the
        number of executions sealed this way. Call once at startup.
        """
        now = _now()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cur = self._conn.execute(
                    "UPDATE executions SET state='outcome_unknown', updated_utc=? WHERE state=?",
                    (now, _IN_FLIGHT),
                )
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise
        if cur.rowcount:
            logger.warning(
                "Execution registry recovery sealed %d in-flight execution(s) as "
                "outcome_unknown",
                cur.rowcount,
            )
        return cur.rowcount

    def admit(
        self,
        *,
        agent_identity: str,
        execution_id: str,
        action_binding: str,
        call_id: str,
    ) -> Admission:
        """
        Atomically reserve (agent_identity, execution_id, action_binding) before
        upstream invocation, or classify why the request cannot proceed.

        `action_binding` is an opaque digest string produced by the caller. A key
        that already exists is never rewritten: an identical binding is a replay
        classified by the stored state, a different binding is a collision. Both
        are refused here, before any upstream effect.
        """
        now = _now()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT state, action_binding FROM executions "
                    "WHERE agent_identity=? AND execution_id=?",
                    (agent_identity, execution_id),
                ).fetchone()
                if row is None:
                    self._conn.execute(
                        "INSERT INTO executions (agent_identity, execution_id, "
                        "action_binding, state, call_id, created_utc, updated_utc) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (agent_identity, execution_id, action_binding, _IN_FLIGHT, call_id, now, now),
                    )
                    self._conn.commit()
                    return Admission(AdmissionStatus.ADMITTED, action_binding)
                self._conn.rollback()
            except BaseException:
                self._conn.rollback()
                raise

        return Admission(_classify_existing(row[0], row[1], action_binding), action_binding)

    def finalize(
        self,
        *,
        agent_identity: str,
        execution_id: str,
        disposition: Disposition,
        terminal_audit_entry_hash: str,
    ) -> None:
        """
        Record the terminal outcome for an admitted execution and pin it to the
        audit entry that carries the same fact. Legal only from `in_flight`; a
        second call is a no-op so a retry of the caller's terminal path cannot
        raise after the effect already happened. Raises ExecutionStateError if
        the key was never admitted.
        """
        now = _now()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT state FROM executions WHERE agent_identity=? AND execution_id=?",
                    (agent_identity, execution_id),
                ).fetchone()
                if row is None:
                    self._conn.rollback()
                    raise ExecutionStateError(
                        f"finalize before admit: execution_id={execution_id!r}"
                    )
                if row[0] != _IN_FLIGHT:
                    self._conn.rollback()
                    logger.warning(
                        "Execution %r already terminal (%s); finalize(%s) ignored",
                        execution_id,
                        row[0],
                        disposition.value,
                    )
                    return
                self._conn.execute(
                    "UPDATE executions SET state=?, terminal_audit_entry_hash=?, "
                    "updated_utc=? WHERE agent_identity=? AND execution_id=?",
                    (
                        disposition.value,
                        terminal_audit_entry_hash,
                        now,
                        agent_identity,
                        execution_id,
                    ),
                )
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _classify_existing(state: str, stored_binding: str, presented_binding: str) -> AdmissionStatus:
    """Map an existing row to a refusal status. Binding mismatch outranks state."""
    if stored_binding != presented_binding:
        return AdmissionStatus.COLLISION_CHANGED_BINDING
    if state == _IN_FLIGHT:
        return AdmissionStatus.REPLAY_IN_FLIGHT
    if state == "outcome_unknown":
        return AdmissionStatus.REPLAY_OUTCOME_UNKNOWN
    return AdmissionStatus.REPLAY_TERMINAL


def _now() -> str:
    return datetime.now(tz=UTC).isoformat()
