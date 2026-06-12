"""SQLite-backed audit store - durable persistence for AuditChain entries (AUDIT-001)."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from dataclasses import asdict
from pathlib import Path

from cmcp_runtime.audit.chain import AuditEntry

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS audit_entries (
    sequence_number   INTEGER NOT NULL,
    session_id        TEXT    NOT NULL,
    entry_id          TEXT    NOT NULL PRIMARY KEY,
    entry_type        TEXT    NOT NULL,
    entry_hash        TEXT    NOT NULL,
    prev_entry_hash   TEXT    NOT NULL,
    payload           TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session ON audit_entries (session_id, sequence_number);
"""


class SqliteAuditStore:
    """
    Append-only SQLite store for audit chain entries.

    One row per AuditEntry. Entries are written synchronously (WAL mode) before
    AuditChain.append() returns, so a crash after acknowledgement still has the
    entry on disk.

    The full entry is serialised as JSON in the `payload` column so the schema
    is forward-compatible with new AuditEntry fields without a migration.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        # check_same_thread=False allows use from async handlers and worker
        # threads; all access is serialised through self._lock.
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(_CREATE_TABLE)
        self._conn.commit()
        logger.info("Audit store opened: path=%s", db_path)

    def append(self, entry: AuditEntry) -> None:
        payload = json.dumps(asdict(entry), sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_entries "
                "(sequence_number, session_id, entry_id, entry_type, entry_hash, prev_entry_hash, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.sequence_number,
                    entry.session_id,
                    entry.entry_id,
                    entry.entry_type,
                    entry.entry_hash,
                    entry.prev_entry_hash,
                    payload,
                ),
            )
            self._conn.commit()

    def find_orphaned_sessions(self) -> list[str]:
        """
        Return session IDs that have a session_start entry but no session_end entry.

        These represent sessions that were open when the gateway last stopped,
        either due to a crash or an unclean shutdown.
        """
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT DISTINCT session_id FROM audit_entries
                WHERE entry_type = 'session_start'
                  AND session_id NOT IN (
                      SELECT session_id FROM audit_entries WHERE entry_type = 'session_end'
                  )
                """
            )
            return [row[0] for row in cur.fetchall()]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
