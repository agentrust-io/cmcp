"""Tests for SQLite-backed audit store and durable AuditChain (AUDIT-001)."""

from __future__ import annotations

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.store import SqliteAuditStore


@pytest.fixture()
def store(tmp_path):
    s = SqliteAuditStore(tmp_path / "audit.db")
    yield s
    s.close()


def test_store_creates_db_file(tmp_path):
    db = tmp_path / "audit.db"
    SqliteAuditStore(db).close()
    assert db.exists()


def test_store_persists_entries(store):
    chain = AuditChain(session_id="s1", store=store)
    chain.append("tool_call", tool_name="read_file", policy_decision="allow")
    # Re-open same DB and verify rows are there
    store.close()
    store2 = SqliteAuditStore(store._db_path)
    cur = store2._conn.execute(
        "SELECT entry_type FROM audit_entries WHERE session_id = ? ORDER BY sequence_number",
        ("s1",),
    )
    types = [row[0] for row in cur.fetchall()]
    assert types == ["session_start", "tool_call"]
    store2.close()


def test_no_orphans_after_clean_close(store, tmp_path):
    chain = AuditChain(session_id="clean", store=store)
    chain.append("session_end")
    assert store.find_orphaned_sessions() == []


def test_orphan_detected_after_crash(store):
    AuditChain(session_id="crash-session", store=store)
    # No session_end appended — simulates crash
    orphans = store.find_orphaned_sessions()
    assert "crash-session" in orphans


def test_chain_without_store_still_works():
    chain = AuditChain(session_id="no-store")
    chain.append("tool_call", tool_name="x", policy_decision="allow")
    assert chain.verify_chain()


def test_chain_with_store_verifies(store):
    chain = AuditChain(session_id="with-store", store=store)
    chain.append("tool_call", tool_name="read", policy_decision="allow")
    chain.append("tool_call", tool_name="write", policy_decision="deny")
    assert chain.verify_chain()
    assert chain.length == 3  # session_start + 2 tool_calls


def test_multiple_sessions_stored_independently(store):
    c1 = AuditChain(session_id="sess-a", store=store)
    c2 = AuditChain(session_id="sess-b", store=store)
    c1.append("tool_call", tool_name="x", policy_decision="allow")
    c2.append("tool_call", tool_name="y", policy_decision="deny")
    c1.append("session_end")

    orphans = store.find_orphaned_sessions()
    assert "sess-a" not in orphans
    assert "sess-b" in orphans
