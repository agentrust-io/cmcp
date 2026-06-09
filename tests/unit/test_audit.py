"""Tests for audit chain and signing key (issues #46, #47)."""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.keys import SigningKey

# ── SigningKey ────────────────────────────────────────────────────────────────

def test_signing_key_public_key_is_32_bytes_hex():
    key = SigningKey()
    assert len(key.public_key_hex) == 64  # 32 bytes × 2 hex chars
    assert all(c in "0123456789abcdef" for c in key.public_key_hex)


def test_signing_key_bytes_match_hex():
    key = SigningKey()
    assert key.public_key_bytes.hex() == key.public_key_hex


def test_signing_key_is_ephemeral():
    """Two separate instantiations must produce different keypairs (ATTEST-004)."""
    k1 = SigningKey()
    k2 = SigningKey()
    assert k1.public_key_hex != k2.public_key_hex


def test_signing_key_sign_produces_64_bytes():
    key = SigningKey()
    sig = key.sign(b"hello")
    assert len(sig) == 64


def test_signing_key_sign_deterministic_for_same_message():
    """Ed25519 is NOT deterministic across key instances, but same key must be stable."""
    key = SigningKey()
    # Ed25519 is deterministic: same key + same message → same signature
    sig1 = key.sign(b"test message")
    sig2 = key.sign(b"test message")
    assert sig1 == sig2


def test_signing_key_different_messages_different_sigs():
    key = SigningKey()
    assert key.sign(b"a") != key.sign(b"b")


# ── AuditChain ────────────────────────────────────────────────────────────────

def test_audit_chain_starts_with_session_start():
    chain = AuditChain("sess-001")
    assert chain.length == 1
    assert chain.entries[0].entry_type == "session_start"
    assert chain.entries[0].sequence_number == 0
    assert chain.entries[0].prev_entry_hash == "genesis"


def test_audit_chain_root_equals_first_entry_hash():
    """Conformance: AUDIT-003."""
    chain = AuditChain("sess-001")
    assert chain.chain_root == chain.entries[0].entry_hash


def test_audit_chain_tip_updates_on_append():
    chain = AuditChain("sess-001")
    first_tip = chain.chain_tip
    chain.append("tool_call", call_id="c1", tool_name="foo", policy_decision="allow")
    assert chain.chain_tip != first_tip
    assert chain.chain_tip == chain.entries[-1].entry_hash


def test_audit_chain_prev_hash_links_entries():
    """Conformance: AUDIT-004."""
    chain = AuditChain("sess-001")
    chain.append("tool_call", call_id="c1", tool_name="t1", policy_decision="allow")
    chain.append("tool_call", call_id="c2", tool_name="t2", policy_decision="deny")
    for i in range(1, chain.length):
        assert chain.entries[i].prev_entry_hash == chain.entries[i - 1].entry_hash


def test_audit_chain_entry_hash_is_sha256_of_body():
    chain = AuditChain("sess-001")
    entry = chain.entries[0]
    assert entry.entry_hash == entry.compute_hash()


def test_audit_chain_verify_chain_passes():
    chain = AuditChain("sess-001")
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
    chain.append("tool_call", call_id="c2", tool_name="t", policy_decision="deny")
    assert chain.verify_chain() is True


def test_audit_chain_verify_chain_detects_tampering():
    chain = AuditChain("sess-001")
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
    # Tamper: change a field after the fact
    chain.entries[1].tool_name = "malicious_tool"
    assert chain.verify_chain() is False


def test_audit_chain_session_id_in_all_entries():
    chain = AuditChain("sess-xyz")
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
    for entry in chain.entries:
        assert entry.session_id == "sess-xyz"


def test_audit_chain_sequence_numbers_increment():
    chain = AuditChain("sess-001")
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
    chain.append("fault", call_id="c2")
    for i, entry in enumerate(chain.entries):
        assert entry.sequence_number == i


def test_audit_chain_entries_returns_copy():
    chain = AuditChain("sess-001")
    entries = chain.entries
    entries.clear()
    assert chain.length == 1  # original not affected


# ── AUDIT-001: monotonic timestamp guard ──────────────────────────────────────

def test_timestamp_clamped_when_clock_steps_backward():
    """AUDIT-001: if wall-clock steps back, timestamp is clamped to previous entry's time."""
    chain = AuditChain("sess-001")
    first_ts = datetime.fromisoformat(chain.entries[0].timestamp_utc)

    # Simulate a clock that returns a time 5 seconds in the past on the next call
    backward = first_ts - timedelta(seconds=5)
    with patch("cmcp_runtime.audit.chain.datetime") as mock_dt:
        mock_dt.now.return_value = backward
        mock_dt.fromisoformat = datetime.fromisoformat
        entry = chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")

    appended_ts = datetime.fromisoformat(entry.timestamp_utc)
    assert appended_ts >= first_ts, (
        f"timestamp {appended_ts} must not be before previous entry {first_ts}"
    )


def test_timestamp_not_clamped_when_clock_moves_forward():
    """AUDIT-001: normal forward-moving timestamps are preserved as-is."""
    chain = AuditChain("sess-001")
    first_ts = datetime.fromisoformat(chain.entries[0].timestamp_utc)

    forward = first_ts + timedelta(seconds=10)
    with patch("cmcp_runtime.audit.chain.datetime") as mock_dt:
        mock_dt.now.return_value = forward
        mock_dt.fromisoformat = datetime.fromisoformat
        entry = chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")

    assert datetime.fromisoformat(entry.timestamp_utc) == forward
