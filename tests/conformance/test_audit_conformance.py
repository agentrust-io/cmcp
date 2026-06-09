"""
Conformance tests: audit chain entry format and SHA-256 hash chaining (issue #47).
Covers AUDIT-001 through AUDIT-005.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    generate_trace_claim,
)

# ---- helpers ----------------------------------------------------------------

def _report():
    return AttestationReportInfo(
        provider="software-only",
        measurement="DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION",
        report_data="aa" * 32,
        attestation_generated_at="2026-06-04T00:00:00+00:00",
        attestation_validity_seconds=86400,
    )


def _summary():
    return CallSummary(
        tool_calls_total=1,
        tool_calls_allowed=1,
        tool_calls_denied=0,
        tool_calls_faulted=0,
        tools_invoked=["tool.a"],
        session_max_sensitivity="public",
        call_graph_summary=CallGraphSummary(
            compliance_domains_touched=["external"],
            cross_boundary_events=[],
        ),
    )


def _claim_dict(chain, key, seq=1, prev=None):
    c = generate_trace_claim(
        session_id=chain._session_id,
        signing_key=key,
        attestation_report=_report(),
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "0" * 64,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "1" * 64),
        call_summary=_summary(),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        sequence_number=seq,
        prev_claim_hash=prev,
        do_sign=False,
    )
    return c.model_dump(exclude_none=True)


def _sha256t(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---- AUDIT-001: Monotonic timestamp guard -----------------------------------


class TestAudit001MonotonicTimestamps:
    """AUDIT-001: timestamps must be monotonically non-decreasing."""

    def test_clock_regression_clamped(self):
        chain = AuditChain("sess-a001-a")
        first_ts = datetime.fromisoformat(chain.entries[0].timestamp_utc)
        backward = first_ts - timedelta(seconds=5)
        with patch("cmcp_runtime.audit.chain.datetime") as m:
            m.now.return_value = backward
            m.fromisoformat = datetime.fromisoformat
            entry = chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
        assert datetime.fromisoformat(entry.timestamp_utc) >= first_ts

    def test_forward_clock_preserved(self):
        chain = AuditChain("sess-a001-b")
        first_ts = datetime.fromisoformat(chain.entries[0].timestamp_utc)
        forward = first_ts + timedelta(seconds=10)
        with patch("cmcp_runtime.audit.chain.datetime") as m:
            m.now.return_value = forward
            m.fromisoformat = datetime.fromisoformat
            entry = chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
        assert datetime.fromisoformat(entry.timestamp_utc) == forward

    def test_all_timestamps_monotonic(self):
        chain = AuditChain("sess-a001-c")
        for i in range(5):
            chain.append("tool_call", call_id=f"c{i}", tool_name="t", policy_decision="allow")
        ts = [datetime.fromisoformat(e.timestamp_utc) for e in chain.entries]
        for i in range(1, len(ts)):
            assert ts[i] >= ts[i - 1]

    def test_first_entry_timestamp_timezone_aware(self):
        chain = AuditChain("sess-a001-d")
        ts = datetime.fromisoformat(chain.entries[0].timestamp_utc)
        assert ts.tzinfo is not None


# ---- AUDIT-002: TEE anchor --------------------------------------------------


class TestAudit002TeeAnchor:
    """AUDIT-002: chain root must be committed to an external TEE anchor."""

    def test_set_anchor_accepts_current_root(self):
        chain = AuditChain("sess-a002-a")
        chain.set_tee_anchor(chain.chain_root)
        assert chain.tee_anchor == chain.chain_root

    def test_set_anchor_rejects_wrong_value(self):
        chain = AuditChain("sess-a002-b")
        with pytest.raises(ValueError, match="does not match current chain_root"):
            chain.set_tee_anchor("0" * 64)

    def test_anchor_none_before_set(self):
        chain = AuditChain("sess-a002-c")
        assert chain.tee_anchor is None

    def test_verify_passes_with_anchor(self):
        chain = AuditChain("sess-a002-d")
        chain.set_tee_anchor(chain.chain_root)
        chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
        assert chain.verify_chain() is True

    def test_chain_substitution_detected(self):
        real = AuditChain("sess-a002-e")
        real.set_tee_anchor(real.chain_root)
        real.append("tool_call", call_id="c1", tool_name="legit", policy_decision="allow")
        fake = AuditChain("sess-a002-e")
        fake.append("tool_call", call_id="c1", tool_name="evil", policy_decision="allow")
        real._entries = fake._entries
        assert real.verify_chain() is False

    def test_verify_warns_when_no_anchor(self, caplog):
        chain = AuditChain("sess-a002-f")
        chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
        with caplog.at_level(logging.WARNING, logger="cmcp_runtime.audit.chain"):
            result = chain.verify_chain()
        assert result is True
        assert "AUDIT-002" in caplog.text


# ---- AUDIT-003: Canonical entry format and entry_hash -----------------------


class TestAudit003EntryFormat:
    """AUDIT-003: entry_hash = SHA-256(canonical JSON of entry minus entry_hash)."""

    def test_session_start_required_fields(self):
        chain = AuditChain("sess-a003-a")
        e = chain.entries[0]
        assert e.entry_type == "session_start"
        assert e.prev_entry_hash == "genesis"
        assert e.sequence_number == 0
        assert len(e.entry_id) > 0
        assert len(e.entry_hash) == 64

    def test_entry_hash_sha256_of_body_minus_entry_hash(self):
        chain = AuditChain("sess-a003-b")
        chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
        for entry in chain.entries:
            d = asdict(entry)
            d.pop("entry_hash")
            expected = hashlib.sha256(
                json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            ).hexdigest()
            assert entry.entry_hash == expected

    def test_payload_hash_sha256_prefixed_not_raw(self):
        chain = AuditChain("sess-a003-c")
        raw = json.dumps({"arg": "secret"}, sort_keys=True, separators=(",", ":")).encode()
        phash = "sha256:" + hashlib.sha256(raw).hexdigest()
        entry = chain.append("tool_call", call_id="c1", tool_name="t",
                              policy_decision="allow", request_payload_hash=phash)
        assert entry.request_payload_hash.startswith("sha256:")
        assert "secret" not in str(asdict(entry))

    def test_field_modification_changes_hash(self):
        chain = AuditChain("sess-a003-d")
        entry = chain.append("tool_call", call_id="c1", tool_name="original", policy_decision="allow")
        orig = entry.entry_hash
        entry.tool_name = "tampered"
        assert entry.compute_hash() != orig

    def test_session_id_in_all_entries(self):
        sid = "sess-a003-e"
        chain = AuditChain(sid)
        chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
        for e in chain.entries:
            assert e.session_id == sid


# ---- AUDIT-004: Hash chain integrity ----------------------------------------


class TestAudit004HashChaining:
    """AUDIT-004: prev_entry_hash links every entry back to the previous one."""

    def test_first_entry_prev_hash_is_genesis(self):
        chain = AuditChain("sess-a004-a")
        assert chain.entries[0].prev_entry_hash == "genesis"

    def test_prev_hash_links_contiguous(self):
        chain = AuditChain("sess-a004-b")
        for i in range(4):
            chain.append("tool_call", call_id=f"c{i}", tool_name="t", policy_decision="allow")
        for i in range(1, chain.length):
            assert chain.entries[i].prev_entry_hash == chain.entries[i - 1].entry_hash

    def test_chain_root_equals_first_entry_hash(self):
        chain = AuditChain("sess-a004-c")
        assert chain.chain_root == chain.entries[0].entry_hash

    def test_chain_tip_equals_last_entry_hash(self):
        chain = AuditChain("sess-a004-d")
        chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
        chain.append("tool_call", call_id="c2", tool_name="t", policy_decision="deny")
        assert chain.chain_tip == chain.entries[-1].entry_hash

    def test_chain_tip_changes_on_each_append(self):
        chain = AuditChain("sess-a004-e")
        tips = [chain.chain_tip]
        for i in range(3):
            chain.append("tool_call", call_id=f"c{i}", tool_name="t", policy_decision="allow")
            tips.append(chain.chain_tip)
        assert len(set(tips)) == len(tips)

    def test_verify_passes_on_unmodified_chain(self):
        chain = AuditChain("sess-a004-f")
        for i in range(3):
            chain.append("tool_call", call_id=f"c{i}", tool_name="t", policy_decision="allow")
        assert chain.verify_chain() is True

    def test_verify_detects_field_tampering(self):
        chain = AuditChain("sess-a004-g")
        chain.append("tool_call", call_id="c1", tool_name="legit", policy_decision="allow")
        chain.entries[1].tool_name = "injected"
        assert chain.verify_chain() is False

    def test_verify_detects_hash_tampering(self):
        chain = AuditChain("sess-a004-h")
        chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
        chain.entries[0].entry_hash = "0" * 64
        assert chain.verify_chain() is False

    def test_sequence_numbers_contiguous_from_zero(self):
        chain = AuditChain("sess-a004-i")
        chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
        chain.append("fault", call_id="c2")
        for i, entry in enumerate(chain.entries):
            assert entry.sequence_number == i


# ---- AUDIT-005: TRACE Claim sequence and chaining ---------------------------


class TestAudit005ClaimSequence:
    """AUDIT-005: TRACE Claims carry sequence_number and prev_claim_hash."""

    def test_sequence_number_in_claim(self):
        chain = AuditChain("sess-a005-a")
        key = SigningKey()
        d = _claim_dict(chain, key, seq=1)
        assert d["gateway"]["sequence_number"] == 1

    def test_sequence_number_reflects_caller_value(self):
        chain = AuditChain("sess-a005-b")
        key = SigningKey()
        for seq in [1, 2, 3, 10, 100]:
            d = _claim_dict(chain, key, seq=seq)
            assert d["gateway"]["sequence_number"] == seq

    def test_prev_claim_hash_absent_for_first_claim(self):
        chain = AuditChain("sess-a005-c")
        key = SigningKey()
        d = _claim_dict(chain, key, seq=1, prev=None)
        assert "prev_claim_hash" not in d["gateway"]

    def test_prev_claim_hash_links_successive_claims(self):
        chain = AuditChain("sess-a005-d")
        key = SigningKey()
        c1 = _claim_dict(chain, key, seq=1)
        c1_hash = _sha256t(
            json.dumps(c1, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        )
        c2 = _claim_dict(chain, key, seq=2, prev=c1_hash)
        assert c2["gateway"]["prev_claim_hash"] == c1_hash

    def test_sequence_numbers_strictly_increasing(self):
        chain = AuditChain("sess-a005-e")
        key = SigningKey()
        seqs = [1, 2, 3, 4, 5]
        for s in seqs:
            d = _claim_dict(chain, key, seq=s)
            assert d["gateway"]["sequence_number"] == s
        assert seqs == sorted(set(seqs))
