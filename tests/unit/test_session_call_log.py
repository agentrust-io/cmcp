"""Unit tests for SessionCallLog and CallLogEntry (issue #94).

Tests:
- domain tracking across calls
- cross-boundary event detection when transitioning from high-sensitivity domains
- get_call_graph_summary structure and edges_represent note
- summary with no cross-boundary events
- TRACE Claim call_graph_summary populated from SessionCallLog
"""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from cmcp_gateway.session.call_log import CallLogEntry, SessionCallLog


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry(tool_name: str, compliance_domain: str = "external", server_url: str = "https://test.example.com/mcp") -> MagicMock:
    """Build a minimal catalog entry mock."""
    e = MagicMock()
    e.tool_name = tool_name
    e.compliance_domain = compliance_domain
    e.server = MagicMock()
    e.server.url = server_url
    return e


# ---------------------------------------------------------------------------
# Basic record_call
# ---------------------------------------------------------------------------


def test_record_call_appends_entry():
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("tool.a"), "allow")
    assert len(log.entries) == 1


def test_record_call_sequence_numbers_contiguous():
    log = SessionCallLog("sess-001")
    for i in range(5):
        log.record_call(f"c{i}", _entry(f"tool.{i}"), "allow")
    for i, entry in enumerate(log.entries):
        assert entry.sequence_number == i


def test_record_call_sets_tool_name_from_catalog():
    log = SessionCallLog("sess-001")
    e = _entry("crm.query", "pii")
    log.record_call("c1", e, "allow")
    assert log.entries[0].tool_name == "crm.query"


def test_record_call_sets_compliance_domain_from_catalog():
    log = SessionCallLog("sess-001")
    e = _entry("phi.lookup", "phi")
    log.record_call("c1", e, "allow")
    assert log.entries[0].compliance_domain == "phi"


def test_record_call_sets_server_identity_from_catalog():
    log = SessionCallLog("sess-001")
    e = _entry("tool.a", server_url="https://server.example.com/mcp")
    log.record_call("c1", e, "allow")
    assert log.entries[0].server_identity == "https://server.example.com/mcp"


def test_record_call_stores_policy_decision():
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("t"), "deny")
    assert log.entries[0].policy_decision == "deny"


def test_record_call_stores_call_id():
    log = SessionCallLog("sess-001")
    log.record_call("abc-123", _entry("t"), "allow")
    assert log.entries[0].call_id == "abc-123"


def test_record_call_timestamp_is_timezone_aware():
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("t"), "allow")
    ts = log.entries[0].timestamp
    assert ts.tzinfo is not None


def test_record_call_catalog_none_uses_unknown_domain():
    log = SessionCallLog("sess-001")
    log.record_call("c1", None, "deny")
    entry = log.entries[0]
    assert entry.compliance_domain == "unknown"
    assert entry.tool_name == "unknown"
    assert entry.server_identity is None


def test_record_call_stores_response_sensitivity_tags():
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("t"), "allow", response_sensitivity_tags=["pii", "restricted"])
    assert log.entries[0].response_sensitivity_tags == ["pii", "restricted"]


def test_record_call_empty_response_sensitivity_tags_by_default():
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("t"), "allow")
    assert log.entries[0].response_sensitivity_tags == []


# ---------------------------------------------------------------------------
# get_call_graph_summary — compliance_domains_touched
# ---------------------------------------------------------------------------


def test_summary_empty_log():
    log = SessionCallLog("sess-001")
    s = log.get_call_graph_summary()
    assert s["compliance_domains_touched"] == []
    assert s["cross_boundary_events"] == []
    assert "edges_represent" in s


def test_summary_single_domain():
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("t", "external"), "allow")
    s = log.get_call_graph_summary()
    assert s["compliance_domains_touched"] == ["external"]


def test_summary_multiple_domains_sorted():
    log = SessionCallLog("sess-001")
    for domain in ["pii", "external", "phi", "external"]:
        log.record_call("c1", _entry("t", domain), "allow")
    s = log.get_call_graph_summary()
    assert s["compliance_domains_touched"] == ["external", "phi", "pii"]


def test_summary_domains_deduplicated():
    log = SessionCallLog("sess-001")
    for _ in range(5):
        log.record_call("c1", _entry("t", "pii"), "allow")
    s = log.get_call_graph_summary()
    assert s["compliance_domains_touched"] == ["pii"]


# ---------------------------------------------------------------------------
# get_call_graph_summary — cross_boundary_events
# ---------------------------------------------------------------------------


def test_no_cross_boundary_all_same_domain():
    log = SessionCallLog("sess-001")
    for i in range(3):
        log.record_call(f"c{i}", _entry(f"t{i}", "external"), "allow")
    s = log.get_call_graph_summary()
    assert s["cross_boundary_events"] == []


def test_no_cross_boundary_only_low_sensitivity():
    """Transitions between non-high-sensitivity domains are not events."""
    log = SessionCallLog("sess-001")
    for domain in ["external", "internal", "external", "public"]:
        log.record_call("c1", _entry("t", domain), "allow")
    s = log.get_call_graph_summary()
    assert s["cross_boundary_events"] == []


def test_cross_boundary_after_pii():
    """pii -> external triggers a cross-boundary event."""
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("t1", "pii"), "allow")
    log.record_call("c2", _entry("t2", "external"), "allow")
    s = log.get_call_graph_summary()
    assert len(s["cross_boundary_events"]) == 1
    ev = s["cross_boundary_events"][0]
    assert ev["from_domain"] == "pii"
    assert ev["to_domain"] == "external"
    assert ev["call_id"] == "c2"
    assert ev["tool_name"] == "t2"
    assert ev["sequence_number"] == 1


def test_cross_boundary_after_phi():
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("t1", "phi"), "allow")
    log.record_call("c2", _entry("t2", "public"), "allow")
    s = log.get_call_graph_summary()
    assert len(s["cross_boundary_events"]) == 1
    assert s["cross_boundary_events"][0]["from_domain"] == "phi"


def test_cross_boundary_after_pci():
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("t1", "pci"), "allow")
    log.record_call("c2", _entry("t2", "external"), "allow")
    s = log.get_call_graph_summary()
    assert len(s["cross_boundary_events"]) == 1


def test_cross_boundary_after_restricted():
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("t1", "restricted"), "allow")
    log.record_call("c2", _entry("t2", "internal"), "allow")
    s = log.get_call_graph_summary()
    assert len(s["cross_boundary_events"]) == 1


def test_no_cross_boundary_pii_to_pii():
    """Same domain after pii does not trigger a cross-boundary event."""
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("t1", "pii"), "allow")
    log.record_call("c2", _entry("t2", "pii"), "allow")
    s = log.get_call_graph_summary()
    assert s["cross_boundary_events"] == []


def test_multiple_cross_boundary_events():
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("t1", "pii"), "allow")
    log.record_call("c2", _entry("t2", "external"), "allow")
    log.record_call("c3", _entry("t3", "phi"), "allow")
    log.record_call("c4", _entry("t4", "public"), "allow")
    s = log.get_call_graph_summary()
    assert len(s["cross_boundary_events"]) == 2


def test_cross_boundary_event_has_required_keys():
    log = SessionCallLog("sess-001")
    log.record_call("c1", _entry("t1", "pii"), "allow")
    log.record_call("c2", _entry("t2", "external"), "allow")
    ev = log.get_call_graph_summary()["cross_boundary_events"][0]
    assert set(ev.keys()) == {"from_domain", "to_domain", "call_id", "tool_name", "sequence_number"}


# ---------------------------------------------------------------------------
# edges_represent note
# ---------------------------------------------------------------------------


def test_summary_includes_edges_represent_note():
    log = SessionCallLog("sess-001")
    s = log.get_call_graph_summary()
    assert "edges_represent" in s
    note = s["edges_represent"]
    assert isinstance(note, str)
    assert "temporal adjacency" in note.lower()
    assert "not data provenance" in note.lower()


# ---------------------------------------------------------------------------
# TRACE Claim call_graph_summary populated from SessionCallLog
# ---------------------------------------------------------------------------


def test_trace_claim_call_graph_summary_from_session_call_log():
    """Integration: close_session with a SessionCallLog uses its call_graph_summary."""
    from cmcp_gateway.audit.chain import AuditChain
    from cmcp_gateway.audit.keys import SigningKey
    from cmcp_gateway.session.manager import SessionManager
    from cmcp_gateway.session.state import SessionState
    from datetime import UTC, datetime
    from unittest.mock import MagicMock

    # Build a minimal GatewayContext mock
    key = SigningKey()
    policy_bundle = MagicMock()
    policy_bundle.bundle_hash = "sha256:" + "a" * 64
    policy_bundle.manifest.version = "1.0.0"

    catalog = MagicMock()
    catalog.catalog_hash = "sha256:" + "b" * 64
    catalog.entries = {}
    catalog.exceptions = []

    config = MagicMock()
    config.attestation.enforcement_mode = "enforcing"

    report = MagicMock()
    report.provider = "software-only"
    report.measurement = "DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION"
    report.report_data = "aa" * 32
    report.raw_evidence = None
    report.measurement_note = None
    report.attestation_validity_seconds = 86400
    report.attestation_generated_at = datetime.now(UTC)

    tee_provider = MagicMock()
    tee_provider.get_attestation_report.return_value = MagicMock()

    ctx = MagicMock()
    ctx.signing_key = key
    ctx.attestation_report = report
    ctx.policy_bundle = policy_bundle
    ctx.catalog = catalog
    ctx.config = config
    ctx.tee_provider = tee_provider

    mgr = SessionManager(ctx)
    state, chain = mgr.create_session()
    session_id = state.session_id

    # Build a SessionCallLog with a pii -> external cross-boundary event
    scl = SessionCallLog(session_id)
    e_pii = _entry("pii.tool", "pii")
    e_ext = _entry("ext.tool", "external")
    scl.record_call("c1", e_pii, "allow")
    scl.record_call("c2", e_ext, "allow")

    claim_dict = mgr.close_session(
        session_id, state, chain, session_call_log=scl
    )

    cg = claim_dict["gateway"]["call_summary"]["call_graph_summary"]
    assert "pii" in cg["compliance_domains_touched"]
    assert "external" in cg["compliance_domains_touched"]
    assert len(cg["cross_boundary_events"]) == 1
    assert cg["cross_boundary_events"][0]["from_domain"] == "pii"
    # Temporal adjacency note must appear
    assert "edges_represent" in cg
    assert "temporal adjacency" in cg["edges_represent"].lower()
