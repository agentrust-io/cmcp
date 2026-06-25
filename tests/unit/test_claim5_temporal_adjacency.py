"""
Tests for Claim 5: temporal adjacency call graph properties.
These tests assert the invariants the experiment demonstrates.
"""
from cmcp_runtime.session.call_log import SessionCallLog, _HIGH_SENSITIVITY_DOMAINS


class _Entry:
    def __init__(self, name, domain):
        self.tool_name = name
        self.compliance_domain = domain
        self.server = type("s", (), {"url": f"https://{domain}/mcp"})()


def _log(*calls):
    log = SessionCallLog("test-session")
    for tool, domain, tags in calls:
        log.record_call(tool, _Entry(tool, domain), "allow", response_sensitivity_tags=tags)
    return log


def test_sequence_numbers_monotonic():
    log = _log(
        ("ehr.get_patient",    "phi",      ["hipaa_phi"]),
        ("analytics.run",      "internal", []),
        ("slack.post_message", "external", []),
    )
    seqs = [e.sequence_number for e in log.entries]
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)


def test_cross_boundary_event_recorded_after_phi():
    log = _log(
        ("ehr.get_patient",      "phi",      ["hipaa_phi"]),
        ("billing.submit_claim", "external", []),
    )
    summary = log.get_call_graph_summary()
    events = summary["cross_boundary_events"]
    assert len(events) == 1
    assert events[0]["from_domain"] == "phi"
    assert events[0]["to_domain"] == "external"
    assert events[0]["tool_name"] == "billing.submit_claim"


def test_no_cross_boundary_within_same_domain():
    log = _log(
        ("ehr.get_patient", "phi", ["hipaa_phi"]),
        ("ehr.get_labs",    "phi", ["hipaa_phi"]),
    )
    summary = log.get_call_graph_summary()
    assert summary["cross_boundary_events"] == []


def test_provenance_disclaimer_in_summary():
    log = _log(("ehr.get_patient", "phi", ["hipaa_phi"]))
    summary = log.get_call_graph_summary()
    disclaimer = summary.get("edges_represent", "")
    assert "temporal adjacency" in disclaimer.lower()
    assert "not data provenance" in disclaimer.lower()


def test_no_false_negatives_by_construction():
    log = _log(
        ("ehr.get_patient",       "phi",      ["hipaa_phi"]),
        ("analytics.run_query",   "internal", ["confidential"]),
        ("billing.submit_claim",  "external", []),
    )
    phi_seq = log.entries[0].sequence_number
    subsequent = [e for e in log.entries[1:]]
    assert all(e.sequence_number > phi_seq for e in subsequent), (
        "Every call after a PHI call must have a higher sequence number (implicit edge)"
    )


def test_denied_call_in_graph():
    log = SessionCallLog("test-denied")
    log.record_call("phi-call",      _Entry("ehr.get_patient", "phi"), "allow",
                    response_sensitivity_tags=["hipaa_phi"])
    log.record_call("blocked-call",  _Entry("slack.post", "external"), "deny",
                    response_sensitivity_tags=[])
    entries = log.entries
    assert len(entries) == 2
    denied = [e for e in entries if e.policy_decision == "deny"]
    assert len(denied) == 1
    assert denied[0].sequence_number > entries[0].sequence_number


def test_compliance_domains_tracked():
    log = _log(
        ("ehr.get_patient",   "phi",      ["hipaa_phi"]),
        ("analytics.run",     "internal", []),
        ("slack.post_message", "external", []),
    )
    summary = log.get_call_graph_summary()
    assert set(summary["compliance_domains_touched"]) == {"phi", "internal", "external"}


def test_high_sensitivity_domains_cover_known_classes():
    for domain in ("phi", "pii", "pci", "restricted"):
        assert domain in _HIGH_SENSITIVITY_DOMAINS, f"{domain} missing from _HIGH_SENSITIVITY_DOMAINS"


def test_multiple_cross_boundary_events():
    log = _log(
        ("ehr.get_patient",    "phi",      ["hipaa_phi"]),
        ("billing.claim",      "external", []),
        ("ehr.get_labs",       "phi",      ["hipaa_phi"]),
        ("slack.notify",       "external", []),
    )
    summary = log.get_call_graph_summary()
    assert len(summary["cross_boundary_events"]) == 2
