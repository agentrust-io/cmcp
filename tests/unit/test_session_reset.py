"""Tests for session reset endpoint (issue #92).

Covers:
- POST /sessions/{id}/reset returns 200 with old/new session IDs
- POST /sessions/{wrong_id}/reset returns 404
- Reset clears attestation_stale and catalog_drift flags
- Audit entry appended on reset
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.mcp.server import MCPServer
from cmcp_runtime.policy.evaluator import PolicyDecision, PolicyEvaluator
from cmcp_runtime.session.state import SessionState
from tests.unit.conftest import wire_mock_gateway

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_catalog() -> ToolCatalog:
    entry = CatalogEntry(
        tool_name="test.tool",
        server=ServerIdentity(
            display_name="Test",
            url="https://test.example.com/mcp",
            tls_fingerprint="SHA256:AAAA/BBBB==",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description="test tool",
            input_schema={},
            output_schema=None,
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="external",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-06-05T00:00:00Z",
        approved_by="test",
    )
    return ToolCatalog(entries={"test.tool": entry}, catalog_hash="sha256:" + "a" * 64)


def _make_evaluator() -> PolicyEvaluator:
    evaluator = MagicMock(spec=PolicyEvaluator)
    evaluator.evaluate.return_value = PolicyDecision(
        allowed=True,
        enforcement_mode=EnforcementMode.ENFORCING,
        rule_matched=None,
        advice={},
        evaluation_ms=0.1,
        would_have_denied=False,
    )
    evaluator.bundle_hash = "sha256:" + "0" * 64
    evaluator.enforcement_mode = EnforcementMode.ENFORCING
    return evaluator


def _make_server(session_id: str = "sess-reset-001"):
    from cmcp_runtime.mcp.proxy import CMCPProxy

    cfg = Config()
    cfg.attestation = AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING)
    cat = _make_catalog()
    ev = _make_evaluator()
    session = SessionState(session_id=session_id)
    chain = AuditChain(session_id)

    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(cat, ev, session, chain, cfg)
        wire_mock_gateway(proxy)

    server = MCPServer(proxy, session=session, audit_chain=chain)
    return server, session, chain


# ── Endpoint happy path ───────────────────────────────────────────────────────


def test_reset_returns_200_with_session_ids():
    """POST /sessions/{id}/reset returns 200 with old/new session IDs and status."""
    server, session, _ = _make_server("sess-reset-001")
    original_id = session.session_id

    client = TestClient(server.app, raise_server_exceptions=True)
    resp = client.post(f"/sessions/{original_id}/reset")

    assert resp.status_code == 200
    body = resp.json()
    assert body["old_session_id"] == original_id
    assert body["new_session_id"] != original_id
    assert body["status"] == "reset"


def test_reset_new_session_id_matches_session_state():
    """After reset, session.session_id equals the new_session_id returned."""
    server, session, _ = _make_server("sess-reset-002")
    original_id = session.session_id

    client = TestClient(server.app, raise_server_exceptions=True)
    resp = client.post(f"/sessions/{original_id}/reset")

    assert resp.status_code == 200
    body = resp.json()
    assert session.session_id == body["new_session_id"]


# ── 404 for wrong session_id ──────────────────────────────────────────────────


def test_reset_wrong_session_id_returns_404():
    """POST /sessions/{wrong_id}/reset returns 404."""
    server, _, _ = _make_server("sess-reset-003")

    client = TestClient(server.app, raise_server_exceptions=True)
    resp = client.post("/sessions/completely-wrong-id/reset")

    assert resp.status_code == 404


def test_reset_wrong_session_id_does_not_change_session():
    """404 response leaves the session unchanged."""
    server, session, _ = _make_server("sess-reset-004")
    original_id = session.session_id

    client = TestClient(server.app, raise_server_exceptions=True)
    client.post("/sessions/completely-wrong-id/reset")

    assert session.session_id == original_id


# ── Flag clearing ─────────────────────────────────────────────────────────────


def test_reset_clears_attestation_stale_flag():
    """Reset clears session.attestation_stale."""
    server, session, _ = _make_server("sess-reset-005")
    session.attestation_stale = True
    original_id = session.session_id

    client = TestClient(server.app, raise_server_exceptions=True)
    resp = client.post(f"/sessions/{original_id}/reset")

    assert resp.status_code == 200
    assert session.attestation_stale is False


def test_reset_clears_catalog_drift_flag():
    """Reset clears session.catalog_drift."""
    server, session, _ = _make_server("sess-reset-006")
    session.catalog_drift = True
    original_id = session.session_id

    client = TestClient(server.app, raise_server_exceptions=True)
    resp = client.post(f"/sessions/{original_id}/reset")

    assert resp.status_code == 200
    assert session.catalog_drift is False


# ── Audit entry ───────────────────────────────────────────────────────────────


def test_reset_appends_session_reset_audit_entry():
    """Reset appends a 'session_reset' audit entry."""
    server, session, chain = _make_server("sess-reset-007")
    original_id = session.session_id

    initial_length = chain.length
    client = TestClient(server.app, raise_server_exceptions=True)
    client.post(f"/sessions/{original_id}/reset")

    reset_entries = [e for e in chain.entries if e.entry_type == "session_reset"]
    assert len(reset_entries) == 1
    assert chain.length > initial_length


def test_reset_audit_chain_remains_valid():
    """Hash chain is internally consistent after a reset."""
    server, session, chain = _make_server("sess-reset-008")
    original_id = session.session_id

    client = TestClient(server.app, raise_server_exceptions=True)
    client.post(f"/sessions/{original_id}/reset")

    assert chain.verify_chain() is True


# ── No session configured ─────────────────────────────────────────────────────


def test_reset_without_session_configured_returns_501():
    """MCPServer without session/audit_chain returns 501."""
    from cmcp_runtime.mcp.proxy import CMCPProxy

    cfg = Config()
    cfg.attestation = AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING)
    cat = _make_catalog()
    ev = _make_evaluator()
    session = SessionState(session_id="bare-sess")
    chain = AuditChain("bare-sess")

    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(cat, ev, session, chain, cfg)
        proxy._mcp_gateway = MagicMock()

    server = MCPServer(proxy)  # no session or audit_chain kwargs
    client = TestClient(server.app, raise_server_exceptions=True)
    resp = client.post("/sessions/bare-sess/reset")
    assert resp.status_code == 501


# ── OPQ_P0006: the reset credential is not the tool-invocation credential ─────


def _make_token_server(session_id: str = "sess-tok-001", *, operator_token: str | None):
    """Server with a tool-invocation bearer token and an optional operator token."""
    from cmcp_runtime.mcp.proxy import CMCPProxy

    cfg = Config()
    cfg.attestation = AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING)
    session = SessionState(session_id=session_id)
    chain = AuditChain(session_id)
    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(_make_catalog(), _make_evaluator(), session, chain, cfg)
        wire_mock_gateway(proxy)
    server = MCPServer(
        proxy,
        session=session,
        audit_chain=chain,
        bearer_token="tool-token",
        operator_token=operator_token,
    )
    return server, session, chain


def test_reset_rejects_the_tool_invocation_token():
    """The credential that invokes tools must not authorize a sensitivity reset."""
    server, session, _ = _make_token_server(operator_token="operator-token")
    client = TestClient(server.app, raise_server_exceptions=True)

    resp = client.post(
        f"/sessions/{session.session_id}/reset",
        headers={"Authorization": "Bearer tool-token"},
    )
    assert resp.status_code == 401
    assert resp.json()["error_code"] == "INVALID_BEARER_TOKEN"


def test_reset_accepts_the_operator_token():
    server, session, _ = _make_token_server(operator_token="operator-token")
    original_id = session.session_id
    client = TestClient(server.app, raise_server_exceptions=True)

    resp = client.post(
        f"/sessions/{original_id}/reset",
        headers={"Authorization": "Bearer operator-token"},
    )
    assert resp.status_code == 200
    assert resp.json()["old_session_id"] == original_id


def test_tool_endpoint_rejects_the_operator_token():
    """The separation runs both ways: the operator credential is not a tool credential."""
    server, _, _ = _make_token_server(operator_token="operator-token")
    client = TestClient(server.app, raise_server_exceptions=True)

    resp = client.get("/tools/list", headers={"Authorization": "Bearer operator-token"})
    assert resp.status_code == 401


def test_reset_falls_back_to_bearer_token_when_no_operator_token():
    """Single-token deployments keep working; startup refuses them outside dev mode."""
    server, session, _ = _make_token_server(operator_token=None)
    client = TestClient(server.app, raise_server_exceptions=True)

    resp = client.post(
        f"/sessions/{session.session_id}/reset",
        headers={"Authorization": "Bearer tool-token"},
    )
    assert resp.status_code == 200


# ── OPQ_P0006: the reset record carries the session boundary ──────────────────


def test_reset_audit_entry_identifies_both_sessions_and_the_credential():
    server, session, chain = _make_token_server(operator_token="operator-token")
    session.update_from_inspection("call-A", ["pii"], False, True)
    original_id = session.session_id

    client = TestClient(server.app, raise_server_exceptions=True)
    resp = client.post(
        f"/sessions/{original_id}/reset",
        headers={"Authorization": "Bearer operator-token"},
    )
    new_id = resp.json()["new_session_id"]

    entry = next(e for e in chain.entries if e.entry_type == "session_reset")
    assert entry.session_id == original_id
    assert entry.session_sensitivity_before == "pii"
    assert entry.session_sensitivity_after == "public"
    assert entry.detail["closed_session_id"] == original_id
    assert entry.detail["successor_session_id"] == new_id
    assert entry.detail["reset_count"] == 1
    assert entry.detail["credential_verified"] == "operator_token"
    assert entry.prev_entry_hash
    # detail is inside the canonical body, so these fields are hash-covered
    assert entry.entry_hash == entry.compute_hash()


def test_entries_after_a_reset_are_attributed_to_the_successor():
    """Before this, every later entry carried the closed session's identifier."""
    server, session, chain = _make_token_server(operator_token="operator-token")
    original_id = session.session_id

    client = TestClient(server.app, raise_server_exceptions=True)
    new_id = client.post(
        f"/sessions/{original_id}/reset",
        headers={"Authorization": "Bearer operator-token"},
    ).json()["new_session_id"]

    later = chain.append("session_start", policy_decision="n/a")
    assert later.session_id == new_id
    reset_entry = next(e for e in chain.entries if e.entry_type == "session_reset")
    assert reset_entry.session_id == original_id
    assert chain.verify_chain()


def test_closed_session_final_value_is_preserved_apart_from_the_successor():
    server, session, _ = _make_token_server(operator_token="operator-token")
    session.update_from_inspection("call-A", ["pii"], False, True)
    original_id = session.session_id

    client = TestClient(server.app, raise_server_exceptions=True)
    resp = client.post(
        f"/sessions/{original_id}/reset",
        headers={"Authorization": "Bearer operator-token"},
    )

    assert resp.json()["closed_session_max_sensitivity"] == "pii"
    assert session.max_sensitivity == "public"
    closed = server._closed_sessions[original_id]
    assert closed.session_id == original_id
    assert closed.max_sensitivity == "pii"
    assert closed.sensitivity_raised_by_call == "call-A"
    assert closed.authorized_by == "operator_token"
