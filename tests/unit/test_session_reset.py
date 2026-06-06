"""Tests for session reset endpoint (issue #92).

Covers:
- POST /sessions/{id}/reset returns 200 with old/new session IDs
- POST /sessions/{wrong_id}/reset returns 404
- Reset clears attestation_stale and catalog_drift flags
- Audit entry appended on reset
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient

from cmcp_gateway.audit.chain import AuditChain
from cmcp_gateway.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_gateway.config import AttestationConfig, Config, EnforcementMode
from cmcp_gateway.mcp.server import MCPServer
from cmcp_gateway.policy.evaluator import PolicyDecision, PolicyEvaluator
from cmcp_gateway.session.state import SessionState

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
    from cmcp_gateway.mcp.proxy import CMCPProxy

    cfg = Config()
    cfg.attestation = AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING)
    cat = _make_catalog()
    ev = _make_evaluator()
    session = SessionState(session_id=session_id)
    chain = AuditChain(session_id)

    with patch("cmcp_gateway.mcp.proxy.MCPGateway"), \
         patch("cmcp_gateway.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(cat, ev, session, chain, cfg)
        proxy._mcp_gateway = MagicMock()
        proxy._mcp_gateway.call_tool = AsyncMock(return_value=MagicMock(
            sensitivity_tags=[], injection_detected=False
        ))

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
    from cmcp_gateway.mcp.proxy import CMCPProxy

    cfg = Config()
    cfg.attestation = AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING)
    cat = _make_catalog()
    ev = _make_evaluator()
    session = SessionState(session_id="bare-sess")
    chain = AuditChain("bare-sess")

    with patch("cmcp_gateway.mcp.proxy.MCPGateway"), \
         patch("cmcp_gateway.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(cat, ev, session, chain, cfg)
        proxy._mcp_gateway = MagicMock()

    server = MCPServer(proxy)  # no session or audit_chain kwargs
    client = TestClient(server.app, raise_server_exceptions=True)
    resp = client.post("/sessions/bare-sess/reset")
    assert resp.status_code == 501
