"""Tests for break-glass catalog exception handling (issue #76)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    CatalogException,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.mcp.server import MCPServer
from cmcp_runtime.policy.evaluator import PolicyDecision, PolicyEvaluator
from cmcp_runtime.session.state import SessionState
from tests.unit.conftest import wire_mock_gateway

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_server_identity(url: str = "https://emergency.example.com/mcp") -> ServerIdentity:
    return ServerIdentity(
        display_name="Emergency Server",
        url=url,
        tls_fingerprint="SHA256:EMER/GENCY==",
        spiffe_id=None,
        transport="http-sse",
        rotation_mode="key-pinned",
    )


def _make_catalog(*tools: str) -> ToolCatalog:
    entries = {}
    for t in (tools or ("normal.tool",)):
        entries[t] = CatalogEntry(
            tool_name=t,
            server=_make_server_identity("https://normal.example.com/mcp"),
            approved_definition=ApprovedDefinition(description="normal", input_schema={}, output_schema=None),
            definition_hash="sha256:" + "0" * 64,
            compliance_domain="external",
            requires_baa=False,
            sensitivity_level="public",
            added_at="2026-06-01T00:00:00Z",
            approved_by="test",
        )
    return ToolCatalog(entries=entries, catalog_hash="sha256:" + "a" * 64)


def _make_proxy(catalog: ToolCatalog) -> MagicMock:
    evaluator = MagicMock(spec=PolicyEvaluator)
    decision = PolicyDecision(
        allowed=True,
        enforcement_mode=EnforcementMode.ENFORCING,
        rule_matched=None,
        advice={},
        evaluation_ms=0.1,
        would_have_denied=False,
    )
    evaluator.evaluate.return_value = decision
    evaluator.authorize_egress.return_value = decision

    proxy = MagicMock()
    proxy._catalog = catalog
    proxy.call_tool = AsyncMock(return_value=MagicMock(
        allowed=True,
        deny_reason=None,
        response="ok",
        audit_entry_hash="sha256:" + "0" * 64,
        would_have_denied=False,
        latency_us=100,
    ))
    return proxy


def _make_server(catalog: ToolCatalog | None = None, bearer_token: str | None = None) -> MCPServer:
    if catalog is None:
        catalog = _make_catalog()
    proxy = _make_proxy(catalog)
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
        return MCPServer(proxy, bearer_token=bearer_token)


# ── Unit: ToolCatalog.add_exception ──────────────────────────────────────────


def test_add_exception_does_not_change_catalog_hash():
    catalog = _make_catalog("normal.tool")
    original_hash = catalog.catalog_hash

    exc_entry = CatalogEntry(
        tool_name="emergency.tool",
        server=_make_server_identity(),
        approved_definition=ApprovedDefinition(description="emergency", input_schema={}, output_schema=None),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="external",
        requires_baa=False,
        sensitivity_level="public",
        added_at="",
        approved_by="ops-team",
    )
    catalog.add_exception(exc_entry, reason="P0 incident", authorized_by="ops@example.com")

    assert catalog.catalog_hash == original_hash


def test_add_exception_makes_entry_callable():
    catalog = _make_catalog()
    exc_entry = CatalogEntry(
        tool_name="emergency.tool",
        server=_make_server_identity(),
        approved_definition=ApprovedDefinition(description="emergency", input_schema={}, output_schema=None),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="external",
        requires_baa=False,
        sensitivity_level="public",
        added_at="",
        approved_by="ops@example.com",
    )
    catalog.add_exception(exc_entry, reason="incident", authorized_by="ops@example.com")

    found = catalog.lookup("emergency.tool")
    assert found is not None
    assert found.catalog_exception is True


def test_add_exception_records_metadata():
    catalog = _make_catalog()
    exc_entry = CatalogEntry(
        tool_name="emergency.tool",
        server=_make_server_identity(),
        approved_definition=ApprovedDefinition(description="emergency", input_schema={}, output_schema=None),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="external",
        requires_baa=False,
        sensitivity_level="public",
        added_at="",
        approved_by="ops@example.com",
    )
    catalog.add_exception(exc_entry, reason="P0 outage", authorized_by="on-call@example.com")

    assert len(catalog.exceptions) == 1
    exc = catalog.exceptions[0]
    assert isinstance(exc, CatalogException)
    assert exc.tool_name == "emergency.tool"
    assert exc.reason == "P0 outage"
    assert exc.authorized_by == "on-call@example.com"
    assert exc.added_at  # non-empty ISO timestamp


def test_multiple_exceptions_tracked():
    catalog = _make_catalog()
    for i in range(3):
        e = CatalogEntry(
            tool_name=f"emergency.tool.{i}",
            server=_make_server_identity(),
            approved_definition=ApprovedDefinition(description="x", input_schema={}, output_schema=None),
            definition_hash="sha256:" + "0" * 64,
            compliance_domain="external",
            requires_baa=False,
            sensitivity_level="public",
            added_at="",
            approved_by="ops",
        )
        catalog.add_exception(e, reason=f"reason {i}", authorized_by="ops")

    assert len(catalog.exceptions) == 3
    assert len(catalog.entries) == 4  # 1 normal + 3 exceptions


# ── Integration: POST /catalog/exception endpoint ────────────────────────────


_SI_PAYLOAD = {
    "display_name": "Emergency Server",
    "url": "https://emergency.example.com/mcp",
    "tls_fingerprint": "SHA256:EMER/GENCY==",
    "transport": "http-sse",
    "rotation_mode": "key-pinned",
}


def test_catalog_exception_endpoint_adds_tools():
    catalog = _make_catalog()
    server = _make_server(catalog)
    client = TestClient(server.app, raise_server_exceptions=False)

    resp = client.post("/catalog/exception", json={
        "server_identity": _SI_PAYLOAD,
        "reason": "P0 incident - fallback server required",
        "authorized_by": "on-call@example.com",
        "tool_names": ["emergency.search", "emergency.fetch"],
    })

    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "ok"
    assert "emergency.search" in body["added_tools"]
    assert "emergency.fetch" in body["added_tools"]
    assert catalog.lookup("emergency.search") is not None
    assert catalog.lookup("emergency.fetch") is not None


def test_catalog_exception_preserves_hash():
    catalog = _make_catalog()
    original_hash = catalog.catalog_hash
    server = _make_server(catalog)
    client = TestClient(server.app, raise_server_exceptions=False)

    client.post("/catalog/exception", json={
        "server_identity": _SI_PAYLOAD,
        "reason": "emergency",
        "authorized_by": "ops@example.com",
        "tool_names": ["emergency.tool"],
    })

    assert catalog.catalog_hash == original_hash


def test_catalog_exception_endpoint_missing_reason():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)

    resp = client.post("/catalog/exception", json={
        "server_identity": _SI_PAYLOAD,
        "authorized_by": "ops@example.com",
        "tool_names": ["t"],
    })

    assert resp.status_code == 422
    assert resp.json()["error_code"] == "MISSING_FIELD"


def test_catalog_exception_endpoint_missing_authorized_by():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)

    resp = client.post("/catalog/exception", json={
        "server_identity": _SI_PAYLOAD,
        "reason": "incident",
        "tool_names": ["t"],
    })

    assert resp.status_code == 422


def test_catalog_exception_endpoint_missing_tool_names():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)

    resp = client.post("/catalog/exception", json={
        "server_identity": _SI_PAYLOAD,
        "reason": "incident",
        "authorized_by": "ops@example.com",
        "tool_names": [],
    })

    assert resp.status_code == 422


def test_catalog_exception_endpoint_missing_server_identity():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)

    resp = client.post("/catalog/exception", json={
        "reason": "incident",
        "authorized_by": "ops@example.com",
        "tool_names": ["t"],
    })

    assert resp.status_code == 422


def test_catalog_exception_endpoint_bad_json():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)

    resp = client.post(
        "/catalog/exception",
        content=b"not json",
        headers={"Content-Type": "application/json"},
    )

    assert resp.status_code == 400
    assert resp.json()["error_code"] == "PARSE_ERROR"


# ── Integration: proxy logs BREAK_GLASS_ACTIVE ───────────────────────────────


def _make_real_proxy_for_break_glass():
    """Build a minimal CMCPProxy with one exception entry to test audit logging."""
    from cmcp_runtime.mcp.proxy import CMCPProxy

    catalog = _make_catalog()
    exc_entry = CatalogEntry(
        tool_name="emergency.tool",
        server=_make_server_identity(),
        approved_definition=ApprovedDefinition(description="emergency", input_schema={}, output_schema=None),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="external",
        requires_baa=False,
        sensitivity_level="public",
        added_at="",
        approved_by="ops@example.com",
    )
    catalog.add_exception(exc_entry, reason="test incident", authorized_by="ops@example.com")

    evaluator = MagicMock(spec=PolicyEvaluator)
    decision = PolicyDecision(
        allowed=True,
        enforcement_mode=EnforcementMode.ENFORCING,
        rule_matched=None,
        advice={},
        evaluation_ms=0.1,
        would_have_denied=False,
    )
    evaluator.evaluate.return_value = decision
    evaluator.authorize_egress.return_value = decision
    evaluator.bundle_hash = "sha256:" + "0" * 64
    evaluator.enforcement_mode = EnforcementMode.ENFORCING

    session = SessionState(session_id="test-session-id")
    chain = AuditChain(session_id="test-session-id")
    config = Config(
        attestation=AttestationConfig(
            provider="software-only",
            enforcement_mode=EnforcementMode.ENFORCING,
        )
    )

    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(
            catalog=catalog,
            policy_evaluator=evaluator,
            session=session,
            audit_chain=chain,
            config=config,
        )
        wire_mock_gateway(proxy, response_text="ok")

    return proxy, chain


@pytest.mark.asyncio
async def test_break_glass_call_logs_audit_entry():
    """Calls routed via a catalog exception produce a break_glass_used audit entry."""
    proxy, chain = _make_real_proxy_for_break_glass()
    await proxy.call_tool("call-1", "emergency.tool", {})

    entry_types = [e.entry_type for e in chain.entries]
    assert "break_glass_used" in entry_types


@pytest.mark.asyncio
async def test_break_glass_call_logs_warning(caplog):
    """BREAK_GLASS_ACTIVE is logged as a warning."""
    import logging
    proxy, _ = _make_real_proxy_for_break_glass()

    with caplog.at_level(logging.WARNING, logger="cmcp_runtime.mcp.proxy"):
        await proxy.call_tool("call-1", "emergency.tool", {})

    assert any("BREAK_GLASS_ACTIVE" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_normal_tool_no_break_glass_audit_entry():
    """Normal catalog entries do not produce a break_glass_used audit entry."""
    proxy, chain = _make_real_proxy_for_break_glass()
    await proxy.call_tool("call-1", "normal.tool", {})

    entry_types = [e.entry_type for e in chain.entries]
    assert "break_glass_used" not in entry_types
