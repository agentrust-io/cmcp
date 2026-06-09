"""Tests for per-workflow Cedar policy scope (issue #79)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.policy.evaluator import PolicyDecision, PolicyEvaluator
from cmcp_runtime.session.state import SessionState

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_entry(tool_name: str = "test.tool") -> CatalogEntry:
    return CatalogEntry(
        tool_name=tool_name,
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


def _make_catalog(*tools: str) -> ToolCatalog:
    entries = {t: _make_entry(t) for t in (tools or ("test.tool",))}
    return ToolCatalog(entries=entries, catalog_hash="sha256:" + "1" * 64)


def _make_evaluator() -> PolicyEvaluator:
    _decision = PolicyDecision(
        allowed=True,
        enforcement_mode=EnforcementMode.ENFORCING,
        rule_matched=None,
        advice={},
        evaluation_ms=0.1,
        would_have_denied=False,
    )
    evaluator = MagicMock(spec=PolicyEvaluator)
    evaluator.evaluate.return_value = _decision
    evaluator.authorize_egress.return_value = _decision
    evaluator.bundle_hash = "sha256:" + "0" * 64
    evaluator.enforcement_mode = EnforcementMode.ENFORCING
    return evaluator


def _make_proxy(evaluator=None):
    from cmcp_runtime.mcp.proxy import CMCPProxy

    cfg = Config()
    cfg.attestation = AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING)
    cat = _make_catalog()
    ev = evaluator or _make_evaluator()
    session = SessionState(session_id="sess-wf-001")
    chain = AuditChain("sess-wf-001")

    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(cat, ev, session, chain, cfg)
        proxy._mcp_gateway = MagicMock()
        proxy._mcp_gateway.call_tool = AsyncMock(return_value=MagicMock(
            sensitivity_tags=[], injection_detected=False
        ))
    return proxy, ev, chain


# ── Cedar context tests ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_workflow_id_omits_key_from_cedar_context():
    """Without workflow_id, the Cedar context should not contain a workflow_id key."""
    proxy, evaluator, _ = _make_proxy()
    await proxy.call_tool("c1", "test.tool", {})

    evaluator.evaluate.assert_called_once()
    ctx = evaluator.evaluate.call_args[0][0]
    assert "workflow_id" not in ctx


@pytest.mark.asyncio
async def test_workflow_id_included_in_cedar_context():
    """When workflow_id is provided, it appears in the Cedar context dict."""
    proxy, evaluator, _ = _make_proxy()
    await proxy.call_tool("c1", "test.tool", {}, workflow_id="workflow_x")

    evaluator.evaluate.assert_called_once()
    ctx = evaluator.evaluate.call_args[0][0]
    assert ctx.get("workflow_id") == "workflow_x"


# ── Audit entry tests ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_entry_has_no_workflow_id_when_not_provided():
    """Audit entry workflow_id is None when call_tool is invoked without one."""
    proxy, _, chain = _make_proxy()
    await proxy.call_tool("c1", "test.tool", {})

    tool_entries = [e for e in chain.entries if e.entry_type == "tool_call"]
    assert len(tool_entries) == 1
    assert tool_entries[0].workflow_id is None


@pytest.mark.asyncio
async def test_audit_entry_records_workflow_id():
    """Audit entry workflow_id is set when call_tool is invoked with workflow_id."""
    proxy, _, chain = _make_proxy()
    await proxy.call_tool("c1", "test.tool", {}, workflow_id="workflow_x")

    tool_entries = [e for e in chain.entries if e.entry_type == "tool_call"]
    assert len(tool_entries) == 1
    assert tool_entries[0].workflow_id == "workflow_x"


@pytest.mark.asyncio
async def test_audit_chain_still_valid_with_workflow_id():
    """Audit chain hash integrity holds after a call with workflow_id."""
    proxy, _, chain = _make_proxy()
    await proxy.call_tool("c1", "test.tool", {}, workflow_id="workflow_x")
    assert chain.verify_chain()


# ── MCPServer integration ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_server_extracts_workflow_id_from_cmcp_params():
    """MCPServer passes workflow_id from request _cmcp field to call_tool."""
    from starlette.testclient import TestClient

    from cmcp_runtime.mcp.server import MCPServer

    proxy, _, chain = _make_proxy()
    # Wrap call_tool so we can inspect arguments
    original = proxy.call_tool
    captured: dict = {}

    async def _spy(call_id, tool_name, arguments, *, workflow_id=None):
        captured["workflow_id"] = workflow_id
        return await original(call_id, tool_name, arguments, workflow_id=workflow_id)

    proxy.call_tool = _spy

    server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=True)

    resp = client.post("/mcp", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "test.tool",
            "arguments": {},
            "_cmcp": {"workflow_id": "workflow_x"},
        },
    })
    assert resp.status_code == 200
    assert captured.get("workflow_id") == "workflow_x"


@pytest.mark.asyncio
async def test_server_response_includes_workflow_id_when_provided():
    """MCPServer echoes workflow_id in the response _cmcp block."""
    from starlette.testclient import TestClient

    from cmcp_runtime.mcp.server import MCPServer

    proxy, _, _ = _make_proxy()
    server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=True)

    resp = client.post("/mcp", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "test.tool",
            "arguments": {},
            "_cmcp": {"workflow_id": "workflow_x"},
        },
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["_cmcp"]["workflow_id"] == "workflow_x"


@pytest.mark.asyncio
async def test_server_response_omits_workflow_id_when_not_provided():
    """MCPServer does not include workflow_id in _cmcp if not in request."""
    from starlette.testclient import TestClient

    from cmcp_runtime.mcp.server import MCPServer

    proxy, _, _ = _make_proxy()
    server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=True)

    resp = client.post("/mcp", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "test.tool",
            "arguments": {},
        },
    })
    assert resp.status_code == 200
    body = resp.json()
    assert "workflow_id" not in body["result"]["_cmcp"]
