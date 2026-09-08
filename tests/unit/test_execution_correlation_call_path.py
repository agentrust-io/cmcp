"""Unavailable execution correlation fails closed at ingress and in the proxy."""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
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

AGENT = "spiffe://example.org/agent-a"


def _decision() -> PolicyDecision:
    return PolicyDecision(
        allowed=True,
        enforcement_mode=EnforcementMode.ENFORCING,
        rule_matched=None,
        advice={},
        evaluation_ms=0.1,
        would_have_denied=False,
    )


def _evaluator() -> PolicyEvaluator:
    evaluator = MagicMock(spec=PolicyEvaluator)
    evaluator.evaluate.return_value = _decision()
    evaluator.authorize_egress.return_value = _decision()
    evaluator.bundle_hash = "sha256:" + "0" * 64
    evaluator.enforcement_mode = EnforcementMode.ENFORCING
    return evaluator


def _make_proxy(chain: AuditChain, mode=EnforcementMode.ENFORCING):
    from cmcp_runtime.mcp.proxy import CMCPProxy

    entry = CatalogEntry(
        tool_name="billing.charge",
        server=ServerIdentity(
            display_name="Local",
            url="https://local.invalid/mcp",
            tls_fingerprint="SHA256:" + "A" * 43 + "=",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description="charge", input_schema={}, output_schema=None
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="public",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-08-25T00:00:00Z",
        approved_by="issue-565",
    )
    catalog = ToolCatalog(entries={"billing.charge": entry}, catalog_hash="sha256:" + "1" * 64)
    config = Config(attestation=AttestationConfig(enforcement_mode=mode))
    with (
        patch("cmcp_runtime.mcp.proxy.MCPGateway") as gateway,
        patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"),
    ):
        scan = MagicMock()
        scan.allowed = True
        scan.threats = []
        scan.content = None
        gateway.return_value.intercept_tool_call.return_value = (True, None)
        gateway.return_value.intercept_tool_response.return_value = scan
        proxy = CMCPProxy(
            catalog,
            _evaluator(),
            SessionState(session_id="s-565"),
            chain,
            config,
        )
    proxy._check_upstream_drift = AsyncMock(return_value=False)
    proxy._forward_to_upstream = AsyncMock(return_value='{"ok": true}')
    return proxy


def _tool_entries(chain: AuditChain):
    return [e for e in chain.entries if e.entry_type in ("tool_call", "fault", "egress_denied")]


@pytest.mark.asyncio
@pytest.mark.parametrize("metadata,allowed,reason,audit_id", [
    ({"execution_id": 17}, False, "execution_invalid_execution_id", None),
    ({"execution_id": True}, False, "execution_invalid_execution_id", None),
    ({"execution_id": []}, False, "execution_invalid_execution_id", None),
    ({"execution_id": {}}, False, "execution_invalid_execution_id", None),
    ({"execution_id": None}, False, "execution_invalid_execution_id", None),
    ({"execution_id": ""}, False, "execution_invalid_execution_id", None),
    ({"execution_id": "has space"}, False, "execution_invalid_execution_id", None),
    ({"execution_id": "x" * 201}, False, "execution_invalid_execution_id", None),
    ({"execution_id": "valid-id"}, False, "execution_correlation_unavailable", "valid-id"),
    ({}, True, None, None),
])
async def test_http_execution_identity_validation(metadata, allowed, reason, audit_id):
    from cmcp_runtime.mcp.server import MCPServer

    chain = AuditChain(session_id="s-565")
    proxy = _make_proxy(chain)
    transport = httpx.ASGITransport(app=MCPServer(proxy).app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "billing.charge", "arguments": {"amount": 100},
                       "_cmcp": metadata},
        })
    assert response.status_code == (200 if allowed else 403)
    assert proxy._forward_to_upstream.await_count == int(allowed)
    assert len(_tool_entries(chain)) == 1
    assert _tool_entries(chain)[0].execution_id == audit_id
    if reason:
        expected_rule = (
            "execution:unavailable" if audit_id else "execution:invalid_execution_id"
        )
        assert _tool_entries(chain)[0].policy_rule_matched == expected_rule


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", list(EnforcementMode))
@pytest.mark.parametrize("execution_id,reason", [
    ("valid-id", "execution_correlation_unavailable"),
    ("", "execution_invalid_execution_id"),
    ("x\ny", "execution_invalid_execution_id"),
])
async def test_direct_proxy_calls_cannot_enable_execution(execution_id, reason, mode):
    chain = AuditChain(session_id="s-565")
    proxy = _make_proxy(chain, mode)
    for amount in (100, 999):
        result = await proxy.call_tool("c1", "billing.charge", {"amount": amount},
                                       execution_id=execution_id)
        assert not result.allowed
        assert result.deny_reason == reason
    proxy._forward_to_upstream.assert_not_awaited()
    assert len(_tool_entries(chain)) == 2


@pytest.mark.asyncio
async def test_execution_refusal_precedes_unknown_tool_lookup_and_discovery():
    """A supplied ID is refused and audited before an unknown tool is resolved."""
    chain = AuditChain(session_id="s-565")
    proxy = _make_proxy(chain)
    lookup = MagicMock(wraps=proxy._catalog.lookup)
    proxy._catalog.lookup = lookup

    result = await proxy.call_tool(
        "unknown-call",
        "unknown.tool",
        {"amount": 100},
        workflow_id="wf-565",
        execution_id="valid-id",
    )

    assert not result.allowed
    assert result.deny_reason == "execution_correlation_unavailable"
    lookup.assert_not_called()
    proxy._check_upstream_drift.assert_not_awaited()
    proxy._forward_to_upstream.assert_not_awaited()

    [entry] = _tool_entries(chain)
    assert entry.call_id == "unknown-call"
    assert entry.tool_name == "unknown.tool"
    assert entry.server_identity is None
    assert entry.workflow_id == "wf-565"
    assert entry.execution_id == "valid-id"
    expected_hash = "sha256:" + hashlib.sha256(b'{"amount":100}').hexdigest()
    assert entry.request_payload_hash == expected_hash
    assert entry.policy_rule_matched == "execution:unavailable"


@pytest.mark.asyncio
async def test_execution_refusal_precedes_upstream_drift_discovery():
    """A supplied ID is refused before catalog or upstream drift discovery."""
    chain = AuditChain(session_id="s-565")
    proxy = _make_proxy(chain)
    lookup = MagicMock(wraps=proxy._catalog.lookup)
    proxy._catalog.lookup = lookup
    proxy._check_upstream_drift = AsyncMock(return_value=True)

    result = await proxy.call_tool(
        "drift-call",
        "billing.charge",
        {"amount": 100},
        execution_id="valid-id",
    )

    assert not result.allowed
    assert result.deny_reason == "execution_correlation_unavailable"
    lookup.assert_not_called()
    proxy._check_upstream_drift.assert_not_awaited()
    proxy._forward_to_upstream.assert_not_awaited()

    [entry] = _tool_entries(chain)
    assert entry.tool_name == "billing.charge"
    assert entry.server_identity is None
    assert entry.execution_id == "valid-id"
    assert entry.policy_rule_matched == "execution:unavailable"


@pytest.mark.asyncio
async def test_execution_refusal_precedes_existing_catalog_drift_health_failure():
    """A supplied ID is audited even when the session is already unhealthy."""
    chain = AuditChain(session_id="s-565")
    proxy = _make_proxy(chain)
    lookup = MagicMock(wraps=proxy._catalog.lookup)
    proxy._catalog.lookup = lookup
    proxy._session.catalog_drift = True

    result = await proxy.call_tool(
        "drifted-call",
        "billing.charge",
        {"amount": 100},
        execution_id="valid-id",
    )

    assert not result.allowed
    assert result.deny_reason == "execution_correlation_unavailable"
    lookup.assert_not_called()
    proxy._check_upstream_drift.assert_not_awaited()
    proxy._forward_to_upstream.assert_not_awaited()

    [entry] = _tool_entries(chain)
    assert entry.call_id == "drifted-call"
    assert entry.tool_name == "billing.charge"
    assert entry.server_identity is None
    assert entry.execution_id == "valid-id"
    assert entry.policy_rule_matched == "execution:unavailable"
