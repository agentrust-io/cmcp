"""Integration tests: CallLog wired into CMCPProxy (issue #94)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cmcp_gateway.audit.chain import AuditChain
from cmcp_gateway.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_gateway.config import AttestationConfig, Config, EnforcementMode
from cmcp_gateway.errors import PolicyDeny
from cmcp_gateway.policy.evaluator import PolicyDecision, PolicyEvaluator
from cmcp_gateway.session.call_log import CallLog
from cmcp_gateway.session.state import SessionState


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


def _make_evaluator(allow: bool = True) -> PolicyEvaluator:
    evaluator = MagicMock(spec=PolicyEvaluator)
    if allow:
        evaluator.evaluate.return_value = PolicyDecision(
            allowed=True,
            enforcement_mode=EnforcementMode.ENFORCING,
            rule_matched=None,
            advice={},
            evaluation_ms=0.1,
            would_have_denied=False,
        )
    else:
        evaluator.evaluate.side_effect = PolicyDeny("denied by Cedar")
    evaluator.bundle_hash = "sha256:" + "0" * 64
    evaluator.enforcement_mode = EnforcementMode.ENFORCING
    return evaluator


def _make_proxy(catalog=None, evaluator=None, call_log=None):
    from cmcp_gateway.mcp.proxy import CMCPProxy

    cfg = Config()
    cfg.attestation = AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING)
    cat = catalog or _make_catalog()
    ev = evaluator or _make_evaluator()
    session = SessionState(session_id="sess-001")
    chain = AuditChain("sess-001")

    with patch("cmcp_gateway.mcp.proxy.MCPGateway"), \
         patch("cmcp_gateway.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(cat, ev, session, chain, cfg, call_log=call_log)
        proxy._mcp_gateway = MagicMock()
        proxy._mcp_gateway.call_tool = AsyncMock(return_value=MagicMock(
            sensitivity_tags=[], injection_detected=False
        ))
    return proxy, session, chain


# ── proxy records call after each tool call ───────────────────────────────────

@pytest.mark.asyncio
async def test_proxy_records_call_after_allow():
    log = CallLog(session_id="sess-001")
    proxy, _, _ = _make_proxy(call_log=log)
    await proxy.call_tool("c1", "test.tool", {})
    assert len(log.records) == 1
    assert log.records[0].tool_name == "test.tool"
    assert log.records[0].allowed is True


@pytest.mark.asyncio
async def test_proxy_records_call_on_catalog_deny():
    log = CallLog(session_id="sess-001")
    proxy, _, _ = _make_proxy(call_log=log)
    await proxy.call_tool("c1", "nonexistent.tool", {})
    assert len(log.records) == 1
    assert log.records[0].allowed is False


@pytest.mark.asyncio
async def test_proxy_records_call_on_policy_deny():
    log = CallLog(session_id="sess-001")
    ev = _make_evaluator(allow=False)
    proxy, _, _ = _make_proxy(evaluator=ev, call_log=log)
    await proxy.call_tool("c1", "test.tool", {})
    assert len(log.records) == 1
    assert log.records[0].allowed is False


@pytest.mark.asyncio
async def test_proxy_accumulates_multiple_calls():
    log = CallLog(session_id="sess-001")
    proxy, _, _ = _make_proxy(call_log=log)
    await proxy.call_tool("c1", "test.tool", {})
    await proxy.call_tool("c2", "test.tool", {})
    await proxy.call_tool("c3", "test.tool", {})
    assert len(log.records) == 3


# ── suspicious sequence detection increments session.suspicious_sequences ─────

@pytest.mark.asyncio
async def test_suspicious_sequence_increments_session_counter():
    log = CallLog(session_id="sess-001")
    proxy, session, _ = _make_proxy(call_log=log)
    # Call the same tool 4 times (threshold=3 → suspicious after 4th)
    for i in range(4):
        await proxy.call_tool(f"c{i}", "test.tool", {})
    assert session.suspicious_sequences >= 1


# ── audit entry appended on suspicious detection ──────────────────────────────

@pytest.mark.asyncio
async def test_suspicious_sequence_writes_audit_entry():
    log = CallLog(session_id="sess-001")
    proxy, _, chain = _make_proxy(call_log=log)
    for i in range(4):
        await proxy.call_tool(f"c{i}", "test.tool", {})
    suspicious_entries = [
        e for e in chain.entries if e.entry_type == "suspicious_call_sequence"
    ]
    assert len(suspicious_entries) >= 1
    assert suspicious_entries[0].tool_name == "test.tool"
    assert suspicious_entries[0].detail is not None
    assert suspicious_entries[0].detail["repeated_tool"] == "test.tool"


@pytest.mark.asyncio
async def test_no_suspicious_entry_when_below_threshold():
    log = CallLog(session_id="sess-001")
    proxy, session, chain = _make_proxy(call_log=log)
    # 3 calls: at threshold but not over — not suspicious
    for i in range(3):
        await proxy.call_tool(f"c{i}", "test.tool", {})
    suspicious_entries = [
        e for e in chain.entries if e.entry_type == "suspicious_call_sequence"
    ]
    assert len(suspicious_entries) == 0
    assert session.suspicious_sequences == 0


# ── default call_log created when none provided ───────────────────────────────

@pytest.mark.asyncio
async def test_proxy_creates_default_call_log():
    proxy, _, _ = _make_proxy()
    assert proxy._call_log is not None
    assert proxy._call_log.session_id == "sess-001"
    await proxy.call_tool("c1", "test.tool", {})
    assert len(proxy._call_log.records) == 1
