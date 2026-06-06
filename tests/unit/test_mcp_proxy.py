"""Tests for CMCPProxy (issues #48, #53, #54)."""

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


def _make_evaluator(allow: bool = True, would_deny: bool = False) -> PolicyEvaluator:
    evaluator = MagicMock(spec=PolicyEvaluator)
    if allow:
        evaluator.evaluate.return_value = PolicyDecision(
            allowed=True,
            enforcement_mode=EnforcementMode.ENFORCING,
            rule_matched=None,
            advice={},
            evaluation_ms=0.1,
            would_have_denied=would_deny,
        )
    else:
        evaluator.evaluate.side_effect = PolicyDeny("denied by Cedar")
    # authorize_egress always allows in ingress-focused proxy tests
    evaluator.authorize_egress.return_value = PolicyDecision(
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


def _make_proxy(catalog=None, evaluator=None, mode=EnforcementMode.ENFORCING):
    from cmcp_gateway.mcp.proxy import CMCPProxy

    cfg = Config()
    cfg.attestation = AttestationConfig(enforcement_mode=mode)
    cat = catalog or _make_catalog()
    ev = evaluator or _make_evaluator()
    session = SessionState(session_id="sess-001")
    chain = AuditChain("sess-001")

    with patch("cmcp_gateway.mcp.proxy.MCPGateway"), \
         patch("cmcp_gateway.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(cat, ev, session, chain, cfg)
        proxy._mcp_gateway = MagicMock()
        proxy._mcp_gateway.call_tool = AsyncMock(return_value=MagicMock(
            sensitivity_tags=[], injection_detected=False
        ))
    return proxy, session, chain


@pytest.mark.asyncio
async def test_proxy_allows_known_tool():
    proxy, _, _ = _make_proxy()
    result = await proxy.call_tool("c1", "test.tool", {"q": "hello"})
    assert result.allowed is True
    assert result.deny_reason is None


@pytest.mark.asyncio
async def test_proxy_denies_unknown_tool():
    proxy, _, _ = _make_proxy()
    result = await proxy.call_tool("c1", "unknown.tool", {})
    assert result.allowed is False
    assert "not in attested catalog" in (result.deny_reason or "")


@pytest.mark.asyncio
async def test_proxy_denies_when_cedar_denies():
    evaluator = _make_evaluator(allow=False)
    proxy, _, _ = _make_proxy(evaluator=evaluator)
    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.allowed is False


@pytest.mark.asyncio
async def test_proxy_writes_audit_entry_on_allow():
    proxy, _, chain = _make_proxy()
    initial_length = chain.length
    await proxy.call_tool("c1", "test.tool", {})
    assert chain.length > initial_length


@pytest.mark.asyncio
async def test_proxy_writes_audit_entry_on_catalog_deny():
    proxy, _, chain = _make_proxy()
    initial_length = chain.length
    await proxy.call_tool("c1", "nonexistent.tool", {})
    assert chain.length > initial_length


@pytest.mark.asyncio
async def test_proxy_writes_audit_entry_on_policy_deny():
    evaluator = _make_evaluator(allow=False)
    proxy, _, chain = _make_proxy(evaluator=evaluator)
    initial_length = chain.length
    await proxy.call_tool("c1", "test.tool", {})
    assert chain.length > initial_length


@pytest.mark.asyncio
async def test_proxy_updates_session_state_on_allow():
    entry = _make_entry()
    entry.sensitivity_level = "pii"
    catalog = ToolCatalog(entries={"test.tool": entry}, catalog_hash="sha256:" + "1" * 64)
    proxy, session, _ = _make_proxy(catalog=catalog)

    proxy._mcp_gateway.call_tool = AsyncMock(return_value=MagicMock(
        sensitivity_tags=["pii"], injection_detected=False
    ))

    assert session.max_sensitivity == "public"
    await proxy.call_tool("c1", "test.tool", {})
    assert session.max_sensitivity == "pii"


@pytest.mark.asyncio
async def test_proxy_advisory_deny_returns_allowed_with_flag():
    evaluator = _make_evaluator(allow=True, would_deny=True)
    proxy, _, _ = _make_proxy(evaluator=evaluator, mode=EnforcementMode.ADVISORY)
    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.allowed is True
    assert result.would_have_denied is True


@pytest.mark.asyncio
async def test_proxy_audit_entry_has_correct_policy_decision_advisory():
    evaluator = _make_evaluator(allow=True, would_deny=True)
    proxy, _, chain = _make_proxy(evaluator=evaluator, mode=EnforcementMode.ADVISORY)
    await proxy.call_tool("c1", "test.tool", {})
    tool_entries = [e for e in chain.entries if e.entry_type == "tool_call"]
    assert tool_entries[-1].policy_decision == "advisory_deny"


@pytest.mark.asyncio
async def test_proxy_audit_entry_has_correct_policy_decision_allow():
    proxy, _, chain = _make_proxy()
    await proxy.call_tool("c1", "test.tool", {})
    tool_entries = [e for e in chain.entries if e.entry_type == "tool_call"]
    assert tool_entries[-1].policy_decision == "allow"


@pytest.mark.asyncio
async def test_proxy_result_contains_audit_entry_hash():
    proxy, _, chain = _make_proxy()
    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.audit_entry_hash == chain.chain_tip


# ── POLICY-004: Cedar context includes arguments ──────────────────────────────

@pytest.mark.asyncio
async def test_cedar_context_includes_arguments():
    """POLICY-004 — arguments must appear in the Cedar context so policies can inspect them."""
    evaluator = _make_evaluator()
    proxy, _, _ = _make_proxy(evaluator=evaluator)
    args = {"patient_id": "p-123", "action": "read"}
    await proxy.call_tool("c1", "test.tool", args)
    ctx = evaluator.evaluate.call_args[0][0]
    assert ctx["arguments"] == args


# ── POLICY-005: request_payload_hash in all audit entries ────────────────────

@pytest.mark.asyncio
async def test_audit_payload_hash_present_on_allow():
    """POLICY-005 — successful calls must record request_payload_hash in the audit entry."""
    proxy, _, chain = _make_proxy()
    await proxy.call_tool("c1", "test.tool", {"k": "v"})
    entry = next(e for e in reversed(chain.entries) if e.entry_type == "tool_call")
    assert entry.request_payload_hash is not None
    assert entry.request_payload_hash.startswith("sha256:")


@pytest.mark.asyncio
async def test_audit_payload_hash_present_on_catalog_deny():
    """POLICY-005 — catalog-miss denials must record request_payload_hash."""
    proxy, _, chain = _make_proxy()
    await proxy.call_tool("c1", "ghost.tool", {"x": 1})
    entry = next(e for e in reversed(chain.entries) if e.entry_type == "tool_call")
    assert entry.request_payload_hash is not None
    assert entry.request_payload_hash.startswith("sha256:")


@pytest.mark.asyncio
async def test_audit_payload_hash_present_on_cedar_deny():
    """POLICY-005 — Cedar policy denials must record request_payload_hash."""
    evaluator = _make_evaluator(allow=False)
    proxy, _, chain = _make_proxy(evaluator=evaluator)
    await proxy.call_tool("c1", "test.tool", {"secret": "leak"})
    entry = next(e for e in reversed(chain.entries) if e.entry_type == "tool_call")
    assert entry.request_payload_hash is not None
    assert entry.request_payload_hash.startswith("sha256:")


@pytest.mark.asyncio
async def test_audit_payload_hash_is_canonical_sha256():
    """POLICY-005 — payload hash must be sha256 of canonical JSON (sort_keys, no spaces)."""
    import hashlib
    import json

    proxy, _, chain = _make_proxy()
    args = {"b": 2, "a": 1}
    await proxy.call_tool("c1", "test.tool", args)
    entry = next(e for e in reversed(chain.entries) if e.entry_type == "tool_call")
    expected_bytes = json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
    expected = f"sha256:{hashlib.sha256(expected_bytes).hexdigest()}"
    assert entry.request_payload_hash == expected


# ── POLICY-003: Cedar exception writes fault audit entry ──────────────────────

@pytest.mark.asyncio
async def test_cedar_exception_writes_fault_audit_entry():
    """POLICY-003 — Cedar backend exception must emit a fault audit entry before re-raising."""
    evaluator = MagicMock(spec=_make_evaluator().__class__)
    evaluator.evaluate.side_effect = RuntimeError("malformed Cedar policy")
    evaluator.authorize_egress.return_value = MagicMock(would_have_denied=False)
    evaluator.bundle_hash = "sha256:" + "0" * 64
    evaluator.enforcement_mode = EnforcementMode.ENFORCING

    proxy, _, chain = _make_proxy(evaluator=evaluator)

    with pytest.raises(RuntimeError):
        await proxy.call_tool("c1", "test.tool", {"x": 1})

    fault_entries = [e for e in chain.entries if e.entry_type == "fault"]
    assert len(fault_entries) == 1
    assert fault_entries[0].policy_decision == "fault"
    assert "RuntimeError" in (fault_entries[0].policy_rule_matched or "")
    assert fault_entries[0].request_payload_hash is not None
