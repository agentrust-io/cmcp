"""Tests for Cedar egress policy enforcement with session state (issue #90)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.errors import PolicyDeny
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyManifest
from cmcp_runtime.policy.evaluator import PolicyDecision, PolicyEvaluator
from cmcp_runtime.session.state import SessionState
from tests.unit.conftest import wire_mock_gateway

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_bundle() -> PolicyBundle:
    return PolicyBundle(
        manifest=PolicyManifest(
            version="1.0.0",
            authored_at="2026-06-05T00:00:00Z",
            author_identity="test",
            commit_sha="abc",
        ),
        policy_files={"allow.cedar": "permit(principal, action, resource);"},
        schema_content='{"cMCP": {}}',
        bundle_hash="sha256:" + "0" * 64,
    )


def _make_config(mode: EnforcementMode = EnforcementMode.ENFORCING) -> Config:
    cfg = Config()
    cfg.attestation = AttestationConfig(enforcement_mode=mode)
    return cfg


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


def _make_proxy_with_egress(egress_allow: bool, ingress_allow: bool = True):
    """
    Build a CMCPProxy where the evaluator returns different decisions for
    ingress vs. egress calls.  Egress calls carry egress=True in their context.
    """
    from cmcp_runtime.mcp.proxy import CMCPProxy

    cfg = _make_config(EnforcementMode.ENFORCING)
    catalog = _make_catalog()
    session = SessionState(session_id="sess-egress")
    chain = AuditChain("sess-egress")

    def _side_effect(context: dict) -> PolicyDecision:
        if context.get("egress"):
            if egress_allow:
                return PolicyDecision(
                    allowed=True,
                    enforcement_mode=EnforcementMode.ENFORCING,
                    rule_matched=None,
                    advice={},
                    evaluation_ms=0.1,
                )
            raise PolicyDeny("egress denied by Cedar policy")
        # ingress
        if ingress_allow:
            return PolicyDecision(
                allowed=True,
                enforcement_mode=EnforcementMode.ENFORCING,
                rule_matched=None,
                advice={},
                evaluation_ms=0.1,
            )
        raise PolicyDeny("ingress denied by Cedar policy")

    evaluator = MagicMock(spec=PolicyEvaluator)
    evaluator.evaluate.side_effect = _side_effect
    # authorize_egress delegates to evaluate() — wire it the same way
    evaluator.authorize_egress.side_effect = lambda tool, resp, sess: _side_effect(
        {"egress": True, "tool_name": tool}
    )
    evaluator.bundle_hash = "sha256:" + "0" * 64
    evaluator.enforcement_mode = EnforcementMode.ENFORCING

    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(catalog, evaluator, session, chain, cfg)
        wire_mock_gateway(proxy)

    return proxy, session, chain, evaluator


# ── Tests: authorize_egress on PolicyEvaluator ────────────────────────────────

def test_authorize_egress_default_policy_allows():
    """Default permit-all policy allows every egress response."""
    with patch("cmcp_runtime.policy.evaluator.CedarBackend") as MockBackend:
        mock = MagicMock()
        mock.evaluate.return_value = MagicMock(
            allowed=True, reason=None, evaluation_ms=0.1
        )
        MockBackend.return_value = mock

        evaluator = PolicyEvaluator(_make_bundle(), _make_config())
        session = SessionState(session_id="s1")
        decision = evaluator.authorize_egress("some.tool", b'{"ok": true}', session)

    assert decision.allowed is True
    assert decision.would_have_denied is False


def test_authorize_egress_passes_sensitivity_level_in_context():
    """authorize_egress translates session.max_sensitivity to an int in context."""
    with patch("cmcp_runtime.policy.evaluator.CedarBackend") as MockBackend:
        mock = MagicMock()
        mock.evaluate.return_value = MagicMock(
            allowed=True, reason=None, evaluation_ms=0.1
        )
        MockBackend.return_value = mock

        evaluator = PolicyEvaluator(_make_bundle(), _make_config())
        session = SessionState(session_id="s2", max_sensitivity="pii")
        evaluator.authorize_egress("crm.query", b"data", session)

    called_ctx = mock.evaluate.call_args[0][0]
    assert called_ctx["sensitivity_level"] == 1  # "pii" -> 1
    assert called_ctx["egress"] is True
    assert called_ctx["response_size_bytes"] == len(b"data")


def test_authorize_egress_passes_injection_and_reset_counts():
    """injection_events count and reset_count are forwarded to Cedar context."""
    with patch("cmcp_runtime.policy.evaluator.CedarBackend") as MockBackend:
        mock = MagicMock()
        mock.evaluate.return_value = MagicMock(
            allowed=True, reason=None, evaluation_ms=0.1
        )
        MockBackend.return_value = mock

        evaluator = PolicyEvaluator(_make_bundle(), _make_config())
        session = SessionState(session_id="s3", reset_count=2)
        # Simulate two injection events
        session.update_from_inspection("c1", [], injection_detected=True, response_allowed=True)
        session.update_from_inspection("c2", [], injection_detected=True, response_allowed=True)

        evaluator.authorize_egress("tool.x", b"bytes", session)

    ctx = mock.evaluate.call_args[0][0]
    assert ctx["injection_events"] == 2
    assert ctx["reset_count"] == 2


def test_authorize_egress_deny_enforcing_raises():
    """In ENFORCING mode a Cedar deny on egress raises PolicyDeny."""
    with patch("cmcp_runtime.policy.evaluator.CedarBackend") as MockBackend:
        mock = MagicMock()
        mock.evaluate.return_value = MagicMock(
            allowed=False, reason="egress-forbid", evaluation_ms=0.2
        )
        MockBackend.return_value = mock

        evaluator = PolicyEvaluator(_make_bundle(), _make_config(EnforcementMode.ENFORCING))
        session = SessionState(session_id="s4", max_sensitivity="hipaa_phi")

        with pytest.raises(PolicyDeny):
            evaluator.authorize_egress("phi.tool", b"sensitive data", session)


def test_authorize_egress_deny_advisory_flags_would_have_denied():
    """In ADVISORY mode a Cedar deny on egress sets would_have_denied=True."""
    with patch("cmcp_runtime.policy.evaluator.CedarBackend") as MockBackend:
        mock = MagicMock()
        mock.evaluate.return_value = MagicMock(
            allowed=False, reason="egress-forbid", evaluation_ms=0.2
        )
        MockBackend.return_value = mock

        evaluator = PolicyEvaluator(_make_bundle(), _make_config(EnforcementMode.ADVISORY))
        session = SessionState(session_id="s5", max_sensitivity="confidential")
        decision = evaluator.authorize_egress("secret.tool", b"data", session)

    assert decision.allowed is True
    assert decision.would_have_denied is True


# ── Tests: CMCPProxy egress integration ───────────────────────────────────────

@pytest.mark.asyncio
async def test_proxy_egress_allow_returns_result():
    """When egress policy allows, call_tool returns allowed=True."""
    proxy, _, _, _ = _make_proxy_with_egress(egress_allow=True)
    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.allowed is True
    assert result.deny_reason is None


@pytest.mark.asyncio
async def test_proxy_egress_deny_returns_denied():
    """When egress policy denies, call_tool returns allowed=False."""
    proxy, _, _, _ = _make_proxy_with_egress(egress_allow=False)
    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.allowed is False
    assert result.deny_reason is not None


@pytest.mark.asyncio
async def test_proxy_egress_deny_writes_audit_entry():
    """An egress_denied audit entry is written when egress policy blocks the response."""
    proxy, _, chain, _ = _make_proxy_with_egress(egress_allow=False)
    await proxy.call_tool("c1", "test.tool", {})

    egress_entries = [e for e in chain.entries if e.entry_type == "egress_denied"]
    assert len(egress_entries) == 1
    entry = egress_entries[0]
    assert entry.tool_name == "test.tool"
    assert entry.policy_decision == "deny"
    assert entry.policy_rule_matched is not None


@pytest.mark.asyncio
async def test_proxy_high_sensitivity_session_blocked_by_egress():
    """
    A session whose max_sensitivity is 'hipaa_phi' (level 3) is blocked by an
    egress policy that checks sensitivity_level, while a public session is allowed.
    """
    from cmcp_runtime.mcp.proxy import CMCPProxy

    cfg = _make_config(EnforcementMode.ENFORCING)
    catalog = _make_catalog()

    def _sensitivity_aware_egress(context: dict) -> PolicyDecision:
        if context.get("egress") and context.get("sensitivity_level", 0) >= 3:
            raise PolicyDeny("high sensitivity egress blocked")
        return PolicyDecision(
            allowed=True,
            enforcement_mode=EnforcementMode.ENFORCING,
            rule_matched=None,
            advice={},
            evaluation_ms=0.1,
        )

    def _make_evaluator_for(session_sensitivity: str) -> MagicMock:
        ev = MagicMock(spec=PolicyEvaluator)
        ev.evaluate.side_effect = _sensitivity_aware_egress
        ev.authorize_egress.side_effect = lambda tool, resp, sess: _sensitivity_aware_egress(
            {"egress": True, "sensitivity_level": {"public": 0, "pii": 1, "confidential": 2, "hipaa_phi": 3}.get(sess.max_sensitivity, 0)}
        )
        ev.bundle_hash = "sha256:" + "0" * 64
        ev.enforcement_mode = EnforcementMode.ENFORCING
        return ev

    # High sensitivity session — should be blocked
    high_session = SessionState(session_id="high", max_sensitivity="hipaa_phi")
    high_chain = AuditChain("high")
    high_ev = _make_evaluator_for("hipaa_phi")

    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        high_proxy = CMCPProxy(catalog, high_ev, high_session, high_chain, cfg)
        wire_mock_gateway(high_proxy)

    high_result = await high_proxy.call_tool("c1", "test.tool", {})
    assert high_result.allowed is False

    # Low sensitivity session — same tool should be allowed
    low_session = SessionState(session_id="low", max_sensitivity="public")
    low_chain = AuditChain("low")
    low_ev = _make_evaluator_for("public")

    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        low_proxy = CMCPProxy(catalog, low_ev, low_session, low_chain, cfg)
        wire_mock_gateway(low_proxy)

    low_result = await low_proxy.call_tool("c1", "test.tool", {})
    assert low_result.allowed is True


@pytest.mark.asyncio
async def test_proxy_after_session_reset_egress_allowed_again():
    """
    After a session reset that clears sensitivity back to 'public', a tool that
    was previously blocked by the high-sensitivity egress policy is allowed again.
    """
    from cmcp_runtime.mcp.proxy import CMCPProxy

    cfg = _make_config(EnforcementMode.ENFORCING)
    catalog = _make_catalog()
    session = SessionState(session_id="resetable", max_sensitivity="hipaa_phi", reset_count=0)
    chain = AuditChain("resetable")

    def _egress_aware(context: dict) -> PolicyDecision:
        if context.get("egress") and context.get("sensitivity_level", 0) >= 3:
            raise PolicyDeny("high sensitivity egress blocked")
        return PolicyDecision(
            allowed=True,
            enforcement_mode=EnforcementMode.ENFORCING,
            rule_matched=None,
            advice={},
            evaluation_ms=0.1,
        )

    evaluator = MagicMock(spec=PolicyEvaluator)
    evaluator.evaluate.side_effect = _egress_aware
    evaluator.authorize_egress.side_effect = lambda tool, resp, sess: _egress_aware(
        {"egress": True, "sensitivity_level": {"public": 0, "pii": 1, "confidential": 2, "hipaa_phi": 3, "mnpi": 3, "trade_secret": 3}.get(sess.max_sensitivity, 0)}
    )
    evaluator.bundle_hash = "sha256:" + "0" * 64
    evaluator.enforcement_mode = EnforcementMode.ENFORCING

    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(catalog, evaluator, session, chain, cfg)
        wire_mock_gateway(proxy)

    # Before reset — high sensitivity should be blocked
    result_before = await proxy.call_tool("c1", "test.tool", {})
    assert result_before.allowed is False

    # Reset the session (operator action)
    session.reset(reason="test reset", authorized_by="operator")
    assert session.max_sensitivity == "public"

    # After reset — same tool should be allowed
    result_after = await proxy.call_tool("c2", "test.tool", {})
    assert result_after.allowed is True
