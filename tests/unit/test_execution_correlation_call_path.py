"""Call-path gates for durable execution correlation (issue #565).

Proves the proxy reserves before upstream, never re-invokes on replay or
collision, refuses a changed binding before upstream, and finalizes the
execution on its one terminal audit write.
"""

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
from cmcp_runtime.execution import AdmissionStatus, provisional_action_binding
from cmcp_runtime.execution.registry import ExecutionRegistry
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


def _make_proxy(chain: AuditChain, registry: ExecutionRegistry | None, *, agent: str = AGENT,
                binding_fn=provisional_action_binding):
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
    config = Config(attestation=AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING))
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
            execution_registry=registry,
            agent_identity=agent,
            action_binding_fn=binding_fn,
        )
    proxy._check_upstream_drift = AsyncMock(return_value=False)
    proxy._forward_to_upstream = AsyncMock(return_value='{"ok": true}')
    return proxy


def _tool_entries(chain: AuditChain):
    return [e for e in chain.entries if e.entry_type in ("tool_call", "fault", "egress_denied")]


@pytest.mark.asyncio
async def test_first_call_reserves_invokes_and_finalizes(tmp_path):
    registry = ExecutionRegistry(tmp_path / "e.db")
    chain = AuditChain(session_id="s-565")
    proxy = _make_proxy(chain, registry)

    result = await proxy.call_tool("call-1", "billing.charge", {"amount": 100}, execution_id="x1")

    assert result.allowed
    assert proxy._forward_to_upstream.await_count == 1
    terminal = _tool_entries(chain)[-1]
    assert terminal.execution_id == "x1"
    row = registry._conn.execute(
        "SELECT state, terminal_audit_entry_hash FROM executions WHERE execution_id='x1'"
    ).fetchone()
    assert row[0] == "completed"
    assert row[1] == terminal.entry_hash


@pytest.mark.asyncio
async def test_replay_after_terminal_does_not_reinvoke_upstream(tmp_path):
    registry = ExecutionRegistry(tmp_path / "e.db")
    proxy = _make_proxy(AuditChain(session_id="s-a"), registry)
    await proxy.call_tool("call-1", "billing.charge", {"amount": 100}, execution_id="x1")
    assert proxy._forward_to_upstream.await_count == 1

    # A fresh session (new chain) replays the same execution_id, exactly the
    # session-independent case #565 exists for.
    replay_proxy = _make_proxy(AuditChain(session_id="s-b"), registry)
    result = await replay_proxy.call_tool(
        "call-2", "billing.charge", {"amount": 100}, execution_id="x1"
    )
    assert not result.allowed
    assert result.deny_reason == "execution:replay_terminal"
    assert replay_proxy._forward_to_upstream.await_count == 0


@pytest.mark.asyncio
async def test_in_flight_replay_does_not_reinvoke_upstream(tmp_path):
    registry = ExecutionRegistry(tmp_path / "e.db")
    registry.admit(
        agent_identity=AGENT, execution_id="x2",
        action_binding=provisional_action_binding("billing.charge", {"amount": 100}),
        call_id="earlier",
    )
    proxy = _make_proxy(AuditChain(session_id="s-a"), registry)
    result = await proxy.call_tool("call-1", "billing.charge", {"amount": 100}, execution_id="x2")
    assert not result.allowed
    assert result.deny_reason == "execution:replay_in_flight"
    assert proxy._forward_to_upstream.await_count == 0


@pytest.mark.asyncio
async def test_changed_binding_is_refused_before_upstream(tmp_path):
    registry = ExecutionRegistry(tmp_path / "e.db")
    proxy = _make_proxy(AuditChain(session_id="s-a"), registry)
    await proxy.call_tool("call-1", "billing.charge", {"amount": 100}, execution_id="x3")
    proxy._forward_to_upstream.reset_mock()

    result = await proxy.call_tool(
        "call-2", "billing.charge", {"amount": 999}, execution_id="x3"
    )
    assert not result.allowed
    assert result.deny_reason == "execution:collision_changed_binding"
    assert proxy._forward_to_upstream.await_count == 0


@pytest.mark.asyncio
async def test_cross_identity_same_execution_id_does_not_collide(tmp_path):
    registry = ExecutionRegistry(tmp_path / "e.db")
    proxy_a = _make_proxy(AuditChain(session_id="s-a"), registry, agent=AGENT)
    proxy_b = _make_proxy(
        AuditChain(session_id="s-b"), registry, agent="spiffe://example.org/agent-b"
    )
    r_a = await proxy_a.call_tool("c1", "billing.charge", {"amount": 100}, execution_id="shared")
    r_b = await proxy_b.call_tool("c2", "billing.charge", {"amount": 100}, execution_id="shared")
    assert r_a.allowed and r_b.allowed
    assert proxy_a._forward_to_upstream.await_count == 1
    assert proxy_b._forward_to_upstream.await_count == 1


@pytest.mark.asyncio
async def test_missing_execution_id_is_unchanged_and_audits_null(tmp_path):
    registry = ExecutionRegistry(tmp_path / "e.db")
    chain = AuditChain(session_id="s-565")
    proxy = _make_proxy(chain, registry)
    result = await proxy.call_tool("call-1", "billing.charge", {"amount": 100})
    assert result.allowed
    assert proxy._forward_to_upstream.await_count == 1
    assert _tool_entries(chain)[-1].execution_id is None
    assert registry._conn.execute("SELECT COUNT(*) FROM executions").fetchone() == (0,)


@pytest.mark.asyncio
async def test_execution_id_without_registry_is_refused(tmp_path):
    proxy = _make_proxy(AuditChain(session_id="s-565"), None)
    result = await proxy.call_tool("call-1", "billing.charge", {"amount": 100}, execution_id="x1")
    assert not result.allowed
    assert result.deny_reason == "execution_correlation_unavailable"
    assert proxy._forward_to_upstream.await_count == 0


@pytest.mark.asyncio
async def test_upstream_fault_finalizes_execution_as_terminal(tmp_path):
    from cmcp_runtime.errors import UpstreamUnavailable

    registry = ExecutionRegistry(tmp_path / "e.db")
    proxy = _make_proxy(AuditChain(session_id="s-a"), registry)
    proxy._forward_to_upstream = AsyncMock(
        side_effect=UpstreamUnavailable("upstream down")
    )
    result = await proxy.call_tool("call-1", "billing.charge", {"amount": 100}, execution_id="x4")
    assert not result.allowed

    # The attempt terminated after transport may have started: outcome_unknown,
    # terminal, and not replayable.
    replay = registry.admit(
        agent_identity=AGENT, execution_id="x4",
        action_binding=provisional_action_binding("billing.charge", {"amount": 100}),
        call_id="c2",
    )
    assert replay.status is AdmissionStatus.REPLAY_OUTCOME_UNKNOWN


@pytest.mark.asyncio
async def test_float_argument_refused_before_upstream(tmp_path):
    registry = ExecutionRegistry(tmp_path / "e.db")
    proxy = _make_proxy(AuditChain(session_id="s-a"), registry)
    result = await proxy.call_tool(
        "call-1", "billing.charge", {"amount": 10.5}, execution_id="xf"
    )
    assert not result.allowed
    assert result.deny_reason == "execution_invalid_binding"
    assert proxy._forward_to_upstream.await_count == 0
    assert registry._conn.execute("SELECT COUNT(*) FROM executions").fetchone() == (0,)


@pytest.mark.asyncio
async def test_injected_binding_fn_is_used_verbatim(tmp_path):
    registry = ExecutionRegistry(tmp_path / "e.db")
    proxy = _make_proxy(
        AuditChain(session_id="s-a"), registry,
        binding_fn=lambda tool, args: "stub-binding",
    )
    await proxy.call_tool("c1", "billing.charge", {"amount": 100}, execution_id="xs")
    row = registry._conn.execute(
        "SELECT action_binding FROM executions WHERE execution_id='xs'"
    ).fetchone()
    assert row == ("stub-binding",)


@pytest.mark.asyncio
async def test_malformed_execution_id_is_refused_before_upstream(tmp_path):
    registry = ExecutionRegistry(tmp_path / "e.db")
    proxy = _make_proxy(AuditChain(session_id="s-a"), registry)
    for bad in ("", "a" * 201, "has space", "x\ny"):
        proxy._forward_to_upstream.reset_mock()
        result = await proxy.call_tool(
            "c1", "billing.charge", {"amount": 100}, execution_id=bad
        )
        assert not result.allowed
        assert result.deny_reason == "execution_invalid_execution_id"
        assert proxy._forward_to_upstream.await_count == 0
    assert registry._conn.execute("SELECT COUNT(*) FROM executions").fetchone() == (0,)


@pytest.mark.asyncio
async def test_malformed_execution_id_is_not_written_to_the_audit_entry(tmp_path):
    registry = ExecutionRegistry(tmp_path / "e.db")
    chain = AuditChain(session_id="s-a")
    proxy = _make_proxy(chain, registry)
    await proxy.call_tool("c1", "billing.charge", {"amount": 100}, execution_id="a" * 400)
    assert _tool_entries(chain)[-1].execution_id is None
