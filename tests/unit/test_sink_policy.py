"""Sink decisions exercise real proxy dispatch and response paths, not scanners."""

from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.config import Config, EnforcementMode, load_config
from cmcp_runtime.errors import ConfigError, UpstreamToolError
from cmcp_runtime.mcp.proxy import CMCPProxy
from cmcp_runtime.mcp.stdio import StdioServer, StdioSpawn
from cmcp_runtime.policy.evaluator import PolicyEvaluator
from cmcp_runtime.session.state import SessionState
from cmcp_runtime.sink_policy import SinkPolicy
from tests.unit.test_egress_policy import _make_bundle, _make_catalog


def proxy_for(*, tool_cap="public", response_cap="public", session_label="public",
              catalog_label="public", mode=EnforcementMode.ENFORCING, enabled=True, caps=None):
    config = Config(sink_policy=SinkPolicy(caps if caps is not None else {"test.tool": tool_cap}, response_cap)
                    if enabled else None)
    config.attestation.enforcement_mode = mode
    catalog = _make_catalog("test.tool", "public.tool")
    catalog.entries["test.tool"] = replace(catalog.entries["test.tool"], sensitivity_level=catalog_label)
    session = SessionState("sink-test", max_sensitivity=session_label)
    chain = AuditChain(session.session_id)
    # Actual Cedar evaluator with a permissive bundle and actual response scanner.
    proxy = CMCPProxy(catalog, PolicyEvaluator(_make_bundle(), config), session, chain, config)
    proxy._advertised_tools = AsyncMock(return_value=None)
    proxy._forward_to_upstream = AsyncMock(return_value="A harmless looking derived summary")
    return proxy, session, chain, config


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", list(EnforcementMode))
@pytest.mark.parametrize("source", ["session", "catalog", "declared"])
async def test_high_label_denies_before_tool_dispatch_in_all_modes(mode, source):
    proxy, _, chain, _ = proxy_for(mode=mode, session_label="confidential" if source == "session" else "public",
                                   catalog_label="confidential" if source == "catalog" else "public")
    result = await proxy.call_tool("c1", "test.tool", {"summary": "Looks safe"},
                                   declared_data_class="confidential" if source == "declared" else "public")
    assert not result.allowed
    assert result.deny_reason == "sink_policy:tool_denied"
    proxy._advertised_tools.assert_not_awaited()
    proxy._forward_to_upstream.assert_not_awaited()
    assert any(e.policy_rule_matched == "sink_policy:tool_denied" for e in chain.entries)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", list(EnforcementMode))
async def test_clean_derived_response_cannot_leave_lower_clearance_sink(mode):
    proxy, session, chain, _ = proxy_for(tool_cap="confidential", catalog_label="confidential", mode=mode)
    result = await proxy.call_tool("c1", "test.tool", {})
    proxy._forward_to_upstream.assert_awaited_once()
    assert not result.allowed and result.response is None
    assert result.deny_reason == "sink_policy:response_denied"
    assert session.max_sensitivity == "confidential"
    assert any(e.entry_type == "egress_denied" for e in chain.entries)


@pytest.mark.asyncio
async def test_positive_protected_tool_and_response():
    proxy, _, _, _ = proxy_for(tool_cap="confidential", response_cap="confidential", session_label="confidential")
    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.allowed and result.response == "A harmless looking derived summary"


@pytest.mark.asyncio
async def test_disabled_policy_preserves_legacy_behavior():
    proxy, _, _, _ = proxy_for(session_label="confidential", enabled=False)
    assert (await proxy.call_tool("c1", "test.tool", {})).allowed


@pytest.mark.asyncio
async def test_unknown_declared_label_fails_closed():
    proxy, _, _, _ = proxy_for()
    result = await proxy.call_tool("c1", "test.tool", {}, declared_data_class="future-secret")
    assert not result.allowed
    proxy._forward_to_upstream.assert_not_awaited()


@pytest.mark.asyncio
async def test_unlisted_tool_fails_closed_and_cannot_disable_captured_policy():
    proxy, _, _, config = proxy_for(caps={})
    config.sink_policy = None
    assert not (await proxy.call_tool("c1", "test.tool", {})).allowed
    proxy._forward_to_upstream.assert_not_awaited()


@pytest.mark.asyncio
async def test_private_read_then_derived_public_write_is_denied():
    proxy, session, _, _ = proxy_for(catalog_label="confidential", response_cap="confidential",
                                    caps={"test.tool": "confidential", "public.tool": "public"})
    assert (await proxy.call_tool("read", "test.tool", {})).allowed
    assert session.max_sensitivity == "confidential"
    proxy._forward_to_upstream.reset_mock()
    result = await proxy.call_tool("write", "public.tool", {"summary": "Apparently harmless", "sink_policy": None},
                                   declared_data_class="public")
    assert not result.allowed and result.deny_reason == "sink_policy:tool_denied"
    proxy._forward_to_upstream.assert_not_awaited()


@pytest.mark.asyncio
async def test_sensitivity_raised_during_discovery_is_rechecked_before_dispatch():
    proxy, session, _, _ = proxy_for()
    async def discover(*args, **kwargs):
        session.update_from_inspection("parallel-read", ["confidential"],
                                       injection_detected=False, response_allowed=True)
    proxy._advertised_tools = AsyncMock(side_effect=discover)
    result = await proxy.call_tool("c1", "test.tool", {})
    assert not result.allowed and result.deny_reason == "sink_policy:tool_denied"
    proxy._forward_to_upstream.assert_not_awaited()


@pytest.mark.asyncio
async def test_reset_during_response_does_not_lower_inflight_floor():
    proxy, session, _, _ = proxy_for(tool_cap="confidential", session_label="confidential")
    async def return_after_reset(*args, **kwargs):
        session.reset(reason="operator reset", authorized_by="operator")
        return "A harmless looking derived summary"
    proxy._forward_to_upstream = AsyncMock(side_effect=return_after_reset)
    result = await proxy.call_tool("c1", "test.tool", {})
    assert not result.allowed and result.response is None


@pytest.mark.asyncio
async def test_upstream_error_plaintext_never_reaches_gateway_log(caplog):
    proxy, _, chain, _ = proxy_for()
    secret = "private-contract-canary-471"
    proxy._forward_to_upstream.side_effect = UpstreamToolError(secret)
    result = await proxy.call_tool("c1", "test.tool", {})
    assert not result.allowed
    assert secret not in caplog.text
    assert secret not in str(result)
    assert all(secret not in str(entry) for entry in chain.entries)


@pytest.mark.asyncio
async def test_child_stderr_suppressed_at_log_sink(caplog):
    server = StdioServer(StdioSpawn("unused"), log_stderr=False)
    server._proc = MagicMock()
    server._proc.stderr.read = AsyncMock(return_value=b"private-stderr-canary")
    await server._collect_stderr()
    assert server.stderr_bytes == len(b"private-stderr-canary")
    assert "private-stderr-canary" not in caplog.text
    assert "stderr suppressed" in caplog.text


@pytest.mark.asyncio
async def test_proxy_wires_stderr_control_into_real_spawn_seam(monkeypatch):
    proxy, _, _, _ = proxy_for()
    entry = proxy._catalog.entries["test.tool"]
    entry.server = replace(entry.server, transport="stdio", spawn=StdioSpawn("unused"))
    monkeypatch.setattr(StdioServer, "start", AsyncMock())
    server = await proxy._stdio_for(entry)
    assert server._log_stderr is False


def test_policy_copies_caller_mapping():
    caps = {"test.tool": "public"}
    policy = SinkPolicy(caps, "public")
    caps["test.tool"] = "confidential"
    assert policy.tool_max_sensitivity["test.tool"] == "public"
    with pytest.raises(TypeError):
        policy.tool_max_sensitivity["test.tool"] = "confidential"


@pytest.mark.parametrize("value", [None, {}, {"tool_max_sensitivity": {}},
    {"tool_max_sensitivity": {}, "response_max_sensitivity": "typo"},
    {"tool_max_sensitivity": {"x": "typo"}, "response_max_sensitivity": "public"},
    {"tool_max_sensitivity": [], "response_max_sensitivity": "public"},
    {"tool_max_sensitivity": {}, "response_max_sensitivity": "public", "advisory": True},
])
def test_malformed_sink_config_is_rejected(tmp_path, value):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"sink_policy": value}))
    with pytest.raises(ConfigError):
        load_config(str(path))


def test_custom_label_is_validated_and_ranked(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"sensitivity": {"vocabulary": {"top_secret": 4}},
        "sink_policy": {"tool_max_sensitivity": {"x": "top_secret"}, "response_max_sensitivity": "top_secret"}}))
    assert load_config(str(path)).sink_policy.response_max_sensitivity == "top_secret"
