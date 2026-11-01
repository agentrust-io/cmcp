"""An Allow that Cedar reaches while reporting evaluation errors must deny.

Cedar skips a policy whose condition errors and decides on what is left, so a
forbid that errors on an absent context attribute cannot stop a permit that
matches. cMCP fails closed on that outcome instead of enforcing the Allow.
These run the real cedarpy engine end to end; nothing in the decision path is
mocked.
"""

from __future__ import annotations

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.config import EnforcementMode
from cmcp_runtime.errors import PolicyDeny
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyManifest
from cmcp_runtime.policy.cedar import CedarBackend
from cmcp_runtime.policy.decisions import Decision
from cmcp_runtime.policy.evaluator import PolicyEvaluator
from cmcp_runtime.session.state import SessionState
from tests.unit.conftest import wire_mock_gateway
from tests.unit.test_egress_policy import _make_catalog, _make_config

PERMIT = "permit(principal, action, resource);\n"

# The forbid reads an attribute the runtime context never carries.
FORBID_MISSING_ATTR = PERMIT + (
    "forbid(principal, action, resource) when {\n"
    '    context.workflow_allowed_tools.contains("lookup")\n'
    "};\n"
)

# Before both phases carried one context contract, each phase carried only one
# of these two attributes, so this forbid errored in both.
FORBID_ONCE_SPLIT_ACROSS_PHASES = PERMIT + (
    "forbid(principal, action, resource) when {\n"
    "    context.response_size_bytes > 10 &&\n"
    '    context.compliance_domain == "external"\n'
    "};\n"
)


CONTEXT = {
    "tool_name": "lookup",
    "session_max_sensitivity": "public",
    "workflow_id": "default",
}


def _bundle(policy: str) -> PolicyBundle:
    return PolicyBundle(
        manifest=PolicyManifest(
            version="1.0.0",
            authored_at="2026-10-19T00:00:00Z",
            author_identity="test",
            commit_sha="abc",
        ),
        policy_files={"policy.cedar": policy},
        schema_content='{"cMCP": {}}',
        bundle_hash="sha256:" + "0" * 64,
    )


# -- adapter ---------------------------------------------------------------


def test_permit_plus_forbid_with_missing_context_attribute_denies():
    result = CedarBackend(policy_content=FORBID_MISSING_ATTR).evaluate(CONTEXT)
    assert result.allowed is False
    assert result.error is not None
    assert "workflow_allowed_tools" in result.error
    assert "workflow_allowed_tools" in result.reason
    # The matched ids name the permit; they must not travel as deny advice.
    assert result.policy_ids == ()


def test_permit_plus_forbid_on_missing_resource_entity_denies():
    policy = (
        'permit(principal, action, resource == Resource::"delete_customer_record");\n'
        "forbid(principal, action, resource) when {\n"
        '    resource.owner == "someone"\n'
        "};\n"
    )
    result = CedarBackend(policy_content=policy).evaluate(
        {**CONTEXT, "resource": "delete_customer_record"}
    )
    assert result.allowed is False
    assert result.error is not None


def test_forbid_with_supplied_attribute_still_denies_cleanly():
    policy = PERMIT + (
        "forbid(principal, action, resource) when {\n"
        '    context.session_max_sensitivity == "public"\n'
        "};\n"
    )
    result = CedarBackend(policy_content=policy).evaluate(CONTEXT)
    assert result.allowed is False
    assert result.error is None
    assert result.policy_ids == ("policy1",)


def test_permit_only_allows_without_error():
    result = CedarBackend(policy_content=PERMIT).evaluate(CONTEXT)
    assert result.allowed is True
    assert result.error is None


def test_forbid_guarded_with_has_allows_when_attribute_absent():
    """The supported way to write an optional-attribute forbid keeps working."""
    policy = PERMIT + (
        "forbid(principal, action, resource) when {\n"
        "    context has workflow_allowed_tools &&\n"
        '    context.workflow_allowed_tools.contains("lookup")\n'
        "};\n"
    )
    result = CedarBackend(policy_content=policy).evaluate(CONTEXT)
    assert result.allowed is True
    assert result.error is None


# -- evaluator -------------------------------------------------------------


def test_enforcing_evaluator_raises_with_the_error_in_the_detail():
    evaluator = PolicyEvaluator(_bundle(FORBID_MISSING_ATTR), _make_config())
    with pytest.raises(PolicyDeny) as excinfo:
        evaluator.evaluate(CONTEXT)
    assert "workflow_allowed_tools" in str(excinfo.value.detail)
    assert excinfo.value.advice == {}


def test_advisory_evaluator_flags_would_have_denied_as_plain_deny():
    # The permit carries an escalation annotation; an error-deny must not
    # borrow it and turn into STEP_UP.
    policy = '@escalate("oncall")\n' + FORBID_MISSING_ATTR
    evaluator = PolicyEvaluator(_bundle(policy), _make_config(EnforcementMode.ADVISORY))
    decision = evaluator.evaluate(CONTEXT)
    assert decision.allowed is True
    assert decision.would_have_denied is True
    assert decision.decision is Decision.DENY
    assert decision.advice == {}
    assert "workflow_allowed_tools" in (decision.rule_matched or "")


def test_missing_attribute_forbid_denies_at_ingress_and_at_egress():
    evaluator = PolicyEvaluator(_bundle(FORBID_MISSING_ATTR), _make_config())
    with pytest.raises(PolicyDeny) as ingress:
        evaluator.evaluate(CONTEXT)
    assert "workflow_allowed_tools" in str(ingress.value.detail)
    with pytest.raises(PolicyDeny) as egress:
        evaluator.authorize_egress("lookup", b"x" * 64, SessionState(session_id="s"))
    assert "workflow_allowed_tools" in str(egress.value.detail)


def test_once_split_forbid_now_evaluates_cleanly_in_both_phases():
    """Both keys exist in both phases, so the forbid decides instead of erroring."""
    evaluator = PolicyEvaluator(_bundle(FORBID_ONCE_SPLIT_ACROSS_PHASES), _make_config())
    ingress = evaluator.evaluate(
        {**CONTEXT, "compliance_domain": "external", "response_size_bytes": 0}
    )
    assert ingress.allowed is True
    with pytest.raises(PolicyDeny) as egress:
        evaluator.authorize_egress("lookup", b"x" * 64, SessionState(session_id="s"))
    assert "evaluation error" not in str(egress.value.detail)


# -- proxy -----------------------------------------------------------------


def _proxy(policy: str):
    from unittest.mock import patch

    from cmcp_runtime.mcp.proxy import CMCPProxy

    cfg = _make_config()
    evaluator = PolicyEvaluator(_bundle(policy), cfg)
    session = SessionState(session_id="sess-frxc")
    chain = AuditChain("sess-frxc")
    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(_make_catalog("lookup"), evaluator, session, chain, cfg)
        wire_mock_gateway(proxy)
    return proxy, chain


@pytest.mark.asyncio
async def test_call_tool_does_not_reach_upstream_on_allow_with_errors():
    proxy, chain = _proxy(FORBID_MISSING_ATTR)
    result = await proxy.call_tool("c1", "lookup", {})
    assert result.allowed is False
    proxy._forward_to_upstream.assert_not_called()
    denied = [e for e in chain.entries if e.policy_decision == "deny"]
    assert denied
    assert any("workflow_allowed_tools" in (e.policy_rule_matched or "") for e in denied)


@pytest.mark.asyncio
async def test_call_tool_permit_only_still_reaches_upstream():
    proxy, _ = _proxy(PERMIT)
    result = await proxy.call_tool("c1", "lookup", {})
    assert result.allowed is True
    proxy._forward_to_upstream.assert_called_once()
