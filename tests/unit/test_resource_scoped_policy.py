"""Resource-scoped Cedar policies must actually enforce.

Regression guard: the Cedar backend builds the request resource from the
`resource` key in the evaluation context. If the proxy/evaluator omit it, the
resource defaults to Resource::"default" and a policy like

    forbid(principal, action, resource == Resource::"salesforce.contacts");

never matches, so every call silently default-denies (or, in advisory mode,
forwards). These tests pin the context shape and the end-to-end decision.
"""

from __future__ import annotations

import pytest

from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.errors import PolicyDeny
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyManifest
from cmcp_runtime.policy.evaluator import PolicyEvaluator
from cmcp_runtime.session.state import SessionState
from tests.unit.test_call_log_integration import _make_catalog, _make_proxy

RESOURCE_POLICY = """
// Permit calls from the demo-agent workflow.
permit (principal, action, resource) when { context.workflow_id == "demo-agent" };

// Block one tool by resource name. forbid overrides permit.
forbid (principal, action, resource == Resource::"salesforce.contacts");
"""


def _bundle(policy_content: str) -> PolicyBundle:
    return PolicyBundle(
        manifest=PolicyManifest(
            version="1.0.0",
            authored_at="2026-06-10T00:00:00Z",
            author_identity="test",
            commit_sha="abc",
        ),
        policy_files={"demo.cedar": policy_content},
        schema_content='{"cMCP": {}}',
        bundle_hash="sha256:" + "0" * 64,
    )


def _evaluator(mode: EnforcementMode = EnforcementMode.ENFORCING) -> PolicyEvaluator:
    cfg = Config(attestation=AttestationConfig(enforcement_mode=mode))
    return PolicyEvaluator(_bundle(RESOURCE_POLICY), cfg)


# ── the proxy must put the tool name in the Cedar resource slot ───────────────


def test_build_cedar_context_sets_resource_to_tool_name():
    proxy, _, _ = _make_proxy(catalog=_make_catalog("salesforce.contacts"))
    ctx = proxy._build_cedar_context("salesforce.contacts", {}, "demo-agent")
    assert ctx["resource"] == "salesforce.contacts"


# ── ingress: resource-scoped forbid actually denies ──────────────────────────


def test_resource_forbid_denies_sensitive_tool():
    ev = _evaluator()
    ctx = {
        "tool_name": "salesforce.contacts",
        "resource": "salesforce.contacts",
        "session_max_sensitivity": "public",
        "workflow_id": "demo-agent",
    }
    with pytest.raises(PolicyDeny):
        ev.evaluate(ctx)


def test_permitted_tool_is_allowed():
    ev = _evaluator()
    decision = ev.evaluate(
        {
            "tool_name": "echo",
            "resource": "echo",
            "session_max_sensitivity": "public",
            "workflow_id": "demo-agent",
        }
    )
    assert decision.allowed is True
    assert decision.would_have_denied is False


def test_wrong_workflow_is_denied():
    ev = _evaluator()
    with pytest.raises(PolicyDeny):
        ev.evaluate(
            {
                "tool_name": "echo",
                "resource": "echo",
                "session_max_sensitivity": "public",
                "workflow_id": "stranger",
            }
        )


# ── egress: the allowed tool's response must not be denied on the way back ────


def test_egress_allows_permitted_tool():
    ev = _evaluator()
    session = SessionState(session_id="sess-egress")
    decision = ev.authorize_egress("echo", b"{}", session, workflow_id="demo-agent")
    assert decision.allowed is True
    assert decision.would_have_denied is False


def test_egress_denies_forbidden_resource():
    ev = _evaluator()
    session = SessionState(session_id="sess-egress")
    with pytest.raises(PolicyDeny):
        ev.authorize_egress(
            "salesforce.contacts", b"{}", session, workflow_id="demo-agent"
        )
