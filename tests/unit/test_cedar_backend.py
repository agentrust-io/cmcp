"""Parity and fail-closed tests for cMCP's Cedar adapter (#472)."""

from __future__ import annotations

from unittest.mock import patch

from cmcp_runtime.policy.cedar import CedarBackend


def test_request_mapping_preserves_agt_v4_contract():
    request = CedarBackend.build_request(
        {
            "agent_id": "agent-7",
            "tool_name": "ehr.treatment_plan_writer",
            "resource": "salesforce.contacts",
            "workflow_id": "clinical",
        }
    )
    assert request == {
        "principal": 'Agent::"agent-7"',
        "action": 'Action::"Ehr.treatmentPlanWriter"',
        "resource": 'Resource::"salesforce.contacts"',
        "context": {"workflow_id": "clinical"},
    }


def test_real_engine_returns_matched_policy_ids():
    backend = CedarBackend(
        policy_content='@id("blocked") forbid (principal, action, resource);'
    )
    result = backend.evaluate({"tool_name": "echo"})
    assert result.allowed is False
    # cedarpy assigns stable positional ids; cMCP's annotation parser uses the
    # same ids to recover @reason and other structured advice.
    assert result.policy_ids == ("policy0",)
    assert result.error is None


def test_engine_error_fails_closed():
    backend = CedarBackend(policy_content="not cedar")
    result = backend.evaluate({"tool_name": "echo"})
    assert result.allowed is False
    assert result.error is not None


def test_unavailable_engine_fails_closed():
    backend = CedarBackend(policy_content="permit (principal, action, resource);")
    with patch("cmcp_runtime.policy.cedar.cedarpy.is_authorized", side_effect=RuntimeError("down")):
        result = backend.evaluate({"tool_name": "echo"})
    assert result.allowed is False
    assert result.error == "down"
