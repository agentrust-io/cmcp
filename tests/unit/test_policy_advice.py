"""Tests for Cedar annotation-based advice on policy denies."""

from __future__ import annotations

import pytest

from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.errors import PolicyDeny
from cmcp_runtime.policy.annotations import parse_policy_annotations
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyManifest
from cmcp_runtime.policy.evaluator import PolicyEvaluator

HITL_POLICY = """
// Rule 1: permit everything by default.
permit (principal, action, resource);

// Rule 2: HITL escalation for high-risk patients (EU AI Act Art. 14).
@id("hitl-high-risk")
@reason("human-review-required")
@regulation("eu-ai-act-art-14")
@reviewer_role("attending-physician")
forbid (principal, action == Action::"Ehr.treatmentPlanWriter", resource)
when { context.arguments has patient_risk_category
       && context.arguments.patient_risk_category == "high" };
"""


def _bundle(policy_content: str) -> PolicyBundle:
    return PolicyBundle(
        manifest=PolicyManifest(
            version="1.0.0",
            authored_at="2026-06-10T00:00:00Z",
            author_identity="test",
            commit_sha="abc",
        ),
        policy_files={"allow.cedar": policy_content},
        schema_content='{"cMCP": {}}',
        bundle_hash="sha256:" + "0" * 64,
    )


def _config(mode: EnforcementMode) -> Config:
    return Config(attestation=AttestationConfig(enforcement_mode=mode))


def _context(risk: str) -> dict:
    return {
        "tool_name": "ehr.treatment_plan_writer",
        "arguments": {"patient_risk_category": risk},
        "session_max_sensitivity": "confidential",
        "workflow_id": "clinical-decision-support",
    }


# ── parse_policy_annotations ──────────────────────────────────────────────────


def test_parse_annotations_maps_implicit_ids():
    annotations = parse_policy_annotations(HITL_POLICY)
    assert "policy0" not in annotations  # unannotated permit
    assert annotations["policy1"] == {
        "id": "hitl-high-risk",
        "reason": "human-review-required",
        "regulation": "eu-ai-act-art-14",
        "reviewer_role": "attending-physician",
    }


def test_parse_annotations_ignores_commented_policies():
    text = """
// permit (principal, action, resource);
@reason("real")
forbid (principal, action, resource);
"""
    annotations = parse_policy_annotations(text)
    assert annotations == {"policy0": {"reason": "real"}}


def test_parse_annotations_handles_escaped_quotes():
    text = '@note("say \\"hello\\"") forbid (principal, action, resource);'
    assert parse_policy_annotations(text) == {"policy0": {"note": 'say "hello"'}}


def test_parse_annotations_empty_for_unannotated_bundle():
    assert parse_policy_annotations("permit (principal, action, resource);") == {}


# ── PolicyEvaluator advice flow ───────────────────────────────────────────────


def test_enforcing_deny_carries_advice():
    evaluator = PolicyEvaluator(
        bundle=_bundle(HITL_POLICY), config=_config(EnforcementMode.ENFORCING)
    )
    with pytest.raises(PolicyDeny) as exc_info:
        evaluator.evaluate(_context("high"))
    assert exc_info.value.advice["reason"] == "human-review-required"
    assert exc_info.value.advice["regulation"] == "eu-ai-act-art-14"
    assert exc_info.value.advice["reviewer_role"] == "attending-physician"


def test_advisory_deny_carries_advice():
    evaluator = PolicyEvaluator(
        bundle=_bundle(HITL_POLICY), config=_config(EnforcementMode.ADVISORY)
    )
    decision = evaluator.evaluate(_context("high"))
    assert decision.allowed is True
    assert decision.would_have_denied is True
    assert decision.advice["reason"] == "human-review-required"


def test_allow_has_no_advice():
    evaluator = PolicyEvaluator(
        bundle=_bundle(HITL_POLICY), config=_config(EnforcementMode.ENFORCING)
    )
    decision = evaluator.evaluate(_context("standard"))
    assert decision.allowed is True
    assert decision.advice == {}


def test_deny_without_annotations_has_empty_advice():
    deny_all = 'forbid (principal, action, resource);'
    evaluator = PolicyEvaluator(
        bundle=_bundle(deny_all), config=_config(EnforcementMode.ENFORCING)
    )
    with pytest.raises(PolicyDeny) as exc_info:
        evaluator.evaluate(_context("standard"))
    assert exc_info.value.advice == {}
