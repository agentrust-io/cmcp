"""Exercise the starter files through PolicyEvaluator and the real Cedar engine."""

from pathlib import Path
from typing import Any

import pytest

from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.errors import PolicyDeny
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyManifest
from cmcp_runtime.policy.evaluator import PolicyEvaluator

TEMPLATES = Path(__file__).resolve().parents[2] / "examples" / "policy-templates"


def _evaluator(*guards: str) -> PolicyEvaluator:
    names = ("tool-allowlist.cedar", *guards)
    bundle = PolicyBundle(
        manifest=PolicyManifest(
            version="1.0.0",
            authored_at="2026-10-02T00:00:00Z",
            author_identity="test",
            commit_sha="test",
        ),
        policy_files={name: (TEMPLATES / name).read_text() for name in names},
        schema_content="{}",
        bundle_hash="sha256:" + "0" * 64,
    )
    return PolicyEvaluator(
        bundle,
        Config(attestation=AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING)),
    )


def _context(**overrides: Any) -> dict[str, Any]:
    return {
        "agent_id": "example-agent",
        "tool_name": "a",
        "resource": "a",
        "workflow_id": "default",
        "session_max_sensitivity": "public",
        "baa_covered": True,
        "compliance_domain": "internal",
        "arguments": {},
        **overrides,
    }


@pytest.mark.parametrize("tool", ["a", "b"])
def test_allowlist_permits_listed_tools(tool: str) -> None:
    assert _evaluator().evaluate(_context(tool_name=tool, resource=tool)).allowed


def test_allowlist_denies_unlisted_resource_even_with_listed_action() -> None:
    with pytest.raises(PolicyDeny):
        _evaluator().evaluate(_context(resource="c"))


@pytest.mark.parametrize("sensitivity", ["pii", "hipaa_phi", "mnpi"])
@pytest.mark.parametrize("covered", [True, False])
def test_sensitive_guard_checks_coverage(sensitivity: str, covered: bool) -> None:
    evaluator = _evaluator("sensitive-egress-guard.cedar")
    context = _context(session_max_sensitivity=sensitivity, baa_covered=covered)
    if covered:
        assert evaluator.evaluate(context).allowed
    else:
        with pytest.raises(PolicyDeny):
            evaluator.evaluate(context)


def test_sensitive_guard_permits_public_internal_without_coverage() -> None:
    assert _evaluator("sensitive-egress-guard.cedar").evaluate(_context(baa_covered=False)).allowed


@pytest.mark.parametrize("sensitivity", ["public", "pii", "hipaa_phi", "mnpi"])
def test_sensitive_guard_denies_external_even_with_coverage(sensitivity: str) -> None:
    with pytest.raises(PolicyDeny):
        _evaluator("sensitive-egress-guard.cedar").evaluate(
            _context(session_max_sensitivity=sensitivity, compliance_domain="external")
        )


@pytest.mark.parametrize("arguments", [{}, {"amount": 999}, {"amount": 1000}])
def test_amount_cap_permits_absent_or_at_most_cap(arguments: dict[str, int]) -> None:
    assert _evaluator("per-call-amount-cap.cedar").evaluate(_context(arguments=arguments)).allowed


def test_amount_cap_denies_above_cap() -> None:
    with pytest.raises(PolicyDeny):
        _evaluator("per-call-amount-cap.cedar").evaluate(_context(arguments={"amount": 1001}))


@pytest.mark.parametrize(
    "overrides",
    [{"resource": "c"}, {"compliance_domain": "external"}, {"arguments": {"amount": 1001}}],
)
def test_combined_templates_preserve_each_restriction(overrides: dict[str, Any]) -> None:
    with pytest.raises(PolicyDeny):
        _evaluator("sensitive-egress-guard.cedar", "per-call-amount-cap.cedar").evaluate(
            _context(**overrides)
        )


def test_combined_templates_permit_covered_internal_call_at_cap() -> None:
    assert (
        _evaluator("sensitive-egress-guard.cedar", "per-call-amount-cap.cedar")
        .evaluate(_context(session_max_sensitivity="hipaa_phi", arguments={"amount": 1000}))
        .allowed
    )
