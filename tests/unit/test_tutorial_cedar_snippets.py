"""Execute the tutorial's actual snippets through the runtime's Cedar evaluator."""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

import cedarpy
import pytest

from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.errors import PolicyDeny
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyManifest
from cmcp_runtime.policy.cedar import CedarBackend
from cmcp_runtime.policy.evaluator import PolicyEvaluator

DOC = Path(__file__).resolve().parents[2] / "docs/tutorials/cedar-policy-walkthrough.md"


def _blocks(language: str) -> list[str]:
    return re.findall(rf"```{language}\n(.*?)\n```", DOC.read_text(), re.DOTALL)


def _evaluator(snippet: int) -> PolicyEvaluator:
    policies = _blocks("cedar")
    assert len(policies) == 4, "Update scenarios when tutorial snippets change"
    bundle = PolicyBundle(
        manifest=PolicyManifest(
            version="1.0.0",
            authored_at="2026-06-10T00:00:00Z",
            author_identity="test",
            commit_sha="abc",
        ),
        policy_files={"tutorial.cedar": policies[snippet]},
        schema_content=_blocks("json")[1],
        bundle_hash="sha256:" + "0" * 64,
    )
    config = Config(attestation=AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING))
    return PolicyEvaluator(bundle, config)


def _context(tool: str, workflow: str, sensitivity: str) -> dict[str, str]:
    return {
        "tool_name": tool,
        "resource": tool,
        "workflow_id": workflow,
        "session_max_sensitivity": sensitivity,
    }


@pytest.mark.parametrize(
    "snippet,tool,workflow,sensitivity,allowed",
    [
        (0, "echo", "any_workflow", "public", True),
        (1, "crm.get_customer", "customer_onboarding", "public", True),
        (1, "kyc.verify_identity", "customer_onboarding", "public", True),
        (1, "salesforce.contacts", "customer_onboarding", "public", True),
        (1, "salesforce.contacts", "customer_onboarding", "pii", False),
        (1, "crm.get_customer", "customer_onboarding", "pii", True),
        (1, "crm.get_customer", "other_workflow", "public", False),
        (1, "unlisted_tool", "customer_onboarding", "public", False),
        (2, "unlisted_tool", "other_workflow", "public", True),
        (3, "tool_a", "my_workflow", "public", True),
        (3, "tool_b", "my_workflow", "public", True),
        (3, "tool_a", "other_workflow", "public", False),
        (3, "unlisted_tool", "my_workflow", "public", False),
    ],
)
def test_tutorial_policy_decisions(snippet, tool, workflow, sensitivity, allowed):
    evaluator = _evaluator(snippet)
    context = _context(tool, workflow, sensitivity)
    if allowed:
        assert evaluator.evaluate(context).allowed
    else:
        with pytest.raises(PolicyDeny):
            evaluator.evaluate(context)


@pytest.mark.parametrize("snippet", [0, 1])
def test_tutorial_schema_validates_policies(snippet):
    result = cedarpy.validate_policies(_blocks("cedar")[snippet], _blocks("json")[1])
    assert result.validation_passed, result.errors


@pytest.mark.parametrize(
    "example,tool,allowed", [(0, "crm.get_customer", True), (1, "salesforce.contacts", False)]
)
def test_cli_examples_match_runtime_requests(example, tool, allowed):
    commands = [block for block in _blocks("bash") if block.startswith("cedar authorize")]
    assert len(commands) == 2
    args = shlex.split(commands[example].replace("\\\n", " "))[2:]
    options = dict(zip(args[::2], args[1::2], strict=True))
    context = json.loads(options["--context"])
    context.update(tool_name=tool, resource=tool)
    request = CedarBackend.build_request(context)
    for field in ("principal", "action", "resource"):
        assert request[field] == options[f"--{field}"]
    assert request["context"] == json.loads(options["--context"])
    if allowed:
        assert _evaluator(1).evaluate(context).allowed
    else:
        with pytest.raises(PolicyDeny):
            _evaluator(1).evaluate(context)
