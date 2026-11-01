"""Both policy phases carry the same Cedar context contract.

CedarBackend denies an Allow that Cedar reached while reporting evaluation
errors (a forbid that errors cannot stop a permit). That is only safe if the
runtime supplies every context key a shipped policy reads, in both phases:
otherwise a policy written for one phase turns into a deny in the other.

These tests run the real cedarpy engine and the shipped policy files; only the
upstream transport and the AGT scanner are mocked.
"""

from __future__ import annotations

import dataclasses
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import ToolCatalog, load_catalog
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.policy.bundle import load_policy_bundle
from cmcp_runtime.policy.cedar import CedarBackend
from cmcp_runtime.policy.evaluator import PolicyEvaluator
from cmcp_runtime.session.state import SessionState
from tests.unit.conftest import wire_mock_gateway

REPO = Path(__file__).resolve().parents[2]
BFSI = REPO / "examples" / "bfsi-demo"

BENIGN = "Account ACME-001: 3 open opportunities, owner J. Smith"


def _config() -> Config:
    return Config(attestation=AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING))


def _bfsi_catalog() -> ToolCatalog:
    """The shipped BFSi catalog plus two tools the PHI forbid can act on.

    Every shipped BFSi entry has requires_baa false and none is hipaa_phi, so
    block-phi-to-uncovered.cedar needs a PHI source (ehr.read) and a tool whose
    server is not BAA covered (fax.send) to have anything to decide.
    """
    catalog = load_catalog(str(BFSI / "catalog.json"))
    entries = dict(catalog.entries)
    entries["ehr.read"] = dataclasses.replace(
        entries["crm.query"], tool_name="ehr.read", sensitivity_level="hipaa_phi"
    )
    entries["fax.send"] = dataclasses.replace(
        entries["crm.query"], tool_name="fax.send", sensitivity_level="public",
        requires_baa=True,
    )
    return ToolCatalog(entries=entries, catalog_hash=catalog.catalog_hash)


def _bfsi_proxy(response_text: str):
    from cmcp_runtime.mcp.proxy import CMCPProxy

    cfg = _config()
    evaluator = PolicyEvaluator(load_policy_bundle(str(BFSI / "policies")), cfg)
    session = SessionState(session_id="sess-bfsi")
    chain = AuditChain("sess-bfsi")
    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(_bfsi_catalog(), evaluator, session, chain, cfg)
        wire_mock_gateway(proxy, response_text=response_text)
    # The demo catalog points at localhost mock servers; do not dial them.
    proxy._discover_tools = AsyncMock(return_value=None)
    return proxy, chain


def _terminal_events(chain: AuditChain) -> list[str]:
    return [str(e.entry_type) for e in chain.entries]


# -- the shipped BFSi bundle -------------------------------------------------


@pytest.mark.asyncio
async def test_bfsi_bundle_delivers_a_benign_response():
    proxy, chain = _bfsi_proxy(BENIGN)
    result = await proxy.call_tool("c1", "crm.query", {"query": "ACME"})
    assert result.allowed is True, result.deny_reason
    proxy._forward_to_upstream.assert_called_once()
    assert BENIGN in str(result.response)
    assert "egress_denied" not in _terminal_events(chain)


@pytest.mark.asyncio
async def test_bfsi_bundle_delivers_a_benign_response_from_an_uncovered_tool():
    proxy, chain = _bfsi_proxy(BENIGN)
    result = await proxy.call_tool("c1", "fax.send", {"query": "ACME"})
    assert result.allowed is True, result.deny_reason
    assert "egress_denied" not in _terminal_events(chain)


@pytest.mark.asyncio
async def test_bfsi_bundle_allows_phi_from_a_covered_tool_in_both_phases():
    proxy, chain = _bfsi_proxy(BENIGN)
    result = await proxy.call_tool("c1", "ehr.read", {"query": "A123456"})
    assert result.allowed is True, result.deny_reason
    assert proxy._session.max_sensitivity == "hipaa_phi"


@pytest.mark.asyncio
async def test_bfsi_bundle_denies_at_egress_once_the_session_holds_phi():
    """fax.send goes out on a public session; PHI arrives while it is in flight.

    Ingress allows fax.send (nothing sensitive yet). A concurrent ehr.read
    completes before fax.send returns, so at egress the session holds PHI and
    the destination is not BAA covered: block-phi-to-uncovered.cedar matches.
    """
    proxy, chain = _bfsi_proxy(BENIGN)
    calls: list[str] = []

    async def forward(*args, **kwargs):
        calls.append("forward")
        if len(calls) == 1:
            inner = await proxy.call_tool("c2", "ehr.read", {"query": "A123456"})
            assert inner.allowed is True, inner.deny_reason
        return BENIGN

    proxy._forward_to_upstream.side_effect = forward
    result = await proxy.call_tool("c1", "fax.send", {"query": "ACME"})
    assert calls == ["forward", "forward"]  # both calls passed ingress
    assert proxy._session.max_sensitivity == "hipaa_phi"
    assert result.allowed is False
    assert result.response is None
    assert "egress_denied" in _terminal_events(chain)
    # A matched forbid, not an evaluation error.
    assert "evaluation error" not in (result.deny_reason or "")


# -- every shipped .cedar file through both phases ---------------------------


def _shipped_cedar_files() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "*.cedar"],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout.split()
        files = [REPO / name for name in out]
    except (OSError, subprocess.CalledProcessError):
        files = [p for p in REPO.rglob("*.cedar") if ".venv" not in p.parts]
    assert files, "no shipped .cedar files found"
    return sorted(files)


def _phase_contexts(tool: str, arguments: dict) -> tuple[dict, dict]:
    from cmcp_runtime.mcp.proxy import CMCPProxy

    cfg = _config()
    evaluator = PolicyEvaluator(load_policy_bundle(str(BFSI / "policies")), cfg)
    session = SessionState(session_id="sess-contract")
    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(_bfsi_catalog(), evaluator, session, AuditChain("s"), cfg)
    ingress = proxy._build_cedar_context(tool, arguments, "default")
    egress = evaluator.egress_context(
        tool, BENIGN.encode(), session, workflow_id="default", call_context=ingress,
    )
    return ingress, egress


PERMIT = "\npermit(principal, action, resource);\n"


@pytest.mark.parametrize("path", _shipped_cedar_files(), ids=lambda p: p.relative_to(REPO).as_posix())
@pytest.mark.parametrize("arguments", [{}, {"amount": 5}], ids=["no-args", "amount"])
def test_shipped_policy_evaluates_without_errors_in_both_phases(path: Path, arguments: dict):
    ingress, egress = _phase_contexts("crm.query", arguments)
    policy = path.read_text(encoding="utf-8") + PERMIT
    for phase, context in (("ingress", ingress), ("egress", egress)):
        result = CedarBackend(policy_content=policy).evaluate(context)
        assert result.error is None, f"{phase}: {result.error}"


def test_both_phases_carry_the_same_context_keys():
    ingress, egress = _phase_contexts("crm.query", {"amount": 5})
    assert set(ingress) == set(egress)
    assert ingress["egress"] is False and egress["egress"] is True
    assert isinstance(egress["session_max_sensitivity"], str)
    assert egress["arguments"] == ingress["arguments"] == {"amount": 5}


def test_egress_context_without_call_context_still_has_every_key():
    """Callers that predate call_context get conservative defaults."""
    _, full = _phase_contexts("crm.query", {})
    evaluator = PolicyEvaluator(load_policy_bundle(str(BFSI / "policies")), _config())
    bare = evaluator.egress_context("crm.query", b"x", SessionState(session_id="s"))
    assert set(full) - {"workflow_id"} <= set(bare)
    assert bare["baa_covered"] is False
    assert bare["compliance_domain"] == "external"
