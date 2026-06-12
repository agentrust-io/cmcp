"""
Silent-mode contract: silent quiets logs, never the evidence.

enforcement_mode: silent must behave exactly like advisory with respect to
the audit chain -- every would-have-denied decision is recorded as
advisory_deny -- while emitting no operational log lines for the deny.
This is the documented contract (docs/configuration.md); these tests exist
so it cannot regress silently.
"""

from __future__ import annotations

import logging

import pytest

from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyManifest
from cmcp_runtime.policy.evaluator import PolicyEvaluator

DENY_ALL = "forbid (principal, action, resource);"


def _evaluator(mode: EnforcementMode) -> PolicyEvaluator:
    bundle = PolicyBundle(
        manifest=PolicyManifest(
            version="1.0.0",
            authored_at="2026-06-11T00:00:00Z",
            author_identity="test",
            commit_sha="abc",
        ),
        policy_files={"allow.cedar": DENY_ALL},
        schema_content='{"cMCP": {}}',
        bundle_hash="sha256:" + "0" * 64,
    )
    return PolicyEvaluator(
        bundle=bundle,
        config=Config(attestation=AttestationConfig(enforcement_mode=mode)),
    )


CONTEXT = {
    "tool_name": "test.tool",
    "arguments": {},
    "session_max_sensitivity": "public",
}


def test_silent_deny_flags_would_have_denied():
    decision = _evaluator(EnforcementMode.SILENT).evaluate(dict(CONTEXT))
    assert decision.allowed is True
    assert decision.would_have_denied is True


def test_silent_emits_no_deny_log_lines(caplog):
    with caplog.at_level(logging.INFO, logger="cmcp_runtime.policy.evaluator"):
        _evaluator(EnforcementMode.SILENT).evaluate(dict(CONTEXT))
    assert not any("deny" in r.message.lower() for r in caplog.records)


def test_advisory_does_emit_deny_log_line(caplog):
    with caplog.at_level(logging.INFO, logger="cmcp_runtime.policy.evaluator"):
        _evaluator(EnforcementMode.ADVISORY).evaluate(dict(CONTEXT))
    assert any("advisory deny" in r.message.lower() for r in caplog.records)


@pytest.mark.asyncio
async def test_silent_mode_audit_chain_records_advisory_deny():
    """The core contract: in silent mode the hash-chained audit log still
    records the would-have-denied decision."""
    from unittest.mock import patch

    from cmcp_runtime.audit.chain import AuditChain
    from cmcp_runtime.catalog.loader import (
        ApprovedDefinition,
        CatalogEntry,
        ServerIdentity,
        ToolCatalog,
    )
    from cmcp_runtime.mcp.proxy import CMCPProxy
    from cmcp_runtime.session.state import SessionState

    from .conftest import wire_mock_gateway

    entry = CatalogEntry(
        tool_name="test.tool",
        server=ServerIdentity(
            display_name="t",
            url="http://localhost:8080/mcp",
            tls_fingerprint="SHA256:" + "A" * 43 + "=",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description="t", input_schema={"type": "object"}, output_schema=None
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="internal",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-06-11T00:00:00Z",
        approved_by="test",
    )
    catalog = ToolCatalog(
        entries={"test.tool": entry}, catalog_hash="sha256:" + "1" * 64
    )
    session = SessionState(session_id="silent-contract")
    chain = AuditChain("silent-contract")
    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(
            catalog=catalog,
            policy_evaluator=_evaluator(EnforcementMode.SILENT),
            session=session,
            audit_chain=chain,
            config=Config(
                attestation=AttestationConfig(enforcement_mode=EnforcementMode.SILENT)
            ),
        )
        wire_mock_gateway(proxy)

    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.allowed is True
    assert result.would_have_denied is True

    tool_entries = [e for e in chain.entries if e.entry_type == "tool_call"]
    assert tool_entries, "audit chain must record the call in silent mode"
    assert tool_entries[-1].policy_decision == "advisory_deny"
