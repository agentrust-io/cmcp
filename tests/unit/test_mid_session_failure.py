"""Tests for mid-session failure handling (issue #71).

Covers:
- Attestation staleness detection and 503 response
- Catalog drift detection and 503 response
- Audit entries logged on first detection
- Healthy proxy passes calls through normally
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cmcp_gateway.audit.chain import AuditChain
from cmcp_gateway.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_gateway.config import AttestationConfig, Config, EnforcementMode
from cmcp_gateway.policy.evaluator import PolicyDecision, PolicyEvaluator
from cmcp_gateway.session.state import SessionState

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_entry(tool_name: str = "test.tool") -> CatalogEntry:
    return CatalogEntry(
        tool_name=tool_name,
        server=ServerIdentity(
            display_name="Test",
            url="https://test.example.com/mcp",
            tls_fingerprint="SHA256:AAAA/BBBB==",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description="test tool",
            input_schema={},
            output_schema=None,
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="external",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-06-05T00:00:00Z",
        approved_by="test",
    )


def _make_catalog(catalog_hash: str = "sha256:" + "a" * 64) -> ToolCatalog:
    return ToolCatalog(entries={"test.tool": _make_entry()}, catalog_hash=catalog_hash)


def _make_evaluator() -> PolicyEvaluator:
    evaluator = MagicMock(spec=PolicyEvaluator)
    evaluator.evaluate.return_value = PolicyDecision(
        allowed=True,
        enforcement_mode=EnforcementMode.ENFORCING,
        rule_matched=None,
        advice={},
        evaluation_ms=0.1,
        would_have_denied=False,
    )
    evaluator.bundle_hash = "sha256:" + "0" * 64
    evaluator.enforcement_mode = EnforcementMode.ENFORCING
    return evaluator


def _make_proxy(
    attestation_generated_at: datetime | None = None,
    attestation_validity_seconds: int = 3600,
    catalog_hash: str | None = None,
    catalog: ToolCatalog | None = None,
):
    from cmcp_gateway.mcp.proxy import CMCPProxy

    cfg = Config()
    cfg.attestation = AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING)
    cat = catalog or _make_catalog()
    ev = _make_evaluator()
    session = SessionState(session_id="sess-health-001")
    chain = AuditChain("sess-health-001")

    with patch("cmcp_gateway.mcp.proxy.MCPGateway"), \
         patch("cmcp_gateway.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(
            cat, ev, session, chain, cfg,
            attestation_generated_at=attestation_generated_at,
            attestation_validity_seconds=attestation_validity_seconds,
            catalog_hash=catalog_hash,
        )
        proxy._mcp_gateway = MagicMock()
        proxy._mcp_gateway.call_tool = AsyncMock(return_value=MagicMock(
            sensitivity_tags=[], injection_detected=False
        ))
    return proxy, session, chain


# ── Attestation staleness ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_attestation_not_stale_request_proceeds():
    """Fresh attestation: tool call succeeds normally."""
    generated_at = datetime.now(UTC) - timedelta(seconds=60)
    proxy, session, _ = _make_proxy(
        attestation_generated_at=generated_at,
        attestation_validity_seconds=3600,
    )
    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.allowed is True
    assert session.attestation_stale is False


@pytest.mark.asyncio
async def test_attestation_stale_returns_503_reason():
    """Expired attestation: call_tool returns deny with reason 'attestation_stale'."""
    generated_at = datetime.now(UTC) - timedelta(seconds=7200)
    proxy, session, _ = _make_proxy(
        attestation_generated_at=generated_at,
        attestation_validity_seconds=3600,
    )
    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.allowed is False
    assert result.deny_reason == "attestation_stale"


@pytest.mark.asyncio
async def test_attestation_stale_sets_flag_on_session():
    """Expired attestation sets session.attestation_stale = True."""
    generated_at = datetime.now(UTC) - timedelta(seconds=7200)
    proxy, session, _ = _make_proxy(
        attestation_generated_at=generated_at,
        attestation_validity_seconds=3600,
    )
    assert session.attestation_stale is False
    await proxy.call_tool("c1", "test.tool", {})
    assert session.attestation_stale is True


@pytest.mark.asyncio
async def test_attestation_stale_appends_audit_entry():
    """Attestation staleness detection appends an 'attestation_stale' audit entry."""
    generated_at = datetime.now(UTC) - timedelta(seconds=7200)
    proxy, _, chain = _make_proxy(
        attestation_generated_at=generated_at,
        attestation_validity_seconds=3600,
    )
    initial_length = chain.length
    await proxy.call_tool("c1", "test.tool", {})
    stale_entries = [e for e in chain.entries if e.entry_type == "attestation_stale"]
    assert len(stale_entries) == 1
    assert chain.length > initial_length


@pytest.mark.asyncio
async def test_attestation_stale_audit_entry_logged_only_once():
    """Audit entry for staleness is only written once, not on every call."""
    generated_at = datetime.now(UTC) - timedelta(seconds=7200)
    proxy, _, chain = _make_proxy(
        attestation_generated_at=generated_at,
        attestation_validity_seconds=3600,
    )
    await proxy.call_tool("c1", "test.tool", {})
    await proxy.call_tool("c2", "test.tool", {})
    stale_entries = [e for e in chain.entries if e.entry_type == "attestation_stale"]
    assert len(stale_entries) == 1


@pytest.mark.asyncio
async def test_no_attestation_generated_at_skips_staleness_check():
    """Without attestation_generated_at, staleness check is skipped and calls proceed."""
    proxy, session, _ = _make_proxy(attestation_generated_at=None)
    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.allowed is True
    assert session.attestation_stale is False


# ── Catalog drift ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_catalog_drift_detected_returns_503_reason():
    """Catalog hash mismatch: call_tool returns deny with reason 'catalog_drift'."""
    original_hash = "sha256:" + "a" * 64
    different_hash = "sha256:" + "b" * 64
    # catalog has different_hash but proxy is told original_hash was the startup hash
    cat = _make_catalog(catalog_hash=different_hash)
    proxy, session, _ = _make_proxy(catalog=cat, catalog_hash=original_hash)
    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.allowed is False
    assert result.deny_reason == "catalog_drift"


@pytest.mark.asyncio
async def test_catalog_drift_sets_flag_on_session():
    """Catalog drift sets session.catalog_drift = True."""
    cat = _make_catalog(catalog_hash="sha256:" + "b" * 64)
    proxy, session, _ = _make_proxy(catalog=cat, catalog_hash="sha256:" + "a" * 64)
    assert session.catalog_drift is False
    await proxy.call_tool("c1", "test.tool", {})
    assert session.catalog_drift is True


@pytest.mark.asyncio
async def test_catalog_drift_appends_audit_entry():
    """Catalog drift detection appends a 'catalog_drift' audit entry."""
    cat = _make_catalog(catalog_hash="sha256:" + "b" * 64)
    proxy, _, chain = _make_proxy(catalog=cat, catalog_hash="sha256:" + "a" * 64)
    await proxy.call_tool("c1", "test.tool", {})
    drift_entries = [e for e in chain.entries if e.entry_type == "catalog_drift"]
    assert len(drift_entries) == 1


@pytest.mark.asyncio
async def test_catalog_drift_audit_entry_logged_only_once():
    """Audit entry for drift is only written once, not on every call."""
    cat = _make_catalog(catalog_hash="sha256:" + "b" * 64)
    proxy, _, chain = _make_proxy(catalog=cat, catalog_hash="sha256:" + "a" * 64)
    await proxy.call_tool("c1", "test.tool", {})
    await proxy.call_tool("c2", "test.tool", {})
    drift_entries = [e for e in chain.entries if e.entry_type == "catalog_drift"]
    assert len(drift_entries) == 1


@pytest.mark.asyncio
async def test_catalog_no_drift_proceeds():
    """Matching catalog hash: calls proceed normally."""
    matching_hash = "sha256:" + "a" * 64
    cat = _make_catalog(catalog_hash=matching_hash)
    proxy, session, _ = _make_proxy(catalog=cat, catalog_hash=matching_hash)
    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.allowed is True
    assert session.catalog_drift is False


# ── Attestation staleness takes precedence over catalog drift ─────────────────


@pytest.mark.asyncio
async def test_attestation_stale_checked_before_catalog_drift():
    """When both conditions apply, attestation_stale is returned first."""
    generated_at = datetime.now(UTC) - timedelta(seconds=7200)
    cat = _make_catalog(catalog_hash="sha256:" + "b" * 64)
    proxy, _, _ = _make_proxy(
        attestation_generated_at=generated_at,
        attestation_validity_seconds=3600,
        catalog=cat,
        catalog_hash="sha256:" + "a" * 64,
    )
    result = await proxy.call_tool("c1", "test.tool", {})
    assert result.deny_reason == "attestation_stale"
