"""Tests for CatalogScanner / AGT MCPSecurityScanner integration (issue #58)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cmcp_gateway.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_gateway.catalog.scanner import CatalogScanner, CatalogScanResult, DriftResult


def _make_entry(tool_name: str, description: str = "test tool") -> CatalogEntry:
    return CatalogEntry(
        tool_name=tool_name,
        server=ServerIdentity(
            display_name="Test Server",
            url="https://test.example.com/mcp",
            tls_fingerprint="SHA256:AAAA==",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description=description,
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


def _make_catalog(*tools: str) -> ToolCatalog:
    entries = {t: _make_entry(t) for t in (tools or ("test.tool",))}
    return ToolCatalog(entries=entries, catalog_hash="sha256:" + "1" * 64)


# ── When AGT is available ─────────────────────────────────────────────────────

def test_scan_catalog_safe_returns_clean_result():
    with patch("cmcp_gateway.catalog.scanner._AGT_AVAILABLE", True), \
         patch("cmcp_gateway.catalog.scanner.MCPSecurityScanner") as MockScanner:
            mock_instance = MagicMock()
            mock_instance.scan_tool.return_value = []  # no threats
            mock_instance.register_tool.return_value = MagicMock()
            MockScanner.return_value = mock_instance

            scanner = CatalogScanner()
            result = scanner.scan_catalog(_make_catalog("crm.query", "hr.lookup"))

    assert isinstance(result, CatalogScanResult)
    assert result.safe is True
    assert result.tools_scanned == 2
    assert result.tools_flagged == 0
    assert result.threats == []


def test_scan_catalog_flags_threat():
    mock_threat = MagicMock()
    mock_threat.threat_type.value = "tool_poisoning"
    mock_threat.severity.value = "high"
    mock_threat.description = "hidden instruction in description"

    with patch("cmcp_gateway.catalog.scanner._AGT_AVAILABLE", True), \
         patch("cmcp_gateway.catalog.scanner.MCPSecurityScanner") as MockScanner:
            mock_instance = MagicMock()
            mock_instance.scan_tool.return_value = [mock_threat]
            mock_instance.register_tool.return_value = MagicMock()
            MockScanner.return_value = mock_instance

            scanner = CatalogScanner()
            result = scanner.scan_catalog(_make_catalog("malicious.tool"))

    assert result.safe is False
    assert result.tools_flagged == 1
    assert len(result.threats) == 1
    assert result.threats[0]["tool_name"] == "malicious.tool"
    assert result.threats[0]["threat_type"] == "tool_poisoning"


def test_scan_catalog_registers_all_tools():
    with patch("cmcp_gateway.catalog.scanner._AGT_AVAILABLE", True), \
         patch("cmcp_gateway.catalog.scanner.MCPSecurityScanner") as MockScanner:
            mock_instance = MagicMock()
            mock_instance.scan_tool.return_value = []
            mock_instance.register_tool.return_value = MagicMock()
            MockScanner.return_value = mock_instance

            scanner = CatalogScanner()
            scanner.scan_catalog(_make_catalog("tool.a", "tool.b", "tool.c"))

    assert mock_instance.register_tool.call_count == 3


def test_check_drift_returns_clean_when_no_changes():
    with patch("cmcp_gateway.catalog.scanner._AGT_AVAILABLE", True), \
         patch("cmcp_gateway.catalog.scanner.MCPSecurityScanner") as MockScanner:
            mock_instance = MagicMock()
            mock_instance.check_rug_pull.return_value = []
            MockScanner.return_value = mock_instance

            scanner = CatalogScanner()
            result = scanner.check_drift("crm.query", "CRM Server", {"description": "same"})

    assert isinstance(result, DriftResult)
    assert result.drifted is False
    assert result.threats == []


def test_check_drift_detects_rug_pull():
    mock_threat = MagicMock()
    mock_threat.threat_type.value = "rug_pull"
    mock_threat.description = "description changed after approval"

    with patch("cmcp_gateway.catalog.scanner._AGT_AVAILABLE", True), \
         patch("cmcp_gateway.catalog.scanner.MCPSecurityScanner") as MockScanner:
            mock_instance = MagicMock()
            mock_instance.check_rug_pull.return_value = [mock_threat]
            MockScanner.return_value = mock_instance

            scanner = CatalogScanner()
            result = scanner.check_drift("crm.query", "CRM Server", {"description": "changed description with injected instruction"})

    assert result.drifted is True
    assert result.threats[0]["threat_type"] == "rug_pull"


# ── When AGT is not available (graceful fallback) ─────────────────────────────

def test_scan_catalog_safe_without_agt():
    with patch("cmcp_gateway.catalog.scanner._AGT_AVAILABLE", False):
        scanner = CatalogScanner()
        result = scanner.scan_catalog(_make_catalog("crm.query"))

    assert result.safe is True
    assert result.tools_scanned == 1
    assert result.threats == []


def test_check_drift_returns_clean_without_agt():
    with patch("cmcp_gateway.catalog.scanner._AGT_AVAILABLE", False):
        scanner = CatalogScanner()
        result = scanner.check_drift("crm.query", "CRM", {})

    assert result.drifted is False
