"""
Tool catalog security scanning via AGT MCPSecurityScanner — implements issue #58.

AGT's MCPSecurityScanner provides:
  - SHA-256 tool fingerprinting (detects definition mutation / rug-pull P4.2)
  - Typosquatting detection (P4.1)
  - Hidden instruction scanning in tool descriptions (P2.1)
  - Tool drift detection via check_rug_pull()

This module wires the scanner into cMCP's catalog load and drift detection flow.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from cmcp_gateway.catalog.loader import ToolCatalog

logger = logging.getLogger(__name__)

try:
    from agent_os.mcp_security import MCPSecurityScanner
    _AGT_AVAILABLE = True
except ImportError:
    _AGT_AVAILABLE = False


@dataclass
class CatalogScanResult:
    """Result of scanning the full tool catalog at load time."""

    safe: bool
    tools_scanned: int
    tools_flagged: int
    threats: list[dict[str, str]]  # [{tool_name, threat_type, severity, description}]


@dataclass
class DriftResult:
    """Result of a rug-pull / drift check on a single tool."""

    tool_name: str
    drifted: bool
    threats: list[dict[str, str]]


class CatalogScanner:
    """
    Wraps AGT MCPSecurityScanner for catalog-level security checks.

    Used in two contexts:
    1. At catalog load time: scan all tools for typosquatting and hidden instructions
    2. At runtime: check_drift() called when notifications/tools/list_changed received
       from upstream (P4.2 rug-pull detection)

    Falls back to a no-op scanner if agent-os-kernel is not installed.
    """

    def __init__(self) -> None:
        if _AGT_AVAILABLE:
            try:
                self._scanner: Any = MCPSecurityScanner()
                self._available = True
                logger.info("CatalogScanner: AGT MCPSecurityScanner active")
            except Exception as exc:
                logger.warning("CatalogScanner: AGT init failed (%s) — running without security scan", exc)
                self._scanner = None
                self._available = False
        else:
            self._scanner = None
            self._available = False
            logger.info("CatalogScanner: agent-os-kernel not installed — no catalog scanning")

    def scan_catalog(self, catalog: ToolCatalog) -> CatalogScanResult:
        """
        Scan all catalog entries at load time.

        Registers every tool with the AGT scanner (for future drift detection)
        and scans for:
          - Hidden instructions in tool descriptions (P2.1 tool poisoning)
          - Typosquatting / look-alike tool names (P4.1)
        """
        if not self._available or self._scanner is None:
            return CatalogScanResult(
                safe=True,
                tools_scanned=len(catalog.entries),
                tools_flagged=0,
                threats=[],
            )

        all_threats: list[dict[str, str]] = []
        tools_flagged = 0

        for tool_name, entry in catalog.entries.items():
            server_name = entry.server.display_name or entry.server.url
            description = entry.approved_definition.description

            try:
                # Register the tool fingerprint (enables future drift detection)
                self._scanner.register_tool(
                    tool_name=tool_name,
                    server_name=server_name,
                    description=description,
                    schema=entry.approved_definition.input_schema or {},
                )

                # Scan for threats
                threats = self._scanner.scan_tool(
                    tool_name=tool_name,
                    description=description,
                    server_name=server_name,
                )

                if threats:
                    tools_flagged += 1
                    for threat in threats:
                        threat_type = threat.threat_type.value if hasattr(threat.threat_type, "value") else str(threat.threat_type)
                        severity = threat.severity.value if hasattr(threat.severity, "value") else str(getattr(threat, "severity", "unknown"))
                        all_threats.append({
                            "tool_name": tool_name,
                            "threat_type": threat_type,
                            "severity": severity,
                            "description": str(getattr(threat, "description", "")),
                        })
                        logger.warning(
                            "CATALOG_THREAT: tool=%s type=%s severity=%s",
                            tool_name, threat_type, severity,
                        )
            except Exception as exc:
                logger.debug("CatalogScanner: scan_tool failed for %s: %s", tool_name, exc)

        return CatalogScanResult(
            safe=(tools_flagged == 0),
            tools_scanned=len(catalog.entries),
            tools_flagged=tools_flagged,
            threats=all_threats,
        )

    def check_drift(
        self,
        tool_name: str,
        server_name: str,
        current_definition: dict[str, Any],
    ) -> DriftResult:
        """
        Check if a tool's definition has drifted from the registered fingerprint.

        Called when notifications/tools/list_changed is received from an upstream
        server (P4.2 rug-pull detection). Returns DriftResult with drifted=True
        if the definition has changed since the catalog was sealed.
        """
        if not self._available or self._scanner is None:
            return DriftResult(tool_name=tool_name, drifted=False, threats=[])

        try:
            threats = self._scanner.check_rug_pull(
                tool_name=tool_name,
                server_name=server_name,
                current_definition=current_definition,
            )
            if threats:
                threat_list = [
                    {
                        "tool_name": tool_name,
                        "threat_type": t.threat_type.value if hasattr(t.threat_type, "value") else str(t.threat_type),
                        "description": str(getattr(t, "description", "")),
                    }
                    for t in threats
                ]
                logger.error(
                    "CATALOG_DRIFT_DETECTED: tool=%s threats=%d",
                    tool_name, len(threats),
                )
                return DriftResult(tool_name=tool_name, drifted=True, threats=threat_list)
        except Exception as exc:
            logger.debug("CatalogScanner: check_rug_pull failed for %s: %s", tool_name, exc)

        return DriftResult(tool_name=tool_name, drifted=False, threats=[])
