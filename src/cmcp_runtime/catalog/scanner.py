"""cMCP-owned catalog threat classification and drift hints."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from cmcp_runtime.catalog.loader import ToolCatalog

_HIDDEN_INSTRUCTION = re.compile(
    r"(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above)|"
    r"<(?:system|instruction|hidden|prompt)\b",
    re.IGNORECASE,
)


def _digest(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class CatalogScanResult:
    safe: bool
    tools_scanned: int
    tools_flagged: int
    threats: list[dict[str, str]]
    available: bool = True


@dataclass
class DriftResult:
    tool_name: str
    drifted: bool
    threats: list[dict[str, str]]
    available: bool = True


class CatalogScanner:
    """Classify poisoned descriptions and remember approved definitions."""

    def __init__(self) -> None:
        self._registered: dict[tuple[str, str], str] = {}

    def scan_catalog(self, catalog: ToolCatalog) -> CatalogScanResult:
        threats: list[dict[str, str]] = []
        flagged = 0
        for tool_name, entry in catalog.entries.items():
            server_name = entry.server.display_name or entry.server.url
            definition = {
                "description": entry.approved_definition.description,
                "inputSchema": entry.approved_definition.input_schema or {},
            }
            self._registered[(tool_name, server_name)] = _digest(definition)
            if _HIDDEN_INSTRUCTION.search(entry.approved_definition.description):
                flagged += 1
                threats.append(
                    {
                        "tool_name": tool_name,
                        "threat_type": "tool_poisoning",
                        "severity": "high",
                        "description": "hidden instruction in tool description",
                    }
                )
        return CatalogScanResult(not threats, len(catalog.entries), flagged, threats)

    def check_drift(
        self, tool_name: str, server_name: str, current_definition: dict[str, Any]
    ) -> DriftResult:
        expected = self._registered.get((tool_name, server_name))
        drifted = expected is not None and _digest(current_definition) != expected
        threats = (
            [
                {
                    "tool_name": tool_name,
                    "threat_type": "rug_pull",
                    "description": "tool definition changed after approval",
                }
            ]
            if drifted
            else []
        )
        return DriftResult(tool_name, drifted, threats)
