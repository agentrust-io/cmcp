"""cMCP-owned runtime gateway controls.

This module replaces the small AGT v4 runtime surface cMCP used.  AGT remains
an optional governance/evidence tool in CI, but the installed gateway has no
``agent_os`` dependency.  The enforcement contract is deliberately narrow:
catalog allowlisting, bounded per-session call budgets, dangerous-parameter
blocking, and fail-closed response scanning.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any


@dataclass
class GovernancePolicy:
    """Runtime controls used by :class:`MCPGateway`."""

    allowed_tools: list[str] = field(default_factory=list)
    max_tool_calls: int = 10


@dataclass(frozen=True)
class ResponseThreat:
    category: str
    description: str


@dataclass(frozen=True)
class ResponseScanResult:
    is_safe: bool
    threats: list[ResponseThreat] = field(default_factory=list)


@dataclass
class MCPResponseDecision:
    allowed: bool
    reason: str
    content: str | None = None
    threats: list[dict[str, str]] = field(default_factory=list)
    action: str = "allowed"


_DANGEROUS_ARGUMENT_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b\d{3}-\d{2}-\d{4}\b",
        r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        r";\s*(rm|del|format|mkfs)\b",
        r"\$\(.*\)",
        r"`[^`]+`",
    )
)

_INJECTION_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"<(?:important|system|instruction|instructions|hidden|inject|admin|override|prompt|context|role)\b[^>]*>",
        r"\[(?:system|admin|instructions?)\]",
        r"ignore\s+(?:all\s+)?previous\s+(?:instructions?|context|rules?)",
        r"(?:forget|disregard|override)\s+(?:all\s+)?(?:previous|above|prior|earlier)",
        r"\bexecute\s+this\b",
        r"\byou\s+are\s+now\b",
        r"\bnew\s+(?:role|instruction|directive|persona)\s*:",
        r"\bfrom\s+now\s+on\b",
        r"\bdo\s+not\s+(?:follow|obey|listen)\b",
    )
)

_CREDENTIAL_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"AKIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z\-_]{35}",
        r"gh[pousr]_[A-Za-z0-9_]{20,}",
        r"sk-[A-Za-z0-9]{20,}",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    )
)

_PII_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b\d{3}-\d{2}-\d{4}\b",
        r"\b(?:4\d{3}|5[1-5]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    )
)

_URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_EXFILTRATION_PATTERN = re.compile(
    r"(?:api[_-]?key|token|secret|payload|data|dump|upload|exfil|webhook|webhook\.site|requestbin|pastebin|ngrok|transfer\.sh)",
    re.IGNORECASE,
)


class MCPResponseScanner:
    """Detect prompt injection, credentials, PII, and exfiltration URLs."""

    def scan_response(self, content: str | None, tool_name: str = "unknown") -> ResponseScanResult:
        if not content:
            return ResponseScanResult(is_safe=True)
        threats: list[ResponseThreat] = []
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(content):
                threats.append(ResponseThreat("prompt_injection", "Instruction detected"))
        for pattern in _CREDENTIAL_PATTERNS:
            if pattern.search(content):
                threats.append(ResponseThreat("credential_leak", "Credential detected"))
        for pattern in _PII_PATTERNS:
            if pattern.search(content):
                threats.append(ResponseThreat("pii_leak", "PII detected"))
        for match in _URL_PATTERN.finditer(content):
            if _EXFILTRATION_PATTERN.search(match.group(0)):
                threats.append(ResponseThreat("data_exfiltration", "Exfiltration URL detected"))
        return ResponseScanResult(is_safe=not threats, threats=threats)


class MCPGateway:
    """Fail-closed catalog and response enforcement owned by cMCP."""

    def __init__(
        self,
        policy: GovernancePolicy,
        *,
        response_scanner: MCPResponseScanner | None = None,
    ) -> None:
        self.policy = policy
        self._response_scanner = response_scanner or MCPResponseScanner()
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    def intercept_tool_call(
        self, agent_id: str, tool_name: str, params: dict[str, Any]
    ) -> tuple[bool, str]:
        try:
            if tool_name not in self.policy.allowed_tools:
                return False, f"Tool '{tool_name}' is not on the allow list"
            encoded = json.dumps(params, default=str)
            for pattern in _DANGEROUS_ARGUMENT_PATTERNS:
                if pattern.search(encoded):
                    return False, "Parameters matched a dangerous pattern"
            with self._lock:
                count = self._counts.get(agent_id, 0)
                if count >= self.policy.max_tool_calls:
                    return False, f"Agent '{agent_id}' exceeded call budget"
                self._counts[agent_id] = count + 1
            return True, "Allowed by policy"
        except Exception:
            return False, "Internal gateway error - access denied (fail closed)"

    def intercept_tool_response(
        self, agent_id: str, tool_name: str, response_content: str | Any
    ) -> MCPResponseDecision:
        del agent_id
        try:
            text = response_content if isinstance(response_content, str) else json.dumps(response_content, default=str)
            result = self._response_scanner.scan_response(text, tool_name)
            threats = [
                {"category": threat.category, "description": threat.description}
                for threat in result.threats
            ]
            if threats:
                categories = ", ".join(sorted({threat["category"] for threat in threats}))
                return MCPResponseDecision(
                    allowed=False,
                    reason=f"Response blocked - {categories} detected",
                    content=None,
                    threats=threats,
                    action="blocked",
                )
            return MCPResponseDecision(True, "Response clean", text, [], "allowed")
        except Exception:
            return MCPResponseDecision(
                False,
                "Response scanner error - blocked (fail closed)",
                None,
                [],
                "error",
            )
