"""
Response inspection pipeline — implements issues #61, #65, #81.

Stage 4 (injection detection) and Stage 3 (sensitivity classification) now
delegate to AGT components where available:
  - agent_os.prompt_injection.PromptInjectionDetector  (Stage 4)
  - agent_os.credential_redactor.CredentialRedactor    (Stage 3 PII redaction)
  - agent_os.mcp_response_scanner.MCPResponseScanner   (Stage 4 MCP-specific threats)

Falls back to the original regex-based detection if AGT is unavailable.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from cmcp_gateway.catalog.loader import CatalogEntry

# ── AGT components (optional — fall back gracefully) ─────────────────────────
try:
    from agent_os.prompt_injection import PromptInjectionDetector, ThreatLevel
    from agent_os.credential_redactor import CredentialRedactor
    from agent_os.mcp_response_scanner import MCPResponseScanner as AGTResponseScanner
    _AGT_AVAILABLE = True
except ImportError:
    _AGT_AVAILABLE = False

# ── Fallback injection patterns (used when AGT not available) ─────────────────
# Starter set per docs/spec/response-inspection.md §Stage 4.
_DEFAULT_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"<system>[\s\S]*?</system>", "xml-system-tag"),
    (r"<instructions>[\s\S]*?</instructions>", "xml-instructions-tag"),
    (r"<context>[\s\S]*?</context>", "xml-context-tag"),  # FP risk: legitimate XML data
    (r"(?i)ignore (previous|all|above) instructions", "ignore-instructions"),
    (r"(?i)disregard (your|the) (previous|system|initial) (prompt|instructions|context)", "disregard-instructions"),
    (r"(?i)(you are now|from now on you are|act as) [A-Z][a-zA-Z]+", "persona-hijack"),  # FP risk: role descriptions
    (r"(?i)(exfiltrate|send|forward|transmit) (the|all|this|user|customer) (data|information|context|message)", "exfiltrate"),
    (r"SYSTEM OVERRIDE", "system-override"),
    (r"---BEGIN SYSTEM---", "begin-system-marker"),
    (r"\[INST\][\s\S]*?\[/INST\]", "llama-instruction-markers"),
]

_COMPILED_PATTERNS = [(re.compile(p, re.DOTALL), name) for p, name in _DEFAULT_INJECTION_PATTERNS]


@dataclass
class StageResult:
    stage: str
    decision: str  # "allow", "deny", "skip"
    reason: str | None = None
    stripped_fields: list[str] | None = None
    sensitivity_tags: list[str] = field(default_factory=list)
    injection_pattern: str | None = None


@dataclass
class InspectionResult:
    call_id: str
    final_decision: str  # "allow" or "deny"
    deny_reason: str | None
    sensitivity_tags: list[str]
    stripped_fields: list[str] | None
    injection_pattern_matched: str | None
    stage_results: dict[str, str]
    response_payload_hash: str | None
    modified_response: bytes | None  # None if not modified (allow as-is)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stage1_size_check(response_bytes: bytes, max_bytes: int) -> StageResult:
    """Stage 1: reject responses that exceed the configured size limit."""
    if len(response_bytes) > max_bytes:
        return StageResult(
            stage="size",
            decision="deny",
            reason=f"response size {len(response_bytes)} exceeds limit {max_bytes}",
        )
    return StageResult(stage="size", decision="allow")


def _stage4_injection_detection(
    response_text: str,
    custom_patterns: list[tuple[re.Pattern[str], str]] | None = None,
    _agt_detector: Any | None = None,
) -> StageResult:
    """
    Stage 4: detect indirect prompt injection patterns in the response text.

    Uses AGT PromptInjectionDetector (12-vector) when available, falls back to
    the regex starter set from docs/spec/response-inspection.md §Stage 4.
    """
    # Try AGT first
    if _AGT_AVAILABLE and _agt_detector is not None:
        try:
            result = _agt_detector.detect(response_text)
            if result.is_injection:
                pattern_name = result.injection_type.value if hasattr(result.injection_type, "value") else str(result.injection_type)
                # Log pattern name and bounded window, not full content
                return StageResult(
                    stage="injection",
                    decision="deny",
                    reason=f"AGT injection detected: {pattern_name} (confidence={result.confidence:.2f})",
                    injection_pattern=f"agt:{pattern_name}",
                )
            return StageResult(stage="injection", decision="allow")
        except Exception:
            pass  # Fall through to regex

    # Fallback: regex patterns
    patterns = custom_patterns or _COMPILED_PATTERNS
    for pattern, name in patterns:
        match = pattern.search(response_text)
        if match:
            start = max(0, match.start() - 25)
            end = min(len(response_text), match.end() + 25)
            context_window = repr(response_text[start:end])
            return StageResult(
                stage="injection",
                decision="deny",
                reason=f"injection pattern '{name}' matched near {context_window}",
                injection_pattern=name,
            )
    return StageResult(stage="injection", decision="allow")


def _classify_sensitivity(
    catalog_entry: CatalogEntry,
    response_text: str | None = None,
    _agt_redactor: Any | None = None,
) -> list[str]:
    """
    Stage 3: derive sensitivity tags from catalog metadata and content.

    When AGT CredentialRedactor is available, also scans response content for
    credentials, PII, and sensitive patterns. Catalog-level annotation is always
    applied regardless of content scanning.
    """
    tags: list[str] = []

    # Catalog-level annotation (always applied)
    if catalog_entry.sensitivity_level and catalog_entry.sensitivity_level != "public":
        tags.append(catalog_entry.sensitivity_level)

    # AGT CredentialRedactor — scan response content for PII/credentials
    if _AGT_AVAILABLE and _agt_redactor is not None and response_text:
        try:
            matches = _agt_redactor.find_credentials(response_text)
            if matches:
                # Any credential/PII match elevates to at least 'pii'
                if "pii" not in tags and "confidential" not in tags and \
                   "hipaa_phi" not in tags and "mnpi" not in tags:
                    tags.append("pii")
        except Exception:
            pass  # Degraded gracefully

    return tags


class InspectionPipeline:
    """
    4-stage response inspection pipeline.

    All stages run even when an earlier stage would deny — this produces a
    complete audit record. Final decision = deny if ANY stage returns deny.

    After completing all stages, calls session.update_from_inspection() to
    propagate sensitivity state (the only place session state is updated).

    When agent-os-kernel is installed, stages 3 and 4 use AGT components:
      Stage 3: AGT CredentialRedactor + catalog annotations
      Stage 4: AGT PromptInjectionDetector (12-vector) + AGT MCPResponseScanner
    Falls back to regex patterns and catalog-only classification if AGT is unavailable.
    """

    def __init__(
        self,
        max_response_size_bytes: int = 2 * 1024 * 1024,
        custom_injection_patterns: list[tuple[re.Pattern[str], str]] | None = None,
    ) -> None:
        self._max_bytes = max_response_size_bytes
        self._injection_patterns = custom_injection_patterns

        # Instantiate AGT components once per pipeline instance
        if _AGT_AVAILABLE:
            try:
                self._agt_injection_detector = PromptInjectionDetector()
                self._agt_redactor = CredentialRedactor()
                self._agt_response_scanner = AGTResponseScanner()
            except Exception:
                self._agt_injection_detector = None
                self._agt_redactor = None
                self._agt_response_scanner = None
        else:
            self._agt_injection_detector = None
            self._agt_redactor = None
            self._agt_response_scanner = None

    def run(
        self,
        call_id: str,
        catalog_entry: CatalogEntry,
        response_bytes: bytes,
        session: Any | None = None,
    ) -> InspectionResult:
        """
        Run all 4 stages. Returns InspectionResult with final decision.
        Calls session.update_from_inspection() if session is provided.
        """
        response_payload_hash = f"sha256:{_sha256_hex(response_bytes)}"

        stage_results: dict[str, str] = {}
        deny_reasons: list[str] = []
        stripped_fields: list[str] | None = None
        injection_pattern: str | None = None
        sensitivity_tags: list[str] = []

        # Stage 1: size check
        s1 = _stage1_size_check(response_bytes, self._max_bytes)
        stage_results["size"] = s1.decision
        if s1.decision == "deny":
            deny_reasons.append(s1.reason or "size exceeded")

        # Stage 2: schema validation (Phase 1 GA — issue #74; skipped here)
        stage_results["schema"] = "skip"

        # Stage 3: sensitivity classification (AGT CredentialRedactor + catalog)
        try:
            response_text_for_s3 = response_bytes.decode("utf-8", errors="replace")
        except Exception:
            response_text_for_s3 = ""
        s3_tags = _classify_sensitivity(
            catalog_entry,
            response_text=response_text_for_s3,
            _agt_redactor=self._agt_redactor,
        )
        sensitivity_tags.extend(s3_tags)
        stage_results["classification"] = "allow"

        # Stage 4: injection detection (AGT PromptInjectionDetector + MCPResponseScanner)
        try:
            response_text = response_text_for_s3
        except Exception:
            response_text = ""

        # AGT MCPResponseScanner catches MCP-specific threats (tool poisoning in responses)
        if self._agt_response_scanner is not None:
            try:
                agt_scan = self._agt_response_scanner.scan_response(
                    response_text, tool_name=catalog_entry.tool_name
                )
                if not agt_scan.is_safe:
                    threat_name = str(agt_scan.threats[0]) if agt_scan.threats else "mcp_threat"
                    deny_reasons.append(f"AGT MCPResponseScanner: {threat_name}")
                    injection_pattern = f"agt_mcp:{threat_name}"
                    stage_results["injection"] = "deny"
            except Exception:
                pass

        s4 = _stage4_injection_detection(
            response_text,
            self._injection_patterns,
            _agt_detector=self._agt_injection_detector,
        )
        stage_results["injection"] = s4.decision
        if s4.decision == "deny":
            deny_reasons.append(s4.reason or "injection detected")
            injection_pattern = s4.injection_pattern

        final = "deny" if deny_reasons else "allow"

        # Handoff to session state — happens even for denied responses
        # (a denied high-sensitivity response still raises session sensitivity)
        injection_detected = s4.decision == "deny"
        if session is not None:
            session.update_from_inspection(
                call_id=call_id,
                sensitivity_tags=sensitivity_tags,
                injection_detected=injection_detected,
                response_allowed=(final == "allow"),
            )

        return InspectionResult(
            call_id=call_id,
            final_decision=final,
            deny_reason="; ".join(deny_reasons) if deny_reasons else None,
            sensitivity_tags=sensitivity_tags,
            stripped_fields=stripped_fields,
            injection_pattern_matched=injection_pattern,
            stage_results=stage_results,
            response_payload_hash=response_payload_hash,
            modified_response=None,
        )
