"""
Response inspection pipeline: implements issues #61, #65, #81.

Stage 4 injection detection and Stage 3 sensitivity classification are owned by
cMCP and use versioned local patterns so runtime behavior does not depend on AGT.
"""

from __future__ import annotations

import hashlib
import json
import logging
import pathlib
import re
from dataclasses import dataclass, field
from typing import Any

import jsonschema

from cmcp_runtime.catalog.loader import CatalogEntry

_log = logging.getLogger(__name__)

# Stable cMCP-owned sensitivity thresholds.
_INJECTION_THRESHOLDS: dict[str, float] = {"strict": 0.3, "balanced": 0.5, "permissive": 0.7}

# ── Versioned injection patterns ──────────────────────────────────────────────
# INJECT-006: loaded from patterns_v1.json so every change is auditable and
# tied to a semantic version. The version string is included in every
# InspectionResult so audit consumers know which pattern set made the decision.
_PATTERNS_FILE = pathlib.Path(__file__).parent / "patterns_v1.json"


def _load_patterns() -> tuple[list[tuple[str, str]], str]:
    """Load injection patterns from the versioned config file.

    Returns (raw_pairs, version) where raw_pairs is a list of (regex_str, name)
    tuples ready for compilation, and version is the semantic version string from
    the config (e.g. "1.0.0").
    """
    data = json.loads(_PATTERNS_FILE.read_text(encoding="utf-8"))
    version: str = data["version"]
    pairs: list[tuple[str, str]] = [
        (entry["regex"], entry["name"]) for entry in data["patterns"]
    ]
    _log.info("injection patterns loaded: version=%s count=%d file=%s", version, len(pairs), _PATTERNS_FILE)
    return pairs, version


_DEFAULT_INJECTION_PATTERNS, _PATTERNS_VERSION = _load_patterns()
_COMPILED_PATTERNS = [(re.compile(pat, re.DOTALL), name) for pat, name in _DEFAULT_INJECTION_PATTERNS]


@dataclass
class StageResult:
    stage: str
    decision: str  # "allow", "deny", "skip"
    reason: str | None = None
    stripped_fields: list[str] | None = None
    sensitivity_tags: list[str] = field(default_factory=list)
    injection_pattern: str | None = None
    injection_scanner: str | None = None  # INJECT-003: which scanner triggered the deny
    injection_score: float | None = None  # INJECT-003: confidence score if available


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
    # INJECT-003: scanner attribution for audit chain context
    injection_scanner: str | None = None  # which scanner detected: "agt_mcp", "agt_detector", "regex", "timeout"
    injection_score: float | None = None  # confidence score (0.0–1.0) if available
    injection_threshold: float | None = None  # threshold in effect when the decision was made
    patterns_version: str | None = None  # INJECT-006: semantic version of the active regex pattern set


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


def _stage2_schema_validation(
    response_bytes: bytes,
    catalog_entry: CatalogEntry,
) -> tuple[StageResult, bytes]:
    """
    Stage 2: validate response against the catalog entry's approved output_schema.

    Mode is per catalog entry (catalog_entry.schema_validation_mode, default "redact").

    Returns a (StageResult, response_bytes) tuple where response_bytes may be
    modified (surplus fields stripped) in redact mode.
    """
    output_schema = catalog_entry.approved_definition.output_schema
    if output_schema is None:
        return StageResult(stage="schema", decision="skip"), response_bytes

    # Only validate JSON responses; non-JSON passes through
    try:
        payload: Any = json.loads(response_bytes)
    except (json.JSONDecodeError, ValueError):
        return StageResult(stage="schema", decision="allow", reason="non-JSON response; schema check skipped"), response_bytes

    # Identify surplus fields at the top level only
    surplus: list[str] = []
    if isinstance(payload, dict) and isinstance(output_schema.get("properties"), dict):
        allowed_props: set[str] = set(output_schema["properties"].keys())
        surplus = [k for k in payload if k not in allowed_props]

    mode = catalog_entry.schema_validation_mode

    if not surplus:
        # No surplus fields: still run jsonschema for type/required violations
        try:
            jsonschema.validate(payload, output_schema)
        except jsonschema.ValidationError as exc:
            return (
                StageResult(
                    stage="schema",
                    decision="deny",
                    reason=f"RESPONSE_SCHEMA_VIOLATION: {exc.message}",
                ),
                response_bytes,
            )
        return StageResult(stage="schema", decision="allow"), response_bytes

    # Surplus fields present: mode determines action
    if mode == "strict":
        return (
            StageResult(
                stage="schema",
                decision="deny",
                reason="RESPONSE_SCHEMA_VIOLATION_STRICT",
                stripped_fields=surplus,
            ),
            response_bytes,
        )

    if mode == "log":
        return (
            StageResult(
                stage="schema",
                decision="allow",
                reason="surplus fields logged",
                stripped_fields=surplus,
            ),
            response_bytes,
        )

    # mode == "redact" (default): strip surplus fields and return modified bytes
    assert isinstance(payload, dict)  # guaranteed by surplus check above
    redacted = {k: v for k, v in payload.items() if k not in surplus}
    modified_bytes = json.dumps(redacted, separators=(",", ":"), ensure_ascii=False).encode()
    return (
        StageResult(
            stage="schema",
            decision="allow",
            reason="surplus fields redacted",
            stripped_fields=surplus,
        ),
        modified_bytes,
    )


def _stage4_injection_detection(
    response_text: str,
    custom_patterns: list[tuple[re.Pattern[str], str]] | None = None,
) -> StageResult:
    """
    Stage 4: detect indirect prompt injection patterns in the response text.

    Uses the versioned cMCP pattern set from
    docs/spec/response-inspection.md §Stage 4.
    """
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
                injection_scanner="regex",
            )
    return StageResult(stage="injection", decision="allow")


# cMCP-owned PII and credential patterns.
_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "pii"),           # SSN
    (re.compile(r"\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"), "pii"),  # Visa
    (re.compile(r"\b5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"), "pii"),  # MC
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "pii"),  # email
    (re.compile(r"\b(\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b"), "pii"),  # phone
    (re.compile(r"\b(?:dob|date of birth|birthdate)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b", re.I), "pii"),
    (re.compile(r"\b(?:patient|mrn|member\s*id)[:\s]+[A-Z0-9\-]{4,20}\b", re.I), "hipaa_phi"),
    (re.compile(r"\b(?:diagnosis|icd[- ]?\d+|cpt[- ]?\d+)\b", re.I), "hipaa_phi"),
]


def _extract_schema_sensitivity_tags(
    response_json: dict[str, Any],
    output_schema: dict[str, Any] | None,
) -> list[str]:
    """Extract sensitivity tags from x-sensitivity annotations in output_schema properties."""
    if output_schema is None:
        return []
    tags: list[str] = []
    properties = output_schema.get("properties", {})
    for field_name, field_schema in properties.items():
        sensitivity = field_schema.get("x-sensitivity")
        if sensitivity and field_name in response_json:
            if isinstance(sensitivity, str):
                if sensitivity not in tags:
                    tags.append(sensitivity)
            elif isinstance(sensitivity, list):
                for s in sensitivity:
                    if s not in tags:
                        tags.append(s)
    return tags


def _classify_sensitivity(
    catalog_entry: CatalogEntry,
    response_text: str | None = None,
) -> list[str]:
    """
    Stage 3: derive sensitivity tags from three sources (applied in order):

    1. catalog_entry.sensitivity_level: always applied
    2. field-level x-sensitivity annotations in output_schema properties
    3. cMCP pattern matching on response content
    """
    tags: list[str] = []

    # Source 1: catalog-level annotation
    if (catalog_entry.sensitivity_level and catalog_entry.sensitivity_level != "public"
            and catalog_entry.sensitivity_level not in tags):
        tags.append(catalog_entry.sensitivity_level)

    # Source 2: field-level tags from output_schema
    if response_text:
        try:
            response_json = json.loads(response_text)
            if isinstance(response_json, dict):
                schema_tags = _extract_schema_sensitivity_tags(
                    response_json,
                    catalog_entry.approved_definition.output_schema,
                )
                for t in schema_tags:
                    if t not in tags:
                        tags.append(t)
        except (json.JSONDecodeError, ValueError):
            pass

    # Source 3: content pattern matching.
    #
    if response_text:
        for pattern, tag in _PII_PATTERNS:
            if len(tags) >= 4:  # cap scan at 4 distinct tags
                break
            if pattern.search(response_text) and tag not in tags:
                tags.append(tag)

    return tags


class SensitivityClassificationStage:
    """
    Stage 3 of the InspectionPipeline: sensitivity classification.

    Applies three classification sources in order:
    1. catalog_entry.sensitivity_level annotation
    2. x-sensitivity field-level tags in output_schema properties
    3. Content pattern matching using cMCP-owned patterns
    """

    def run(
        self,
        response_json: dict[str, Any],
        catalog_entry: CatalogEntry,
    ) -> StageResult:
        """
        Classify a tool response and return a StageResult with sensitivity_tags set.
        response_json is the parsed JSON body; pass {} for non-JSON responses.
        """
        response_text = json.dumps(response_json, separators=(",", ":"), ensure_ascii=False)
        tags = _classify_sensitivity(
            catalog_entry,
            response_text=response_text,
        )
        return StageResult(
            stage="classification",
            decision="allow",
            sensitivity_tags=tags,
        )


class InspectionPipeline:
    """
    4-stage response inspection pipeline.

    All stages run even when an earlier stage would deny: this produces a
    complete audit record. Final decision = deny if ANY stage returns deny.

    After completing all stages, calls session.update_from_inspection() to
    propagate sensitivity state (the only place session state is updated).

    Stages 3 and 4 use cMCP-owned, versioned classifiers and scanners.
    """

    def __init__(
        self,
        max_response_size_bytes: int = 2 * 1024 * 1024,
        custom_injection_patterns: list[tuple[re.Pattern[str], str]] | None = None,
        scanner_timeout_seconds: float = 5.0,
        injection_sensitivity: str = "balanced",
    ) -> None:
        self._max_bytes = max_response_size_bytes
        self._injection_patterns = custom_injection_patterns
        # Retained as a public constructor argument for configuration compatibility.
        self._scanner_timeout = scanner_timeout_seconds
        self._injection_threshold: float | None = _INJECTION_THRESHOLDS.get(injection_sensitivity)


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
        modified_response: bytes | None = None

        # Stage 1: size check
        s1 = _stage1_size_check(response_bytes, self._max_bytes)
        stage_results["size"] = s1.decision
        if s1.decision == "deny":
            deny_reasons.append(s1.reason or "size exceeded")

        # Stage 2: schema validation (issue #74)
        s2, response_bytes = _stage2_schema_validation(response_bytes, catalog_entry)
        stage_results["schema"] = s2.decision
        if s2.decision == "deny":
            deny_reasons.append(s2.reason or "schema violation")
        if s2.stripped_fields:
            stripped_fields = s2.stripped_fields
        if s2.decision == "allow" and s2.stripped_fields and s2.reason == "surplus fields redacted":
            # Redact mode modified the bytes: expose to caller
            modified_response = response_bytes

        # Stage 3: sensitivity classification (cMCP patterns + catalog)
        try:
            response_text_for_s3 = response_bytes.decode("utf-8", errors="replace")
        except Exception:
            response_text_for_s3 = ""
        s3_tags = _classify_sensitivity(
            catalog_entry,
            response_text=response_text_for_s3,
        )
        sensitivity_tags.extend(s3_tags)
        stage_results["classification"] = "allow"

        # Stage 4: injection detection
        # INJECT-005: scan bytes decoded strictly: non-UTF-8 is treated as a deny to
        # prevent bypass via invalid byte sequences that errors="replace" would corrupt.
        try:
            response_text = response_bytes.decode("utf-8")
        except UnicodeDecodeError:
            deny_reasons.append("INJECT-005: non-UTF-8 response rejected before injection scan")
            injection_pattern = "non-utf8-response"
            stage_results["injection"] = "deny"
            final = "deny"
            if session is not None:
                session.update_from_inspection(
                    call_id=call_id,
                    sensitivity_tags=sensitivity_tags,
                    injection_detected=True,
                    response_allowed=False,
                )
            return InspectionResult(
                call_id=call_id,
                final_decision="deny",
                deny_reason="; ".join(dict.fromkeys(deny_reasons)),
                sensitivity_tags=sensitivity_tags,
                stripped_fields=stripped_fields,
                injection_pattern_matched=injection_pattern,
                stage_results=stage_results,
                response_payload_hash=response_payload_hash,
                modified_response=None,
                injection_scanner="utf8_guard",
                injection_threshold=self._injection_threshold,
                patterns_version=_PATTERNS_VERSION,
            )

        injection_scanner: str | None = None
        injection_score: float | None = None

        s4 = _stage4_injection_detection(response_text, self._injection_patterns)
        stage_results["injection"] = s4.decision
        if s4.decision == "deny":
            deny_reasons.append(s4.reason or "injection detected")
            injection_pattern = s4.injection_pattern
            if not injection_scanner:
                injection_scanner = s4.injection_scanner
                injection_score = s4.injection_score

        # POLICY-008: deduplicate deny_reasons so the audit record reflects distinct
        # policy firings, not duplicated entries from multiple code paths.
        deny_reasons = list(dict.fromkeys(deny_reasons))
        final = "deny" if deny_reasons else "allow"

        # Handoff to session state: happens even for denied responses
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
            deny_reason="; ".join(dict.fromkeys(deny_reasons)) if deny_reasons else None,
            sensitivity_tags=sensitivity_tags,
            stripped_fields=stripped_fields,
            injection_pattern_matched=injection_pattern,
            stage_results=stage_results,
            response_payload_hash=response_payload_hash,
            modified_response=modified_response,
            injection_scanner=injection_scanner,
            injection_score=injection_score,
            injection_threshold=self._injection_threshold,
            patterns_version=_PATTERNS_VERSION,
        )
