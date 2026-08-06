"""Tests for Stage 3 sensitivity classification (issue #80)."""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
)
from cmcp_runtime.inspection.pipeline import SensitivityClassificationStage


def _make_entry(
    sensitivity_level: str = "public",
    output_schema: dict[str, Any] | None = None,
) -> CatalogEntry:
    return CatalogEntry(
        tool_name="test.tool",
        server=ServerIdentity(
            display_name="Test",
            url="https://test.example.com/mcp",
            tls_fingerprint="SHA256:AAAA/BBBB==",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description="test",
            input_schema={},
            output_schema=output_schema,
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="external",
        requires_baa=False,
        sensitivity_level=sensitivity_level,
        added_at="2026-06-01T00:00:00Z",
        approved_by="test",
    )


# ── Source 1: catalog annotation ──────────────────────────────────────────────

def test_catalog_annotated_sensitivity_public_no_tags():
    stage = SensitivityClassificationStage()
    result = stage.run({}, _make_entry("public"))
    assert result.decision == "allow"
    assert result.sensitivity_tags == []


def test_catalog_annotated_sensitivity_pii():
    stage = SensitivityClassificationStage()
    result = stage.run({}, _make_entry("pii"))
    assert "pii" in result.sensitivity_tags


def test_catalog_annotated_sensitivity_hipaa_phi():
    stage = SensitivityClassificationStage()
    result = stage.run({}, _make_entry("hipaa_phi"))
    assert "hipaa_phi" in result.sensitivity_tags


def test_catalog_annotated_sensitivity_no_duplicate():
    stage = SensitivityClassificationStage()
    entry = _make_entry("pii")
    result = stage.run({}, entry)
    assert result.sensitivity_tags.count("pii") == 1


# ── Source 2: field-level tags from output_schema ─────────────────────────────

def test_field_level_string_sensitivity_tag():
    schema = {
        "type": "object",
        "properties": {
            "ssn": {"type": "string", "x-sensitivity": "pii"},
            "name": {"type": "string"},
        },
    }
    stage = SensitivityClassificationStage()
    result = stage.run({"ssn": "123-45-6789", "name": "Alice"}, _make_entry(output_schema=schema))
    assert "pii" in result.sensitivity_tags


def test_field_level_list_sensitivity_tags():
    schema = {
        "type": "object",
        "properties": {
            "diagnosis": {"type": "string", "x-sensitivity": ["hipaa_phi", "pii"]},
        },
    }
    stage = SensitivityClassificationStage()
    result = stage.run({"diagnosis": "diabetes"}, _make_entry(output_schema=schema))
    assert "hipaa_phi" in result.sensitivity_tags
    assert "pii" in result.sensitivity_tags


def test_field_level_absent_field_no_tag():
    schema = {
        "type": "object",
        "properties": {
            "ssn": {"type": "string", "x-sensitivity": "pii"},
        },
    }
    stage = SensitivityClassificationStage()
    result = stage.run({"name": "Bob"}, _make_entry(output_schema=schema))
    assert "pii" not in result.sensitivity_tags


def test_no_output_schema_no_field_tags():
    # Field-level tags only fire when a property has x-sensitivity; without a schema, none fire.
    # Use non-PII content so source-3 pattern matching also produces no tags.
    stage = SensitivityClassificationStage()
    with patch("cmcp_runtime.inspection.pipeline._AGT_AVAILABLE", False):
        result = stage.run({"ssn": "not-a-real-ssn"}, _make_entry(output_schema=None))
    assert result.sensitivity_tags == []


# ── Source 3: pattern matching fallback ───────────────────────────────────────

def test_ssn_pattern_detected_no_agt():
    stage = SensitivityClassificationStage()
    with patch("cmcp_runtime.inspection.pipeline._AGT_AVAILABLE", False):
        result = stage.run({"data": "SSN is 123-45-6789"}, _make_entry())
    assert "pii" in result.sensitivity_tags


def test_email_pattern_detected_no_agt():
    stage = SensitivityClassificationStage()
    with patch("cmcp_runtime.inspection.pipeline._AGT_AVAILABLE", False):
        result = stage.run({"contact": "user@example.com"}, _make_entry())
    assert "pii" in result.sensitivity_tags


def test_phi_pattern_detected_no_agt():
    stage = SensitivityClassificationStage()
    with patch("cmcp_runtime.inspection.pipeline._AGT_AVAILABLE", False):
        result = stage.run({"note": "patient mrn: ABC12345"}, _make_entry())
    assert "hipaa_phi" in result.sensitivity_tags


def test_no_pii_no_tag_no_agt():
    stage = SensitivityClassificationStage()
    with patch("cmcp_runtime.inspection.pipeline._AGT_AVAILABLE", False):
        result = stage.run({"message": "hello world"}, _make_entry())
    assert result.sensitivity_tags == []


# ── Deduplication across sources ──────────────────────────────────────────────

def test_no_duplicate_pii_from_catalog_and_field():
    schema = {
        "type": "object",
        "properties": {
            "ssn": {"type": "string", "x-sensitivity": "pii"},
        },
    }
    stage = SensitivityClassificationStage()
    with patch("cmcp_runtime.inspection.pipeline._AGT_AVAILABLE", False):
        result = stage.run({"ssn": "123-45-6789"}, _make_entry("pii", output_schema=schema))
    assert result.sensitivity_tags.count("pii") == 1


# ── Source 3 with AGT present: local patterns must still run (#476) ───────────
#
# The previous implementation called `_agt_redactor.find_credentials()`, a method
# that has never existed on agt-core's CredentialRedactor (verified against the
# pinned 4.1.0 wheel: the real names are find_matches / find_pii_matches). The
# call raised AttributeError into a bare `except Exception: pass`, and because
# the local patterns sat in the `else` branch of that check they never ran
# either. With AGT installed, content-based classification was dead.

class _RedactorMissingMethod:
    """An agt-core CredentialRedactor without the method the caller expects."""


class _RedactorRaising:
    @staticmethod
    def find_matches(_value: str) -> list[str]:
        raise RuntimeError("upstream blew up")

    @staticmethod
    def find_pii_matches(_value: str) -> list[str]:
        raise RuntimeError("upstream blew up")


class _RedactorSuffixBlind:
    """Reproduces microsoft/agent-governance-toolkit#3494: a secret with a
    suffix glued to it is not matched at all, so AGT alone calls it clean."""

    @staticmethod
    def find_matches(value: str) -> list[str]:
        return ["AKIA"] if "AKIAIOSFODNN7EXAMPLE" in value and "_old" not in value else []

    @staticmethod
    def find_pii_matches(_value: str) -> list[str]:
        return []


def test_local_patterns_still_run_when_agt_lacks_the_method():
    stage = SensitivityClassificationStage()
    with patch("cmcp_runtime.inspection.pipeline._AGT_AVAILABLE", True):
        result = stage.run(
            {"data": "SSN is 123-45-6789"}, _make_entry(), _RedactorMissingMethod()
        )
    assert "pii" in result.sensitivity_tags


def test_local_patterns_still_run_when_agt_raises():
    stage = SensitivityClassificationStage()
    with patch("cmcp_runtime.inspection.pipeline._AGT_AVAILABLE", True):
        result = stage.run(
            {"data": "SSN is 123-45-6789"}, _make_entry(), _RedactorRaising()
        )
    assert "pii" in result.sensitivity_tags


def test_suffixed_secret_still_tagged_despite_agt_3494():
    stage = SensitivityClassificationStage()
    blind = _RedactorSuffixBlind()
    with patch("cmcp_runtime.inspection.pipeline._AGT_AVAILABLE", True):
        clean = stage.run({"k": "AKIAIOSFODNN7EXAMPLE x@y.com"}, _make_entry(), blind)
        suffixed = stage.run({"k": "AKIAIOSFODNN7EXAMPLE_old x@y.com"}, _make_entry(), blind)
    # AGT catches the bare key; only the local pass catches the suffixed one.
    assert "pii" in clean.sensitivity_tags
    assert "pii" in suffixed.sensitivity_tags


# ── AGT component construction is independent (#476) ──────────────────────────
#
# All three components were built in one try block, so a failure constructing
# the first left the other two unbuilt and all three silently None. One upstream
# API change disabled three security components at once, with no log line.

def test_one_failing_agt_component_does_not_disable_the_others():
    from cmcp_runtime.inspection.pipeline import InspectionPipeline

    def _boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("upstream API changed")

    with (
        patch("cmcp_runtime.inspection.pipeline._AGT_AVAILABLE", True),
        patch("cmcp_runtime.inspection.pipeline.DetectionConfig", _boom),
        patch("cmcp_runtime.inspection.pipeline.CredentialRedactor", lambda: "redactor"),
        patch("cmcp_runtime.inspection.pipeline.AGTResponseScanner", lambda: "scanner"),
    ):
        pipeline = InspectionPipeline()

    # The detector failed, but the other two must still be constructed.
    assert pipeline._agt_injection_detector is None
    assert pipeline._agt_redactor == "redactor"
    assert pipeline._agt_response_scanner == "scanner"


def test_failing_agt_component_is_logged_not_swallowed(caplog: Any) -> None:
    import logging

    from cmcp_runtime.inspection.pipeline import InspectionPipeline

    def _boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("upstream API changed")

    with (
        caplog.at_level(logging.WARNING, logger="cmcp_runtime.inspection.pipeline"),
        patch("cmcp_runtime.inspection.pipeline._AGT_AVAILABLE", True),
        patch("cmcp_runtime.inspection.pipeline.DetectionConfig", _boom),
        patch("cmcp_runtime.inspection.pipeline.CredentialRedactor", lambda: "redactor"),
        patch("cmcp_runtime.inspection.pipeline.AGTResponseScanner", lambda: "scanner"),
    ):
        InspectionPipeline()

    assert any("PromptInjectionDetector unavailable" in r.message for r in caplog.records)
