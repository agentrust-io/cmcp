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
