"""Tests for Stage 2 response schema validation (issue #74)."""

from __future__ import annotations

import json

from cmcp_gateway.catalog.loader import ApprovedDefinition, CatalogEntry, ServerIdentity
from cmcp_gateway.inspection.pipeline import InspectionPipeline, _stage2_schema_validation


def _make_entry(
    output_schema: dict | None = None,
    schema_validation_mode: str = "redact",
) -> CatalogEntry:
    return CatalogEntry(
        tool_name="test.tool",
        server=ServerIdentity(
            display_name="Test",
            url="https://test.example.com",
            tls_fingerprint="SHA256:AAAA/BBBB==",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description="test tool",
            input_schema={},
            output_schema=output_schema,
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="external",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-06-01T00:00:00Z",
        approved_by="test",
        schema_validation_mode=schema_validation_mode,  # type: ignore[arg-type]
    )


_SCHEMA_WITH_PROPERTIES = {
    "type": "object",
    "properties": {
        "result": {"type": "string"},
        "count": {"type": "integer"},
    },
}

_VALID_PAYLOAD = {"result": "ok", "count": 3}
_SURPLUS_PAYLOAD = {"result": "ok", "count": 3, "internal_id": "secret", "debug": True}


# ── Skip when output_schema is None ──────────────────────────────────────────

def test_skip_when_no_output_schema():
    entry = _make_entry(output_schema=None)
    result, out_bytes = _stage2_schema_validation(b'{"result": "ok"}', entry)
    assert result.decision == "skip"
    assert result.stage == "schema"


def test_pipeline_records_skip_when_no_schema():
    pipeline = InspectionPipeline()
    entry = _make_entry(output_schema=None)
    ir = pipeline.run("c1", entry, b'{"result": "ok"}')
    assert ir.stage_results["schema"] == "skip"
    assert ir.modified_response is None


# ── Non-JSON response passes through ─────────────────────────────────────────

def test_non_json_response_allows():
    entry = _make_entry(output_schema=_SCHEMA_WITH_PROPERTIES)
    result, out_bytes = _stage2_schema_validation(b"plain text response", entry)
    assert result.decision == "allow"
    assert out_bytes == b"plain text response"


def test_pipeline_non_json_passes_through():
    pipeline = InspectionPipeline()
    entry = _make_entry(output_schema=_SCHEMA_WITH_PROPERTIES)
    ir = pipeline.run("c1", entry, b"plain text response")
    assert ir.final_decision == "allow"
    assert ir.stage_results["schema"] == "allow"
    assert ir.modified_response is None


# ── Valid response matching schema: allow ─────────────────────────────────────

def test_valid_response_allows():
    entry = _make_entry(output_schema=_SCHEMA_WITH_PROPERTIES)
    payload_bytes = json.dumps(_VALID_PAYLOAD).encode()
    result, out_bytes = _stage2_schema_validation(payload_bytes, entry)
    assert result.decision == "allow"
    assert result.stripped_fields is None or result.stripped_fields == []
    assert out_bytes == payload_bytes


def test_pipeline_valid_response_no_modification():
    pipeline = InspectionPipeline()
    entry = _make_entry(output_schema=_SCHEMA_WITH_PROPERTIES)
    ir = pipeline.run("c1", entry, json.dumps(_VALID_PAYLOAD).encode())
    assert ir.final_decision == "allow"
    assert ir.modified_response is None


# ── Redact mode: strips surplus fields ───────────────────────────────────────

def test_redact_mode_strips_surplus_fields():
    entry = _make_entry(output_schema=_SCHEMA_WITH_PROPERTIES, schema_validation_mode="redact")
    payload_bytes = json.dumps(_SURPLUS_PAYLOAD).encode()
    result, out_bytes = _stage2_schema_validation(payload_bytes, entry)
    assert result.decision == "allow"
    assert result.stripped_fields is not None
    assert set(result.stripped_fields) == {"internal_id", "debug"}
    redacted = json.loads(out_bytes)
    assert "internal_id" not in redacted
    assert "debug" not in redacted
    assert redacted["result"] == "ok"
    assert redacted["count"] == 3


def test_pipeline_redact_mode_sets_modified_response():
    pipeline = InspectionPipeline()
    entry = _make_entry(output_schema=_SCHEMA_WITH_PROPERTIES, schema_validation_mode="redact")
    ir = pipeline.run("c1", entry, json.dumps(_SURPLUS_PAYLOAD).encode())
    assert ir.final_decision == "allow"
    assert ir.modified_response is not None
    redacted = json.loads(ir.modified_response)
    assert "internal_id" not in redacted
    assert "debug" not in redacted
    assert ir.stripped_fields is not None
    assert set(ir.stripped_fields) == {"internal_id", "debug"}


def test_pipeline_redact_mode_no_modified_response_when_no_surplus():
    pipeline = InspectionPipeline()
    entry = _make_entry(output_schema=_SCHEMA_WITH_PROPERTIES, schema_validation_mode="redact")
    ir = pipeline.run("c1", entry, json.dumps(_VALID_PAYLOAD).encode())
    assert ir.modified_response is None


# ── Strict mode: deny on surplus fields ──────────────────────────────────────

def test_strict_mode_denies_on_surplus():
    entry = _make_entry(output_schema=_SCHEMA_WITH_PROPERTIES, schema_validation_mode="strict")
    payload_bytes = json.dumps(_SURPLUS_PAYLOAD).encode()
    result, out_bytes = _stage2_schema_validation(payload_bytes, entry)
    assert result.decision == "deny"
    assert result.reason == "RESPONSE_SCHEMA_VIOLATION_STRICT"
    assert result.stripped_fields is not None
    assert set(result.stripped_fields) == {"internal_id", "debug"}
    # Response bytes unchanged in strict mode
    assert out_bytes == payload_bytes


def test_pipeline_strict_mode_denies():
    pipeline = InspectionPipeline()
    entry = _make_entry(output_schema=_SCHEMA_WITH_PROPERTIES, schema_validation_mode="strict")
    ir = pipeline.run("c1", entry, json.dumps(_SURPLUS_PAYLOAD).encode())
    assert ir.final_decision == "deny"
    assert ir.stage_results["schema"] == "deny"
    assert "RESPONSE_SCHEMA_VIOLATION_STRICT" in (ir.deny_reason or "")


def test_strict_mode_allows_valid_response():
    entry = _make_entry(output_schema=_SCHEMA_WITH_PROPERTIES, schema_validation_mode="strict")
    payload_bytes = json.dumps(_VALID_PAYLOAD).encode()
    result, out_bytes = _stage2_schema_validation(payload_bytes, entry)
    assert result.decision == "allow"


# ── Log mode: passes through but records surplus_fields ──────────────────────

def test_log_mode_allows_with_surplus_logged():
    entry = _make_entry(output_schema=_SCHEMA_WITH_PROPERTIES, schema_validation_mode="log")
    payload_bytes = json.dumps(_SURPLUS_PAYLOAD).encode()
    result, out_bytes = _stage2_schema_validation(payload_bytes, entry)
    assert result.decision == "allow"
    assert result.stripped_fields is not None
    assert set(result.stripped_fields) == {"internal_id", "debug"}
    # Response bytes unmodified in log mode
    assert out_bytes == payload_bytes


def test_pipeline_log_mode_passes_through_unmodified():
    pipeline = InspectionPipeline()
    entry = _make_entry(output_schema=_SCHEMA_WITH_PROPERTIES, schema_validation_mode="log")
    payload_bytes = json.dumps(_SURPLUS_PAYLOAD).encode()
    ir = pipeline.run("c1", entry, payload_bytes)
    assert ir.final_decision == "allow"
    assert ir.stage_results["schema"] == "allow"
    # Log mode does not set modified_response (bytes unchanged)
    assert ir.modified_response is None
    assert ir.stripped_fields is not None
    assert set(ir.stripped_fields) == {"internal_id", "debug"}
