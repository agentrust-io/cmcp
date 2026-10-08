"""Published audit schema accepts runtime records and rejects malformed variants."""

from __future__ import annotations

import json
from dataclasses import asdict, fields
from pathlib import Path
from typing import get_args
from uuid import uuid4

import pytest
from jsonschema import Draft7Validator, FormatChecker, ValidationError

from cmcp_runtime.audit.chain import AuditChain, AuditEntry, EntryType
from tests.unit.test_unadmitted_observation_bounds import _persisted_comparison

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas/audit-entry.schema.json"
OPTIONAL_FIELDS = {
    "detail",
    "workflow_id",
    "evidence_class",
    "effective_data_class",
    "execution_id",
}


@pytest.fixture
def validator() -> Draft7Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema, format_checker=FormatChecker())


@pytest.fixture
def tool_call() -> dict:
    chain = AuditChain(str(uuid4()))
    entry = chain.append(
        "tool_call",
        call_id=str(uuid4()),
        tool_name="approved_tool",
        server_identity="server-1",
        policy_decision="allow",
        latency_us=12,
        response_inspection_result="pass",
        workflow_id="workflow-1",
        evidence_class="tls-pinned",
        effective_data_class="internal",
        execution_id="execution-1",
        detail={"source": "upstream", "count": 1, "ratio": 0.5},
    )
    assert chain.verify_chain()
    return json.loads(json.dumps(asdict(entry)))


def test_schema_enum_covers_every_runtime_entry_type(validator: Draft7Validator) -> None:
    allowed = set(validator.schema["properties"]["entry_type"]["enum"])
    assert set(get_args(EntryType)) <= allowed


def test_schema_declares_every_serialized_field(validator: Draft7Validator) -> None:
    assert {field.name for field in fields(AuditEntry)} <= set(validator.schema["properties"])
    assert validator.schema["additionalProperties"] is False


@pytest.mark.parametrize("entry_type", get_args(EntryType))
def test_all_runtime_event_types_serialize_and_validate(validator, entry_type) -> None:
    chain = AuditChain(str(uuid4()))
    chain.append(entry_type)
    for entry in chain.entries:
        validator.validate(json.loads(json.dumps(asdict(entry))))
    assert chain.verify_chain()


def test_conventional_tool_call_control(validator, tool_call) -> None:
    validator.validate(tool_call)


def test_legacy_tool_call_without_new_optional_fields(validator, tool_call) -> None:
    legacy = {key: value for key, value in tool_call.items() if key not in OPTIONAL_FIELDS}
    validator.validate(legacy)


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 65])
async def test_actual_persisted_unadmitted_records_validate(validator, tmp_path, count) -> None:
    rows = await _persisted_comparison(tmp_path, [f"late_tool_{i}" for i in range(count)])
    observations = [row for row in rows if row["entry_type"] == "tool_observed_unadmitted"]
    assert len(observations) == count
    assert all(row["call_id"] is None for row in observations)
    assert any(row["detail"].get("recorded_name_truncated") is False for row in observations)
    if count == 65:
        assert observations[-1]["detail"]["omitted_name_count"] == 1
    for row in rows:
        validator.validate(row)


@pytest.mark.parametrize(
    "field,value",
    [
        ("unexpected", "value"),
        ("entry_type", "future_unknown_event"),
        ("call_id", 42),
        ("call_id", "invalid-uuid"),
        ("detail", []),
        ("detail", {"nested": {"value": 1}}),
        ("detail", {"items": []}),
        ("detail", {"absent": None}),
        ("workflow_id", 1),
        ("evidence_class", None),
        ("effective_data_class", False),
        ("execution_id", {}),
    ],
)
def test_invalid_record_mutants_are_rejected(validator, tool_call, field, value) -> None:
    validator.validate(tool_call)
    mutant = {**tool_call, field: value}
    with pytest.raises(ValidationError):
        validator.validate(mutant)


def test_call_id_remains_required_even_when_null_is_allowed(validator, tool_call) -> None:
    validator.validate({**tool_call, "call_id": None})
    del tool_call["call_id"]
    with pytest.raises(ValidationError):
        validator.validate(tool_call)
