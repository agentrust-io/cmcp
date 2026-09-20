"""Validate complete HTTP-emitted claims, including optional audit summaries."""

import copy
import json
from pathlib import Path

import jsonschema
import pytest

from cmcp_runtime.cli import build_server
from cmcp_runtime.kill_switch import KillSwitchBlockStore
from tests.unit.test_kill_switch_durable import _bearer, _client, _ctx, _operator

SCHEMA = json.loads(
    (Path(__file__).parents[2] / "schemas/trace-claim.schema.json").read_text(encoding="utf-8")
)


@pytest.mark.asyncio
@pytest.mark.parametrize("trip", [False, True], ids=["session-close", "operator-trip"])
async def test_complete_emitted_claim_validates(tmp_path, trip):
    # Software-only context: this checks the emitted wire contract, not attestation.
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        if trip:
            response = await client.post(
                "/kill-switch/trip",
                json={"reason": "schema regression", "authorized_by": "oncall"},
                headers=_operator(),
            )
            assert response.status_code == 200, response.text
            claim = response.json()["claim"]
        else:
            response = await client.post(
                f"/sessions/{server._session.session_id}/close", headers=_bearer()
            )
            assert response.status_code == 200, response.text
            claim = response.json()
    gateway = claim["gateway"]
    assert "call_log_summary" in gateway
    assert "edges_represent" in gateway["call_summary"]["call_graph_summary"]
    jsonschema.validate(claim, SCHEMA)

    # Each formerly missing declaration is necessary; unknown fields stay refused.
    for owner, field in [
        (SCHEMA["properties"]["gateway"], "call_log_summary"),
        (
            SCHEMA["properties"]["gateway"]["properties"]["call_summary"]["properties"][
                "call_graph_summary"
            ],
            "edges_represent",
        ),
    ]:
        narrowed = copy.deepcopy(owner)
        del narrowed["properties"][field]
        instance = (
            gateway
            if field == "call_log_summary"
            else gateway["call_summary"]["call_graph_summary"]
        )
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance, narrowed)

    for field, invalid in [
        ("total_calls", -1),
        ("total_calls", "0"),
        ("tools_called", [1]),
        ("suspicious_sequences_detected", -1),
        ("unknown", True),
    ]:
        malformed = copy.deepcopy(claim)
        malformed["gateway"]["call_log_summary"][field] = invalid
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(malformed, SCHEMA)
    for value in [1, None]:
        malformed = copy.deepcopy(claim)
        malformed["gateway"]["call_summary"]["call_graph_summary"]["edges_represent"] = value
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(malformed, SCHEMA)

    historical = copy.deepcopy(claim)
    del historical["gateway"]["call_log_summary"]
    del historical["gateway"]["call_summary"]["call_graph_summary"]["edges_represent"]
    jsonschema.validate(historical, SCHEMA)
