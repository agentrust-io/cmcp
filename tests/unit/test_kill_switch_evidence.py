"""Evidence a verifier can check: the claim says the switch was armed, and refusals are signed."""

from __future__ import annotations

import copy
import json
import pathlib

import jsonschema
import pytest

from cmcp_runtime.audit.trace_claim import REFUSAL_RECEIPT_TYPE
from cmcp_runtime.cli import build_server
from cmcp_runtime.config import KillSwitchConfig
from cmcp_runtime.kill_switch import KillSwitchBlockStore
from cmcp_runtime.startup import run_startup
from cmcp_verify import verify_kill_switch_refusal
from tests.unit.test_kill_switch_durable import (
    _AGENT_ID,
    _bearer,
    _client,
    _ctx,
    _operator,
    _tool_call_body,
)
from tests.unit.test_kill_switch_mid_session import _deny_every_call
from tests.unit.test_startup import _minimal_setup

_SCHEMA = json.loads(
    (pathlib.Path(__file__).parents[2] / "schemas" / "trace-claim.schema.json").read_text()
)
# The kill_switch object's own schema. Whole-claim validation is covered in
# test_trace_claim.py; here the subject is only the block this change adds.
_KILL_SWITCH_SCHEMA = _SCHEMA["properties"]["gateway"]["properties"]["kill_switch"]


def _validate_kill_switch(claim: dict) -> None:
    jsonschema.validate(instance=claim["gateway"]["kill_switch"], schema=_KILL_SWITCH_SCHEMA)


def _trip_body() -> dict[str, str]:
    return {"reason": "exfiltration attempt reported by SOC", "authorized_by": "oncall"}


async def _operator_trip(server, client) -> dict:
    resp = await client.post("/kill-switch/trip", json=_trip_body(), headers=_operator())
    assert resp.status_code == 200, resp.text
    return resp.json()["claim"]


async def _refusal(client) -> dict:
    resp = await client.post("/mcp", json=_tool_call_body("refused"), headers=_bearer())
    assert resp.status_code == 403
    return resp.json()["error"]["data"]["receipt"]


# ── The claim records the armed switch ──────────────────────────────────────


@pytest.mark.asyncio
async def test_claim_records_armed_settings_when_not_tripped(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    sid = server._session.session_id
    async with _client(server) as client:
        claim = (await client.post(f"/sessions/{sid}/close", headers=_bearer())).json()
    ks = claim["gateway"]["kill_switch"]
    assert ks == {"enabled": True, "window_seconds": 300, "deny_rate_threshold": 0.9, "min_calls": 5}
    _validate_kill_switch(claim)


@pytest.mark.asyncio
async def test_claim_names_the_operator_as_the_trigger(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        claim = await _operator_trip(server, client)
    assert claim["gateway"]["kill_switch"]["trigger"] == "operator"
    _validate_kill_switch(claim)


@pytest.mark.asyncio
async def test_claim_names_the_deny_rate_as_the_trigger(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    _deny_every_call(server)
    sid = server._session.session_id
    async with _client(server) as client:
        for i in range(server._session_manager._kill_switch._config.min_calls):
            await client.post("/mcp", json=_tool_call_body(str(i)), headers=_bearer())
    claim = server._session_manager.get_trace_claim(sid)
    assert claim["gateway"]["kill_switch"]["trigger"] == "deny_rate"
    _validate_kill_switch(claim)


@pytest.mark.asyncio
async def test_claim_has_no_kill_switch_block_when_the_switch_is_disabled(tmp_path):
    ctx = _ctx(KillSwitchBlockStore(tmp_path / "audit.db"))
    ctx.config.kill_switch = KillSwitchConfig(enabled=False)
    server = build_server(ctx)
    sid = server._session.session_id
    async with _client(server) as client:
        claim = (await client.post(f"/sessions/{sid}/close", headers=_bearer())).json()
    assert "kill_switch" not in claim["gateway"]


# ── Signed refusals ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_refusal_receipt_verifies_against_the_tripped_sessions_claim(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        claim = await _operator_trip(server, client)
        receipt = await _refusal(client)

    assert receipt["type"] == REFUSAL_RECEIPT_TYPE
    assert receipt["agent_id"] == _AGENT_ID
    result = verify_kill_switch_refusal(receipt, claim)
    assert result.valid, result.errors
    assert result.session_id == claim["gateway"]["session_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("agent_id", "spiffe://example.com/agent/someone-else", "signature verification failed"),
        ("refused_at", "2020-01-01T00:00:00+00:00", "signature verification failed"),
        ("claim_digest", "sha256:" + "0" * 64, "does not match the claim"),
        ("type", "something/else", "receipt type"),
    ],
)
async def test_an_altered_receipt_fails(tmp_path, field, value, expected):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        claim = await _operator_trip(server, client)
        receipt = await _refusal(client)
    receipt[field] = value
    result = verify_kill_switch_refusal(receipt, claim)
    assert not result.valid
    assert any(expected in e for e in result.errors), result.errors


@pytest.mark.asyncio
async def test_a_receipt_does_not_verify_against_another_gateways_claim(tmp_path):
    first = build_server(_ctx(KillSwitchBlockStore(tmp_path / "a.db")))
    second = build_server(_ctx(KillSwitchBlockStore(tmp_path / "b.db")))
    async with _client(first) as client:
        await _operator_trip(first, client)
        receipt = await _refusal(client)
    async with _client(second) as client:
        other_claim = await _operator_trip(second, client)
    result = verify_kill_switch_refusal(receipt, other_claim)
    assert not result.valid
    assert any("key that signed the claim" in e for e in result.errors)


@pytest.mark.asyncio
async def test_a_tampered_claim_fails_even_with_a_genuine_receipt(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        claim = await _operator_trip(server, client)
        receipt = await _refusal(client)
    forged = copy.deepcopy(claim)
    # Say the switch was set far more strictly than it was.
    forged["gateway"]["kill_switch"]["min_calls"] = 1
    assert forged != claim
    result = verify_kill_switch_refusal(receipt, forged)
    assert not result.valid
    assert any("claim signature" in e for e in result.errors)


@pytest.mark.asyncio
async def test_a_receipt_from_a_gateway_blocked_at_start_says_it_has_no_claim(tmp_path):
    store = KillSwitchBlockStore(tmp_path / "audit.db")
    store.block(_AGENT_ID, reason="deny_rate_threshold")
    server = build_server(_ctx(store))
    async with _client(server) as client:
        receipt = await _refusal(client)
    assert "claim_digest" not in receipt
    assert receipt["session_id"] == server._session.session_id


# ── Startup ──────────────────────────────────────────────────────────────────


def test_enabled_kill_switch_without_an_identity_refuses_to_start(tmp_path, monkeypatch):
    """Enabled with no Agent Manifest, the switch would look armed and stop nothing."""
    import cmcp_runtime.config as _cfg

    monkeypatch.setattr(_cfg, "DEV_MODE", True)
    config_path = _minimal_setup(tmp_path, "kill_switch:\n  enabled: true\n")
    monkeypatch.setenv("CMCP_DEV_MODE", "1")
    with pytest.raises(SystemExit) as exc_info:
        run_startup(str(config_path))
    assert exc_info.value.code == 1
