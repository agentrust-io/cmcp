"""The kill switch stops a session at the call that trips it, and an operator can trip it directly."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from cmcp_runtime.cli import build_server
from cmcp_runtime.config import KillSwitchConfig
from cmcp_runtime.kill_switch import KillSwitchBlockStore
from cmcp_runtime.mcp.proxy import CallResult
from tests.unit.test_kill_switch_durable import (
    _AGENT_ID,
    _bearer,
    _client,
    _ctx,
    _operator,
    _tool_call_body,
    _unblock_body,
)


def _deny_every_call(server) -> None:
    """Replace the enforcement pipeline with one that denies and audits every call.

    Everything around it stays real: admission, the per-call kill switch
    observation, the seal, and the halt.
    """
    proxy = server._proxy

    async def denying_impl(call_id: str, tool_name: str, *args: Any, **kwargs: Any) -> CallResult:
        entry = proxy._audit.append(
            "tool_call",
            call_id=call_id,
            tool_name=tool_name,
            policy_decision="deny",
            policy_rule_matched="deny-all",
        )
        return CallResult(
            call_id=call_id,
            tool_name=tool_name,
            allowed=False,
            would_have_denied=False,
            response=None,
            deny_reason="policy",
            latency_us=1,
            audit_entry_hash=entry.entry_hash,
        )

    proxy._call_tool_impl = denying_impl


def _server(tmp_path, **ctx_overrides: Any):
    ctx = _ctx(KillSwitchBlockStore(tmp_path / "audit.db"))
    for name, value in ctx_overrides.items():
        setattr(ctx, name, value)
    return build_server(ctx)


# ── Automatic trip, mid-session ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_session_is_sealed_at_the_call_that_trips_the_switch(tmp_path):
    server = _server(tmp_path)
    _deny_every_call(server)
    sid = server._session.session_id
    min_calls = server._session_manager._kill_switch._config.min_calls

    async with _client(server) as client:
        for i in range(min_calls):
            resp = await client.post("/mcp", json=_tool_call_body(str(i)), headers=_bearer())
            assert resp.status_code == 403
            assert resp.json()["error"]["data"]["error_code"] == "POLICY_DENY"

        # The client never closed the session, and it is closed anyway.
        claim = server._session_manager.get_trace_claim(sid)
        assert claim is not None
        assert claim["gateway"]["kill_switch_triggered"] is True
        assert server._proxy.halted_identity == _AGENT_ID

        trips = [
            e for e in server._closed_chains[sid].entries
            if e.entry_type == "break_glass_used" and e.detail["reason"] == "kill_switch_triggered"
        ]
        assert len(trips) == 1
        assert "tripping_call_id" in trips[0].detail

        after = await asyncio.wait_for(
            client.post("/mcp", json=_tool_call_body("after"), headers=_bearer()), 5
        )
        assert after.status_code == 403
        assert after.json()["error"]["data"]["error_code"] == "KILL_SWITCH_TRIPPED"


@pytest.mark.asyncio
async def test_calls_counted_mid_session_are_not_counted_again_at_close(tmp_path):
    server = _server(tmp_path)
    _deny_every_call(server)
    evaluator = server._session_manager._kill_switch
    # One below the trip point, so the session stays open.
    calls = evaluator._config.min_calls - 1

    async with _client(server) as client:
        for i in range(calls):
            await client.post("/mcp", json=_tool_call_body(str(i)), headers=_bearer())
        assert len(evaluator._events[_AGENT_ID]) == calls

        sid = server._session.session_id
        closed = await client.post(f"/sessions/{sid}/close", headers=_bearer())
        assert closed.status_code == 200
        assert closed.json()["gateway"]["kill_switch_triggered"] is False
        assert len(evaluator._events[_AGENT_ID]) == calls


@pytest.mark.asyncio
async def test_unblock_after_a_mid_session_trip_resumes_service(tmp_path):
    server = _server(tmp_path)
    _deny_every_call(server)
    tripped_sid = server._session.session_id
    async with _client(server) as client:
        for i in range(server._session_manager._kill_switch._config.min_calls):
            await client.post("/mcp", json=_tool_call_body(str(i)), headers=_bearer())
        assert server._proxy.halted_identity == _AGENT_ID

        resp = await client.post("/kill-switch/unblock", json=_unblock_body(), headers=_operator())
        assert resp.status_code == 200, resp.text
        assert resp.json()["session_id"] != tripped_sid
        assert server._proxy.halted_identity is None


# ── Operator trip ────────────────────────────────────────────────────────────


def _trip_body() -> dict[str, str]:
    return {"reason": "exfiltration attempt reported by SOC", "authorized_by": "oncall"}


@pytest.mark.asyncio
async def test_operator_trip_stops_the_session_and_returns_its_claim(tmp_path):
    store = KillSwitchBlockStore(tmp_path / "audit.db")
    server = build_server(_ctx(store))
    sid = server._session.session_id
    async with _client(server) as client:
        resp = await client.post("/kill-switch/trip", json=_trip_body(), headers=_operator())
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "tripped"
        assert body["agent_id"] == _AGENT_ID
        assert body["claim"]["gateway"]["session_id"] == sid
        assert body["claim"]["gateway"]["kill_switch_triggered"] is True
        assert store.is_blocked(_AGENT_ID)

        entry = next(
            e for e in server._closed_chains[sid].entries
            if e.entry_type == "break_glass_used"
            and e.detail["reason"] == "kill_switch_operator_trip"
        )
        assert entry.detail["authorized_by"] == "oncall"
        assert entry.detail["credential_verified"] == "operator_token"

        refused = await client.post("/mcp", json=_tool_call_body(), headers=_bearer())
        assert refused.status_code == 403
        again = await client.post("/kill-switch/trip", json=_trip_body(), headers=_operator())
        assert again.status_code == 409


@pytest.mark.asyncio
async def test_operator_trip_requires_the_operator_token(tmp_path):
    server = _server(tmp_path)
    async with _client(server) as client:
        resp = await client.post("/kill-switch/trip", json=_trip_body(), headers=_bearer())
        assert resp.status_code == 401
        assert server._proxy.halted_identity is None


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["reason", "authorized_by"])
async def test_operator_trip_requires_every_field(tmp_path, missing):
    server = _server(tmp_path)
    body = _trip_body()
    del body[missing]
    async with _client(server) as client:
        resp = await client.post("/kill-switch/trip", json=body, headers=_operator())
        assert resp.status_code == 422
        assert server._proxy.halted_identity is None


@pytest.mark.asyncio
async def test_operator_trip_is_refused_when_the_kill_switch_is_disabled(tmp_path):
    server = _server(tmp_path)
    server._session_manager._ctx.config.kill_switch = KillSwitchConfig(enabled=False)
    async with _client(server) as client:
        resp = await client.post("/kill-switch/trip", json=_trip_body(), headers=_operator())
        assert resp.status_code == 409
        assert resp.json()["error_code"] == "KILL_SWITCH_DISABLED"


@pytest.mark.asyncio
async def test_operator_trip_with_no_bound_identity_changes_nothing(tmp_path):
    server = _server(tmp_path, agent_manifest=None)
    sid = server._session.session_id
    async with _client(server) as client:
        resp = await client.post("/kill-switch/trip", json=_trip_body(), headers=_operator())
        assert resp.status_code == 409
        assert resp.json()["error_code"] == "NO_AGENT_IDENTITY"
        assert server._session.session_id == sid
        assert server._session_manager.get_trace_claim(sid) is None
