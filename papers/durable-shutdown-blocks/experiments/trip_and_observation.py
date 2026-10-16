"""Slow-operation trip and a fresh-observation protocol prototype.

Part A (slow-operation trip). Hypothesis: with the pinned cMCP gateway, an
operator trip admits no call after the trip starts, every later call is refused
with KILL_SWITCH_TRIPPED, and recovery requires the operator unblock. We also
record, without treating it as a pass condition, what happens to operations
that were already admitted: cooperative coroutines that finish inside the drain
deadline, coroutines cancelled at the deadline, and work in a worker thread
that cancellation cannot stop.

Part B (fresh observation). The pinned code has no current-state proof; a
refusal receipt is historical. This prototype (harness code, not cMCP code)
answers a verifier nonce with a statement of the durable block state, signed
by the gateway key that signed the closing claim. Hypothesis: the verifier
accepts a fresh statement, rejects a replayed statement and a statement from a
different key, and a statement after unblock reports unblocked while the old
refusal receipt still verifies. Control: a verifier without the nonce check
accepts the replay, so the criterion must fail for it.

Usage: trip_and_observation.py run SCRATCH [--no-nonce-check]
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import time

AGENT = None


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_server(db: Path, drain_s: float, effects: list, mode: str, duration: float):
    from cmcp_runtime.cli import build_server
    from cmcp_runtime.kill_switch import KillSwitchBlockStore
    from cmcp_runtime.mcp.proxy import CallResult
    from tests.unit.test_kill_switch_durable import _ctx
    server = build_server(_ctx(KillSwitchBlockStore(db)))
    server._session_close_drain_s = drain_s
    proxy = server._proxy
    clock = time.perf_counter

    async def slow_impl(call_id, tool_name, *args, **kwargs):
        rec = {"call_id": tool_name, "start": clock(), "done": None, "cancelled": False}
        effects.append(rec)

        def blocking():
            time.sleep(duration)
            rec["done"] = clock()  # the effect happens here, in the worker thread
        try:
            if mode == "thread":
                await asyncio.to_thread(blocking)
            else:
                await asyncio.sleep(duration)
                rec["done"] = clock()
        except asyncio.CancelledError:
            rec["cancelled"] = True
            raise
        entry = proxy._audit.append("tool_call", call_id=call_id, tool_name=tool_name,
                                    policy_decision="allow", policy_rule_matched="experiment")
        return CallResult(call_id=call_id, tool_name=tool_name, allowed=True, would_have_denied=False,
                          response="ok", deny_reason=None, latency_us=1, audit_entry_hash=entry.entry_hash)

    proxy._call_tool_impl = slow_impl
    return server


def body(name):
    return {"jsonrpc": "2.0", "id": name, "method": "tools/call", "params": {"name": name, "arguments": {}}}


def code_of(resp):
    try:
        data = resp.json()
    except Exception:
        return f"http-{resp.status_code}"
    if "result" in data:
        return "admitted"
    err = data.get("error", {})
    d = err.get("data") if isinstance(err, dict) else None
    return (d or {}).get("error_code", f"http-{resp.status_code}")


async def slow_trip(scratch: Path, label: str, mode: str, duration: float, drain_s: float) -> dict:
    from tests.unit.test_kill_switch_durable import _AGENT_ID, _bearer, _client, _operator, _unblock_body
    from cmcp_verify import verify_kill_switch_refusal
    effects: list = []
    server = make_server(scratch / f"{label}.db", drain_s, effects, mode, duration)
    clock = time.perf_counter
    async with _client(server) as client:
        inflight = [asyncio.create_task(client.post("/mcp", json=body(f"slow-{i}"), headers=_bearer()))
                    for i in range(4)]
        while sum(1 for e in effects if e["call_id"].startswith("slow-")) < 4:
            await asyncio.sleep(0.005)
        t_trip = clock()
        trip = asyncio.create_task(client.post("/kill-switch/trip", json={"reason": "experiment",
                                   "authorized_by": "oncall"}, headers=_operator()))
        await asyncio.sleep(0.05)
        t_late = clock()
        late = asyncio.create_task(client.post("/mcp", json=body("late-during-trip"), headers=_bearer()))
        trip_resp = await trip
        t_trip_done = clock()
        claim = trip_resp.json().get("claim")
        late_resp = await late
        slow_resps = await asyncio.gather(*inflight, return_exceptions=True)
        after = await client.post("/mcp", json=body("after-trip"), headers=_bearer())
        receipt = after.json().get("error", {}).get("data", {}).get("receipt") if after.status_code == 403 else None
        receipt_valid = bool(receipt and claim and verify_kill_switch_refusal(receipt, claim).valid)
        # Let worker threads finish so their late effects are observed.
        await asyncio.sleep(duration + 0.5)
        unblock = await client.post("/kill-switch/unblock", json=_unblock_body(), headers=_operator())
        resumed = await client.post("/mcp", json=body("after-unblock"), headers=_bearer())
    started_after_trip = [e["call_id"] for e in effects if e["start"] > t_trip
                          and e["call_id"] not in ("after-unblock",)]
    slow = [e for e in effects if e["call_id"].startswith("slow-")]
    ms = lambda t: None if t is None else round((t - t_trip) * 1000)
    result = {
        "label": label, "operation": mode, "operation_seconds": duration, "drain_deadline_seconds": drain_s,
        "trip_status": trip_resp.status_code, "trip_returned_ms_after_start": ms(t_trip_done),
        "slow_call_responses": sorted(code_of(r) if not isinstance(r, Exception) else type(r).__name__
                                      for r in slow_resps),
        "slow_effects_completed_before_trip_returned": sum(1 for e in slow if e["done"] and e["done"] <= t_trip_done),
        "slow_effects_completed_after_trip_returned": sum(1 for e in slow if e["done"] and e["done"] > t_trip_done),
        "slow_effects_never_completed": sum(1 for e in slow if not e["done"]),
        "last_completed_effect_ms_after_trip_start": ms(max((e["done"] for e in slow if e["done"]), default=None)),
        "late_call_sent_ms_after_trip_start": ms(t_late), "late_call": code_of(late_resp),
        "after_trip_call": code_of(after), "refusal_receipt_verifies_against_claim": receipt_valid,
        "effects_started_after_trip_start": started_after_trip,
        "unblock_status": unblock.status_code, "after_unblock_call": code_of(resumed),
    }
    result["ok"] = (trip_resp.status_code == 200 and not started_after_trip
                    and result["late_call"] == "KILL_SWITCH_TRIPPED"
                    and result["after_trip_call"] == "KILL_SWITCH_TRIPPED" and receipt_valid
                    and unblock.status_code == 200 and result["after_unblock_call"] == "admitted")
    server._session_manager  # keep reference until here
    return result, server, claim, receipt


# ------------------------------------------------------------- Part B
OBS_TYPE = "harness/kill-switch-observation/v0"


def observe(server, signing_key, nonce: str) -> dict:
    """Gateway side: answer one verifier nonce with the current durable block state."""
    from cmcp_verify.verify import _canonical_json
    store = server._session_manager._kill_switch._store
    agent = server._session_manager._ctx.agent_manifest.agent_id
    stmt = {"type": OBS_TYPE, "agent_id": agent, "nonce": nonce, "blocked": store.is_blocked(agent),
            "blocked_at": store.blocked_at(agent), "halted_identity": server._proxy.halted_identity,
            "observed_at": time.time(), "gateway_key": _b64(signing_key.public_key_bytes)}
    stmt["signature"] = _b64(signing_key.sign(_canonical_json(stmt)))
    return stmt


def verify_observation(stmt: dict, *, claim: dict, nonce: str, agent_id: str, check_nonce=True) -> list:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cmcp_verify.verify import _canonical_json
    errors = []
    body = {k: v for k, v in stmt.items() if k != "signature"}
    if stmt.get("type") != OBS_TYPE:
        errors.append("type")
    if stmt.get("gateway_key") != claim["trace"]["cnf"]["jwk"]["x"]:
        errors.append("key is not the claim key")
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(stmt["gateway_key"])).verify(
            _unb64(stmt["signature"]), _canonical_json(body))
    except (InvalidSignature, ValueError, KeyError):
        errors.append("signature")
    if check_nonce and stmt.get("nonce") != nonce:
        errors.append("nonce mismatch (not fresh)")
    if stmt.get("agent_id") != agent_id:
        errors.append("agent")
    return errors


async def fresh_observation(scratch: Path, check_nonce: bool) -> dict:
    from cmcp_runtime.audit.keys import SigningKey
    from cmcp_verify import verify_kill_switch_refusal
    from tests.unit.test_kill_switch_durable import _AGENT_ID, _bearer, _client, _operator, _unblock_body
    effects: list = []
    server = make_server(scratch / "observation.db", 5.0, effects, "async", 0.01)
    key = server._session_manager._ctx.signing_key
    async with _client(server) as client:
        trip = await client.post("/kill-switch/trip", json={"reason": "experiment", "authorized_by": "oncall"},
                                 headers=_operator())
        claim = trip.json()["claim"]
        refused = await client.post("/mcp", json=body("refused"), headers=_bearer())
        if code_of(refused) != "KILL_SWITCH_TRIPPED":
            return {"nonce_check": check_nonce, "call_after_trip": code_of(refused), "ok": False}
        receipt = refused.json()["error"]["data"]["receipt"]
        n1 = secrets.token_hex(32)
        o1 = observe(server, key, n1)
        e1 = verify_observation(o1, claim=claim, nonce=n1, agent_id=_AGENT_ID, check_nonce=check_nonce)
        await client.post("/kill-switch/unblock", json=_unblock_body(), headers=_operator())
        receipt_after_unblock = verify_kill_switch_refusal(receipt, claim).valid
        n2 = secrets.token_hex(32)
        o2 = observe(server, key, n2)
        e2 = verify_observation(o2, claim=claim, nonce=n2, agent_id=_AGENT_ID, check_nonce=check_nonce)
        n3 = secrets.token_hex(32)
        e_replay = verify_observation(o1, claim=claim, nonce=n3, agent_id=_AGENT_ID, check_nonce=check_nonce)
        other = SigningKey()
        n4 = secrets.token_hex(32)
        forged = observe(server, other, n4)
        forged["blocked"] = True
        forged["signature"] = _b64(other.sign(__import__("cmcp_verify.verify", fromlist=["_canonical_json"])
                                              ._canonical_json({k: v for k, v in forged.items() if k != "signature"})))
        e_forged = verify_observation(forged, claim=claim, nonce=n4, agent_id=_AGENT_ID, check_nonce=check_nonce)
    # Scope: a separate gateway store has never seen the block.
    independent = make_server(scratch / "observation-independent.db", 5.0, [], "async", 0.01)
    n5 = secrets.token_hex(32)
    o5 = observe(independent, independent._session_manager._ctx.signing_key, n5)
    rows = {
        "fresh_while_blocked": {"accepted": not e1, "blocked": o1["blocked"]},
        "old_refusal_receipt_after_unblock_still_verifies": receipt_after_unblock,
        "fresh_after_unblock": {"accepted": not e2, "blocked": o2["blocked"]},
        "replayed_blocked_statement_for_new_nonce": {"accepted": not e_replay, "errors": e_replay},
        "statement_signed_by_other_key": {"accepted": not e_forged, "errors": e_forged},
        "independent_store_reports_blocked": o5["blocked"],
    }
    ok = (rows["fresh_while_blocked"] == {"accepted": True, "blocked": True} and receipt_after_unblock
          and rows["fresh_after_unblock"] == {"accepted": True, "blocked": False}
          and not rows["replayed_blocked_statement_for_new_nonce"]["accepted"]
          and not rows["statement_signed_by_other_key"]["accepted"])
    return {"nonce_check": check_nonce, **rows, "ok": ok}


async def main(scratch: Path, check_nonce: bool) -> dict:
    scratch.mkdir(parents=True, exist_ok=True)
    trips = []
    for label, mode, duration, drain in (("cooperative-within-deadline", "async", 1.0, 5.0),
                                         ("cooperative-past-deadline", "async", 3.0, 0.3),
                                         ("worker-thread-past-deadline", "thread", 1.5, 0.3)):
        result, *_ = await slow_trip(scratch, label, mode, duration, drain)
        trips.append(result)
    obs = await fresh_observation(scratch, check_nonce)
    passed = sum(t["ok"] for t in trips) + obs["ok"]
    return {"experiment": "slow-trip-and-fresh-observation", "slow_operation_trips": trips,
            "fresh_observation": obs, "cases_passed": passed, "cases_total": len(trips) + 1,
            "criterion_met": passed == len(trips) + 1}


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    result = asyncio.run(main(Path(sys.argv[2]), "--no-nonce-check" not in sys.argv))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["criterion_met"] else 1)
