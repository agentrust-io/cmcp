"""In-flight kill-switch cancellation: boundary case (drain timeout).

Blocks the worker for longer than the server's ``_session_close_drain_s``
so the trip's drain times out and returns while the worker is still
running. If the effect then commits, the caller cannot distinguish
"the trip prevented the effect" from "the effect committed but the trip
returned success". That is the scenario Imran Siddique's October 11 report
described.
"""
from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from cmcp_runtime.cli import build_server
from cmcp_runtime.kill_switch import KillSwitchBlockStore
from cmcp_runtime.mcp.proxy import CallResult
from tests.unit.test_kill_switch_durable import (
    _bearer,
    _ctx,
    _client,
    _operator,
    _tool_call_body,
)


pytestmark = pytest.mark.asyncio


class _BoundarySync:
    def __init__(self, effect_path: Path, block_for_s: float) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.worker_completed_at: float | None = None
        self.effect_path = effect_path
        self.block_for_s = block_for_s


def _build_blocking_server(tmp_path, sync: _BoundarySync):
    ctx = _ctx(KillSwitchBlockStore(tmp_path / "audit.db"))
    server = build_server(ctx)
    proxy = server._proxy
    original_impl = proxy._call_tool_impl

    async def blocking_impl(
        call_id: str, tool_name: str, *args: Any, **kwargs: Any
    ) -> CallResult:
        def worker() -> None:
            sync.entered.set()
            sync.release.wait(sync.block_for_s)
            sync.effect_path.write_text("committed")
            sync.worker_completed_at = time.monotonic()

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, worker)
        return await original_impl(call_id, tool_name, *args, **kwargs)

    proxy._call_tool_impl = blocking_impl
    return server, original_impl


async def test_worker_effect_beyond_drain_timeout(tmp_path):
    probe_ctx = _ctx(KillSwitchBlockStore(tmp_path / "audit_probe.db"))
    probe_server = build_server(probe_ctx)
    drain_timeout_s = float(probe_server._session_close_drain_s)
    assert drain_timeout_s > 0.0
    block_for_s = drain_timeout_s + 2.0

    sync = _BoundarySync(
        effect_path=tmp_path / "effect_marker", block_for_s=block_for_s,
    )
    server, _original = _build_blocking_server(tmp_path, sync)

    trip_completed_at: float | None = None
    trip_status: int | None = None
    trip_elapsed_s: float | None = None

    try:
        async with _client(server) as client:
            call_task = asyncio.create_task(
                client.post("/mcp", json=_tool_call_body("1"), headers=_bearer())
            )
            entered = await asyncio.get_running_loop().run_in_executor(
                None, sync.entered.wait, 30.0
            )
            assert entered is True

            trip_started_at = time.monotonic()
            trip_response = await client.post(
                "/kill-switch/trip",
                json={"reason": "boundary-repro", "authorized_by": "operator-repro"},
                headers=_operator(),
            )
            trip_completed_at = time.monotonic()
            trip_elapsed_s = trip_completed_at - trip_started_at
            trip_status = trip_response.status_code
            assert trip_status in (200, 201, 204, 409), (
                f"trip failed: {trip_status} {trip_response.text}"
            )

            try:
                await asyncio.wait_for(asyncio.shield(call_task), timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError, RuntimeError):
                pass

            sync.release.set()

            for _ in range(int((block_for_s + 5.0) * 50)):
                if sync.worker_completed_at is not None:
                    break
                await asyncio.get_running_loop().run_in_executor(
                    None, time.sleep, 0.02
                )
    finally:
        sync.release.set()

    effect_committed = sync.effect_path.exists()
    worker_completed = sync.worker_completed_at is not None

    print()
    print("=" * 70)
    print("IN-FLIGHT WORKER-EFFECT BOUNDARY RESULT")
    print("=" * 70)
    print(f"drain_timeout_s:         {drain_timeout_s:.3f}")
    print(f"worker_block_for_s:      {block_for_s:.3f}")
    print(f"trip_status:             {trip_status}")
    if trip_elapsed_s is not None:
        print(f"trip_elapsed_s:          {trip_elapsed_s:.3f}")
    if trip_completed_at is not None:
        print(f"trip_returned_at:        {trip_completed_at:.6f}")
    print(f"worker_completed:        {worker_completed}")
    if worker_completed:
        print(f"worker_completed_at:     {sync.worker_completed_at:.6f}")
    else:
        print("worker_completed_at:     <never>")
    print(f"effect_marker_exists:    {effect_committed}")
    print("=" * 70)

    if not worker_completed:
        pytest.skip("worker did not complete; safe outcome.")
    if not effect_committed:
        pytest.skip("effect did not commit; safe outcome.")
    if (trip_completed_at is not None
            and sync.worker_completed_at is not None
            and sync.worker_completed_at > trip_completed_at):
        pytest.xfail(
            "REPRODUCED: effect committed AFTER trip returned. "
            f"drain={drain_timeout_s:.3f}s block={block_for_s:.3f}s "
            f"effect={sync.worker_completed_at:.6f} trip={trip_completed_at:.6f}"
        )
    pytest.skip("effect committed before trip returned.")
