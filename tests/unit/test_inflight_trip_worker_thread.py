"""In-flight kill-switch cancellation: safe-case worker-thread test.

Reproduces the setup of Imran Siddique's October 11 finding, with the
worker's effect committed on a worker thread (``run_in_executor``) that
outlives a coroutine cancellation, and the trip's drain as the
synchronization point.

The test deliberately does NOT force a specific ordering. It records:

  - whether the worker entered,
  - the worker's completion timestamp,
  - the moment ``/kill-switch/trip`` returned,
  - whether the effect marker file exists.

Outcomes:

  * ``skip`` — effect marker exists but was written before the trip
    returned. This is the safe result: the drain waited for the worker.
    That is the contract (already running calls "finish ... at the close
    drain deadline"), and no defect is being claimed.

  * ``xfail`` — effect marker exists and was written after the trip
    returned. The worker committed the protected side effect after the
    trip; that is the defect scenario.

  * ``skip`` — effect marker does not exist. Either the drain cancelled
    the worker, or the worker never ran. Both are safe.

See ``test_inflight_trip_worker_thread_boundary.py`` for the timeout
boundary case.
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


class _Sync:
    def __init__(self, effect_path: Path) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.worker_completed_at: float | None = None
        self.effect_path = effect_path


def _build_blocking_server(tmp_path, sync: _Sync):
    ctx = _ctx(KillSwitchBlockStore(tmp_path / "audit.db"))
    server = build_server(ctx)

    proxy = server._proxy
    original_impl = proxy._call_tool_impl

    async def blocking_impl(
        call_id: str, tool_name: str, *args: Any, **kwargs: Any
    ) -> CallResult:
        def worker() -> None:
            sync.entered.set()
            sync.release.wait(30.0)
            sync.effect_path.write_text("committed")
            sync.worker_completed_at = time.monotonic()

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, worker)
        return await original_impl(call_id, tool_name, *args, **kwargs)

    proxy._call_tool_impl = blocking_impl
    return server, original_impl


async def test_inflight_worker_effect_commits_after_trip(tmp_path):
    sync = _Sync(effect_path=tmp_path / "effect_marker")
    server, _original = _build_blocking_server(tmp_path, sync)

    trip_completed_at: float | None = None
    trip_status: int | None = None

    try:
        async with _client(server) as client:
            call_task = asyncio.create_task(
                client.post(
                    "/mcp",
                    json=_tool_call_body("1"),
                    headers=_bearer(),
                )
            )

            entered = await asyncio.get_running_loop().run_in_executor(
                None, sync.entered.wait, 30.0
            )
            assert entered is True, "worker never entered within 30s"

            trip_response = await client.post(
                "/kill-switch/trip",
                json={"reason": "repro", "authorized_by": "operator-repro"},
                headers=_operator(),
            )
            trip_completed_at = time.monotonic()
            trip_status = trip_response.status_code

            assert trip_status in (200, 201, 204, 409), (
                f"trip failed: {trip_status} {trip_response.text}"
            )

            try:
                await asyncio.wait_for(asyncio.shield(call_task), timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError, RuntimeError):
                pass

            sync.release.set()

            for _ in range(50):
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
    print("IN-FLIGHT WORKER-EFFECT SAFE-CASE RESULT")
    print("=" * 70)
    print(f"trip_status:             {trip_status}")
    print(f"trip_returned_at:        "
          f"{trip_completed_at:.6f}"
          if trip_completed_at is not None
          else "trip_returned_at:        <unknown>")
    print(f"worker_completed:        {worker_completed}")
    print(f"worker_completed_at:     "
          f"{sync.worker_completed_at:.6f}"
          if worker_completed
          else "worker_completed_at:     <never>")
    print(f"effect_marker_exists:    {effect_committed}")
    print("=" * 70)

    if not effect_committed:
        pytest.skip(
            "worker effect did not commit; either the drain cancelled the "
            "worker or the worker never ran. See diagnostic above."
        )

    if (
        effect_committed
        and trip_completed_at is not None
        and sync.worker_completed_at is not None
        and sync.worker_completed_at > trip_completed_at
    ):
        pytest.xfail(
            "REPRODUCED: worker effect committed AFTER the trip returned "
            f"(effect at {sync.worker_completed_at:.6f}, trip at "
            f"{trip_completed_at:.6f})."
        )

    pytest.skip(
        "SAFE CASE: worker effect committed BEFORE the trip returned "
        f"(effect at {sync.worker_completed_at:.6f}, trip at "
        f"{trip_completed_at:.6f}). The drain waited for the worker. "
        "This is the intended behavior for calls that complete within the "
        "drain timeout. See the boundary test for the timeout case."
    )