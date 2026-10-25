"""A stopped admission path is distinct from a delegated thread's outcome."""
import asyncio
import threading

import pytest

from cmcp_runtime.cli import build_server
from cmcp_runtime.kill_switch import KillSwitchBlockStore
from tests.unit.test_kill_switch_durable import _bearer, _client, _ctx, _operator, _tool_call_body


@pytest.mark.asyncio
@pytest.mark.parametrize("finish_before_trip", [False, True])
async def test_worker_completion_and_trip_are_separate_observations(tmp_path, monkeypatch, finish_before_trip):
    entered = threading.Event()
    release = threading.Event()
    completed = threading.Event()
    effect = tmp_path / "synthetic-effect"
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    server._session_close_drain_s = 0.01
    worker_future = None

    def worker():
        entered.set()
        if not release.wait(5):
            raise RuntimeError("test did not release delegated worker")
        effect.write_text("committed")
        completed.set()

    async def dispatch(*args, **kwargs):
        nonlocal worker_future
        worker_future = asyncio.get_running_loop().run_in_executor(None, worker)
        # Shield retains an observable completion future after cancellation of
        # the gateway call. It does not prevent cancellation of that awaiter.
        await asyncio.shield(worker_future)
        raise RuntimeError("synthetic tool completed")

    monkeypatch.setattr(server._proxy, "_call_tool_impl", dispatch)
    call = None
    try:
        async with _client(server) as client:
            call = asyncio.create_task(client.post("/mcp", json=_tool_call_body("worker"), headers=_bearer()))
            assert await asyncio.to_thread(entered.wait, 1)
            if finish_before_trip:
                release.set()
                await asyncio.wait_for(asyncio.shield(worker_future), 1)
                await call
            response = await client.post("/kill-switch/trip", json={"reason": "test", "authorized_by": "test"},
                                         headers=_operator())
            assert response.status_code == 200, response.text
            assert completed.is_set() == finish_before_trip
            assert effect.exists() == finish_before_trip
            blocked = await client.post("/mcp", json=_tool_call_body("after-trip"), headers=_bearer())
            assert blocked.status_code == 403
            # Deliberately release only after observing the trip response.
            release.set()
            await asyncio.wait_for(asyncio.shield(worker_future), 1)
            assert completed.is_set()
            assert effect.read_text() == "committed"
    finally:
        release.set()
        if worker_future is not None:
            await asyncio.wait_for(asyncio.shield(worker_future), 2)
        if call is not None:
            await asyncio.gather(call, return_exceptions=True)
