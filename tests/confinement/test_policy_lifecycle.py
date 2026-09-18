import asyncio
import json

import pytest
from examples.confinement.adapter import Refused
from examples.confinement.lifecycle import PolicyGate

from tests.confinement.gateway import make_gateway


async def test_live_cutover_waits_for_admitted_call_then_blocks_queued_release(tmp_path):
    sink = tmp_path / "received.jsonl"
    proxy, dispatch = make_gateway(sink)
    entered, finish = asyncio.Event(), asyncio.Event()

    async def held_dispatch(tool, arguments):
        entered.set()
        await finish.wait()
        return await dispatch(tool, arguments)

    gate = PolicyGate(held_dispatch, {"permitted.tool", "public.tool"})
    try:
        first = asyncio.create_task(gate("permitted.tool", {"value": "first"}))
        await entered.wait()
        update = asyncio.create_task(gate.replace(1, set()))
        await asyncio.sleep(0)
        queued = asyncio.create_task(gate("permitted.tool", {"value": "queued"}))
        assert not update.done()
        finish.set()
        assert (await first)["allowed"]
        assert await update == 1
        assert not (await queued)["allowed"]
        assert not (await gate("permitted.tool", {"value": "later"}))["allowed"]
        assert [json.loads(line)["arguments"]["value"] for line in sink.read_text().splitlines()] == ["first"]
        await gate.replace(2, {"permitted.tool", "public.tool"})
        # Restoring an alias never weakens the original cMCP classification.
        assert not (await gate("public.tool", {"value": "still confidential"}))["allowed"]
        assert (await gate("permitted.tool", {"value": "restored"}))["allowed"]
    finally:
        await proxy.aclose()


@pytest.mark.parametrize("revision,tools", [(0, set()), (True, set()), (1, {"unknown"}), (1, ["permitted.tool"])])
async def test_invalid_policy_update_closes_admission_until_newer_valid_revision(tmp_path, revision, tools):
    sink = tmp_path / "received.jsonl"
    proxy, dispatch = make_gateway(sink)
    gate = PolicyGate(dispatch, {"permitted.tool"})
    try:
        with pytest.raises(Refused):
            await gate.replace(revision, tools)
        assert not (await gate("permitted.tool", {"value": "must not arrive"}))["allowed"]
        assert not sink.exists()
        await gate.replace(2, {"permitted.tool"})
        assert (await gate("permitted.tool", {"value": "recovered"}))["allowed"]
        with pytest.raises(Refused):
            await gate.replace(1, {"permitted.tool"})
        assert not (await gate("permitted.tool", {"value": "rollback"}))["allowed"]
        assert len(sink.read_text().splitlines()) == 1
    finally:
        await proxy.aclose()
