"""Kill/pause the real bridge after plaintext delivery, observe Docker externally."""

import asyncio
import json
import os
import signal
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from examples.confinement.adapter import DockerSandbox

from tests.confinement.test_linux import observers

pytestmark = pytest.mark.skipif(not os.environ.get("CMCP_CONFINEMENT_IMAGE"),
                                reason="requires native Linux Docker CI")


async def running(observer, container):
    # Empty successful listing means removed; command failure must propagate.
    value = await observer.docker("ps", "--filter", "name=^/" + container + "$", "--format", "{{.Names}}")
    return container.encode() in value.splitlines()


@pytest.mark.parametrize("failure", ["kill", "pause", "watchdog", "unguarded"])
async def test_independent_lease_stops_container_after_bridge_failure(tmp_path, failure):
    image = os.environ["CMCP_CONFINEMENT_IMAGE"]
    observer = DockerSandbox(image)
    canary = "canary-" + uuid4().hex
    metadata = None
    async with observers() as (received, addresses):
        bridge = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "tests.confinement.bridge_worker", image, str(tmp_path), failure,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL, start_new_session=True,
        )
        try:
            bridge.stdin.write(json.dumps({"canary": canary, "mode": "linger", **addresses}).encode() + b"\n")
            await bridge.stdin.drain()
            bridge.stdin.close()
            async with asyncio.timeout(15):
                while metadata is None:
                    try:
                        metadata = json.loads((tmp_path / "ready.json").read_text())
                    except (FileNotFoundError, json.JSONDecodeError):
                        assert bridge.returncode is None, "bridge exited before admitting data"
                        await asyncio.sleep(0.05)
            container = metadata["container"]
            assert await running(observer, container)
            # Independent sink confirms this was a plaintext-bearing session.
            assert canary in (tmp_path / "sink.jsonl").read_text()
            if failure == "watchdog":
                os.kill(metadata["watchdog"], signal.SIGKILL)
            elif failure == "pause":
                os.kill(bridge.pid, signal.SIGSTOP)
            else:
                bridge.kill()
            if failure == "unguarded":
                await asyncio.sleep(3)
                stopped = not await running(observer, container)
                assert not stopped, "removing watchdog must expose the surviving container"
                with pytest.raises(AssertionError):
                    assert stopped
            else:
                async with asyncio.timeout(10):
                    while await running(observer, container):
                        await asyncio.sleep(0.1)
                stopped = True
            assert all(not values for values in received.values())
            if report := os.environ.get("CMCP_CONFINEMENT_EVIDENCE"):
                with Path(report).open("a", encoding="utf-8") as artifact:
                    artifact.write(json.dumps({"lifecycle_failure": failure,
                                               "stopped": stopped, "network_deliveries": 0}) + "\n")
        finally:
            if bridge.returncode is None:
                bridge.kill()
            await bridge.wait()
            if metadata is not None:
                containers = await observer.docker("ps", "--all", "--format", "{{.Names}}")
                if metadata["container"].encode() in containers.splitlines():
                    await observer.docker("rm", "--force", metadata["container"])
