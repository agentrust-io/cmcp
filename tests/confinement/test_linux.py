"""Independent sink observations and deliberately weakened synthetic controls."""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from uuid import uuid4

import pytest
from examples.confinement import adapter

from tests.confinement.gateway import make_gateway

pytestmark = pytest.mark.skipif(not os.environ.get("CMCP_CONFINEMENT_IMAGE"),
                                reason="requires native Linux Docker CI")
ALIASES = {"permitted": "permitted.tool", "public": "public.tool"}


@asynccontextmanager
async def observers():
    received = {"tcp": [], "tcp6": [], "dns": []}

    async def tcp(reader, writer, key):
        received[key].append(await reader.read(4096))
        writer.close()
        await writer.wait_closed()

    class DNS(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            received["dns"].append(data)

    ipv4 = await asyncio.start_server(lambda r, w: tcp(r, w, "tcp"), "127.0.0.1", 0)
    ipv6 = await asyncio.start_server(lambda r, w: tcp(r, w, "tcp6"), "::1", 0)
    udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(DNS, local_addr=("127.0.0.1", 0))
    try:
        yield received, {"tcp": ipv4.sockets[0].getsockname()[1],
                         "tcp6": ipv6.sockets[0].getsockname()[1],
                         "dns": udp.get_extra_info("sockname")[1]}
    finally:
        ipv4.close()
        ipv6.close()
        await ipv4.wait_closed()
        await ipv6.wait_closed()
        udp.close()


async def capture(sandbox, received, sink, canary):
    # Docker cp reads the stopped container's filesystem independently of the agent.
    try:
        file_data = await sandbox.docker("cp", sandbox.name + ":/export/leak.txt", "-")
    except adapter.Refused:
        file_data = b""
    logger = await asyncio.create_subprocess_exec(
        *sandbox.command, "logs", sandbox.name,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    log_data, _ = await asyncio.wait_for(logger.communicate(), 10)
    info = json.loads(await sandbox.docker("inspect", sandbox.name))[0]
    deliveries = [json.loads(line) for line in sink.read_text().splitlines()] if sink.exists() else []
    return {
        "network": {key: sum(canary.encode() in value for value in values)
                    for key, values in received.items()},
        "file": canary.encode() in file_data, "logs": canary.encode() in log_data,
        "running": info["State"]["Running"],
        "permitted": sum(d["name"] == "permitted.tool" for d in deliveries),
        "public": sum(d["name"] == "public.tool" for d in deliveries),
        "core_limits": [d["arguments"]["core_limit"] for d in deliveries],
    }


def require_confinement(observation):
    assert observation["network"] == {"tcp": 0, "tcp6": 0, "dns": 0}
    assert not observation["file"]
    assert not observation["logs"]
    assert not observation["running"]
    assert observation["public"] == 0


async def run_case(tmp_path, monkeypatch, *, mutation=None, mode="normal", unavailable=False):
    sandbox = adapter.DockerSandbox(os.environ["CMCP_CONFINEMENT_IMAGE"])
    sink = tmp_path / (uuid4().hex + ".jsonl")
    canary = "canary-" + uuid4().hex
    proxy, dispatch = make_gateway(sink, public_ceiling="confidential" if mutation == "sink" else "public")
    if unavailable:
        async def dispatch(tool, arguments):
            raise ConnectionError("gateway unavailable")
    if mutation in {"network", "filesystem", "logging"}:
        # Deliberately disable BOTH the profile setting and its admission check.
        # This is test-only and never accepts real data. Inspection alone must
        # reject the mutant; then exercise the kernel restriction causally.
        original = adapter.verify_container
        flag, replacement = {
            "network": ("--network=none", "--network=host"),
            "filesystem": ("--read-only", None),
            "logging": ("--log-driver=none", "--log-driver=json-file"),
        }[mutation]
        sandbox.arguments.remove(flag)
        if replacement:
            sandbox.arguments.insert(1, replacement)

        def weakened_inspect(info):
            with pytest.raises(adapter.Refused):
                original(info)
            # Only omit the inspection after proving it detects the weakening.

        monkeypatch.setattr(adapter, "verify_container", weakened_inspect)
    try:
        await sandbox.create()
        async with observers() as (received, addresses):
            refused = False
            try:
                stats = await sandbox.execute({"canary": canary, "mode": mode, **addresses}, dispatch, ALIASES,
                                              timeout=2 if mode == "stall" else 15)
            except adapter.Refused:
                refused, stats = True, {}
            observation = await capture(sandbox, received, sink, canary)
            return observation, stats, refused
    finally:
        await proxy.aclose()
        await sandbox.remove()


async def test_confinement_and_fresh_restart(tmp_path, monkeypatch):
    for _ in range(2):
        observation, stats, refused = await run_case(tmp_path, monkeypatch)
        assert not refused
        require_confinement(observation)
        assert observation["permitted"] == 1
        assert observation["core_limits"] == [[0, 0]]
        assert stats["allowed"] == 1 and stats["denied"] == 1
        assert stats["stderr_bytes"] > 0


@pytest.mark.parametrize("mutation", ["network", "filesystem", "logging", "sink"])
async def test_removed_restriction_is_detected_at_independent_sink(tmp_path, monkeypatch, mutation):
    observation, _, refused = await run_case(tmp_path, monkeypatch, mutation=mutation)
    assert not refused
    assert observation["permitted"] == 1
    if mutation == "network":
        assert observation["network"] == {"tcp": 2, "tcp6": 1, "dns": 1}
    elif mutation == "filesystem":
        assert observation["file"]
    elif mutation == "logging":
        assert observation["logs"]
    else:
        assert observation["public"] == 1
    with pytest.raises(AssertionError):
        require_confinement(observation)


@pytest.mark.parametrize("mode,unavailable", [
    ("raw_stdout", False), ("configuration", False), ("normal", True),
    ("crash", False), ("stall", False), ("oversize", False), ("stderr_flood", False),
])
async def test_invalid_channel_or_unavailable_gateway_closes_session(tmp_path, monkeypatch, mode, unavailable):
    observation, _, refused = await run_case(tmp_path, monkeypatch, mode=mode, unavailable=unavailable)
    assert refused
    require_confinement(observation)
    assert observation["permitted"] == 0
