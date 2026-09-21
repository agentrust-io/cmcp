"""Contract tests run on every OS; actual Docker evidence is in test_linux.py."""

import asyncio
import json
import sys
from copy import deepcopy

import pytest
from examples.confinement.adapter import (
    DockerSandbox,
    Refused,
    check_core_pattern,
    create_arguments,
    decode_request,
    verify_container,
)


@pytest.mark.parametrize("pattern", ["|/usr/lib/systemd/systemd-coredump %P", " |handler", ""])
def test_unsupported_crash_policy_refused(pattern):
    with pytest.raises(Refused):
        check_core_pattern(pattern)


def test_file_core_policy_and_immutable_image():
    check_core_pattern("core.%p")
    assert "--network=none" in create_arguments("sha256:" + "a" * 64, "cmcp-" + "b" * 32)
    with pytest.raises(Refused):
        create_arguments("agent:latest", "cmcp-" + "b" * 32)


@pytest.mark.parametrize("value", [
    {"operation": "missing", "arguments": {}},
    {"operation": "ok", "arguments": {}, "declared_data_class": "public"},
    {"operation": "ok", "arguments": {}, "sink_policy": None},
    {"operation": ["ok"], "arguments": {}},
    {"operation": "ok", "arguments": []}, [], "secret", None,
])
def test_agent_cannot_select_configuration_or_arbitrary_metadata(value):
    with pytest.raises(Refused, match="^invalid agent request$"):
        decode_request(json.dumps(value).encode(), {"ok": "trusted.tool"})


def test_valid_alias_and_non_json():
    assert decode_request(b'{"operation":"ok","arguments":{"x":1}}', {"ok": "trusted.tool"}) == ("trusted.tool", {"x": 1})
    with pytest.raises(Refused, match="^invalid agent request$"):
        decode_request(b"private plaintext\n", {})


async def test_used_container_cannot_receive_a_second_session(monkeypatch):
    monkeypatch.setattr("examples.confinement.adapter.shutil.which", lambda name: "/usr/bin/docker")
    sandbox = DockerSandbox("sha256:" + "a" * 64)
    sandbox._used = True

    async def dispatch(tool, arguments):
        pytest.fail("must refuse before dispatch")

    with pytest.raises(Refused, match="fresh container"):
        await sandbox.execute({}, dispatch, {})


async def test_output_flood_cleanup_drains_real_child_pipes(monkeypatch):
    # Unit seam replaces Docker only. A real process fills the actual pipes;
    # the hosted suite separately verifies that the container is stopped.
    monkeypatch.setattr("examples.confinement.adapter.shutil.which", lambda name: sys.executable)
    monkeypatch.setattr("examples.confinement.adapter.host_preflight", lambda: None)
    class NoWatchdog:
        def __init__(self, command):
            pass

        async def start(self):
            pass

        async def pulse(self):
            await asyncio.Future()

        async def close(self):
            pass

    monkeypatch.setattr("examples.confinement.adapter.LeaseWatchdog", NoWatchdog)
    sandbox = DockerSandbox("sha256:" + "a" * 64)
    sandbox.command = [sys.executable, "-c",
                       "import sys,time; sys.stdin.readline(); "
                       "sys.stderr.write('x'*2000000); sys.stderr.flush(); time.sleep(60)"]

    async def docker(*args):
        return json.dumps([valid_inspect()]).encode()

    async def dispatch(tool, arguments):
        pytest.fail("flood must never reach dispatch")

    sandbox.docker = docker
    with pytest.raises(Refused, match="agent exchange failed"):
        await asyncio.wait_for(sandbox.execute({}, dispatch, {}, timeout=1), 5)


def valid_inspect():
    return {"Mounts": [], "Config": {
        "User": "10001:10001", "Entrypoint": ["python"], "Cmd": ["-I", "/agent.py"],
    }, "HostConfig": {
        "NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
        "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges=true"],
        "LogConfig": {"Type": "none"}, "RestartPolicy": {"Name": "no"},
        "PidsLimit": 32, "Memory": 134217728, "MemorySwap": 134217728,
        "IpcMode": "private", "Ulimits": [{"Name": "core", "Soft": 0, "Hard": 0}],
    }}


@pytest.mark.parametrize("section,key,value", [
    ("HostConfig", "NetworkMode", "host"), ("HostConfig", "ReadonlyRootfs", False),
    ("HostConfig", "Privileged", True), ("HostConfig", "CapAdd", ["SYS_ADMIN"]),
    ("HostConfig", "LogConfig", {"Type": "json-file"}),
    ("HostConfig", "RestartPolicy", {"Name": "always"}),
    ("HostConfig", "Ulimits", [{"Name": "core", "Soft": -1, "Hard": -1}]),
    ("HostConfig", "Binds", ["/tmp:/export"]), ("HostConfig", "PidMode", "host"),
    ("HostConfig", "IpcMode", "host"), ("Config", "User", "0"),
    ("Config", "Volumes", {"/export": {}}),
])
def test_inspection_refuses_weakened_profile(section, key, value):
    info = valid_inspect()
    verify_container(info)
    mutant = deepcopy(info)
    mutant[section][key] = value
    with pytest.raises(Refused):
        verify_container(mutant)


@pytest.mark.parametrize("reply", [None, b"bad\n"])
async def test_watchdog_requires_bounded_ack_even_when_pipe_drains(reply):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from examples.confinement.adapter import LeaseWatchdog

    reader = asyncio.StreamReader()
    if reply is not None:
        reader.feed_data(reply)
    writer = SimpleNamespace(write=Mock(), drain=AsyncMock())
    watcher = LeaseWatchdog([])
    watcher.process = SimpleNamespace(returncode=None, stdin=writer, stdout=reader)
    with pytest.raises(Refused, match="watchdog"):
        await asyncio.wait_for(watcher.pulse(), 2)
    writer.write.assert_called_once_with(b".")
    writer.drain.assert_awaited_once()
