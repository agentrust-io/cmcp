"""Experimental native-Linux Docker adapter. See docs/confinement.md.

The host, Docker daemon, gateway and approved tools are trusted. Only the agent
container is adversarial. This is not a TEE or a general-purpose agent runner.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import sys
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from types import MappingProxyType
from uuid import uuid4

MAX_FRAME = 65536
MAX_OUTPUT = 1024 * 1024
MAX_CALLS = 16
DOCKER_HOST = "unix:///var/run/docker.sock"


class Refused(RuntimeError):
    """Fixed messages only: untrusted bytes must not reach host diagnostics."""


def check_core_pattern(pattern: str) -> None:
    # RLIMIT_CORE is ignored for piped kernel core handlers (core(5)).
    if not pattern.strip() or pattern.lstrip().startswith("|"):
        raise Refused("unsupported host core-dump policy")


def host_preflight() -> None:
    if sys.platform != "linux":
        raise Refused("native Linux host required")
    check_core_pattern(Path("/proc/sys/kernel/core_pattern").read_text())
    import resource

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def create_arguments(image: str, name: str) -> list[str]:
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise Refused("an immutable local image ID is required")
    if not re.fullmatch(r"cmcp-[a-f0-9]{32}", name):
        raise Refused("invalid container name")
    return [
        "create", "--name", name, "--interactive", "--network=none",
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
        "--user=10001:10001", "--pids-limit=32", "--memory=128m",
        "--memory-swap=128m", "--ulimit=core=0:0", "--log-driver=none",
        "--restart=no", "--entrypoint=python", image, "-I", "/agent.py",
    ]


def verify_container(info: dict) -> None:
    """Inspect the created container before starting it or supplying plaintext."""
    h, c = info["HostConfig"], info["Config"]
    required = (
        h["NetworkMode"] == "none", h["ReadonlyRootfs"],
        not h["Privileged"], h["CapDrop"] == ["ALL"], not h.get("CapAdd"),
        h["SecurityOpt"] == ["no-new-privileges=true"],
        h["LogConfig"]["Type"] == "none", h["RestartPolicy"]["Name"] == "no",
        h["PidsLimit"] == 32, h["Memory"] == 128 * 1024 * 1024,
        h["MemorySwap"] == 128 * 1024 * 1024,
        not h.get("Binds"), not h.get("Devices"), not h.get("DeviceRequests"),
        not h.get("PidMode"), h.get("IpcMode") == "private",
        not h.get("PortBindings"), not info.get("Mounts"),
        c["User"] == "10001:10001", not c.get("Volumes"),
        c["Entrypoint"] == ["python"], c["Cmd"] == ["-I", "/agent.py"],
        any(u == {"Name": "core", "Soft": 0, "Hard": 0} for u in h["Ulimits"]),
    )
    if not all(required):
        raise Refused("container confinement inspection failed")


class DockerSandbox:
    """Single-use sandbox; stdin/stdout are private gateway transport only."""

    def __init__(self, image: str):
        self.name = "cmcp-" + uuid4().hex
        self.arguments = create_arguments(image, self.name)
        self._used = False
        executable = shutil.which("docker")
        if executable is None:
            raise Refused("Docker is unavailable")
        # Explicit socket ignores DOCKER_HOST / remote context selection.
        self.command = [executable, "--host", DOCKER_HOST]

    async def docker(self, *args: str) -> bytes:
        process = await asyncio.create_subprocess_exec(
            *self.command, *args, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            out, _ = await asyncio.wait_for(process.communicate(), 20)
        except BaseException:
            if process.returncode is None:
                process.kill()
            await process.wait()
            raise
        if process.returncode:
            raise Refused("Docker operation failed")
        return out

    async def create(self) -> None:
        host_preflight()
        # A remote/VM-backed daemon would invalidate the host core-pattern check.
        info = json.loads(await self.docker("info", "--format", "{{json .}}"))
        if info.get("OSType") != "linux" or "Docker Desktop" in info.get("OperatingSystem", ""):
            raise Refused("native Linux Docker daemon required")
        await self.docker(*self.arguments)
        inspect = json.loads(await self.docker("inspect", self.name))[0]
        verify_container(inspect)

    async def remove(self) -> None:
        await self.docker("rm", "--force", self.name)

    async def execute(
        self, initial: dict, dispatch: Callable[[str, dict], Awaitable[dict]],
        operations: Mapping[str, str], *, timeout: float = 15,
    ) -> dict[str, int]:
        # The caller is trusted and must classify initial data before this call.
        # Freeze aliases; the agent cannot choose catalog names or call IDs.
        if self._used:
            raise Refused("a fresh container is required for each session")
        self._used = True
        aliases = MappingProxyType(dict(operations))
        payload = json.dumps(initial).encode() + b"\n"
        if len(payload) > MAX_FRAME:
            raise Refused("initial frame too large")
        host_preflight()  # recheck immediately before plaintext admission
        verify_container(json.loads(await self.docker("inspect", self.name))[0])
        process = await asyncio.create_subprocess_exec(
            *self.command, "start", "--attach", "--interactive", self.name,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, limit=MAX_FRAME,
        )
        stats = {"allowed": 0, "denied": 0, "stderr_bytes": 0}

        async def drain() -> None:
            while chunk := await process.stderr.read(4096):
                stats["stderr_bytes"] += len(chunk)
                if stats["stderr_bytes"] > MAX_OUTPUT:
                    raise Refused("stderr budget exceeded")

        async def exchange() -> None:
            process.stdin.write(payload)
            await process.stdin.drain()
            calls, total = 0, 0
            while line := await process.stdout.readline():
                total += len(line)
                calls += 1
                if len(line) > MAX_FRAME or total > MAX_OUTPUT or calls > MAX_CALLS:
                    raise Refused("stdout budget exceeded")
                tool, arguments = decode_request(line, aliases)
                result = await dispatch(tool, arguments)
                # Only a boolean outcome crosses into public harness statistics.
                stats["allowed" if result.get("allowed") is True else "denied"] += 1
                reply = json.dumps(result).encode() + b"\n"
                if len(reply) > MAX_FRAME:
                    raise Refused("gateway response too large")
                process.stdin.write(reply)
                await process.stdin.drain()
            process.stdin.close()
            await process.wait()
            if process.returncode:
                raise Refused("agent failed")

        tasks = [asyncio.create_task(exchange()), asyncio.create_task(drain())]
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout)
            return stats
        except Exception:
            # Do not expose parser values, exception messages, or agent output.
            raise Refused("agent exchange failed") from None
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            # Kill the container, not merely its attached CLI process.
            try:
                # Also stop if the attach client failed while the container
                # survived. Docker stop succeeds for an already stopped child.
                await self.docker("stop", "--time", "0", self.name)
            finally:
                if process.returncode is None:
                    process.kill()
                # Readers were cancelled above. Drain the killed attach client's
                # remaining pipe buffers: wait() alone can deadlock on a full
                # asyncio pipe after an output-flood rejection.
                await process.communicate()


def decode_request(line: bytes, operations: Mapping[str, str]) -> tuple[str, dict]:
    try:
        value = json.loads(line)
        if (not isinstance(value, dict) or set(value) != {"operation", "arguments"}
                or not isinstance(value["operation"], str)
                or value["operation"] not in operations
                or not isinstance(value["arguments"], dict)):
            raise ValueError
        return operations[value["operation"]], value["arguments"]
    except (ValueError, TypeError, KeyError, RecursionError):
        raise Refused("invalid agent request") from None
