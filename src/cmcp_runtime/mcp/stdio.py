"""stdio upstream: the gateway spawns the MCP server as its own child.

Design and its costs: ``docs/spec/stdio-transport.md``. The short version is that
the agent never spawns anything once cMCP is in the path, so the child can be a
child of the gateway, which is already inside the enclave. Nothing crosses the
TEE boundary that does not cross it today.

What this buys, and it is the reason to do it at all: the gateway chooses when to
``exec``, so it digests the executable first and refuses to spawn on a mismatch.
A pinned TLS fingerprint identifies an endpoint. A verified digest identifies the
code.

What it costs, restated here because a reader of this file should not have to go
find it: the child runs in the same isolation domain as the policy evaluator and
the audit chain. Memory isolation protects the gateway from the host, not from
its own child. And the gateway's launch measurement does not cover a process
spawned later, which is why the child's digest is reported as its own evidence
class rather than folded into hardware attestation.

Three decisions the spec left open, settled here:

**One child per session, never a pool.** A pool is faster and leaks state between
sessions: a server that keeps anything in memory carries it from one agent's
session into the next, and the audit chain cannot see that happen. The cost is a
spawn per session, which is the correct thing to pay.

**stderr never enters the audit chain.** MCP servers write diagnostics there, and
diagnostics contain payloads. The audit chain is meant to be shareable, so the
content goes to the gateway's own logger and only the byte count reaches the
record: enough to see that a child is complaining, not enough to leak what about.

**A framing error is fatal to the session.** Newline-delimited JSON-RPC
desynchronizes if a child logs to stdout, and resynchronizing means guessing
which bytes were a response. Guessing wrong means attributing one call's result
to another call, in an artifact whose entire purpose is saying what happened.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
from dataclasses import dataclass
from typing import Any

from cmcp_runtime.errors import ConfigError, UpstreamToolError, UpstreamUnavailable

logger = logging.getLogger(__name__)

__all__ = [
    "SPAWN_MEASURED",
    "SPAWN_UNMEASURED",
    "StdioServer",
    "StdioSpawnRefused",
    "measure_executable",
    "resolve_executable",
]

#: Evidence classes, extending the tls-pinned / hash-only pair in LIMITATIONS.md.
SPAWN_MEASURED = "spawn-measured"
SPAWN_UNMEASURED = "spawn-unmeasured"

#: A response larger than this is refused rather than buffered. A child that can
#: make the gateway allocate without bound is a denial of service inside the
#: enclave, which is the one place it hurts most.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

#: stderr is kept only to report its size and to log the tail. Bounded for the
#: same reason.
MAX_STDERR_CAPTURE = 64 * 1024

_DIGEST_PREFIX = "sha256:"


class StdioSpawnRefused(ConfigError):
    """The gateway declined to spawn. Never a warning, never a degraded start.

    Raised when the executable's digest does not match the catalog, or when it
    has no digest to match and unmeasured spawning is not explicitly enabled.
    """


def resolve_executable(command: str) -> str:
    """Absolute path of *command*, resolved once, before anything is measured.

    Resolved rather than passed through so the digest and the exec refer to the
    same file. Measuring ``server`` from ``PATH`` and then exec'ing ``server``
    invites a different file to answer the second lookup.
    """
    resolved = shutil.which(command) if os.path.basename(command) == command else command
    if not resolved or not os.path.isfile(resolved):
        raise StdioSpawnRefused(f"stdio server executable not found: {command!r}")
    return os.path.realpath(resolved)


def measure_executable(path: str) -> str:
    """``sha256:`` digest of the file that will be executed.

    A file that cannot be read cannot be measured, and an unmeasurable spawn is
    refused rather than degraded. This is not hypothetical: a Windows Store
    Python is an App Execution Alias, a reparse point that executes fine and
    cannot be opened for reading, so "executable" and "readable" are genuinely
    different properties.
    """
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError as exc:
        raise StdioSpawnRefused(
            f"cannot read {path!r} to measure it ({exc.strerror or exc}). An "
            "executable that cannot be measured cannot be pinned, so it is not "
            "spawned. Point the catalog at a real file rather than a shim or alias."
        ) from exc
    return _DIGEST_PREFIX + h.hexdigest()


@dataclass(frozen=True)
class StdioSpawn:
    """What the catalog says about how to start this server."""

    command: str
    args: tuple[str, ...] = ()
    binary_digest: str | None = None
    """Expected ``sha256:`` digest of :attr:`measure_target`. ``None`` means the
    catalog does not pin the server, which is only permitted when the deployment
    opts in."""
    measure_target: str | None = None
    """Which file the digest covers. Defaults to the resolved executable.

    For an interpreted server the executable is the interpreter, and pinning the
    interpreter is close to useless: every Python MCP server on a host shares one
    digest, so the pin would match a completely different server. The thing worth
    pinning is the entrypoint, so a catalog entry running
    ``python -m some_server`` or ``python server.py`` sets this to the script and
    the digest covers the code that actually differs.

    The interpreter is still resolved and still recorded; it is simply not what
    the pin is about.
    """


class StdioServer:
    """One spawned MCP server, for the lifetime of one session."""

    def __init__(
        self,
        spawn: StdioSpawn,
        *,
        allow_unmeasured: bool = False,
        env: dict[str, str] | None = None,
    ) -> None:
        self._spawn = spawn
        self._allow_unmeasured = allow_unmeasured
        self._env = env
        self._proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()
        self._stderr_bytes = 0
        self.executable: str | None = None
        self.measure_target: str | None = None
        self.measured_digest: str | None = None
        self.evidence_class: str | None = None

    @property
    def stderr_bytes(self) -> int:
        """How much the child wrote to stderr. The content is never recorded."""
        return self._stderr_bytes

    async def start(self) -> None:
        """Measure, decide, then spawn. Never the other way round."""
        executable = resolve_executable(self._spawn.command)
        target = self._spawn.measure_target or executable
        expected = self._spawn.binary_digest

        if expected is not None:
            # Only measured when there is something to compare it against. An
            # unreadable interpreter must not block a catalog that pins the
            # script, which is the case that matters for interpreted servers.
            digest = measure_executable(resolve_executable(target))
            if digest != expected:
                raise StdioSpawnRefused(
                    f"stdio server digest does not match the catalog: "
                    f"{target!r} measured {digest}, catalog pins {expected}. Not spawned."
                )
            self.evidence_class = SPAWN_MEASURED
        else:
            if not self._allow_unmeasured:
                raise StdioSpawnRefused(
                    f"stdio server {self._spawn.command!r} has no binary_digest in the "
                    "catalog. Spawning an unmeasured binary inside the enclave requires "
                    "attestation.allow_unmeasured_spawn=true, which records every such "
                    "call as spawn-unmeasured."
                )
            self.evidence_class = SPAWN_UNMEASURED
            # Observed even when unpinned, where the file can be read at all. An
            # unreadable target is recorded as None rather than blocking a spawn
            # the operator has already opted into.
            try:
                digest = measure_executable(resolve_executable(target))
            except StdioSpawnRefused as exc:
                digest = None
                logger.warning("stdio server target could not be measured: %s", exc)
            logger.warning(
                "SPAWN_UNMEASURED: %s has no catalog digest; what ran is recorded (%s) "
                "but was not checked against anything",
                self._spawn.command,
                digest or "unreadable",
            )

        self.measure_target = target

        self.executable = executable
        self.measured_digest = digest

        self._proc = await asyncio.create_subprocess_exec(
            executable,
            *self._spawn.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._env,
            # asyncio's default stream limit is 64 KiB, which is smaller than a
            # perfectly ordinary tool response. Left at the default, readline()
            # raises before MAX_RESPONSE_BYTES is ever consulted, so the bound
            # the gateway actually enforces has to be the bound it declares.
            limit=MAX_RESPONSE_BYTES,
        )
        logger.info(
            "stdio server spawned: %s (%s, digest %s)",
            self._spawn.command,
            self.evidence_class,
            digest,
        )

    async def call(self, call_id: str, tool_name: str, arguments: dict[str, Any]) -> str:
        """One JSON-RPC ``tools/call`` over the child's stdin/stdout."""
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            raise UpstreamUnavailable("stdio server is not running")

        request = {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        line = json.dumps(request, separators=(",", ":")).encode() + b"\n"

        # One call at a time. The framing carries an id, but interleaving writes
        # on one pipe and matching responses by id would mean trusting the child
        # to return the id it was given, which is the thing being verified.
        async with self._lock:
            try:
                self._proc.stdin.write(line)
                await self._proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as exc:
                raise UpstreamUnavailable(
                    f"stdio server closed its input: {self._spawn.command}", detail=str(exc)
                ) from exc

            try:
                raw = await self._proc.stdout.readline()
            except ValueError as exc:
                # A line longer than the limit, or one still unterminated at it.
                # asyncio reports both as a bare ValueError, and an over-sized
                # response is a refusal with a reason rather than a stray
                # exception surfacing from inside the enclave.
                await self.close()
                raise UpstreamUnavailable(
                    f"stdio server response exceeds {MAX_RESPONSE_BYTES} bytes without "
                    f"a newline, so the JSON-RPC stream cannot be framed and the session "
                    f"is terminated: {self._spawn.command}",
                    detail=str(exc),
                ) from exc

        if not raw:
            await self._collect_stderr()
            raise UpstreamUnavailable(
                f"stdio server produced no response and may have exited: "
                f"{self._spawn.command} (exit={self._proc.returncode}, "
                f"stderr={self._stderr_bytes} bytes)"
            )
        if len(raw) > MAX_RESPONSE_BYTES:
            raise UpstreamUnavailable(
                f"stdio server response exceeds {MAX_RESPONSE_BYTES} bytes; refused"
            )

        try:
            body = json.loads(raw)
        except ValueError as exc:
            # Fatal, deliberately. A child that logs to stdout has desynchronized
            # the stream, and skipping to the next parsable line means guessing
            # which bytes were a response to which call.
            await self.close()
            raise UpstreamUnavailable(
                f"stdio server wrote a non-JSON line, so the JSON-RPC stream is "
                f"desynchronized and the session is terminated: {self._spawn.command}. "
                "A server that logs to stdout must be changed to log to stderr.",
                detail=str(exc),
            ) from exc

        if not isinstance(body, dict):
            await self.close()
            raise UpstreamUnavailable("stdio server returned a non-object JSON-RPC body")
        if body.get("id") != call_id:
            await self.close()
            raise UpstreamUnavailable(
                f"stdio server answered id {body.get('id')!r} for request {call_id!r}; "
                "a mismatched response cannot be attributed and the session is terminated"
            )
        if "error" in body:
            error = body["error"] if isinstance(body["error"], dict) else {}
            raise UpstreamToolError(
                f"Upstream tool error from {tool_name}: "
                f"{str(error.get('message', 'unknown'))[:200]}"
            )
        return _text_content(body.get("result"))

    async def _collect_stderr(self) -> None:
        if self._proc is None or self._proc.stderr is None:
            return
        try:
            data = await asyncio.wait_for(
                self._proc.stderr.read(MAX_STDERR_CAPTURE), timeout=0.5
            )
        except TimeoutError:
            return
        if data:
            self._stderr_bytes += len(data)
            # Logged, never recorded: diagnostics carry payloads and the audit
            # chain is meant to be shareable.
            logger.warning(
                "stdio server stderr (%d bytes): %s",
                len(data),
                data[-2048:].decode("utf-8", "replace"),
            )

    async def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None or proc.returncode is not None:
            return
        try:
            if proc.stdin is not None:
                proc.stdin.close()
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except TimeoutError:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass


def _text_content(result: Any) -> str:
    """Text content of an MCP result.

    Deliberately identical to the HTTP path in ``proxy.py``: newline-joined text
    parts, falling back to the serialized result. Two transports that extract
    responses differently would produce different ``response_content`` for the
    same server, and the audit chain hashes that.
    """
    content = result.get("content", []) if isinstance(result, dict) else []
    texts = [
        c.get("text", "")
        for c in content
        if isinstance(c, dict) and c.get("type") == "text"
    ]
    if texts:
        return "\n".join(texts)
    return json.dumps(result, default=str)
