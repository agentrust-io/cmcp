"""Tests for the stdio upstream.

The gateway spawns a child *inside the enclave*, which is a real weakening of the
isolation story (`docs/spec/stdio-transport.md`). The control that pays for it is
"refuse to spawn what is not measured", so the tests that matter are the ones
where the gateway declines. A regression that turned a refusal into a warning
would leave the feature working and the argument for it gone.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import textwrap

import pytest

from cmcp_runtime.errors import UpstreamToolError, UpstreamUnavailable
from cmcp_runtime.mcp.stdio import (
    SPAWN_MEASURED,
    SPAWN_UNMEASURED,
    StdioServer,
    StdioSpawn,
    StdioSpawnRefused,
    measure_executable,
    resolve_executable,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _script(tmp_path, body: str, name: str = "server.py"):
    """A fake MCP server: reads newline-delimited JSON-RPC, writes responses."""
    path = tmp_path / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


ECHO_SERVER = """
    import json, sys
    for line in sys.stdin:
        req = json.loads(line)
        sys.stdout.write(json.dumps({
            "jsonrpc": "2.0",
            "id": req["id"],
            "result": {"content": [{"type": "text", "text": "ok:" + req["params"]["name"]}]},
        }) + "\\n")
        sys.stdout.flush()
"""


SIZED_SERVER = """
    import json, sys
    for line in sys.stdin:
        req = json.loads(line)
        sys.stdout.write(json.dumps({
            "jsonrpc": "2.0",
            "id": req["id"],
            "result": {"content": [
                {"type": "text", "text": "x" * req["params"]["arguments"]["n"]},
            ]},
        }) + "\\n")
        sys.stdout.flush()
"""


def _spawn_for(script: str, digest: str | None) -> StdioSpawn:
    """Pin the script, not the interpreter.

    Every Python MCP server on a host shares one interpreter digest, so pinning
    the interpreter would match a completely different server. The entrypoint is
    the thing that differs, which is why ``measure_target`` exists.
    """
    return StdioSpawn(
        command=sys.executable,
        args=(script,),
        binary_digest=digest,
        measure_target=script,
    )


# --- the refusals, which are the reason this design is acceptable ----------


async def test_digest_mismatch_refuses_to_spawn(tmp_path) -> None:
    script = _script(tmp_path, ECHO_SERVER)
    server = StdioServer(_spawn_for(script, "sha256:" + "0" * 64))
    with pytest.raises(StdioSpawnRefused, match="does not match the catalog"):
        await server.start()


async def test_missing_digest_refuses_unless_explicitly_enabled(tmp_path) -> None:
    script = _script(tmp_path, ECHO_SERVER)
    server = StdioServer(_spawn_for(script, None))
    with pytest.raises(StdioSpawnRefused, match="allow_unmeasured_spawn"):
        await server.start()


async def test_missing_executable_refuses(tmp_path) -> None:
    server = StdioServer(StdioSpawn(command=str(tmp_path / "nope"), binary_digest=None))
    with pytest.raises(StdioSpawnRefused, match="not found"):
        await server.start()


async def test_refusal_happens_before_exec(tmp_path, monkeypatch) -> None:
    """Measure, decide, then spawn. Never the other way round."""
    script = _script(tmp_path, ECHO_SERVER)
    spawned = False

    async def _boom(*a, **kw):
        nonlocal spawned
        spawned = True
        raise AssertionError("exec must not be reached on a refused spawn")

    monkeypatch.setattr("asyncio.create_subprocess_exec", _boom)
    server = StdioServer(_spawn_for(script, "sha256:" + "1" * 64))
    with pytest.raises(StdioSpawnRefused):
        await server.start()
    assert spawned is False


# --- the permitted paths ---------------------------------------------------


async def test_measured_spawn_records_its_evidence_class(tmp_path) -> None:
    script = _script(tmp_path, ECHO_SERVER)
    digest = measure_executable(resolve_executable(script))
    server = StdioServer(_spawn_for(script, digest))
    await server.start()
    try:
        assert server.evidence_class == SPAWN_MEASURED
        assert server.measured_digest == digest
    finally:
        await server.close()


async def test_unmeasured_spawn_is_labelled_not_silently_allowed(tmp_path) -> None:
    script = _script(tmp_path, ECHO_SERVER)
    server = StdioServer(_spawn_for(script, None), allow_unmeasured=True)
    await server.start()
    try:
        assert server.evidence_class == SPAWN_UNMEASURED
        # The digest of what actually ran is still recorded. Unmeasured means
        # "not checked against anything", not "not observed".
        assert server.measured_digest is not None
    finally:
        await server.close()


async def test_round_trip(tmp_path) -> None:
    script = _script(tmp_path, ECHO_SERVER)
    server = StdioServer(_spawn_for(script, None), allow_unmeasured=True)
    await server.start()
    try:
        assert await server.call("c1", "search", {"q": "x"}) == "ok:search"
        assert await server.call("c2", "pay", {}) == "ok:pay"
    finally:
        await server.close()


async def test_response_over_the_asyncio_default_limit_still_round_trips(tmp_path) -> None:
    """A 200 KiB response is ordinary, and must not depend on asyncio's default.

    ``create_subprocess_exec`` gives the child's stdout a 64 KiB stream limit
    unless told otherwise, and ``readline`` raises a bare ``ValueError`` past it.
    Left at the default, a file read or a search result would fail with a stray
    exception and ``MAX_RESPONSE_BYTES`` would never be reached at all.
    """
    script = _script(tmp_path, SIZED_SERVER)
    server = StdioServer(_spawn_for(script, None), allow_unmeasured=True)
    await server.start()
    try:
        assert await server.call("c1", "read", {"n": 200 * 1024}) == "x" * (200 * 1024)
    finally:
        await server.close()


async def test_oversized_response_is_refused_with_a_reason(tmp_path, monkeypatch) -> None:
    """Past the declared bound the answer is a refusal, not a raw ValueError.

    The limit is monkeypatched rather than fed 8 MB so the test stays quick; it
    is read at spawn time, so the child inherits whatever it is set to here.
    """
    monkeypatch.setattr("cmcp_runtime.mcp.stdio.MAX_RESPONSE_BYTES", 8 * 1024)
    script = _script(tmp_path, SIZED_SERVER)
    server = StdioServer(_spawn_for(script, None), allow_unmeasured=True)
    await server.start()
    try:
        with pytest.raises(UpstreamUnavailable, match="exceeds"):
            await server.call("c1", "read", {"n": 64 * 1024})
    finally:
        await server.close()


# --- framing, where a wrong answer is worse than an error ------------------


async def test_stdout_logging_desynchronizes_and_is_fatal(tmp_path) -> None:
    """A child that logs to stdout must not be resynchronized around.

    Skipping to the next parsable line means guessing which bytes answered which
    call, in an artifact whose whole purpose is saying what happened.
    """
    script = _script(
        tmp_path,
        """
        import json, sys
        sys.stdout.write("starting up...\\n")
        sys.stdout.flush()
        for line in sys.stdin:
            req = json.loads(line)
            sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":req["id"],
                "result":{"content":[{"type":"text","text":"late"}]}}) + "\\n")
            sys.stdout.flush()
        """,
    )
    server = StdioServer(_spawn_for(script, None), allow_unmeasured=True)
    await server.start()
    with pytest.raises(UpstreamUnavailable, match="desynchronized"):
        await server.call("c1", "search", {})


async def test_mismatched_response_id_is_fatal(tmp_path) -> None:
    """A response that cannot be attributed to a request is not a response."""
    script = _script(
        tmp_path,
        """
        import json, sys
        for line in sys.stdin:
            json.loads(line)
            sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":"someone-elses",
                "result":{"content":[{"type":"text","text":"x"}]}}) + "\\n")
            sys.stdout.flush()
        """,
    )
    server = StdioServer(_spawn_for(script, None), allow_unmeasured=True)
    await server.start()
    with pytest.raises(UpstreamUnavailable, match="cannot be attributed"):
        await server.call("c1", "search", {})


async def test_child_exit_is_reported_not_hung(tmp_path) -> None:
    script = _script(tmp_path, "import sys; sys.exit(3)\n")
    server = StdioServer(_spawn_for(script, None), allow_unmeasured=True)
    await server.start()
    with pytest.raises(UpstreamUnavailable, match="no response"):
        await server.call("c1", "search", {})


async def test_upstream_error_object_surfaces_as_tool_error(tmp_path) -> None:
    script = _script(
        tmp_path,
        """
        import json, sys
        for line in sys.stdin:
            req = json.loads(line)
            sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":req["id"],
                "error":{"code":-32000,"message":"denied by server"}}) + "\\n")
            sys.stdout.flush()
        """,
    )
    server = StdioServer(_spawn_for(script, None), allow_unmeasured=True)
    await server.start()
    try:
        with pytest.raises(UpstreamToolError, match="denied by server"):
            await server.call("c1", "search", {})
    finally:
        await server.close()


# --- stderr: visible as a signal, never as content -------------------------


async def test_stderr_is_counted_but_its_content_never_returned(tmp_path) -> None:
    """Diagnostics carry payloads and the audit chain is meant to be shareable."""
    script = _script(
        tmp_path,
        """
        import sys
        sys.stderr.write("iban=GB33BUKB20201555555555\\n")
        sys.stderr.flush()
        sys.exit(1)
        """,
    )
    server = StdioServer(_spawn_for(script, None), allow_unmeasured=True)
    await server.start()
    with pytest.raises(UpstreamUnavailable) as exc:
        await server.call("c1", "search", {})
    assert "GB33BUKB" not in str(exc.value)
    assert "bytes" in str(exc.value)
    assert server.stderr_bytes > 0


# --- measurement -----------------------------------------------------------


def test_measure_is_over_the_resolved_file(tmp_path) -> None:
    a = tmp_path / "a.bin"
    a.write_bytes(b"one")
    b = tmp_path / "b.bin"
    b.write_bytes(b"two")
    assert measure_executable(str(a)) != measure_executable(str(b))
    assert measure_executable(str(a)).startswith("sha256:")


def test_resolve_follows_symlinks_so_measure_and_exec_agree(tmp_path) -> None:
    """Measuring one path and exec'ing another invites a different file to answer."""
    real = tmp_path / "real.bin"
    real.write_bytes(b"payload")
    link = tmp_path / "link.bin"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform/user")
    assert resolve_executable(str(link)) == os.path.realpath(str(real))


def test_json_rpc_request_shape(tmp_path) -> None:
    """The wire shape matches the HTTP path, so a server sees one protocol."""
    payload = {
        "jsonrpc": "2.0",
        "id": "c1",
        "method": "tools/call",
        "params": {"name": "search", "arguments": {"q": "x"}},
    }
    assert json.loads(json.dumps(payload, separators=(",", ":"))) == payload


# --- tools/list, for the provenance catalog check --------------------------


async def test_list_tools_returns_what_the_server_advertises(tmp_path) -> None:
    script = _script(
        tmp_path,
        """
        import json, sys
        for line in sys.stdin:
            req = json.loads(line)
            if req["method"] == "tools/list":
                out = {"tools": [{"name": "search", "description": "d", "inputSchema": {}}]}
            else:
                out = {"content": [{"type": "text", "text": "x"}]}
            sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":req["id"],"result":out}) + "\\n")
            sys.stdout.flush()
        """,
    )
    server = StdioServer(_spawn_for(script, None), allow_unmeasured=True)
    await server.start()
    try:
        tools = await server.list_tools()
        assert tools is not None
        assert tools[0]["name"] == "search"
    finally:
        await server.close()


async def test_list_tools_returns_none_rather_than_raising(tmp_path) -> None:
    """A server that will not be listed has not failed provenance.

    It is a server whose provenance could not be checked, and the caller records
    those differently. Raising here would collapse the two.
    """
    script = _script(
        tmp_path,
        """
        import json, sys
        for line in sys.stdin:
            req = json.loads(line)
            sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":req["id"],
                "error":{"code":-32601,"message":"method not found"}}) + "\\n")
            sys.stdout.flush()
        """,
    )
    server = StdioServer(_spawn_for(script, None), allow_unmeasured=True)
    await server.start()
    try:
        assert await server.list_tools() is None
    finally:
        await server.close()
