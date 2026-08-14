"""Official MCP client -> stdio bridge -> real cMCP gateway proof (#491)."""

from __future__ import annotations

import os
import socket
import sys
import threading
import time

import anyio
import pytest
import uvicorn
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from tests.unit.test_mcp_proxy import _make_proxy

from cmcp_runtime.mcp.server import MCPServer


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.asyncio
async def test_official_client_call_reaches_real_gateway_audit_chain():
    proxy, _, chain = _make_proxy()
    app = MCPServer(proxy=proxy, bearer_token="bridge-test-token").app
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        await anyio.sleep(0.01)
    assert server.started

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-c",
            "from cmcp_runtime.cli import main; main()",
            "client-bridge",
            "--gateway-url",
            f"http://127.0.0.1:{port}/mcp",
        ],
        cwd=os.getcwd(),
        env={**os.environ, "CMCP_BEARER_TOKEN": "bridge-test-token"},
    )
    try:
        async with (
            stdio_client(params) as (read_stream, write_stream),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            tools = await session.list_tools()
            assert any(tool.name == "test.tool" for tool in tools.tools)
            result = await session.call_tool("test.tool", {})
            assert result.isError is not True
    finally:
        server.should_exit = True
        thread.join(timeout=10)

    tool_entries = [entry for entry in chain.entries if entry.entry_type == "tool_call"]
    assert tool_entries
    assert tool_entries[-1].tool_name == "test.tool"
