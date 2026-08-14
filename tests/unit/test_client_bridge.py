"""Client-side stdio bridge tests for #491 / design #510."""

from __future__ import annotations

import io
import json

import httpx
from click.testing import CliRunner

from cmcp_runtime.cli import main
from cmcp_runtime.mcp.client_bridge import bridge_stream


def test_bridge_forwards_jsonrpc_and_bearer_token():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,
                                         "result": {"tools": []}})

    source = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
    sink = io.StringIO()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        bridge_stream(source, sink, gateway_url="https://gateway.example/mcp",
                      bearer_token="secret", client=client)
    assert seen["authorization"] == "Bearer secret"
    assert seen["body"]["method"] == "tools/list"
    assert json.loads(sink.getvalue())["result"] == {"tools": []}


def test_malformed_input_returns_one_error_line_without_forwarding():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    sink = io.StringIO()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        bridge_stream(io.StringIO("not-json\n"), sink,
                      gateway_url="https://gateway.example/mcp",
                      bearer_token="secret", client=client)
    assert json.loads(sink.getvalue())["error"]["code"] == -32000
    assert calls == 0
    assert sink.getvalue().count("\n") == 1


def test_http_error_does_not_echo_gateway_body_or_token():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="secret internal detail", request=request)

    sink = io.StringIO()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        bridge_stream(io.StringIO('{"jsonrpc":"2.0","id":7,"method":"tools/list"}\n'),
                      sink, gateway_url="https://gateway.example/mcp",
                      bearer_token="do-not-leak", client=client)
    output = sink.getvalue()
    assert "HTTP 401" in output
    assert "secret internal detail" not in output
    assert "do-not-leak" not in output


def test_cli_requires_token_environment_variable():
    result = CliRunner().invoke(
        main, ["client-bridge", "--gateway-url", "https://gateway.example/mcp"],
        env={"CMCP_BEARER_TOKEN": ""},
    )
    assert result.exit_code != 0
    assert "CMCP_BEARER_TOKEN is unset" in result.output
