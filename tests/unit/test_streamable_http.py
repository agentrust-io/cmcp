"""MCP 2026-07-28 Streamable HTTP transport contract tests."""

from __future__ import annotations

import json

import httpx
import pytest

from cmcp_runtime.mcp.streamable_http import (
    build_request,
    parameter_headers,
    parse_response,
)


def test_request_mirrors_modern_metadata_into_headers():
    body, headers = build_request(
        "c1", "tools/call", {"name": "echo", "arguments": {}}, name="echo"
    )
    assert headers == {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "echo",
    }
    assert body["params"]["_meta"][
        "io.modelcontextprotocol/protocolVersion"
    ] == headers["MCP-Protocol-Version"]


def test_non_ascii_name_uses_base64_sentinel():
    _, headers = build_request(
        "c1", "tools/call", {"name": "héllo", "arguments": {}}, name="héllo"
    )
    assert headers["Mcp-Name"] == "=?base64?aMOpbGxv?="


def test_sse_parser_ignores_notifications_and_returns_final_response():
    final = {"jsonrpc": "2.0", "id": "c1", "result": {"content": []}}
    text = (
        ": keepalive\n\n"
        'data: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n'
        f"data: {json.dumps(final)}\n\n"
    )
    response = httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        text=text,
    )
    assert parse_response(response, "c1") == final


def test_sse_parser_fails_closed_without_final_response():
    response = httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        text='data: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n',
    )
    with pytest.raises(ValueError, match="without a matching final response"):
        parse_response(response, "c1")


def test_parser_rejects_unadvertised_content_type():
    response = httpx.Response(200, headers={"content-type": "text/plain"}, text="ok")
    with pytest.raises(ValueError, match="unsupported MCP response content type"):
        parse_response(response, "c1")


def test_parameter_headers_follow_static_property_paths():
    schema = {
        "type": "object",
        "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "options": {
                "type": "object",
                "properties": {
                    "dry_run": {"type": "boolean", "x-mcp-header": "Dry-Run"}
                },
            },
        },
    }
    assert parameter_headers(
        schema, {"region": "us-west1", "options": {"dry_run": True}}
    ) == {"Mcp-Param-Region": "us-west1", "Mcp-Param-Dry-Run": "true"}


@pytest.mark.parametrize(
    "annotation, property_type",
    [("bad header", "string"), ("Region", "number")],
)
def test_invalid_parameter_header_annotation_fails_closed(annotation, property_type):
    schema = {
        "properties": {
            "value": {"type": property_type, "x-mcp-header": annotation}
        }
    }
    with pytest.raises(ValueError, match="invalid x-mcp-header"):
        parameter_headers(schema, {"value": "x"})
