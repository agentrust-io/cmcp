"""
Reference MCP server for soak testing — exposes echo, get_data, and delay tools.

Runs as a standalone Starlette/uvicorn process or in-process via TestClient.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

# 1KB of synthetic PII-tagged data for get_data responses
_SYNTHETIC_DATA = {
    "records": [
        {"id": f"rec-{i:04d}", "name": f"User {i}", "email": f"user{i}@example.com",
         "ssn_last4": f"{i:04d}", "account_balance": 1000.0 + i * 10.5}
        for i in range(20)
    ],
    "_sensitivity": ["pii"],
}


async def _handle_mcp(request: Request) -> JSONResponse:
    try:
        msg = json.loads(await request.body())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None})

    rpc_id = msg.get("id")
    method = msg.get("method", "")
    params = msg.get("params", {})

    if method == "initialize":
        return JSONResponse({
            "jsonrpc": "2.0", "id": rpc_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "soak-reference-server", "version": "0.1.0"},
            },
        })

    if method == "tools/list":
        return JSONResponse({
            "jsonrpc": "2.0", "id": rpc_id,
            "result": {"tools": [
                {"name": "echo", "description": "Returns input unchanged", "inputSchema": {"type": "object"}},
                {"name": "get_data", "description": "Returns 1KB synthetic PII-tagged data", "inputSchema": {"type": "object"}},
                {"name": "delay", "description": "Sleeps for ms milliseconds", "inputSchema": {"type": "object", "properties": {"ms": {"type": "number"}}}},
            ]},
        })

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if tool_name == "echo":
            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "result": {"content": [{"type": "text", "text": json.dumps(arguments)}]},
            })

        if tool_name == "get_data":
            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "result": {"content": [{"type": "text", "text": json.dumps(_SYNTHETIC_DATA)}]},
            })

        if tool_name == "delay":
            ms = float(arguments.get("ms", 0))
            await asyncio.sleep(ms / 1000)
            return JSONResponse({
                "jsonrpc": "2.0", "id": rpc_id,
                "result": {"content": [{"type": "text", "text": f"delayed {ms}ms"}]},
            })

        return JSONResponse({
            "jsonrpc": "2.0", "id": rpc_id,
            "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
        })

    return JSONResponse({
        "jsonrpc": "2.0", "id": rpc_id,
        "error": {"code": -32601, "message": f"Unknown method: {method}"},
    })


def make_app() -> Starlette:
    return Starlette(routes=[Route("/mcp", _handle_mcp, methods=["POST"])])
