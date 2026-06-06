"""
HTTP/SSE MCP server — inbound agent-facing endpoint (issue #48).

Receives MCP JSON-RPC 2.0 calls from agent hosts, routes them through
CMCPProxy, and returns results. Uses AGT's StatelessKernel for execution
context management.

Phase 1 scope: HTTP/SSE transport only. stdio excluded (docs/spec/transport.md).
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from agent_os.stateless import StatelessKernel
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from cmcp_gateway.mcp.proxy import CMCPProxy

logger = logging.getLogger(__name__)


class MCPServer:
    """
    HTTP/SSE MCP server wrapping CMCPProxy.

    Presents itself to the agent host as a single MCP endpoint.
    The proxy routes calls to upstream servers based on the attested catalog.
    """

    def __init__(self, proxy: CMCPProxy) -> None:
        self._proxy = proxy
        self._kernel = StatelessKernel()
        self.app = Starlette(routes=[
            Route("/mcp", self._handle_mcp, methods=["POST"]),
            Route("/health", self._health, methods=["GET"]),
            Route("/tools/list", self._list_tools, methods=["GET"]),
        ])

    async def _handle_mcp(self, request: Request) -> Response:
        """Handle MCP JSON-RPC 2.0 calls."""
        try:
            body = await request.body()
            msg = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            import hashlib
            payload_hash = f"sha256:{hashlib.sha256(body).hexdigest()}"
            logger.warning(
                "MCP_PARSE_FAILURE: payload_hash=%s error=%s", payload_hash, exc
            )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": "Parse error",
                        "data": {
                            "error_code": "MCP_PARSE_FAILURE",
                            "payload_hash": payload_hash,
                        },
                    },
                    "id": None,
                },
                status_code=400,
            )

        rpc_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {})

        if method == "tools/call":
            return await self._handle_tool_call(rpc_id, params)
        if method == "tools/list":
            return await self._handle_tools_list(rpc_id)
        if method == "initialize":
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "cmcp-gateway", "version": "0.1.0"},
                },
            })
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
                "id": rpc_id,
            },
            status_code=404,
        )

    async def _handle_tool_call(self, rpc_id: Any, params: dict[str, Any]) -> Response:
        """Route a tools/call request through the proxy."""
        tool_name: str = params.get("name", "")
        arguments: dict[str, Any] = params.get("arguments", {})
        call_id = str(uuid.uuid4())

        try:
            result = await self._proxy.call_tool(call_id, tool_name, arguments)
        except Exception as exc:
            logger.error("TEE_FAULT during call_tool: call_id=%s error=%s", call_id, exc)
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "Internal error",
                        "data": {"error_code": "TEE_FAULT", "call_id": call_id},
                    },
                    "id": rpc_id,
                },
                status_code=500,
            )

        if not result.allowed:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": result.deny_reason or "Denied",
                        "data": {
                            "error_code": "POLICY_DENY" if "catalog" not in (result.deny_reason or "") else "TOOL_NOT_IN_CATALOG",
                            "call_id": call_id,
                        },
                    },
                    "id": rpc_id,
                },
                status_code=403,
            )

        return JSONResponse({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "content": [{"type": "text", "text": str(result.response)}],
                "_cmcp": {
                    "call_id": call_id,
                    "audit_entry_hash": result.audit_entry_hash,
                    "would_have_denied": result.would_have_denied,
                    "latency_us": result.latency_us,
                },
            },
        })

    async def _handle_tools_list(self, rpc_id: Any) -> Response:
        """Return the attested tool catalog as MCP tools list."""
        tools = [
            {
                "name": name,
                "description": entry.approved_definition.description,
                "inputSchema": entry.approved_definition.input_schema,
            }
            for name, entry in self._proxy._catalog.entries.items()
        ]
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"tools": tools},
        })

    async def _list_tools(self, request: Request) -> Response:
        """GET /tools/list convenience endpoint."""
        return await self._handle_tools_list(None)

    async def _health(self, request: Request) -> Response:
        return JSONResponse({"status": "ok"})
