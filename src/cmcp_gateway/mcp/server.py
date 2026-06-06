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
from typing import TYPE_CHECKING, Any

from agent_os.stateless import StatelessKernel
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from cmcp_gateway.mcp.proxy import CMCPProxy

if TYPE_CHECKING:
    from cmcp_gateway.audit.chain import AuditChain
    from cmcp_gateway.session.manager import SessionManager
    from cmcp_gateway.session.state import SessionState

logger = logging.getLogger(__name__)


class MCPServer:
    """
    HTTP/SSE MCP server wrapping CMCPProxy.

    Presents itself to the agent host as a single MCP endpoint.
    The proxy routes calls to upstream servers based on the attested catalog.
    """

    def __init__(
        self,
        proxy: CMCPProxy,
        *,
        session_manager: SessionManager | None = None,
        audit_chain: AuditChain | None = None,
        session: SessionState | None = None,
    ) -> None:
        self._proxy = proxy
        self._session_manager = session_manager
        self._audit_chain = audit_chain
        self._session = session
        self._kernel = StatelessKernel()
        self.app = Starlette(routes=[
            Route("/mcp", self._handle_mcp, methods=["POST"]),
            Route("/health", self._health, methods=["GET"]),
            Route("/tools/list", self._list_tools, methods=["GET"]),
            Route(
                "/sessions/{session_id}/trace-claim",
                self._get_trace_claim,
                methods=["GET"],
            ),
            Route("/audit/export", self._audit_export, methods=["GET"]),
            Route(
                "/sessions/{session_id}/reset",
                self._session_reset,
                methods=["POST"],
            ),
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

    async def _get_trace_claim(self, request: Request) -> Response:
        """GET /sessions/{session_id}/trace-claim — returns signed TRACE Claim for a closed session."""
        if self._session_manager is None:
            return JSONResponse(
                {"error": "session management not available"}, status_code=501
            )
        session_id: str = request.path_params["session_id"]
        claim = self._session_manager.get_trace_claim(session_id)
        if claim is None:
            return JSONResponse(
                {"error": f"trace claim not found for session_id={session_id}"},
                status_code=404,
            )
        return JSONResponse(claim)

    async def _audit_export(self, request: Request) -> Response:
        """GET /audit/export?session_id=<id> — returns signed audit bundle."""
        if self._session_manager is None or self._audit_chain is None:
            return JSONResponse(
                {"error": "audit export not available"}, status_code=501
            )
        session_id: str | None = request.query_params.get("session_id")
        if not session_id:
            return JSONResponse(
                {"error": "query parameter 'session_id' is required"},
                status_code=400,
            )
        try:
            bundle = self._session_manager.get_audit_bundle(
                session_id, self._audit_chain
            )
        except ValueError as exc:
            logger.error(
                "Audit chain integrity failure: session_id=%s error=%s",
                session_id,
                exc,
            )
            return JSONResponse(
                {"error": "audit chain integrity check failed"}, status_code=500
            )
        return JSONResponse(bundle)

    async def _session_reset(self, request: Request) -> Response:
        """POST /sessions/{session_id}/reset — operator-only session sensitivity reset."""
        if self._session is None or self._audit_chain is None:
            return JSONResponse(
                {"error": "session management not configured"}, status_code=501
            )
        session_id: str = request.path_params["session_id"]
        if session_id != self._session.session_id:
            return JSONResponse(
                {"error": f"session_id={session_id} not found"}, status_code=404
            )
        old_id, new_id = self._session.reset(
            reason="operator reset via API",
            authorized_by="api",
        )
        self._audit_chain.append(
            "session_reset",
            call_id=None,
            tool_name=None,
            policy_decision="n/a",
            session_sensitivity_before=self._session.max_sensitivity,
            session_sensitivity_after=self._session.max_sensitivity,
        )
        return JSONResponse({
            "old_session_id": old_id,
            "new_session_id": new_id,
            "status": "reset",
            "attestation_stale": False,
        })
