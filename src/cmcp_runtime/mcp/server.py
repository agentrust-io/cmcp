"""
HTTP/SSE MCP server — inbound agent-facing endpoint (issue #48).

Receives MCP JSON-RPC 2.0 calls from agent hosts, routes them through
CMCPProxy, and returns results. Uses AGT's StatelessKernel for execution
context management.

Phase 1 scope: HTTP/SSE transport only. stdio excluded (docs/spec/transport.md).
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from agent_os.stateless import StatelessKernel
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from cmcp_runtime.catalog.loader import ApprovedDefinition, CatalogEntry, ServerIdentity
from cmcp_runtime.mcp.proxy import CMCPProxy

if TYPE_CHECKING:
    from cmcp_runtime.audit.chain import AuditChain
    from cmcp_runtime.session.manager import SessionManager
    from cmcp_runtime.session.state import SessionState

logger = logging.getLogger(__name__)

# Endpoints exempt from bearer-token auth (Kubernetes liveness / readiness probes)
_AUTH_EXEMPT_PATHS = {"/health", "/readyz"}


async def _unhandled_error_handler(request: Request, exc: Exception) -> Response:
    """NET-004: return generic 500 without leaking exception class or message."""
    logger.error(
        "UNHANDLED_EXCEPTION: method=%s path=%s error=%s",
        request.method,
        request.url.path,
        exc,
        exc_info=True,
    )
    return JSONResponse(
        {"error": "Internal server error", "error_code": "INTERNAL_ERROR"},
        status_code=500,
    )


class _RateLimitMiddleware(BaseHTTPMiddleware):
    """NET-002: per-IP rate limit for unauthenticated endpoints (/health).

    Uses a sliding-window counter: at most `requests_per_minute` requests
    from a single IP address within any 60-second window.
    """

    def __init__(
        self,
        app: Any,
        *,
        paths: frozenset[str],
        requests_per_minute: int = 60,
    ) -> None:
        super().__init__(app)
        self._paths = paths
        self._limit = requests_per_minute
        self._window = 60.0
        self._counts: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.url.path not in self._paths:
            return await call_next(request)
        ip = request.client[0] if request.client else "unknown"
        now = time.monotonic()
        async with self._lock:
            cutoff = now - self._window
            hits = self._counts[ip]
            # Prune timestamps outside the window
            while hits and hits[0] <= cutoff:
                hits.pop(0)
            if len(hits) >= self._limit:
                return JSONResponse(
                    {"error": "Too Many Requests", "error_code": "RATE_LIMITED"},
                    status_code=429,
                    headers={"Retry-After": "60"},
                )
            hits.append(now)
        return await call_next(request)


class _BearerAuthMiddleware(BaseHTTPMiddleware):
    """AUTH-001 (CRITICAL): validate Authorization: Bearer <token> on all protected endpoints."""

    def __init__(self, app: Any, *, bearer_token: str) -> None:
        super().__init__(app)
        self._token = bearer_token

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.url.path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)
        auth = request.headers.get("Authorization", "")
        prefix = "Bearer "
        if not auth.startswith(prefix):
            return JSONResponse(
                {"error": "unauthorized", "error_code": "MISSING_BEARER_TOKEN"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer realm=\"cmcp-runtime\""},
            )
        provided = auth[len(prefix):]
        # Constant-time compare to prevent timing oracle on the token
        if not hmac.compare_digest(provided, self._token):
            logger.warning("AUTH_FAILURE: invalid bearer token from %s", request.client)
            return JSONResponse(
                {"error": "unauthorized", "error_code": "INVALID_BEARER_TOKEN"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer realm=\"cmcp-runtime\""},
            )
        return await call_next(request)


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
        bearer_token: str | None = None,
        session: SessionState | None = None,
        max_request_bytes: int = 1_000_000,
    ) -> None:
        self._proxy = proxy
        self._session_manager = session_manager
        self._audit_chain = audit_chain
        self._session = session
        self._max_request_bytes = max_request_bytes
        self._audit = audit_chain
        self._kernel = StatelessKernel()
        # NET-002: rate-limit unauthenticated /health before auth middleware runs.
        # Starlette applies middleware outermost-first (first in list = first to run).
        rate_limit = Middleware(
            _RateLimitMiddleware,
            paths=frozenset({"/health", "/readyz"}),
            requests_per_minute=60,
        )
        middleware = [rate_limit] + (
            [Middleware(_BearerAuthMiddleware, bearer_token=bearer_token)]
            if bearer_token is not None
            else []
        )
        # AUTH-004: session cleanup interval configurable via env var (default 60s)
        self._cleanup_interval_s: int = int(
            os.environ.get("CMCP_SESSION_CLEANUP_INTERVAL_SECONDS", "60")
        )

        self.app = Starlette(
            routes=[
                Route("/mcp", self._handle_mcp, methods=["POST"]),
                Route("/health", self._health, methods=["GET"]),
                Route("/readyz", self._readyz, methods=["GET"]),
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
                Route("/catalog/exception", self._catalog_exception, methods=["POST"]),
            ],
            middleware=middleware,
            exception_handlers={Exception: _unhandled_error_handler},
        )

    async def _handle_mcp(self, request: Request) -> Response:
        """Handle MCP JSON-RPC 2.0 calls."""
        # DOS-001: reject oversized requests before parsing to prevent OOM
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self._max_request_bytes:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "Request body too large"},
                    "id": None,
                },
                status_code=413,
            )
        try:
            body = await request.body()
            if len(body) > self._max_request_bytes:
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "error": {"code": -32600, "message": "Request body too large"},
                        "id": None,
                    },
                    status_code=413,
                )
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
                    "serverInfo": {"name": "cmcp-runtime", "version": "0.1.0"},
                },
            })
        # INJECT-002: sanitize method before reflecting it in the error response
        safe_method = (method or "")[:64].encode("ascii", errors="replace").decode("ascii")
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {safe_method}",
                },
                "id": rpc_id,
            },
            status_code=404,
        )

    async def _handle_tool_call(self, rpc_id: Any, params: dict[str, Any]) -> Response:
        """Route a tools/call request through the proxy."""
        # POLICY-002: canonicalize tool names at ingress so Cedar policy, catalog, and
        # request all use the same case — prevents case-variant bypass of deny rules.
        tool_name: str = params.get("name", "").lower()
        arguments: dict[str, Any] = params.get("arguments", {})
        call_id = str(uuid.uuid4())
        workflow_id: str | None = params.get("_cmcp", {}).get("workflow_id")

        try:
            result = await self._proxy.call_tool(call_id, tool_name, arguments, workflow_id=workflow_id)
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
            _HEALTH_REASONS = {"attestation_stale", "catalog_drift"}
            if result.deny_reason in _HEALTH_REASONS:
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32000,
                            "message": result.deny_reason,
                            "data": {
                                "error_code": result.deny_reason.upper(),
                                "call_id": call_id,
                            },
                        },
                        "id": rpc_id,
                    },
                    status_code=503,
                )
            # INJECT-003: log deny_reason internally; do not reflect internal detail to caller
            error_code = (
                "TOOL_NOT_IN_CATALOG"
                if "catalog" in (result.deny_reason or "")
                else "POLICY_DENY"
            )
            logger.info(
                "POLICY_DENY: call_id=%s error_code=%s reason=%s",
                call_id, error_code, result.deny_reason,
            )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "Request denied by policy",
                        "data": {
                            "error_code": error_code,
                            "call_id": call_id,
                        },
                    },
                    "id": rpc_id,
                },
                status_code=403,
            )

        cmcp_meta: dict[str, Any] = {
            "call_id": call_id,
            "audit_entry_hash": result.audit_entry_hash,
            "would_have_denied": result.would_have_denied,
            "latency_us": result.latency_us,
        }
        if workflow_id is not None:
            cmcp_meta["workflow_id"] = workflow_id
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "content": [{"type": "text", "text": str(result.response)}],
                "_cmcp": cmcp_meta,
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

    async def _readyz(self, request: Request) -> Response:
        """GET /readyz - structured readiness probe (CONF-007).

        Returns 200 {"status": "ready", "checks": {...}} when all components are
        operational; 503 {"status": "not_ready", "checks": {...}} when any check
        fails.  Each check maps to "ok" or "failed: <reason>".
        Safe for unauthenticated Kubernetes readiness probes.
        """
        checks: dict[str, str] = {}
        not_ready = False

        # Cedar policy: evaluator must be present and loaded
        if self._proxy._policy is not None:
            checks["policy"] = "ok"
        else:
            checks["policy"] = "failed: Cedar policy engine not loaded"
            not_ready = True

        # TEE attestation: check provider availability and staleness
        attest_reason = self._proxy._check_health()
        if attest_reason is None:
            checks["attestation"] = "ok"
        else:
            checks["attestation"] = f"failed: {attest_reason}"
            not_ready = True

        # AGT (agent_os kernel): verify the library is importable and responsive
        try:
            import agent_os  # noqa: F401
            checks["agt"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["agt"] = f"failed: agent_os unavailable ({exc})"
            not_ready = True

        status = "not_ready" if not_ready else "ready"
        return JSONResponse({"status": status, "checks": checks}, status_code=503 if not_ready else 200)

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

    async def _catalog_exception(self, request: Request) -> Response:
        """POST /catalog/exception — add a break-glass catalog exception at runtime.

        The exception is visible in the TRACE Claim but does NOT modify catalog_hash.
        Requires the same bearer token as all other operator endpoints.
        """
        try:
            body = await request.body()
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JSONResponse(
                {"error": "invalid JSON body", "error_code": "PARSE_ERROR"},
                status_code=400,
            )

        reason: str | None = data.get("reason")
        authorized_by: str | None = data.get("authorized_by")
        tool_names: list[str] | None = data.get("tool_names")
        server_identity_raw: dict[str, Any] | None = data.get("server_identity")

        if not reason or not isinstance(reason, str):
            return JSONResponse(
                {"error": "'reason' is required", "error_code": "MISSING_FIELD"},
                status_code=422,
            )
        if not authorized_by or not isinstance(authorized_by, str):
            return JSONResponse(
                {"error": "'authorized_by' is required", "error_code": "MISSING_FIELD"},
                status_code=422,
            )
        if not tool_names or not isinstance(tool_names, list) or not all(isinstance(n, str) for n in tool_names):
            return JSONResponse(
                {"error": "'tool_names' must be a non-empty list of strings", "error_code": "MISSING_FIELD"},
                status_code=422,
            )
        if not server_identity_raw or not isinstance(server_identity_raw, dict):
            return JSONResponse(
                {"error": "'server_identity' is required", "error_code": "MISSING_FIELD"},
                status_code=422,
            )

        required_si_fields = ("display_name", "url", "tls_fingerprint")
        missing = [f for f in required_si_fields if not server_identity_raw.get(f)]
        if missing:
            return JSONResponse(
                {
                    "error": f"server_identity missing fields: {missing}",
                    "error_code": "MISSING_FIELD",
                },
                status_code=422,
            )

        try:
            server = ServerIdentity(
                display_name=server_identity_raw["display_name"],
                url=server_identity_raw["url"],
                tls_fingerprint=server_identity_raw["tls_fingerprint"],
                spiffe_id=server_identity_raw.get("spiffe_id"),
                transport=server_identity_raw.get("transport", "http-sse"),
                rotation_mode=server_identity_raw.get("rotation_mode", "key-pinned"),
            )
        except (KeyError, TypeError) as exc:
            return JSONResponse(
                {"error": f"invalid server_identity: {exc}", "error_code": "INVALID_FIELD"},
                status_code=422,
            )

        added: list[str] = []
        for tool_name in tool_names:
            entry = CatalogEntry(
                tool_name=tool_name,
                server=server,
                approved_definition=ApprovedDefinition(
                    description=f"Break-glass exception: {reason}",
                    input_schema={},
                    output_schema=None,
                ),
                definition_hash="sha256:" + "0" * 64,
                compliance_domain="external",
                requires_baa=False,
                sensitivity_level="public",
                added_at="",
                approved_by=authorized_by,
            )
            self._proxy._catalog.add_exception(entry, reason=reason, authorized_by=authorized_by)
            added.append(tool_name)

        logger.warning(
            "BREAK_GLASS_EXCEPTION_ADDED: tools=%s reason=%r authorized_by=%r",
            added,
            reason,
            authorized_by,
        )

        return JSONResponse(
            {
                "status": "ok",
                "added_tools": added,
                "reason": reason,
                "authorized_by": authorized_by,
            },
            status_code=201,
        )

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
        # AUTH-002: lock guards against a concurrent tool-call coroutine modifying sensitivity.
        async with self._session.mutation_lock:
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
