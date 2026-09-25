"""
HTTP/SSE MCP server - inbound agent-facing endpoint (issue #48).

Receives MCP JSON-RPC 2.0 calls from agent hosts, routes them through
CMCPProxy, and returns results. Runtime enforcement is owned by cMCP.

Phase 1 scope: HTTP/SSE transport only. stdio excluded (docs/spec/transport.md).
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import time
import uuid
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from cmcp_runtime.catalog.loader import ApprovedDefinition, CatalogEntry, ServerIdentity
from cmcp_runtime.errors import KillSwitchTripped
from cmcp_runtime.mcp.proxy import SESSION_CLOSE_DRAIN_SECONDS, CMCPProxy

if TYPE_CHECKING:
    from cmcp_runtime.audit.chain import AuditChain
    from cmcp_runtime.session.manager import SessionManager
    from cmcp_runtime.session.state import ClosedSessionRecord, SessionState

logger = logging.getLogger(__name__)


class StatelessKernel:
    """Backward-compatible marker for the former unused construction hook.

    cMCP performs enforcement in :class:`CMCPProxy`; this marker keeps the
    constructor seam stable for embedders and tests without an external runtime.
    """


# Endpoints exempt from bearer-token auth (Kubernetes liveness / readiness probes)
_AUTH_EXEMPT_PATHS = {"/health", "/readyz"}

# The operator interface. These routes are not reachable as MCP tools and, when an
# operator token is configured, they do not accept the tool-invocation token: a
# reset lowers accumulated session sensitivity, so the credential that authorizes
# one must not be the credential an agent host already holds.
_OPERATOR_PATH_RE = re.compile(
    r"^/(?:sessions/[^/]+/reset|catalog/exception|kill-switch/(?:unblock|trip))$"
)

# DOS-001: default ceiling on a single request body. Overridable per
# deployment via MCPServer(max_request_bytes=...). Named here rather than
# left inline on the constructor so the argument-shape caps below can be
# derived from it instead of restating the number.
_DEFAULT_MAX_REQUEST_BYTES = 1_000_000

# #518: DOS-001's byte cap bounds total size, not shape. A payload well under
# the limit can still push toward Python's recursion limit through deep
# nesting, or cost real time to iterate through a flat object with thousands
# of short keys. These values mirror `_MAX_ARG_DEPTH` / `_MAX_ARG_KEYS` in
# scripts/mock_upstream.py - same judgment call, same margin above any real
# `arguments` payload this repo ships examples for, kept in sync rather than
# unified per qubeena07's review on #518.
_MAX_ARG_DEPTH = 20
_MAX_ARG_KEYS = 256

# #562: docs/spec/proxy-security.md's Fuzzing Definition of Done specs
# MAX_STRING_LENGTH at 1MB per string field, separate from the depth/key
# caps above. A single oversized string can sit inside an otherwise
# shallow, low-key-count payload and slip past both of those unbounded,
# up to whatever the whole-body byte cap happens to be.
#
# Not set to the spec's literal 1MB: that equals the whole-body default
# below, and a 1MB string plus any JSON structure around it already
# exceeds that cap, so the check could never fire before DOS-001's size
# rejection already had. Derived from the default instead, so a single
# string cannot consume the whole request budget, the cap is actually
# reachable, and raising the default carries this along with it rather
# than silently leaving it behind. This is scoped against the *default*
# max_request_bytes; a deployment that configures a smaller value simply
# has the whole-body cap bind first, which is a safe direction to fail
# in, not a gap. Worth revisiting to the spec's literal value if the
# default is ever raised toward the spec's stated 10MB (see #562).
#
# Checked as UTF-8 byte length, not character count, since a codepoint
# count understates the actual memory and processing cost of multi-byte
# text.
_MAX_ARG_STRING_LENGTH = _DEFAULT_MAX_REQUEST_BYTES // 2


def _reject_nan_and_infinity(text: str) -> float:
    raise ValueError(f"non-standard JSON value not allowed: {text}")


def _valid_rpc_id(value: Any) -> bool:
    # JSON-RPC 2.0 id must be a string, number, or null -- not a bool, even
    # though bool is an int subclass in Python.
    return value is None or (isinstance(value, (str, int, float)) and not isinstance(value, bool))


def _over_string_cap(text: str) -> bool:
    return len(text.encode("utf-8")) > _MAX_ARG_STRING_LENGTH


def _object_shape_violation(value: dict[str, Any], depth: int) -> str | None:
    if len(value) > _MAX_ARG_KEYS:
        return f"object has more than {_MAX_ARG_KEYS} keys"
    for key, child in value.items():
        # Keys carry the same cost as values and are not covered by the key
        # *count* cap above, so a single huge key would otherwise slip
        # through every check here.
        if isinstance(key, str) and _over_string_cap(key):
            return f"object key over the length cap of {_MAX_ARG_STRING_LENGTH} bytes"
        violation = _arg_shape_violation(child, depth=depth + 1)
        if violation is not None:
            return violation
    return None


def _arg_shape_violation(value: Any, *, depth: int = 0) -> str | None:
    """Return a message describing the first depth/key-count/string-length
    violation found under `value`, or None if it fits within `_MAX_ARG_DEPTH` /
    `_MAX_ARG_KEYS` / `_MAX_ARG_STRING_LENGTH`."""
    if depth > _MAX_ARG_DEPTH:
        return f"arguments nested past the depth cap of {_MAX_ARG_DEPTH}"
    if isinstance(value, dict):
        return _object_shape_violation(value, depth)
    if isinstance(value, list):
        for child in value:
            violation = _arg_shape_violation(child, depth=depth + 1)
            if violation is not None:
                return violation
        return None
    if isinstance(value, str) and _over_string_cap(value):
        return f"string value over the length cap of {_MAX_ARG_STRING_LENGTH} bytes"
    return None


# Revisions the gateway can negotiate at `initialize`, newest first.
#
# `initialize` belongs to the handshake era only. `PROTOCOL_VERSION` (#509) is
# the revision the gateway speaks *outbound* to upstream servers, and it is
# 2026-07-28 - the revision that removed `initialize` altogether. It must never
# be the answer to a handshake: it names a protocol in which this request does
# not exist, and in which every subsequent request must carry `_meta` and the
# mirrored `MCP-Protocol-Version` / `Mcp-Method` headers that a handshake-era
# client has no way to send.
#
# `2025-11-25` is the newest revision that still defines `initialize`, so it
# heads the list: a client offering the latest handshake revision must get it
# echoed rather than be downgraded.
_LEGACY_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")


def _negotiate_protocol_version(params: dict[str, Any]) -> str:
    """Pick the revision to answer `initialize` with.

    Per the lifecycle spec: if the server supports the requested version it MUST
    respond with that same version, otherwise it MUST respond with another it
    supports, which SHOULD be the latest. A client that does not support the
    answer SHOULD disconnect, which is why a needless downgrade is not a
    harmless one.

    The gateway advertises `tools` only, so the revision affects transport
    framing rather than the surface exposed here.
    """
    requested = params.get("protocolVersion")
    if isinstance(requested, str) and requested in _LEGACY_PROTOCOL_VERSIONS:
        return requested
    return _LEGACY_PROTOCOL_VERSIONS[0]


def _kill_switch_response(
    rpc_id: Any, agent_id: str | None, receipt: dict[str, Any] | None = None
) -> JSONResponse:
    """JSON-RPC refusal for a call arriving while the kill switch holds the gateway stopped."""
    data: dict[str, Any] = {"error_code": "KILL_SWITCH_TRIPPED", "agent_id": agent_id}
    if receipt is not None:
        data["receipt"] = receipt
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": "Agent identity blocked by the kill switch",
                "data": data,
            },
            "id": rpc_id,
        },
        status_code=403,
    )


def _kill_switch_conflict(agent_id: str) -> JSONResponse:
    """Session lifecycle refusal while the kill switch holds the gateway stopped."""
    return JSONResponse(
        {
            "error": "kill_switch_tripped",
            "error_code": "KILL_SWITCH_TRIPPED",
            "message": (
                f"Agent identity {agent_id!r} is blocked by the kill switch. "
                "POST /kill-switch/unblock to lift the block."
            ),
        },
        status_code=409,
    )


def _invalid_request(rpc_id: Any = None) -> JSONResponse:
    """Return a bounded JSON-RPC Invalid Request response."""
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "error": {
                "code": -32600,
                "message": "Invalid Request",
                "data": {"error_code": "MCP_INVALID_REQUEST"},
            },
            "id": rpc_id,
        },
        status_code=400,
    )


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
        max_clients: int = 10_000,
    ) -> None:
        super().__init__(app)
        self._paths = paths
        self._limit = requests_per_minute
        self._window = 60.0
        self._max_clients = max_clients
        self._counts: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    def _prune_inactive_clients(self, cutoff: float) -> None:
        expired_clients = [
            client for client, timestamps in self._counts.items()
            if not timestamps or timestamps[-1] <= cutoff
        ]
        for client in expired_clients:
            del self._counts[client]

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.url.path not in self._paths:
            return await call_next(request)
        ip = request.client[0] if request.client else "unknown"
        now = time.monotonic()
        async with self._lock:
            cutoff = now - self._window
            # Reclaim clients whose complete window has expired. Without this,
            # one request from each spoofed/churned address grows the map for
            # the process lifetime.
            self._prune_inactive_clients(cutoff)
            if ip not in self._counts and len(self._counts) >= self._max_clients:
                return JSONResponse(
                    {"error": "Too Many Requests", "error_code": "RATE_LIMITED"},
                    status_code=429,
                    headers={"Retry-After": "60"},
                )
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
    """AUTH-001 (CRITICAL): validate Authorization: Bearer <token> on all protected endpoints.

    Operator routes are matched against ``_OPERATOR_PATH_RE`` and, when an
    operator token is configured, accept only that token. Where none is
    configured they fall back to the bearer token, which keeps existing
    single-token deployments working; startup refuses that outside dev mode.
    """

    def __init__(
        self, app: Any, *, bearer_token: str, operator_token: str | None = None
    ) -> None:
        super().__init__(app)
        self._token = bearer_token
        self._operator_token = operator_token

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.url.path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)
        expected = self._token
        if self._operator_token is not None and _OPERATOR_PATH_RE.match(request.url.path):
            expected = self._operator_token
        auth = request.headers.get("Authorization", "")
        prefix = "Bearer "
        if not auth.startswith(prefix):
            return JSONResponse(
                {"error": "unauthorized", "error_code": "MISSING_BEARER_TOKEN"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer realm=\"cmcp-runtime\""},
            )
        provided = auth[len(prefix):]
        # Constant-time compare to prevent timing oracle on the token. Compared
        # as bytes: compare_digest raises TypeError on a str holding non-ASCII
        # characters, and header values are caller-controlled latin-1 text.
        if not hmac.compare_digest(provided.encode(), expected.encode()):
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
        operator_token: str | None = None,
        session: SessionState | None = None,
        max_request_bytes: int = _DEFAULT_MAX_REQUEST_BYTES,
    ) -> None:
        self._proxy = proxy
        self._session_manager = session_manager
        self._audit_chain = audit_chain
        self._session = session
        self._max_request_bytes = max_request_bytes
        self._operator_token = operator_token
        self._audit = audit_chain
        # Chains of closed sessions, kept so /audit/export still serves them
        # after the live session rotates.
        self._closed_chains: dict[str, AuditChain] = {}
        # Preserve the successor across failed resource cleanup. The manager
        # independently retains claim/partial-close state if creation fails.
        # At most one close can be pending: admission stays sealed until it
        # resolves, and a close naming any other session is rejected before it
        # reaches commit. One slot, so a close nobody retries cannot accumulate.
        # The successor is None when the close tripped the kill switch.
        self._pending_close: (
            tuple[str, dict[str, Any], SessionState | None, AuditChain | None] | None
        ) = None
        self._kernel = StatelessKernel()
        # NET-002: rate-limit unauthenticated /health before auth middleware runs.
        # Starlette applies middleware outermost-first (first in list = first to run).
        rate_limit = Middleware(
            _RateLimitMiddleware,
            paths=frozenset({"/health", "/readyz"}),
            requests_per_minute=60,
        )
        middleware = [rate_limit] + (
            [
                Middleware(
                    _BearerAuthMiddleware,
                    bearer_token=bearer_token,
                    operator_token=operator_token,
                )
            ]
            if bearer_token is not None
            else []
        )
        # Final state of sessions closed by a credentialed reset, kept so the
        # value a closed session reached survives the successor starting at the
        # minimum level.
        self._closed_sessions: dict[str, ClosedSessionRecord] = {}
        # AUTH-004: session cleanup interval configurable via env var (default 60s)
        self._cleanup_interval_s: int = int(
            os.environ.get("CMCP_SESSION_CLEANUP_INTERVAL_SECONDS", "60")
        )
        self._session_close_drain_s: float = float(
            os.environ.get(
                "CMCP_SESSION_CLOSE_DRAIN_SECONDS", str(SESSION_CLOSE_DRAIN_SECONDS)
            )
        )

        self.app = Starlette(
            lifespan=self._lifespan,
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
                Route(
                    "/sessions/{session_id}/close",
                    self._session_close,
                    methods=["POST"],
                ),
                Route("/catalog/exception", self._catalog_exception, methods=["POST"]),
                Route("/kill-switch/unblock", self._kill_switch_unblock, methods=["POST"]),
                Route("/kill-switch/trip", self._kill_switch_trip, methods=["POST"]),
            ],
            middleware=middleware,
            exception_handlers={Exception: _unhandled_error_handler},
        )

    @asynccontextmanager
    async def _lifespan(self, app: Starlette) -> AsyncIterator[None]:
        """Drain admitted calls and close session resources on graceful shutdown."""
        try:
            yield
        finally:
            await self._proxy.shutdown(drain_timeout=self._session_close_drain_s)

    async def _parse_mcp_envelope(self, request: Request) -> dict[str, Any] | Response:
        """Read, size-check, and parse the request body.

        Returns the parsed JSON-RPC message dict, or an error Response if the
        body is oversized, unparsable, or not a JSON object.
        """
        # DOS-001: reject oversized requests before parsing to prevent OOM
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                cl = int(content_length)
            except ValueError:
                return JSONResponse({"error": "invalid Content-Length"}, status_code=400)
            if cl > self._max_request_bytes:
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
            # #518: parse_constant intercepts NaN/Infinity/-Infinity before
            # json.loads would otherwise accept them silently.
            msg = json.loads(body, parse_constant=_reject_nan_and_infinity)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
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

        if not isinstance(msg, dict):
            return _invalid_request()
        return msg

    async def _handle_mcp(self, request: Request) -> Response:
        """Handle MCP JSON-RPC 2.0 calls."""
        parsed = await self._parse_mcp_envelope(request)
        if isinstance(parsed, Response):
            return parsed
        msg = parsed

        # #518: strict jsonrpc/id validation, matching scripts/mock_upstream.py.
        rpc_id = msg.get("id")
        if "id" in msg and not _valid_rpc_id(rpc_id):
            return _invalid_request()
        if msg.get("jsonrpc") != "2.0":
            return _invalid_request(rpc_id)

        method = msg.get("method", "")
        if not isinstance(method, str):
            return _invalid_request(rpc_id)
        params = msg.get("params", {})

        if method == "tools/call":
            if not isinstance(params, dict):
                return _invalid_request(rpc_id)
            return await self._handle_tool_call(rpc_id, params)
        if method == "tools/list":
            return await self._handle_tools_list(rpc_id)
        if method == "initialize":
            # `InitializeRequestParams` is an object. Treating a non-object as
            # an empty one would answer a malformed handshake with a successful
            # negotiation, so it is rejected the same way `tools/call` rejects
            # its own non-object params. Absent `params` stays legal and
            # negotiates the newest revision.
            if not isinstance(params, dict):
                return _invalid_request(rpc_id)
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "protocolVersion": _negotiate_protocol_version(params),
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

    def _deny_response(self, rpc_id: Any, call_id: str, result: Any) -> JSONResponse:
        """Build the JSON-RPC error response for a policy-denied tool call."""
        deny_reason = result.deny_reason or ""
        # Upstream transport/tool failure is a 502, not a policy deny.
        if deny_reason.startswith("upstream_error:"):
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "Upstream MCP server error",
                        "data": {
                            "error_code": deny_reason.removeprefix("upstream_error:"),
                            "call_id": call_id,
                        },
                    },
                    "id": rpc_id,
                },
                status_code=502,
            )
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
        error_data: dict[str, Any] = {
            "error_code": error_code,
            "call_id": call_id,
        }
        # Advice annotations come from the hash-pinned policy bundle
        # (operator-authored, not caller input), so reflecting them does
        # not violate INJECT-003. They carry e.g. HITL escalation payloads.
        if result.advice:
            error_data["advice"] = result.advice
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": "Request denied by policy",
                    "data": error_data,
                },
                "id": rpc_id,
            },
            status_code=403,
        )

    async def _handle_tool_call(self, rpc_id: Any, params: dict[str, Any]) -> Response:
        """Route a tools/call request through the proxy."""
        # `params` is a dict (the caller already rejected non-dict params before
        # dispatching here), but its members are not: `name` and `arguments`
        # are exactly as caller-controlled as `_cmcp` below, which is already
        # guarded ("A malformed _cmcp (string, list, number) must not 500 the
        # call path"). `.lower()` on a non-string `name`, or handing a non-dict
        # `arguments` to call_tool, is the same failure that guard exists to
        # prevent, just unguarded here.
        raw_name = params.get("name", "")
        if not isinstance(raw_name, str):
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32602, "message": "Invalid params: name must be a string"},
                    "id": rpc_id,
                },
                status_code=400,
            )
        # POLICY-002: canonicalize tool names at ingress so Cedar policy, catalog, and
        # request all use the same case - prevents case-variant bypass of deny rules.
        tool_name: str = raw_name.lower()
        arguments: dict[str, Any] = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: arguments must be an object",
                    },
                    "id": rpc_id,
                },
                status_code=400,
            )

        # #518/#562: depth, key-count and string-length caps, matching
        # scripts/mock_upstream.py.
        violation = _arg_shape_violation(arguments)
        if violation is not None:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32602, "message": f"Invalid params: {violation}"},
                    "id": rpc_id,
                },
                status_code=400,
            )

        call_id = str(uuid.uuid4())
        # A malformed _cmcp (string, list, number) must not 500 the call path.
        cmcp_params = params.get("_cmcp")
        if not isinstance(cmcp_params, dict):
            cmcp_params = {}
        raw_workflow = cmcp_params.get("workflow_id")
        workflow_id: str | None = raw_workflow if isinstance(raw_workflow, str) else None
        # #565: validated session-independent execution identity, supplied beside
        # workflow_id and independent of it. Only an omitted ID is absent.
        # Map present non-strings to an invalid empty ID so the proxy uses its
        # audited refusal path instead of silently bypassing correlation.
        raw_execution = cmcp_params.get("execution_id")
        execution_id: str | None = (
            raw_execution if isinstance(raw_execution, str)
            else "" if "execution_id" in cmcp_params else None
        )
        # #479 piece 2: the caller may declare a class for this specific call.
        raw_data_class = cmcp_params.get("data_class")
        declared_data_class: str | None = (
            raw_data_class if isinstance(raw_data_class, str) else None
        )

        try:
            result = await self._proxy.call_tool(
                call_id,
                tool_name,
                arguments,
                workflow_id=workflow_id,
                declared_data_class=declared_data_class,
                execution_id=execution_id,
            )
        except KillSwitchTripped as exc:
            receipt = None
            if (
                self._session_manager is not None
                and self._session is not None
                and exc.detail is not None
            ):
                receipt = self._session_manager.refusal_receipt(
                    exc.detail, self._session.session_id
                )
            logger.warning(
                "KILL_SWITCH_REFUSED: agent_id=%s tool=%s session=%s",
                exc.detail,
                tool_name,
                self._session.session_id if self._session is not None else None,
            )
            return _kill_switch_response(rpc_id, exc.detail, receipt)
        except Exception as exc:
            logger.error("TEE_FAULT during call_tool: call_id=%s error=%s", call_id, exc)
            await self._observe_for_kill_switch(call_id)
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

        await self._observe_for_kill_switch(call_id)
        if not result.allowed:
            return self._deny_response(rpc_id, call_id, result)

        cmcp_meta: dict[str, Any] = {
            "call_id": call_id,
            "audit_entry_hash": result.audit_entry_hash,
            "would_have_denied": result.would_have_denied,
            "latency_us": result.latency_us,
        }
        if self._session is not None:
            cmcp_meta["session_id"] = self._session.session_id
        if result.would_have_denied and result.advice:
            cmcp_meta["advice"] = result.advice
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

    async def _observe_for_kill_switch(self, call_id: str) -> None:
        """Count a completed call toward the kill switch, and stop the session at a trip."""
        if (
            self._session_manager is None
            or self._session is None
            or self._audit_chain is None
        ):
            return
        session = self._session
        if not self._session_manager.observe_call(session, self._audit_chain, call_id):
            return
        blocked = self._session_manager.blocked_identity()
        if blocked is not None:
            # Refuse new calls from this moment, before the close begins.
            self._proxy.mark_halted(blocked)
        await self._seal_after_trip(session.session_id)

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

        checks["runtime_controls"] = "ok"

        # A gateway the kill switch has stopped is running but serves nothing.
        halted = self._proxy.halted_identity
        if halted is None:
            checks["kill_switch"] = "ok"
        else:
            checks["kill_switch"] = f"failed: agent identity {halted} is blocked"
            not_ready = True

        status = "not_ready" if not_ready else "ready"
        return JSONResponse({"status": status, "checks": checks}, status_code=503 if not_ready else 200)

    async def _get_trace_claim(self, request: Request) -> Response:
        """GET /sessions/{session_id}/trace-claim - returns signed TRACE Claim for a closed session."""
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
        """GET /audit/export?session_id=<id> - returns signed audit bundle."""
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
        # Closed sessions keep their chain available for export after rotation.
        chain = self._closed_chains.get(session_id, self._audit_chain)
        try:
            bundle = self._session_manager.get_audit_bundle(session_id, chain)
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

    async def _session_close(self, request: Request) -> Response:
        """POST /sessions/{session_id}/close - close the session, return its signed TRACE Claim.

        Appends the session_end audit entry, signs the claim, then rotates the
        gateway onto a fresh session so subsequent tool calls keep working.
        The closed session's claim stays available at
        GET /sessions/{session_id}/trace-claim and its audit bundle at
        GET /audit/export?session_id=<id>.
        """
        if (
            self._session_manager is None
            or self._session is None
            or self._audit_chain is None
        ):
            return JSONResponse(
                {"error": "session management not available"}, status_code=501
            )
        session_id: str = request.path_params["session_id"]
        halted = self._proxy.halted_identity
        # Once the trip has closed the session there is nothing left to close.
        # A halted gateway whose session is still open (blocked at start, or a
        # seal that failed) can still have it closed and its claim signed.
        if halted is not None and self._session.session_id in self._closed_chains:
            return _kill_switch_conflict(halted)
        if session_id != self._session.session_id:
            return JSONResponse(
                {
                    "error": "session_not_found",
                    "message": (
                        f"No open session with id '{session_id}'. It may already be "
                        "closed, or you passed the _cmcp.session_id label instead of "
                        "the internal session id. Look up the internal id via "
                        "GET /audit/export?session_id=<label>."
                    ),
                },
                status_code=404,
            )

        async with self._proxy.session_rotation(
            expected_session_id=session_id, drain_timeout=self._session_close_drain_s
        ) as acquired:
            if not acquired:
                return JSONResponse(
                    {
                        "error": "session_not_found",
                        "message": (
                            f"No open session with id '{session_id}'. It may already be "
                            "closed, or you passed the _cmcp.session_id label instead of "
                            "the internal session id. Look up the internal id via "
                            "GET /audit/export?session_id=<label>."
                        ),
                    },
                    status_code=404,
                )

            claim = await self._commit_close(session_id)
        logger.info(
            "Session closed via API: closed=%s now=%s", session_id, self._session.session_id
        )
        return JSONResponse(claim)

    async def _commit_close(self, session_id: str) -> dict[str, Any]:
        """Sign the session's claim, then rotate onto a successor or halt.

        The caller holds ``session_rotation`` for ``session_id``. A close can
        trip the kill switch, and a close can be how a trip is carried out. In
        both cases the blocked identity gets no successor: the claim is still
        returned, and the gateway serves no calls until an operator lifts the
        block.
        """
        assert self._session_manager is not None
        assert self._session is not None and self._audit_chain is not None
        pending = self._pending_close
        new_session: SessionState | None
        new_chain: AuditChain | None
        if pending is not None and pending[0] != session_id:
            raise RuntimeError(
                f"close of {session_id} reached commit while {pending[0]} is "
                "still awaiting recovery"
            )
        if pending is None:
            try:
                claim = self._session_manager.close_session(
                    session_id,
                    self._session,
                    self._audit_chain,
                    call_log=getattr(self._proxy, "_call_log", None),
                    session_call_log=getattr(self._proxy, "_session_call_log", None),
                )
            finally:
                if self._session_manager.is_closing(session_id):
                    self._proxy.mark_close_committed()
            self._closed_chains[session_id] = self._audit_chain
            if self._session_manager.blocked_identity() is None:
                new_session, new_chain = self._session_manager.create_session()
                self._pending_close = (session_id, claim, new_session, new_chain)
            else:
                new_session, new_chain = None, None
                self._pending_close = (session_id, claim, None, None)
        else:
            _, claim, new_session, new_chain = pending

        if new_session is None or new_chain is None:
            blocked = self._session_manager.blocked_identity() or "unknown"
            await self._proxy.halt_session(blocked)
            self._pending_close = None
            logger.warning(
                "KILL_SWITCH_HALTED: session=%s closed with no successor; "
                "agent_id=%s is blocked until an operator unblocks it",
                session_id,
                blocked,
            )
            return claim

        # Cleanup/rebind must succeed before server pointers advance.
        await self._proxy.rebind_session(new_session, new_chain)
        self._pending_close = None
        self._session = new_session
        self._audit_chain = new_chain
        self._audit = new_chain
        return claim

    async def _seal_after_trip(self, session_id: str) -> None:
        """Close the session the kill switch just tripped in, now rather than at client close.

        Admission is already refused (the caller marked the proxy halted), so
        the only calls the close waits for are ones admitted before the trip;
        they finish or are cancelled at the drain deadline. A failure here is
        logged and leaves admission refused: the session can still be closed
        with POST /sessions/{id}/close, which is how the operator recovers it.
        """
        try:
            async with self._proxy.session_rotation(
                expected_session_id=session_id, drain_timeout=self._session_close_drain_s
            ) as acquired:
                if acquired:
                    await self._commit_close(session_id)
        except Exception as exc:
            logger.error(
                "KILL_SWITCH_SEAL_FAILED: session=%s error=%s; admission stays refused "
                "and the session can be closed via POST /sessions/%s/close",
                session_id,
                exc,
                session_id,
            )

    async def _catalog_exception(self, request: Request) -> Response:
        """POST /catalog/exception - add a break-glass catalog exception at runtime.

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

    async def _kill_switch_trip(self, request: Request) -> Response:
        """POST /kill-switch/trip - operator-only: stop the bound agent identity now.

        Body: {"reason": str, "authorized_by": str}. Blocks the identity in the
        durable store, records the trip in the live session's audit chain, then
        closes that session and returns its signed claim. From the moment the
        trip starts no new call is admitted; calls already running finish or
        are cancelled at the close drain deadline. The block lasts until
        POST /kill-switch/unblock.
        """
        if (
            self._session_manager is None
            or self._audit_chain is None
            or self._session is None
        ):
            return JSONResponse(
                {"error": "session management not configured"}, status_code=501
            )
        if not self._session_manager.kill_switch_enabled:
            return JSONResponse(
                {
                    "error": "the kill switch is not enabled on this gateway",
                    "error_code": "KILL_SWITCH_DISABLED",
                },
                status_code=409,
            )
        try:
            data = json.loads(await request.body())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JSONResponse(
                {"error": "invalid JSON body", "error_code": "PARSE_ERROR"},
                status_code=400,
            )
        if not isinstance(data, dict):
            return JSONResponse(
                {"error": "body must be a JSON object", "error_code": "PARSE_ERROR"},
                status_code=400,
            )
        fields: dict[str, str] = {}
        for name in ("reason", "authorized_by"):
            value = data.get(name)
            if not isinstance(value, str) or not value:
                return JSONResponse(
                    {"error": f"'{name}' is required", "error_code": "MISSING_FIELD"},
                    status_code=422,
                )
            fields[name] = value
        halted = self._proxy.halted_identity
        if halted is not None and self._session.session_id in self._closed_chains:
            return _kill_switch_conflict(halted)

        credential = (
            "operator_token" if self._operator_token is not None else "bearer_token"
        )
        session_id = self._session.session_id
        async with self._proxy.session_rotation(
            expected_session_id=session_id, drain_timeout=self._session_close_drain_s
        ) as acquired:
            if not acquired:
                return JSONResponse({"error": "session rotated, retry"}, status_code=409)
            agent_id = self._session_manager.trip_identity(
                self._session,
                self._audit_chain,
                reason=fields["reason"],
                authorized_by=fields["authorized_by"],
                credential=credential,
            )
            if agent_id is None:
                return JSONResponse(
                    {
                        "error": "no agent identity is bound to this gateway",
                        "error_code": "NO_AGENT_IDENTITY",
                    },
                    status_code=409,
                )
            claim = await self._commit_close(session_id)

        logger.warning(
            "KILL_SWITCH_OPERATOR_TRIP: agent_id=%s authorized_by=%r reason=%r session=%s",
            agent_id,
            fields["authorized_by"],
            fields["reason"],
            session_id,
        )
        return JSONResponse({"status": "tripped", "agent_id": agent_id, "claim": claim})

    async def _kill_switch_unblock(self, request: Request) -> Response:
        """POST /kill-switch/unblock - operator-only: lift a kill switch block.

        Body: {"agent_id": str, "reason": str, "authorized_by": str}. The block
        is removed from the durable store first. When the gateway was stopped
        by it, the gateway then resumes: on a fresh session when the stopped
        session was closed by the trip, or on its startup session when the
        block was already in force at start. The unblock is recorded in the
        audit chain of the session that resumes service, with the credential
        that authorised it.
        """
        if self._session_manager is None or self._audit_chain is None:
            return JSONResponse(
                {"error": "session management not configured"}, status_code=501
            )
        try:
            data = json.loads(await request.body())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JSONResponse(
                {"error": "invalid JSON body", "error_code": "PARSE_ERROR"},
                status_code=400,
            )
        if not isinstance(data, dict):
            return JSONResponse(
                {"error": "body must be a JSON object", "error_code": "PARSE_ERROR"},
                status_code=400,
            )
        fields: dict[str, str] = {}
        for name in ("agent_id", "reason", "authorized_by"):
            value = data.get(name)
            if not isinstance(value, str) or not value:
                return JSONResponse(
                    {"error": f"'{name}' is required", "error_code": "MISSING_FIELD"},
                    status_code=422,
                )
            fields[name] = value
        agent_id = fields["agent_id"]

        async with self._proxy.session_rotation(
            drain_timeout=self._session_close_drain_s
        ) as acquired:
            if not acquired:  # pragma: no cover - only a stale session id yields False
                return JSONResponse({"error": "gateway busy"}, status_code=409)
            was_blocked = self._session_manager.unblock_identity(agent_id)
            # A retry after the block was lifted but the resume failed must
            # still be able to resume, or the gateway stays stopped for good.
            if not was_blocked and self._proxy.halted_identity != agent_id:
                return JSONResponse(
                    {
                        "error": f"agent identity {agent_id!r} is not blocked",
                        "error_code": "NOT_BLOCKED",
                    },
                    status_code=404,
                )
            credential = (
                "operator_token" if self._operator_token is not None else "bearer_token"
            )
            detail: dict[str, str | int | float] = {
                "reason": "kill_switch_unblocked",
                "agent_id": agent_id,
                "operator_reason": fields["reason"],
                "authorized_by": fields["authorized_by"],
                "credential_verified": credential,
            }
            halted = self._proxy.halted_identity
            still_blocked = self._session_manager.blocked_identity()
            current_id = self._session.session_id if self._session is not None else ""
            if halted is not None and still_blocked is None:
                if current_id in self._closed_chains:
                    new_session, new_chain = self._session_manager.create_session()
                    await self._proxy.resume_session(new_session, new_chain)
                    self._session = new_session
                    self._audit_chain = new_chain
                    self._audit = new_chain
                    current_id = new_session.session_id
                else:
                    self._proxy.lift_halt()
            self._audit_chain.append("break_glass_used", detail=detail)

        logger.warning(
            "KILL_SWITCH_UNBLOCKED: agent_id=%s authorized_by=%r reason=%r session=%s",
            agent_id,
            fields["authorized_by"],
            fields["reason"],
            current_id,
        )
        return JSONResponse(
            {
                "status": "unblocked",
                "agent_id": agent_id,
                "session_id": current_id,
                "gateway_halted": self._proxy.halted_identity is not None,
            }
        )

    async def _session_reset(self, request: Request) -> Response:
        """POST /sessions/{session_id}/reset - operator-only session sensitivity reset."""
        if self._session is None or self._audit_chain is None:
            return JSONResponse(
                {"error": "session management not configured"}, status_code=501
            )
        session_id: str = request.path_params["session_id"]
        halted = self._proxy.halted_identity
        if halted is not None:
            return _kill_switch_conflict(halted)
        if session_id != self._session.session_id:
            return JSONResponse(
                {"error": f"session_id={session_id} not found"}, status_code=404
            )
        async with self._proxy.exclude_session_transition(
            expected_session_id=session_id,
            drain_timeout=self._session_close_drain_s,
        ) as acquired:
            if not acquired:
                return JSONResponse(
                    {"error": f"session_id={session_id} not found"}, status_code=404
                )
            # Re-read after acquiring: a close may have rotated the session
            # while this request waited its turn. The proxy checks its session
            # before draining so a stale reset cannot cancel successor calls.
            if session_id != self._session.session_id:
                return JSONResponse(
                    {"error": f"session_id={session_id} not found"}, status_code=404
                )
            # #625: reset ends this session and opens a successor, so the
            # session-scoped child, clients, and caches must not outlive it.
            # Released before the reset is recorded, so a failed cleanup leaves
            # the session as it was and the whole request retryable.
            await self._proxy.aclose()
            credential = (
                "operator_token" if self._operator_token is not None else "bearer_token"
            )
            old_id, new_id, closed = await self._session.apply_reset(
                reason="operator reset via API",
                authorized_by=credential,
            )
            sensitivity_before = closed.max_sensitivity
            reset_count = self._session.reset_count
            self._closed_sessions[closed.session_id] = closed
            self._audit_chain.append(
                "session_reset",
                call_id=None,
                tool_name=None,
                policy_decision="n/a",
                session_sensitivity_before=sensitivity_before,
                session_sensitivity_after=self._session.max_sensitivity,
                detail={
                    "closed_session_id": old_id,
                    "successor_session_id": new_id,
                    "reset_count": reset_count,
                    "credential_verified": credential,
                    "reason": "operator reset via API",
                },
            )
            # Entries after the boundary belong to the successor.
            self._audit_chain.rotate_session_id(new_id)
        return JSONResponse({
            "old_session_id": old_id,
            "new_session_id": new_id,
            "closed_session_max_sensitivity": closed.max_sensitivity,
            "reset_count": reset_count,
            "status": "reset",
            "attestation_stale": False,
        })
