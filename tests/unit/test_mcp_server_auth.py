"""Tests for MCP server bearer-token authentication (AUTH-001)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient

from cmcp_gateway.mcp.server import MCPServer


def _make_server(bearer_token: str | None = None) -> MCPServer:
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {}
    proxy.call_tool = AsyncMock(return_value=MagicMock(
        allowed=True, deny_reason=None, response="ok",
        audit_entry_hash="sha256:" + "0" * 64,
        would_have_denied=False, latency_us=100,
    ))
    with patch("cmcp_gateway.mcp.server.StatelessKernel"):
        return MCPServer(proxy, bearer_token=bearer_token)


# ── No auth configured (dev mode) ────────────────────────────────────────────

def test_no_auth_allows_any_request():
    server = _make_server(bearer_token=None)
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "method": "initialize", "id": 1})
    assert resp.status_code == 200


def test_health_always_accessible_without_token():
    server = _make_server(bearer_token="secret")
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.get("/health")
    assert resp.status_code == 200


# ── Auth enabled ──────────────────────────────────────────────────────────────

def test_missing_auth_header_returns_401():
    """AUTH-001 (CRITICAL): request without Authorization → 401."""
    server = _make_server(bearer_token="super-secret-token")
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "method": "initialize", "id": 1})
    assert resp.status_code == 401
    body = resp.json()
    assert body["error_code"] == "MISSING_BEARER_TOKEN"


def test_wrong_token_returns_401():
    server = _make_server(bearer_token="correct-token")
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401
    body = resp.json()
    assert body["error_code"] == "INVALID_BEARER_TOKEN"


def test_correct_token_allows_request():
    server = _make_server(bearer_token="correct-token")
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
        headers={"Authorization": "Bearer correct-token"},
    )
    assert resp.status_code == 200


def test_auth_response_includes_www_authenticate_header():
    server = _make_server(bearer_token="secret")
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/mcp", json={})
    assert "WWW-Authenticate" in resp.headers


def test_tools_list_requires_auth():
    server = _make_server(bearer_token="secret")
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.get("/tools/list")
    assert resp.status_code == 401


def test_audit_export_requires_auth():
    server = _make_server(bearer_token="secret")
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.get("/audit/export?session_id=sess-1")
    assert resp.status_code == 401


# ── DOS-001: request body size limit ─────────────────────────────────────────

def test_oversized_body_returns_413():
    """DOS-001 — request body exceeding max_request_bytes is rejected before parsing."""
    with patch("cmcp_gateway.mcp.server.StatelessKernel"):
        proxy = MagicMock()
        proxy._catalog = MagicMock()
        proxy._catalog.entries = {}
        server = MCPServer(proxy, max_request_bytes=16)
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/mcp", content=b"x" * 17, headers={"Content-Type": "application/json"})
    assert resp.status_code == 413


def test_content_length_check_rejects_before_body_read():
    """DOS-001 — Content-Length check rejects before reading body."""
    with patch("cmcp_gateway.mcp.server.StatelessKernel"):
        proxy = MagicMock()
        proxy._catalog = MagicMock()
        proxy._catalog.entries = {}
        server = MCPServer(proxy, max_request_bytes=100)
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        content=b"{}",
        headers={"Content-Type": "application/json", "Content-Length": "9999"},
    )
    assert resp.status_code == 413


# ── NET-002: /health rate limit ───────────────────────────────────────────────

def _make_server_with_low_rate_limit(requests_per_minute: int = 3) -> MCPServer:
    """Create a server with a very low rate limit for testing."""
    from starlette.middleware import Middleware

    from cmcp_gateway.mcp.server import _RateLimitMiddleware

    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {}
    with patch("cmcp_gateway.mcp.server.StatelessKernel"):
        server = MCPServer(proxy, bearer_token=None)

    # Replace rate-limit middleware with a tighter one for this test
    from starlette.applications import Starlette

    server.app = Starlette(
        routes=server.app.routes,
        middleware=[
            Middleware(
                _RateLimitMiddleware,
                paths=frozenset({"/health"}),
                requests_per_minute=requests_per_minute,
            )
        ],
        exception_handlers={},
    )
    return server


def test_health_allows_requests_within_limit():
    """NET-002: requests within rate limit return 200."""
    server = _make_server_with_low_rate_limit(requests_per_minute=5)
    client = TestClient(server.app, raise_server_exceptions=False)
    for _ in range(3):
        resp = client.get("/health")
        assert resp.status_code == 200


def test_health_rate_limit_returns_429_when_exceeded():
    """NET-002: exceeding rate limit returns 429 with Retry-After header."""
    server = _make_server_with_low_rate_limit(requests_per_minute=2)
    client = TestClient(server.app, raise_server_exceptions=False)

    # First two should pass
    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 200
    # Third exceeds limit
    resp = client.get("/health")
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
    body = resp.json()
    assert body["error_code"] == "RATE_LIMITED"


def test_rate_limit_middleware_paths_only():
    """NET-002: rate limit applies only to configured paths, not all endpoints."""
    from starlette.applications import Starlette
    from starlette.middleware import Middleware

    from cmcp_gateway.mcp.server import _RateLimitMiddleware

    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {}
    with patch("cmcp_gateway.mcp.server.StatelessKernel"):
        server = MCPServer(proxy, bearer_token=None)

    # Rate-limit ONLY /nonexistent (so /health is unaffected)
    server.app = Starlette(
        routes=server.app.routes,
        middleware=[
            Middleware(
                _RateLimitMiddleware,
                paths=frozenset({"/nonexistent"}),
                requests_per_minute=1,
            )
        ],
        exception_handlers={},
    )
    client = TestClient(server.app, raise_server_exceptions=False)
    for _ in range(5):
        resp = client.get("/health")
        assert resp.status_code == 200


# ── CONF-007: /readyz structured readiness probe ────────────────────────────────────


def _make_ready_server() -> MCPServer:
    """Server where all readiness checks pass."""
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {"test.tool": MagicMock()}
    proxy._policy = MagicMock()  # policy present
    proxy._check_health.return_value = None  # attestation healthy
    with patch("cmcp_gateway.mcp.server.StatelessKernel"):
        return MCPServer(proxy, bearer_token="secret")


def test_readyz_returns_200_when_healthy():
    """CONF-007: /readyz returns 200 when all components are operational."""
    server = _make_ready_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["policy"] == "ok"
    assert body["checks"]["attestation"] == "ok"
    assert body["checks"]["agt"] == "ok"


def test_readyz_returns_503_when_policy_missing():
    """CONF-007: missing Cedar policy engine returns 503 and not_ready."""
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {"test.tool": MagicMock()}
    proxy._policy = None  # Cedar policy engine absent
    proxy._check_health.return_value = None
    with patch("cmcp_gateway.mcp.server.StatelessKernel"):
        server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["policy"].startswith("failed:")


def test_readyz_returns_503_when_attestation_stale():
    """CONF-007: stale attestation returns 503 and not_ready."""
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {"test.tool": MagicMock()}
    proxy._policy = MagicMock()
    proxy._check_health.return_value = "attestation_stale"
    with patch("cmcp_gateway.mcp.server.StatelessKernel"):
        server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["attestation"] == "failed: attestation_stale"


def test_readyz_returns_503_when_agt_unavailable():
    """CONF-007: unavailable agent_os returns 503 and not_ready."""
    import sys
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {"test.tool": MagicMock()}
    proxy._policy = MagicMock()
    proxy._check_health.return_value = None
    with patch("cmcp_gateway.mcp.server.StatelessKernel"):
        server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=False)
    # Setting sys.modules["agent_os"] = None causes ImportError on "import agent_os"
    saved = sys.modules.get("agent_os", object())
    sys.modules["agent_os"] = None  # type: ignore[assignment]
    try:
        resp = client.get("/readyz")
    finally:
        if saved is object():
            sys.modules.pop("agent_os", None)
        else:
            sys.modules["agent_os"] = saved
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["agt"].startswith("failed:")


def test_readyz_accessible_without_bearer_token():
    """CONF-007: /readyz must not require authentication (Kubernetes probe)."""
    server = _make_ready_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    # No Authorization header -- should still return 200
    resp = client.get("/readyz")
    assert resp.status_code == 200

# ── INJECT-002: sanitize method in error responses ────────────────────────────

def test_unknown_method_non_ascii_is_replaced():
    """INJECT-002 — non-ASCII bytes in method are replaced so they cannot corrupt logs."""
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "tools/call😀emoji-injection", "id": 1},
    )
    assert resp.status_code == 404
    msg = resp.json()["error"]["message"]
    assert msg.isascii()


def test_unknown_method_truncated_at_64_chars():
    """INJECT-002 — method longer than 64 chars is truncated."""
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    long_method = "a" * 200
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": long_method, "id": 1},
    )
    assert resp.status_code == 404
    msg = resp.json()["error"]["message"]
    assert len(msg) <= len("Method not found: ") + 64


# ── INJECT-003: deny_reason not reflected to caller ──────────────────────────

# ── NET-004: unhandled exceptions return generic 500 ─────────────────────────

def test_unhandled_exception_returns_generic_500():
    """NET-004 — truly unhandled exception must not leak class or message to caller.

    Uses /tools/list which has no try/except — an exception from catalog.entries.items()
    propagates out of the handler and must be caught by the global exception handler.
    """
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries.items.side_effect = RuntimeError("secret internal detail")
    with patch("cmcp_gateway.mcp.server.StatelessKernel"):
        server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.get("/tools/list")
    assert resp.status_code == 500
    body = resp.json()
    assert "secret internal detail" not in str(body)
    assert "RuntimeError" not in str(body)
    assert body.get("error_code") == "INTERNAL_ERROR"


# ── POLICY-002: ingress tool name canonicalized to lowercase ─────────────────

def test_tool_name_is_lowercased_at_ingress():
    """POLICY-002 — tool name from MCP request must be lowercased before catalog lookup."""
    received_names: list[str] = []

    async def _capture(call_id, tool_name, arguments, **kwargs):
        received_names.append(tool_name)
        return MagicMock(
            allowed=True, deny_reason=None, response="ok",
            audit_entry_hash="sha256:" + "0" * 64,
            would_have_denied=False, latency_us=100,
        )

    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {}
    proxy.call_tool = _capture
    with patch("cmcp_gateway.mcp.server.StatelessKernel"):
        server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=False)
    client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "UPPER_TOOL", "arguments": {}}, "id": 1},
    )
    assert received_names == ["upper_tool"]


def test_deny_response_does_not_include_internal_reason():
    """INJECT-003 — internal deny_reason must not appear in 403 response body."""
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {}
    proxy.call_tool = AsyncMock(return_value=MagicMock(
        allowed=False,
        deny_reason="Cedar eval error: AttributeAccessError on principal.secret_field",
        audit_entry_hash=None,
        would_have_denied=False,
        latency_us=0,
    ))
    with patch("cmcp_gateway.mcp.server.StatelessKernel"):
        server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "t", "arguments": {}}, "id": 1},
    )
    assert resp.status_code == 403
    body = resp.json()
    assert "Cedar eval error" not in str(body)
    assert "AttributeAccessError" not in str(body)
    assert body["error"]["message"] == "Request denied by policy"
