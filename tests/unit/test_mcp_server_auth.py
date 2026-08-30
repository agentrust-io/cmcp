"""Tests for MCP server bearer-token authentication (AUTH-001)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from cmcp_runtime.mcp.server import (
    _MAX_ARG_DEPTH,
    _MAX_ARG_KEYS,
    _MAX_ARG_STRING_LENGTH,
    MCPServer,
)


def _make_server(bearer_token: str | None = None) -> MCPServer:
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {}
    proxy.call_tool = AsyncMock(return_value=MagicMock(
        allowed=True, deny_reason=None, response="ok",
        audit_entry_hash="sha256:" + "0" * 64,
        would_have_denied=False, latency_us=100,
    ))
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
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
    """DOS-001 - request body exceeding max_request_bytes is rejected before parsing."""
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
        proxy = MagicMock()
        proxy._catalog = MagicMock()
        proxy._catalog.entries = {}
        server = MCPServer(proxy, max_request_bytes=16)
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/mcp", content=b"x" * 17, headers={"Content-Type": "application/json"})
    assert resp.status_code == 413


def test_content_length_check_rejects_before_body_read():
    """DOS-001 - Content-Length check rejects before reading body."""
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
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


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "valid JSON but not an object",
        1,
        {"jsonrpc": "2.0", "method": [], "id": 1},
        {"jsonrpc": "2.0", "method": "tools/call", "params": [], "id": 1},
    ],
)
def test_structurally_invalid_json_rpc_returns_bounded_400(payload):
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)

    response = client.post("/mcp", json=payload)

    assert response.status_code == 400
    assert response.json() == {
        "jsonrpc": "2.0",
        "error": {
            "code": -32600,
            "message": "Invalid Request",
            "data": {"error_code": "MCP_INVALID_REQUEST"},
        },
        "id": payload.get("id") if isinstance(payload, dict) else None,
    }


# ── NET-002: /health rate limit ───────────────────────────────────────────────

def _make_server_with_low_rate_limit(
    requests_per_minute: int = 3, max_clients: int = 10_000
) -> MCPServer:
    """Create a server with a very low rate limit for testing."""
    from starlette.middleware import Middleware

    from cmcp_runtime.mcp.server import _RateLimitMiddleware

    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {}
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
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
                max_clients=max_clients,
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

    from cmcp_runtime.mcp.server import _RateLimitMiddleware

    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {}
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
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


def test_rate_limit_caps_tracked_client_addresses():
    server = _make_server_with_low_rate_limit(max_clients=2)

    with TestClient(server.app, client=("192.0.2.1", 1001)) as first_client:
        assert first_client.get("/health").status_code == 200
    with TestClient(server.app, client=("192.0.2.2", 1002)) as second_client:
        assert second_client.get("/health").status_code == 200
    with TestClient(server.app, client=("192.0.2.3", 1003)) as third_client:
        response = third_client.get("/health")

    assert response.status_code == 429
    assert response.json()["error_code"] == "RATE_LIMITED"


def test_rate_limit_reclaims_inactive_client_addresses():
    from cmcp_runtime.mcp.server import _RateLimitMiddleware

    limiter = _RateLimitMiddleware(MagicMock(), paths=frozenset({"/health"}), max_clients=1)
    limiter._counts["192.0.2.1"] = [100.0]

    limiter._prune_inactive_clients(cutoff=100.0)

    assert "192.0.2.1" not in limiter._counts


# ── CONF-007: /readyz structured readiness probe ────────────────────────────────────


def _make_ready_server() -> MCPServer:
    """Server where all readiness checks pass."""
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {"test.tool": MagicMock()}
    proxy._policy = MagicMock()  # policy present
    proxy._check_health.return_value = None  # attestation healthy
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
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
    assert body["checks"]["runtime_controls"] == "ok"


def test_readyz_returns_503_when_policy_missing():
    """CONF-007: missing Cedar policy engine returns 503 and not_ready."""
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {"test.tool": MagicMock()}
    proxy._policy = None  # Cedar policy engine absent
    proxy._check_health.return_value = None
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
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
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
        server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["attestation"] == "failed: attestation_stale"


def test_readyz_does_not_depend_on_agent_os():
    """CONF-007: runtime readiness is independent of optional AGT tooling."""
    server = _make_ready_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json()["checks"]["runtime_controls"] == "ok"


def test_readyz_accessible_without_bearer_token():
    """CONF-007: /readyz must not require authentication (Kubernetes probe)."""
    server = _make_ready_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    # No Authorization header -- should still return 200
    resp = client.get("/readyz")
    assert resp.status_code == 200

# ── INJECT-002: sanitize method in error responses ────────────────────────────

def test_unknown_method_non_ascii_is_replaced():
    """INJECT-002 - non-ASCII bytes in method are replaced so they cannot corrupt logs."""
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
    """INJECT-002 - method longer than 64 chars is truncated."""
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
    """NET-004 - truly unhandled exception must not leak class or message to caller.

    Uses /tools/list which has no try/except - an exception from catalog.entries.items()
    propagates out of the handler and must be caught by the global exception handler.
    """
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries.items.side_effect = RuntimeError("secret internal detail")
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
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
    """POLICY-002 - tool name from MCP request must be lowercased before catalog lookup."""
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
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
        server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=False)
    client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "UPPER_TOOL", "arguments": {}}, "id": 1},
    )
    assert received_names == ["upper_tool"]


# tools/call: non-string `name` / non-object `arguments` must not 500
#
# `params.get("name", "").lower()` assumed `name`, when present, is a string:
# the "" default only covers an *absent* name. `params.get("arguments", {})`
# had the identical gap for `arguments`. Both are exactly as caller-controlled
# as `_cmcp` (guarded a few lines below with "A malformed _cmcp (string, list,
# number) must not 500 the call path") -- neither was guarded the same way,
# so a non-string name 500'd the request instead of returning the JSON-RPC
# Invalid Request the malformed input actually is, and a non-object
# `arguments` (an int, for instance) silently passed `_arg_shape_violation`
# (which only recognizes dict/list/str) and reached call_tool unvalidated.


@pytest.mark.parametrize("bad_name", [12345, ["a", "list"], {"nested": "object"}, True, None])
def test_non_string_name_returns_invalid_params_not_500(bad_name):
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": bad_name, "arguments": {}}, "id": 1},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"]["code"] == -32602
    assert "name" in body["error"]["message"]


@pytest.mark.parametrize("bad_arguments", [42, 3.14, "a string", ["a", "list"], True])
def test_non_object_arguments_returns_invalid_params_not_silently_accepted(bad_arguments):
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "safe_tool", "arguments": bad_arguments}, "id": 1},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"]["code"] == -32602
    assert "arguments" in body["error"]["message"]
    proxy = server._proxy
    proxy.call_tool.assert_not_called()


def test_deny_response_does_not_include_internal_reason():
    """INJECT-003 - internal deny_reason must not appear in 403 response body."""
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {}
    proxy.call_tool = AsyncMock(return_value=MagicMock(
        allowed=False,
        deny_reason="Cedar eval error: AttributeAccessError on principal.secret_field",
        audit_entry_hash=None,
        would_have_denied=False,
        latency_us=0,
        advice=None,
    ))
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
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


def test_upstream_error_deny_reason_returns_502():
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {}
    proxy.call_tool = AsyncMock(return_value=MagicMock(
        allowed=False,
        deny_reason="upstream_error:CONNECTION_REFUSED",
        audit_entry_hash=None,
        would_have_denied=False,
        latency_us=0,
        advice=None,
    ))
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
        server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "t", "arguments": {}}, "id": 1},
    )
    assert resp.status_code == 502
    body = resp.json()
    assert body["error"]["message"] == "Upstream MCP server error"
    assert body["error"]["data"]["error_code"] == "CONNECTION_REFUSED"


@pytest.mark.parametrize("reason", ["attestation_stale", "catalog_drift"])
def test_health_deny_reason_returns_503(reason):
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {}
    proxy.call_tool = AsyncMock(return_value=MagicMock(
        allowed=False,
        deny_reason=reason,
        audit_entry_hash=None,
        would_have_denied=False,
        latency_us=0,
        advice=None,
    ))
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
        server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "t", "arguments": {}}, "id": 1},
    )
    assert resp.status_code == 503
    body = resp.json()
    assert body["error"]["message"] == reason
    assert body["error"]["data"]["error_code"] == reason.upper()


def test_deny_response_includes_advice_when_present():
    """Advice annotations come from the operator-authored policy bundle, so
    reflecting them (unlike deny_reason) does not violate INJECT-003."""
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    proxy._catalog.entries = {}
    proxy.call_tool = AsyncMock(return_value=MagicMock(
        allowed=False,
        deny_reason="policy denied",
        audit_entry_hash=None,
        would_have_denied=False,
        latency_us=0,
        advice={"escalation": "HITL"},
    ))
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
        server = MCPServer(proxy)
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "t", "arguments": {}}, "id": 1},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["data"]["advice"] == {"escalation": "HITL"}


# ── #518: strict jsonrpc/id validation, matching scripts/mock_upstream.py ────

def test_missing_jsonrpc_field_returns_invalid_request():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/mcp", json={"method": "initialize", "id": 1})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32600


def test_wrong_jsonrpc_version_returns_invalid_request():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/mcp", json={"jsonrpc": "1.0", "method": "initialize", "id": 1})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32600


def test_jsonrpc_version_as_number_is_rejected():
    """jsonrpc must equal the string "2.0" exactly, not the numeric value 2.0."""
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/mcp", json={"jsonrpc": 2.0, "method": "initialize", "id": 1})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32600


def test_bool_id_returns_invalid_request():
    """id must be a string, number, or null -- bool is an int subclass but not valid."""
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "method": "initialize", "id": True})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32600


def test_object_id_returns_invalid_request():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "method": "initialize", "id": {}})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32600


def test_null_id_is_valid_notification():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "method": "initialize", "id": None})
    assert resp.status_code == 200


def test_string_id_is_valid():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "method": "initialize", "id": "req-1"})
    assert resp.status_code == 200
    assert resp.json()["id"] == "req-1"


# ── #518: argument depth/key-count caps, matching scripts/mock_upstream.py ──

def _nested(depth: int) -> Any:
    value: Any = "leaf"
    for _ in range(depth):
        value = {"a": value}
    return value


def test_arguments_within_depth_cap_is_allowed():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "t", "arguments": {"nested": _nested(_MAX_ARG_DEPTH - 1)}},
            "id": 1,
        },
    )
    assert resp.status_code == 200


def test_arguments_exceeding_depth_cap_returns_invalid_params():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "t", "arguments": {"nested": _nested(_MAX_ARG_DEPTH + 10)}},
            "id": 1,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32602


def test_depth_cap_violation_inside_a_list_is_caught():
    """The depth walk recurses into list items, not only dict values."""
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "t", "arguments": {"items": [_nested(_MAX_ARG_DEPTH + 10)]}},
            "id": 1,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32602


def test_well_formed_list_in_arguments_is_accepted():
    """The list walk must fall through cleanly when nothing inside it violates a
    cap. Without this the only list coverage is the rejection path, which would
    still pass if the walk rejected every list it saw."""
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "t",
                "arguments": {"items": [1, "ok", {"nested": ["fine"]}, None]},
            },
            "id": 1,
        },
    )
    assert resp.status_code != 400


def test_arguments_within_key_cap_is_allowed():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    arguments = {f"k{i}": i for i in range(_MAX_ARG_KEYS)}
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "t", "arguments": arguments},
            "id": 1,
        },
    )
    assert resp.status_code == 200


def test_arguments_exceeding_key_cap_returns_invalid_params():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    arguments = {f"k{i}": i for i in range(_MAX_ARG_KEYS + 1)}
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "t", "arguments": arguments},
            "id": 1,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32602


# ── #562: argument string-length cap, matching scripts/mock_upstream.py ─────

def test_string_within_length_cap_is_allowed():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "t", "arguments": {"text": "a" * 1000}},
            "id": 1,
        },
    )
    assert resp.status_code == 200


def test_string_exceeding_length_cap_returns_invalid_params():
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "t", "arguments": {"text": "a" * (_MAX_ARG_STRING_LENGTH + 1)}},
            "id": 1,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32602


def test_oversized_object_key_returns_invalid_params():
    """A huge key is as expensive as a huge value and is not bounded by the
    key *count* cap, so it must be rejected on its own."""
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    key = "a" * (_MAX_ARG_STRING_LENGTH + 1)
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "t", "arguments": {key: 1}},
            "id": 1,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32602


def test_multibyte_string_length_measured_in_bytes_not_characters():
    """A 4-byte-per-char string well under the byte cap in character count
    but over it in UTF-8 bytes must still be rejected."""
    # U+1F600 (😀) is 4 bytes in UTF-8, 1 codepoint in Python's len(). Choose
    # a character count that clears the string cap in bytes while staying
    # well under the server's default max_request_bytes once JSON-encoded.
    char_count = (_MAX_ARG_STRING_LENGTH // 4) + 1
    oversized_by_bytes = "\U0001F600" * char_count
    assert len(oversized_by_bytes.encode("utf-8")) > _MAX_ARG_STRING_LENGTH
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    # Built and encoded by hand with ensure_ascii=False, rather than passed
    # via the json= kwarg: both json.dumps' default and httpx's json=
    # encoder escape each emoji to a 12-byte \uXXXX\uXXXX surrogate pair,
    # inflating the wire size far past the string's actual UTF-8 length and
    # tripping max_request_bytes instead of the check this test targets.
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "t", "arguments": {"text": oversized_by_bytes}},
            "id": 1,
        },
        ensure_ascii=False,
    ).encode("utf-8")
    assert len(body) < 1_000_000
    resp = client.post(
        "/mcp", content=body, headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32602


# ── #518: non-standard JSON values (NaN, Infinity, -Infinity) ───────────────

@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_non_standard_json_constant_returns_parse_error(literal):
    server = _make_server()
    client = TestClient(server.app, raise_server_exceptions=False)
    body = (
        '{"jsonrpc": "2.0", "method": "tools/call", '
        f'"params": {{"name": "t", "arguments": {{"x": {literal}}}}}, "id": 1}}'
    )
    resp = client.post(
        "/mcp", content=body.encode(), headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32700
