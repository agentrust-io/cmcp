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
