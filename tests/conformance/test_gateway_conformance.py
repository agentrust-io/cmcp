"""
Conformance test suite for the cMCP runtime: 22-case GTC Berlin demo spec.

Uses starlette.testclient.TestClient (synchronous) against an in-process
MCPServer so no asyncio/anyio machinery is needed in test code.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.testclient import TestClient

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.mcp.proxy import CallResult
from cmcp_runtime.mcp.server import MCPServer
from cmcp_runtime.session.state import SessionState

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_catalog_entry(tool_name: str = "mock_tool") -> CatalogEntry:
    return CatalogEntry(
        tool_name=tool_name,
        server=ServerIdentity(
            display_name="Mock Server",
            url="https://mock.example.com/mcp",
            tls_fingerprint="SHA256:MOCK/AAAA==",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description="A mock tool for conformance testing",
            input_schema={"type": "object", "properties": {}},
            output_schema=None,
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="external",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-06-05T00:00:00Z",
        approved_by="conformance-test",
    )


def _make_allowed_result(call_id: str, tool_name: str = "mock_tool") -> CallResult:
    return CallResult(
        call_id=call_id,
        tool_name=tool_name,
        allowed=True,
        would_have_denied=False,
        response="mock response",
        deny_reason=None,
        latency_us=100,
        audit_entry_hash="sha256:" + "a" * 64,
    )


def _make_denied_result(call_id: str, tool_name: str = "mock_tool") -> CallResult:
    return CallResult(
        call_id=call_id,
        tool_name=tool_name,
        allowed=False,
        would_have_denied=False,
        response=None,
        deny_reason="test_deny",
        latency_us=50,
        audit_entry_hash="sha256:" + "b" * 64,
    )


def _make_proxy(*, allowed: bool = True) -> MagicMock:
    """Build a minimal CMCPProxy mock wired with one catalog entry."""
    entry = _make_catalog_entry()
    catalog = ToolCatalog(
        entries={"mock_tool": entry},
        catalog_hash="sha256:" + "c" * 64,
    )
    proxy = MagicMock()
    proxy._catalog = catalog
    # Session transitions release session-scoped resources (#625); the real
    # aclose() is a coroutine, so an auto-specced MagicMock will not do.
    proxy.aclose = AsyncMock()
    proxy.halted_identity = None  # kill switch not holding the gateway

    if allowed:
        # Return allowed for known tools; denied for unknown tools (catalog miss).
        def _call_side_effect(call_id: str, tool_name: str, arguments: dict, **kwargs) -> CallResult:  # type: ignore[type-arg]
            if tool_name in catalog.entries:
                return _make_allowed_result(call_id, tool_name)
            return _make_denied_result(call_id, tool_name)

        proxy.call_tool = AsyncMock(side_effect=_call_side_effect)
    else:
        proxy.call_tool = AsyncMock(
            side_effect=lambda call_id, tool_name, arguments, **kwargs: _make_denied_result(call_id, tool_name)
        )
    return proxy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client() -> TestClient:
    """Minimal MCPServer with a single mock_tool: used by most conformance tests."""
    proxy = _make_proxy(allowed=True)
    server = MCPServer(proxy=proxy)
    return TestClient(server.app)


@pytest.fixture()
def denied_client() -> TestClient:
    """MCPServer whose proxy always returns a denied CallResult."""
    proxy = _make_proxy(allowed=False)
    server = MCPServer(proxy=proxy)
    return TestClient(server.app)


@pytest.fixture()
def session_client() -> tuple[TestClient, SessionState, AuditChain, str]:
    """MCPServer wired with a real SessionState and AuditChain for reset tests."""
    session_id = "sess-conformance-001"
    session = SessionState(session_id=session_id)
    chain = AuditChain(session_id=session_id)
    proxy = _make_proxy(allowed=True)
    server = MCPServer(proxy=proxy, session=session, audit_chain=chain)
    tc = TestClient(server.app)
    return tc, session, chain, session_id


# ---------------------------------------------------------------------------
# Group 1: MCP Protocol conformance (8 tests)
# ---------------------------------------------------------------------------

def test_health_returns_200(client: TestClient) -> None:
    """GET /health returns 200 with {status: ok}."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_mcp_initialize(client: TestClient) -> None:
    """POST /mcp with initialize returns valid MCP init response."""
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "method": "initialize", "id": 1})
    assert resp.status_code == 200
    body = resp.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 1
    result = body["result"]
    assert "protocolVersion" in result
    # `initialize` belongs to the legacy handshake era; the current revision removed it.
    assert result["protocolVersion"] == "2025-11-25"
    assert "capabilities" in result


def test_tools_list_get_endpoint(client: TestClient) -> None:
    """GET /tools/list returns catalog entries in JSON-RPC envelope."""
    resp = client.get("/tools/list")
    assert resp.status_code == 200
    body = resp.json()
    tools = body["result"]["tools"]
    assert isinstance(tools, list)
    assert len(tools) == 1
    assert tools[0]["name"] == "mock_tool"


def test_tools_call_allowed(client: TestClient) -> None:
    """POST /mcp tools/call for known tool returns 200 with result."""
    resp = client.post("/mcp", json={
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 2,
        "params": {"name": "mock_tool", "arguments": {}},
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["jsonrpc"] == "2.0"
    assert "result" in body
    assert "error" not in body


def test_tools_call_unknown_tool_denied(client: TestClient) -> None:
    """POST /mcp tools/call for unknown tool returns error (403 or 200 with error body)."""
    # The proxy mock returns denied for unknown tool because it checks "mock_tool" only.
    # The server checks allowed=False and returns 403.
    resp = client.post("/mcp", json={
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 3,
        "params": {"name": "unknown_tool", "arguments": {}},
    })
    # Either 403 with JSON-RPC error body, or 200 with error field
    body = resp.json()
    assert resp.status_code in (403, 200)
    if resp.status_code == 403:
        assert "error" in body
    else:
        assert "error" in body


def test_mcp_parse_error(client: TestClient) -> None:
    """POST /mcp with invalid JSON returns 400 with JSON-RPC parse error."""
    resp = client.post(
        "/mcp",
        content=b"this is not json{{{",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"]["code"] == -32700
    assert body["error"]["data"]["error_code"] == "MCP_PARSE_FAILURE"


def test_unknown_method_returns_method_not_found(client: TestClient) -> None:
    """POST /mcp with unknown method returns JSON-RPC -32601."""
    resp = client.post("/mcp", json={
        "jsonrpc": "2.0",
        "method": "nonexistent/method",
        "id": 4,
    })
    body = resp.json()
    assert body["error"]["code"] == -32601


# ── Notifications: a message with no id (#D6) ────────────────────────────────

_NOTIFICATIONS = [
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/roots/list_changed",
]


def _post(body: Any) -> tuple[Any, MagicMock]:
    proxy = _make_proxy(allowed=True)
    resp = TestClient(MCPServer(proxy=proxy).app).post("/mcp", json=body)
    return resp, proxy


def _assert_refused(resp: Any, rpc_id: Any = None) -> None:
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32600
    assert resp.json()["id"] == rpc_id


_VALID_PARAMS = [
    ("notifications/initialized", None),
    ("notifications/initialized", {}),
    ("notifications/initialized", {"_meta": {"k": "v"}}),
    ("notifications/roots/list_changed", None),
    ("notifications/roots/list_changed", {"_meta": {}}),
    ("notifications/cancelled", {"requestId": 7}),
    ("notifications/cancelled", {"requestId": "c-1", "reason": "user stopped it"}),
    ("notifications/cancelled", {"requestId": 7, "extra": "kept, as in the schema"}),
    # MCP requires a request id or progress token to be a string or integer.
    ("notifications/cancelled", {"requestId": 1.0}),
    ("notifications/cancelled", {"requestId": 10**400}),
    ("notifications/cancelled", {"requestId": ""}),
    ("notifications/progress", {"progressToken": 10**400, "progress": 0}),
    ("notifications/progress", {"progressToken": "t", "progress": 1}),
    ("notifications/progress", {"progressToken": 3, "progress": 0.5, "total": 2, "message": "half"}),
    ("notifications/progress", {"progressToken": "t", "progress": -1}),  # no minimum in the schema
]

_INVALID_PARAMS = [
    ("notifications/initialized", {"_meta": "x"}),
    ("notifications/initialized", {"_meta": None}),
    ("notifications/cancelled", None),
    ("notifications/cancelled", {}),
    ("notifications/cancelled", {"reason": "no id"}),
    ("notifications/cancelled", {"requestId": True}),
    ("notifications/cancelled", {"requestId": None}),
    ("notifications/cancelled", {"requestId": 1.5}),
    ("notifications/progress", {"progressToken": 2.5, "progress": 0}),
    ("notifications/cancelled", {"requestId": [1]}),
    ("notifications/cancelled", {"requestId": 1, "reason": 5}),
    ("notifications/cancelled", {"requestId": 1, "reason": None}),
    ("notifications/progress", None),
    ("notifications/progress", {}),
    ("notifications/progress", {"progress": 1}),
    ("notifications/progress", {"progressToken": "t"}),
    ("notifications/progress", {"progressToken": True, "progress": 1}),
    ("notifications/progress", {"progressToken": "t", "progress": "1"}),
    ("notifications/progress", {"progressToken": "t", "progress": False}),
    ("notifications/progress", {"progressToken": "t", "progress": 1, "total": "2"}),
    ("notifications/progress", {"progressToken": "t", "progress": 1, "message": 3}),
    ("notifications/tasks/status", {"taskId": "t", "status": "working"}),
]


def _notify(method: str, params: Any) -> tuple[Any, MagicMock]:
    body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    return _post(body)


@pytest.mark.parametrize("method, params", _VALID_PARAMS)
def test_client_notification_is_accepted_without_a_reply(method: str, params: Any) -> None:
    """Each ClientNotification with params its schema allows gets 202 and no body."""
    resp, proxy = _notify(method, params)
    assert resp.status_code == 202
    assert resp.content == b""
    assert proxy.method_calls == []


@pytest.mark.parametrize("method, params", _INVALID_PARAMS)
def test_notification_with_params_its_schema_refuses_is_refused(method: str, params: Any) -> None:
    resp, proxy = _notify(method, params)
    _assert_refused(resp)
    assert proxy.method_calls == []


def test_every_accepted_notification_has_a_valid_case() -> None:
    from cmcp_runtime.mcp.server import _CLIENT_NOTIFICATIONS

    assert set(_NOTIFICATIONS) == set(_CLIENT_NOTIFICATIONS)
    assert set(_NOTIFICATIONS) == {m for m, _ in _VALID_PARAMS}


@pytest.mark.parametrize(
    "params",
    [
        {"requestId": float("nan")},
        {"requestId": float("inf")},
        {"requestId": 1, "reason": None},
    ],
)
def test_validator_refuses_non_finite_and_null_values(params: dict[str, Any]) -> None:
    """JSON cannot carry NaN or Infinity, but the validator does not rely on that."""
    from cmcp_runtime.mcp.server import _accepts_notification

    assert _accepts_notification("notifications/cancelled", params) is False
    assert _accepts_notification(
        "notifications/progress", {"progressToken": "t", "progress": float("nan")}
    ) is False
    assert _accepts_notification(
        "notifications/progress", {"progressToken": "t", "progress": 1, "total": float("inf")}
    ) is False


def test_initialize_offers_no_tasks_so_task_status_is_refused() -> None:
    resp, _ = _post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert "tasks" not in resp.json()["result"]["capabilities"]
    refused, proxy = _notify("notifications/tasks/status", {"taskId": "t", "status": "working"})
    _assert_refused(refused)
    assert proxy.method_calls == []


def test_the_stateless_revision_is_never_negotiated_inbound() -> None:
    """2026-07-28 removed initialize and defines no client notifications on HTTP;
    a client asking for it gets the newest handshake-era revision instead."""
    resp, _ = _post({
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2026-07-28"},
    })
    assert resp.json()["result"]["protocolVersion"] == "2025-11-25"


@pytest.mark.parametrize("when", ["before-any-call", "after-the-call-completed"])
def test_cancel_for_a_call_not_in_flight_is_accepted(when: str) -> None:
    proxy = _make_proxy(allowed=True)
    tc = TestClient(MCPServer(proxy=proxy).app)
    if when == "after-the-call-completed":
        done = tc.post("/mcp", json={
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "mock_tool", "arguments": {}},
        })
        assert done.status_code == 200
    resp = tc.post("/mcp", json={
        "jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 9},
    })
    assert resp.status_code == 202 and resp.content == b""


@pytest.mark.parametrize("version", ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"])
def test_handshake_completes_on_every_negotiated_revision(version: str) -> None:
    proxy = _make_proxy(allowed=True)
    tc = TestClient(MCPServer(proxy=proxy).app)
    init = tc.post("/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
    })
    assert init.json()["result"]["protocolVersion"] == version
    done = tc.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert done.status_code == 202 and done.content == b""
    listed = tc.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert listed.status_code == 200


def test_cancel_does_not_stop_an_in_flight_call() -> None:
    """The cancel is accepted; the call it names still completes and is answered."""
    import asyncio

    import httpx

    proxy = _make_proxy(allowed=True)
    release = asyncio.Event()
    started = asyncio.Event()
    allowed = proxy.call_tool.side_effect

    async def slow_call(*args: Any, **kwargs: Any) -> Any:
        started.set()
        await release.wait()
        return allowed(*args, **kwargs)

    proxy.call_tool = AsyncMock(side_effect=slow_call)
    app = MCPServer(proxy=proxy).app

    async def scenario() -> tuple[Any, Any]:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            call = asyncio.create_task(client.post("/mcp", json={
                "jsonrpc": "2.0", "id": 41, "method": "tools/call",
                "params": {"name": "mock_tool", "arguments": {}},
            }))
            await started.wait()
            cancel = await client.post("/mcp", json={
                "jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": {"requestId": 41, "reason": "test"},
            })
            release.set()
            return cancel, await call

    cancel, call = asyncio.run(scenario())
    assert cancel.status_code == 202
    assert call.status_code == 200 and call.json()["id"] == 41
    assert "result" in call.json()
    proxy.call_tool.assert_awaited_once()


@pytest.mark.parametrize(
    "method",
    [
        "tools/call",
        "tools/list",
        "initialize",
        "ping",
        "unknown/arbitrary-method",
        "notifications/initialised",
        "notifications/tools/list_changed",  # server-to-client only
    ],
)
def test_other_message_without_id_is_refused(method: str) -> None:
    """Without an id only a ClientNotification is accepted; a request never runs."""
    resp, proxy = _post({
        "jsonrpc": "2.0",
        "method": method,
        "params": {"name": "mock_tool", "arguments": {}},
    })
    _assert_refused(resp)
    assert proxy.method_calls == []


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"jsonrpc": "2.0"}, id="no-method"),
        pytest.param({"jsonrpc": "2.0", "method": ""}, id="empty-method"),
        pytest.param({"jsonrpc": "2.0", "method": None}, id="null-method"),
        pytest.param({"jsonrpc": "2.0", "method": 7}, id="number-method"),
        pytest.param({"jsonrpc": "1.0", "method": "notifications/initialized"}, id="bad-version"),
        pytest.param({"method": "notifications/initialized"}, id="no-version"),
    ]
    + [
        pytest.param(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": bad},
            id=f"params-{type(bad).__name__}",
        )
        for bad in ("invalid", 1, True, None, [], ["a"])
    ],
)
def test_malformed_notification_is_refused(body: dict[str, Any]) -> None:
    """A malformed message is never acknowledged as an accepted notification."""
    resp, proxy = _post(body)
    _assert_refused(resp)
    assert proxy.method_calls == []


@pytest.mark.parametrize(
    "raw",
    [
        b'{"jsonrpc":"2.0","method":"notifications/initialized","method":"tools/call"}',
        b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{"x":NaN}}',
        b'{"jsonrpc":"2.0","method":"notifications/initialized"',
    ],
    ids=["duplicate-key", "nan", "truncated"],
)
def test_parser_still_refuses_bad_json_without_id(raw: bytes) -> None:
    proxy = _make_proxy(allowed=True)
    resp = TestClient(MCPServer(proxy=proxy).app).post(
        "/mcp", content=raw, headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32700
    assert proxy.method_calls == []


@pytest.mark.parametrize("method", ["tools/list", "tools/call", "initialize"])
def test_null_id_is_refused_before_dispatch(method: str) -> None:
    """MCP: a request id MUST NOT be null. `"id": null` is not a notification
    either (it has an id), so it is refused and nothing runs."""
    resp, proxy = _post({
        "jsonrpc": "2.0",
        "id": None,
        "method": method,
        "params": {"name": "mock_tool", "arguments": {}} if method == "tools/call" else {},
    })
    _assert_refused(resp)
    assert proxy.method_calls == []


@pytest.mark.parametrize("rpc_id", [True, False, [], {}, 1.5, float("-0.5")])
def test_bad_id_is_still_refused(rpc_id: Any) -> None:
    resp, proxy = _post({"jsonrpc": "2.0", "id": rpc_id, "method": "tools/list"})
    _assert_refused(resp)
    assert proxy.method_calls == []


@pytest.mark.parametrize("rpc_id", ["", "req-1", 0, -3, 1.0, 10**400])
def test_string_and_integer_ids_are_answered(rpc_id: Any) -> None:
    """Any string or integer, a huge one too: it is never turned into a float."""
    resp, _ = _post({"jsonrpc": "2.0", "id": rpc_id, "method": "tools/list"})
    assert resp.status_code == 200
    assert resp.json()["id"] == rpc_id


@pytest.mark.parametrize("method", ["tools/call", "tools/list", "initialize", "unknown/x"])
@pytest.mark.parametrize("params", ["invalid", [], None])
def test_request_with_non_object_params_is_refused(method: str, params: Any) -> None:
    resp, proxy = _post({"jsonrpc": "2.0", "id": 9, "method": method, "params": params})
    _assert_refused(resp, 9)
    assert proxy.method_calls == []


@pytest.mark.parametrize("body", [{"jsonrpc": "2.0", "id": 3}, {"jsonrpc": "2.0", "id": 3, "method": ""}])
def test_request_without_method_is_invalid_not_unknown(body: dict[str, Any]) -> None:
    resp, _ = _post(body)
    _assert_refused(resp, 3)


def test_requests_with_id_are_unchanged() -> None:
    resp, _ = _post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert resp.status_code == 200
    assert resp.json()["result"]["protocolVersion"] == "2025-11-25"
    resp, proxy = _post({
        "jsonrpc": "2.0",
        "id": "c1",
        "method": "tools/call",
        "params": {"name": "mock_tool", "arguments": {}},
    })
    assert resp.status_code == 200
    assert resp.json()["id"] == "c1"
    proxy.call_tool.assert_awaited_once()


def test_tools_list_via_mcp(client: TestClient) -> None:
    """POST /mcp with tools/list returns tool list in JSON-RPC format."""
    resp = client.post("/mcp", json={
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 5,
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["jsonrpc"] == "2.0"
    assert "result" in body
    assert "tools" in body["result"]
    assert any(t["name"] == "mock_tool" for t in body["result"]["tools"])


# ---------------------------------------------------------------------------
# Group 2: TRACE Claim conformance (5 tests)
# ---------------------------------------------------------------------------

def test_trace_claim_not_found_returns_404(client: TestClient) -> None:
    """GET /sessions/nonexistent/trace-claim returns 404 when session_manager configured."""
    # client fixture has no session_manager: returns 501
    # We need a client with a session_manager that returns None for unknown sessions.
    session_mgr = MagicMock()
    session_mgr.get_trace_claim.return_value = None
    proxy = _make_proxy()
    server = MCPServer(proxy=proxy, session_manager=session_mgr)
    tc = TestClient(server.app)

    resp = tc.get("/sessions/nonexistent/trace-claim")
    assert resp.status_code == 404


def test_trace_claim_without_session_manager_returns_501(client: TestClient) -> None:
    """GET /sessions/x/trace-claim without session_manager returns 501."""
    resp = client.get("/sessions/any-id/trace-claim")
    assert resp.status_code == 501


def test_audit_export_without_session_manager_returns_501(client: TestClient) -> None:
    """GET /audit/export without session_manager returns 501."""
    resp = client.get("/audit/export?session_id=some-id")
    assert resp.status_code == 501


def test_audit_export_missing_session_id_param_returns_400() -> None:
    """GET /audit/export without ?session_id returns 400."""
    session_mgr = MagicMock()
    audit_chain = MagicMock()
    proxy = _make_proxy()
    server = MCPServer(proxy=proxy, session_manager=session_mgr, audit_chain=audit_chain)
    tc = TestClient(server.app)

    resp = tc.get("/audit/export")
    assert resp.status_code == 400
    assert "session_id" in resp.json()["error"]


def test_session_reset_without_session_returns_501(client: TestClient) -> None:
    """POST /sessions/x/reset without session configured returns 501."""
    resp = client.post("/sessions/any-id/reset")
    assert resp.status_code == 501


# ---------------------------------------------------------------------------
# Group 3: Policy enforcement conformance (5 tests)
# ---------------------------------------------------------------------------

def test_allowed_tool_call_returns_result(client: TestClient) -> None:
    """Allowed tool returns result with _cmcp metadata."""
    resp = client.post("/mcp", json={
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 10,
        "params": {"name": "mock_tool", "arguments": {}},
    })
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert "_cmcp" in result
    assert "call_id" in result["_cmcp"]
    assert "audit_entry_hash" in result["_cmcp"]


def test_denied_tool_call_returns_403(denied_client: TestClient) -> None:
    """Denied tool returns JSON-RPC error with POLICY_DENY code."""
    resp = denied_client.post("/mcp", json={
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 11,
        "params": {"name": "mock_tool", "arguments": {}},
    })
    assert resp.status_code == 403
    body = resp.json()
    assert "error" in body
    assert body["error"]["data"]["error_code"] == "POLICY_DENY"


def test_result_contains_call_id(client: TestClient) -> None:
    """Response _cmcp.call_id is a UUID string."""
    resp = client.post("/mcp", json={
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 12,
        "params": {"name": "mock_tool", "arguments": {}},
    })
    assert resp.status_code == 200
    call_id = resp.json()["result"]["_cmcp"]["call_id"]
    # Must be a valid UUID
    parsed = uuid.UUID(call_id)
    assert str(parsed) == call_id


def test_result_contains_audit_entry_hash(client: TestClient) -> None:
    """Response _cmcp.audit_entry_hash is present and non-empty."""
    resp = client.post("/mcp", json={
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 13,
        "params": {"name": "mock_tool", "arguments": {}},
    })
    assert resp.status_code == 200
    audit_hash = resp.json()["result"]["_cmcp"]["audit_entry_hash"]
    assert isinstance(audit_hash, str)
    assert len(audit_hash) > 0


def test_denied_call_has_deny_reason_in_response(denied_client: TestClient) -> None:
    """Denied call error message is non-empty."""
    resp = denied_client.post("/mcp", json={
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 14,
        "params": {"name": "mock_tool", "arguments": {}},
    })
    assert resp.status_code == 403
    error = resp.json()["error"]
    assert isinstance(error["message"], str)
    assert len(error["message"]) > 0


# ---------------------------------------------------------------------------
# Group 4: Session management conformance (4 tests)
# ---------------------------------------------------------------------------

def test_session_reset_returns_old_and_new_ids(
    session_client: tuple[TestClient, SessionState, AuditChain, str],
) -> None:
    """POST /sessions/{id}/reset returns {old_session_id, new_session_id, status}."""
    tc, session, _chain, session_id = session_client
    resp = tc.post(f"/sessions/{session_id}/reset")
    assert resp.status_code == 200
    body = resp.json()
    assert body["old_session_id"] == session_id
    assert "new_session_id" in body
    assert body["new_session_id"] != session_id
    assert body["status"] == "reset"


def test_session_reset_wrong_id_returns_404(
    session_client: tuple[TestClient, SessionState, AuditChain, str],
) -> None:
    """POST /sessions/wrong/reset returns 404 when session ID does not match."""
    tc, _session, _chain, _session_id = session_client
    resp = tc.post("/sessions/completely-wrong-id/reset")
    assert resp.status_code == 404


def test_session_reset_clears_attestation_stale(
    session_client: tuple[TestClient, SessionState, AuditChain, str],
) -> None:
    """After reset, attestation_stale is False in the response."""
    tc, session, _chain, session_id = session_client
    resp = tc.post(f"/sessions/{session_id}/reset")
    assert resp.status_code == 200
    assert resp.json()["attestation_stale"] is False


def test_health_exempt_from_bearer_auth(client: TestClient) -> None:
    """Even without an Authorization header, /health returns 200."""
    # The gateway does not enforce bearer auth in this implementation,
    # but /health must always be reachable without credentials.
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
