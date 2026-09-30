"""Optional TRACE gate hook: absent means unchanged, present means gated transport."""

from __future__ import annotations

import base64
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.mcp.proxy import CMCPProxy
from cmcp_runtime.mcp.server import MCPServer
from cmcp_runtime.policy.evaluator import PolicyDecision, PolicyEvaluator
from cmcp_runtime.session.state import SessionState
from cmcp_runtime.trace_gate import decode_trace_token

BEARER = "test-bearer"
POLICY = "sha256:" + "0" * 64


def _evaluator() -> PolicyEvaluator:
    decision = PolicyDecision(
        allowed=True,
        enforcement_mode=EnforcementMode.ENFORCING,
        rule_matched=None,
        advice={},
        evaluation_ms=0.1,
        would_have_denied=False,
    )
    evaluator = MagicMock(spec=PolicyEvaluator)
    evaluator.evaluate.return_value = decision
    evaluator.authorize_egress.return_value = decision
    evaluator.bundle_hash = POLICY
    evaluator.enforcement_mode = EnforcementMode.ENFORCING
    return evaluator


class FakeGate:
    """Records every call; ``refuse`` names the method that raises ValueError."""

    def __init__(self, refuse: str | None = None) -> None:
        self.refuse = refuse
        self.calls: list[tuple[str, Any]] = []

    def _record(self, name: str, detail: Any) -> None:
        self.calls.append((name, detail))
        if self.refuse == name:
            raise ValueError(f"{name}_refused")

    def challenge(
        self, token_bytes: bytes, *, session_id: str, action: dict[str, Any]
    ) -> dict[str, Any]:
        self._record("challenge", (token_bytes, action))
        return {"nonce": "n", "session_id": session_id}

    def admit(self, token_bytes: bytes, credentials: object, *, session_id: str) -> dict[str, Any]:
        self._record("admit", (token_bytes, credentials))
        return {"generation": 1}

    def begin(
        self,
        credentials: object,
        *,
        action: dict[str, Any],
        session_id: str,
        call_id: str,
        policy_digest: str,
    ) -> tuple[Any, dict[str, Any]]:
        self._record("begin", (credentials, action, call_id, policy_digest))
        return ("handle", call_id), {}

    def recheck(self, handle: Any, *, action: dict[str, Any], policy_digest: str) -> None:
        self._record("recheck", (handle, action))

    def receipt(self, handle: Any, *, allowed: bool, reason: str) -> None:
        self._record("receipt", (handle, allowed, reason))

    def refusal(self, *, action: dict[str, Any], session_id: str, call_id: str) -> None:
        self._record("refusal", call_id)

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


def _proxy(
    *, gate: FakeGate | None = None, mode: EnforcementMode = EnforcementMode.ENFORCING
) -> tuple[CMCPProxy, AuditChain, list[dict[str, Any]]]:
    entry = CatalogEntry(
        tool_name="read",
        server=ServerIdentity(
            display_name="Fixture",
            url="https://fixture.invalid/mcp",
            tls_fingerprint="SHA256:" + "A" * 43 + "=",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description="read", input_schema={}, output_schema=None
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="public",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-09-30T00:00:00Z",
        approved_by="test",
    )
    catalog = ToolCatalog(entries={"read": entry}, catalog_hash="sha256:" + "1" * 64)
    chain = AuditChain(session_id="s-trace")
    config = Config(attestation=AttestationConfig(enforcement_mode=mode))
    with (
        patch("cmcp_runtime.mcp.proxy.MCPGateway") as gateway,
        patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"),
    ):
        scan = MagicMock()
        scan.allowed = True
        scan.threats = []
        scan.content = None
        gateway.return_value.intercept_tool_call.return_value = (True, None)
        gateway.return_value.intercept_tool_response.return_value = scan
        proxy = CMCPProxy(
            catalog,
            _evaluator(),
            SessionState(session_id="s-trace"),
            chain,
            config,
            trace_gate=gate,
        )
    sent: list[dict[str, Any]] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if gate is not None:
            # The allow receipt is durable before any byte reaches the upstream.
            assert ("receipt", (("handle", body["id"]), True, "cedar_allowed")) in gate.calls
        sent.append(body)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"content": [{"type": "text", "text": "ok"}]},
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    proxy._client_for_upstream = lambda entry: client  # type: ignore[method-assign]
    proxy._check_upstream_drift = AsyncMock(return_value=False)  # type: ignore[method-assign]
    return proxy, chain, sent


def _token() -> str:
    return base64.urlsafe_b64encode(b"token-bytes").decode().rstrip("=")


async def _post(server: MCPServer, path: str, body: dict[str, Any]) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server.app),
        base_url="https://gateway.test",
        headers={"Authorization": f"Bearer {BEARER}"},
    ) as client:
        return await client.post(path, json=body)


# --- No gate configured: nothing changes -----------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/trace/challenge", "/trace/admit"])
async def test_trace_routes_are_not_registered_without_a_gate(path):
    proxy, _, _ = _proxy()
    server = MCPServer(proxy, bearer_token=BEARER)
    assert proxy.trace_gate is None
    assert all(getattr(r, "path", None) != path for r in server.app.routes)
    body = {"token": _token(), "purpose": "admission"}
    response = await _post(server, path, body)
    unknown = await _post(server, "/no-such-route", body)
    assert response.status_code == 404
    assert (response.content, dict(response.headers)) == (
        unknown.content,
        dict(unknown.headers),
    )


@pytest.mark.asyncio
async def test_proxy_call_is_unchanged_without_a_gate():
    proxy, chain, sent = _proxy()
    result = await proxy.call_tool("call-1", "read", {"q": 1.0})
    assert result.allowed
    assert [(s["id"], s["params"]["arguments"]) for s in sent] == [("call-1", {"q": 1.0})]
    entry = [e for e in chain.entries if e.entry_type == "tool_call"][-1]
    assert entry.policy_rule_matched != "trace:refused"


@pytest.mark.asyncio
async def test_trace_metadata_is_ignored_without_a_gate():
    proxy, _, sent = _proxy()
    proxy.call_tool = AsyncMock(wraps=proxy.call_tool)  # type: ignore[method-assign]
    server = MCPServer(proxy, bearer_token=BEARER)
    response = await _post(
        server,
        "/mcp",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read",
                "arguments": {},
                "_cmcp": {"trace": {"call_id": "chosen-by-client", "credentials": {}}},
            },
        },
    )
    assert response.status_code == 200, response.text
    args, kwargs = proxy.call_tool.await_args
    assert args[0] != "chosen-by-client"
    assert [s["id"] for s in sent] == [args[0]]
    assert set(kwargs) == {"workflow_id", "declared_data_class", "execution_id"}


@pytest.mark.parametrize("mode", [EnforcementMode.ADVISORY, EnforcementMode.SILENT])
def test_gate_requires_enforcing_mode(mode):
    with pytest.raises(ValueError, match="requires enforcing mode"):
        _proxy(gate=FakeGate(), mode=mode)


# --- Gate configured ---------------------------------------------------------


@pytest.mark.asyncio
async def test_gated_call_rechecks_and_receipts_before_transport():
    gate = FakeGate()
    proxy, _, sent = _proxy(gate=gate)
    result = await proxy.call_tool("call-1", "read", {}, trace_credentials={"nonce": "n"})
    assert result.allowed and len(sent) == 1
    assert gate.names() == ["begin", "recheck", "recheck", "receipt", "recheck", "receipt"]
    begin_action = gate.calls[0][1][1]
    assert begin_action == proxy.trace_action("call-1", "read", {})
    assert begin_action["server_identity"] and begin_action["definition_hash"]


@pytest.mark.asyncio
@pytest.mark.parametrize("refuse", ["begin", "recheck"])
async def test_refused_gate_never_reaches_transport(refuse):
    gate = FakeGate(refuse=refuse)
    proxy, chain, sent = _proxy(gate=gate)
    result = await proxy.call_tool("call-1", "read", {}, trace_credentials=None)
    assert not result.allowed
    assert sent == []
    entry = [e for e in chain.entries if e.entry_type == "tool_call"][-1]
    expected = "trace:refused" if refuse == "begin" else "trace:stale"
    assert entry.policy_rule_matched == expected
    if refuse == "begin":
        assert "refusal" in gate.names()
    else:
        assert gate.calls[-1] == ("receipt", (("handle", "call-1"), False, "gateway_terminal"))


@pytest.mark.asyncio
async def test_gated_server_routes_and_call_id_binding():
    gate = FakeGate()
    proxy, _, sent = _proxy(gate=gate)
    server = MCPServer(proxy, bearer_token=BEARER)
    admitted = await _post(
        server, "/trace/admit", {"token": _token(), "credentials": {"nonce": "n"}}
    )
    assert admitted.status_code == 200
    challenge = await _post(
        server,
        "/trace/challenge",
        {"token": _token(), "purpose": "call", "tool_name": "read", "arguments": {}},
    )
    assert challenge.status_code == 200
    call_id = challenge.json()["call_id"]
    assert challenge.json()["action"] == proxy.trace_action(call_id, "read", {})
    response = await _post(
        server,
        "/mcp",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read",
                "arguments": {},
                "_cmcp": {"trace": {"call_id": call_id, "credentials": {"nonce": "n"}}},
            },
        },
    )
    assert response.status_code == 200, response.text
    assert [s["id"] for s in sent] == [call_id]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,body,code",
    [
        ("/trace/challenge", {"token": "not base64!", "purpose": "admission"}, "CHALLENGE"),
        ("/trace/challenge", {"token": _token(), "purpose": "other"}, "CHALLENGE"),
        ("/trace/challenge", {"token": _token(), "purpose": "call", "tool_name": 1}, "CHALLENGE"),
        ("/trace/admit", {"token": _token() + "=", "credentials": {}}, "ADMISSION"),
    ],
)
async def test_gated_routes_refuse_malformed_requests(path, body, code):
    proxy, _, _ = _proxy(gate=FakeGate())
    response = await _post(MCPServer(proxy, bearer_token=BEARER), path, body)
    assert response.status_code == 403
    assert response.json() == {"error_code": f"TRACE_{code}_REFUSED"}


def test_trace_routes_require_bearer_auth():
    from starlette.testclient import TestClient

    proxy, _, _ = _proxy(gate=FakeGate())
    client = TestClient(MCPServer(proxy, bearer_token=BEARER).app)
    body = {"token": _token(), "purpose": "admission"}
    assert client.post("/trace/challenge", json=body).status_code == 401


@pytest.mark.parametrize(
    "value",
    [None, 5, "a" * 90_001, "abc=", "ab+c", "ab/c", "abc!"],
    ids=["none", "int", "oversize", "padded", "plus", "slash", "bang"],
)
def test_decode_trace_token_accepts_only_canonical_base64url(value):
    with pytest.raises(ValueError):
        decode_trace_token(value)


def test_decode_trace_token_round_trips():
    assert decode_trace_token(_token()) == b"token-bytes"
