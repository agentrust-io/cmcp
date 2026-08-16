"""`initialize` must negotiate a handshake-era revision (regression for #509).

#509 replaced the hardcoded `2024-11-05` in the `initialize` result with
`PROTOCOL_VERSION`, which is `2026-07-28` - the revision that removed
`initialize`. Every handshake was then answered with a protocol in which the
request just made does not exist, and in which each later request must carry
`_meta` plus mirrored headers the client has no way to know it should send.

The direction of the swap matters: the constant is correct for the outbound
leg, where the gateway is the client, and wrong for the inbound one, where it
answers a handshake it only reaches because the caller is handshake-era.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from cmcp_runtime.mcp.server import _LEGACY_PROTOCOL_VERSIONS, MCPServer
from cmcp_runtime.mcp.streamable_http import PROTOCOL_VERSION


def _make_server() -> MCPServer:
    proxy = MagicMock()
    proxy._catalog = MagicMock()
    entry = MagicMock()
    entry.approved_definition.description = "a mock tool"
    entry.approved_definition.input_schema = {"type": "object", "properties": {}}
    proxy._catalog.entries = {"mock_tool": entry}
    proxy.call_tool = AsyncMock(return_value=MagicMock(
        allowed=True, deny_reason=None, response="ok",
        audit_entry_hash="sha256:" + "0" * 64,
        would_have_denied=False, latency_us=100, advice=None,
    ))
    with patch("cmcp_runtime.mcp.server.StatelessKernel"):
        return MCPServer(proxy)


@pytest.fixture()
def client() -> TestClient:
    return TestClient(_make_server().app, raise_server_exceptions=False)


def _initialize(client: TestClient, params: object) -> str:
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params},
    )
    assert resp.status_code == 200
    return resp.json()["result"]["protocolVersion"]


@pytest.mark.parametrize("requested", _LEGACY_PROTOCOL_VERSIONS)
def test_initialize_echoes_the_requested_revision(client, requested):
    """What Claude Code, Claude Desktop, Cursor and VS Code actually send."""
    negotiated = _initialize(client, {
        "protocolVersion": requested,
        "capabilities": {},
        "clientInfo": {"name": "claude-code", "version": "1.0.0"},
    })
    assert negotiated == requested


def test_initialize_never_answers_with_the_outbound_revision(client):
    """The regression itself: `2026-07-28` has no `initialize` to answer with."""
    negotiated = _initialize(client, {"protocolVersion": "2025-06-18", "capabilities": {}})
    assert negotiated != PROTOCOL_VERSION


def test_a_client_asking_for_the_stateless_revision_is_not_humoured(client):
    """A handshake is proof the caller is handshake-era, whatever it asked for.

    A client that reaches `initialize` cannot be speaking 2026-07-28, so echoing
    it back would confirm a revision neither side is actually using.
    """
    negotiated = _initialize(client, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}})
    assert negotiated in _LEGACY_PROTOCOL_VERSIONS
    assert negotiated != PROTOCOL_VERSION


@pytest.mark.parametrize("params", [
    {"protocolVersion": "1999-01-01", "capabilities": {}},
    {"capabilities": {}},
    {},
])
def test_unnegotiable_params_fall_back_to_the_newest_supported_revision(client, params):
    """An unknown or absent version still yields a usable answer.

    The lifecycle spec: absent support for the requested version, the server
    MUST answer with another it supports, and that SHOULD be the latest.

    Scope note. These cases assert the *version fallback* only. Two of them are
    incomplete against the schema, which marks `protocolVersion`, `capabilities`
    and `clientInfo` all required on `InitializeRequestParams`, and the gateway
    does not enforce members. That leniency is deliberate and unchanged by this
    branch: the shape check above rejects a `params` that cannot be an
    `InitializeRequestParams` at all, while member validation would be a
    behaviour change of its own, and would have to decide what happens to a
    handshake with no `params` at all. Read these as "negotiation still
    resolves", not as "this payload is conformant".
    """
    assert _initialize(client, params) == _LEGACY_PROTOCOL_VERSIONS[0]


def test_the_newest_handshake_revision_is_2025_11_25():
    """`2025-11-25` is the last revision that defines `initialize`.

    Answering a client that offers it with anything older is a downgrade, and
    the spec says a client that does not support the server's answer SHOULD
    disconnect - so the fallback is not a harmless one.
    """
    assert _LEGACY_PROTOCOL_VERSIONS[0] == "2025-11-25"


def test_2025_11_25_is_echoed_and_not_downgraded(client):
    """The exact case that regressed, hardcoded on purpose.

    `test_initialize_echoes_the_requested_revision` is parametrized over
    `_LEGACY_PROTOCOL_VERSIONS`, so dropping a revision from that tuple also
    drops its own test case. A test that draws its inputs from the constant
    under test cannot catch the constant being wrong, so this one names the
    revision literally.
    """
    negotiated = _initialize(client, {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "claude-code", "version": "1.0.0"},
    })
    assert negotiated == "2025-11-25"
    assert negotiated != "2025-06-18"


def test_unknown_version_falls_back_to_2025_11_25(client):
    """Fallback target named literally, for the same reason."""
    assert _initialize(client, {
        "protocolVersion": "1999-01-01", "capabilities": {},
    }) == "2025-11-25"


@pytest.mark.parametrize("params", [
    ["positional", "params"],
    "a string",
    42,
])
def test_non_object_initialize_params_are_rejected(client, params):
    """`InitializeRequestParams` is an object, so a non-object is not a
    negotiation the gateway should complete."""
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32600
    assert "result" not in resp.json()


def test_outbound_constant_is_unchanged():
    """The fix must not touch the leg #509 got right."""
    assert PROTOCOL_VERSION == "2026-07-28"
    assert PROTOCOL_VERSION not in _LEGACY_PROTOCOL_VERSIONS
