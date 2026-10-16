"""HTTP replies must belong to the exact request in JSON and SSE alike."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.mcp.streamable_http import parse_response
from tests.unit.test_issue_571_finalization import _make_proxy, _provenance, _terminals


def _response(body, media_type):
    request = httpx.Request("POST", "https://local.invalid/mcp")
    if media_type == "application/json":
        return httpx.Response(200, request=request, json=body)
    return httpx.Response(
        200,
        request=request,
        headers={"content-type": media_type},
        text=f"data: {json.dumps(body)}\n\n",
    )


@pytest.mark.parametrize("media_type", ["application/json", "text/event-stream"])
@pytest.mark.parametrize(
    "request_id,response_id",
    [("current", "different"), ("current", None), ("1", 1), ("True", True),
     ("None", None), ("current", ""), ("current", ["current"]),
     ("current", {"id": "current"})],
)
def test_wrong_or_wrong_type_id_is_rejected(media_type, request_id, response_id):
    body = {"jsonrpc": "2.0", "id": response_id, "result": {"content": []}}
    with pytest.raises(ValueError):
        parse_response(_response(body, media_type), request_id)


@pytest.mark.parametrize("media_type", ["application/json", "text/event-stream"])
def test_missing_id_is_rejected(media_type):
    with pytest.raises(ValueError):
        parse_response(_response({"jsonrpc": "2.0", "result": {}}, media_type), "current")


@pytest.mark.parametrize("media_type", ["application/json", "text/event-stream"])
@pytest.mark.parametrize("request_id", ["current", "1", "True", "None"])
@pytest.mark.parametrize("reply", [{"result": {"content": []}},
                                 {"error": {"code": -32603, "message": "failed"}}])
def test_matching_string_id_preserves_result_and_error(media_type, request_id, reply):
    body = {"jsonrpc": "2.0", "id": request_id, **reply}
    assert parse_response(_response(body, media_type), request_id) == body


def test_sse_skips_numeric_id_and_selects_matching_string_id():
    wrong = {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}
    right = {"jsonrpc": "2.0", "id": "1", "result": {"content": ["right"]}}
    response = httpx.Response(
        200, headers={"content-type": "text/event-stream"},
        text=f"data: {json.dumps(wrong)}\n\ndata: {json.dumps(right)}\n\n",
    )
    assert parse_response(response, "1") == right


@pytest.mark.asyncio
@pytest.mark.parametrize("media_type", ["application/json", "text/event-stream"])
@pytest.mark.parametrize("matching", [True, False])
async def test_proxy_reply_binding_retains_one_terminal_outcome(media_type, matching):
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=True))
    reply = {
        "jsonrpc": "2.0", "id": "current" if matching else "different",
        "result": {"content": [{"type": "text", "text": "nonsecret-result"}]},
    }
    client = MagicMock()
    client.post = AsyncMock(return_value=_response(reply, media_type))
    proxy._client_for_upstream = MagicMock(return_value=client)

    result = await proxy.call_tool("current", "test.echo", {})

    assert result.allowed is matching
    terminal, = _terminals(chain)
    assert terminal.call_id == "current"
    if matching:
        assert result.response == "nonsecret-result"
        assert terminal.policy_decision == "allow"
    else:
        assert result.response is None
        assert terminal.response_payload_hash is None
        assert terminal.detail["effect_boundary_state"] == "transport_response_received"
        assert terminal.detail["terminal_disposition"] == "outcome_unknown"
