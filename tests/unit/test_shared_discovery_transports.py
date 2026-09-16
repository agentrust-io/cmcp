"""Drift and provenance share one complete first-contact tools/list acquisition.

The public call pipeline and TRACE provenance verification are real here. HTTP
uses a local MockTransport and stdio uses a measured Python subprocess; only the
unrelated policy/scanner seams are mocked by the existing proxy test helper.
"""

from __future__ import annotations

import json
import sys
import textwrap
from types import SimpleNamespace

import httpx
import pytest
from agentrust_trace.provenance import build_record, sign_record
from agentrust_trace.sign import generate_key, key_to_jwk

from cmcp_runtime.config import DriftPolicy
from cmcp_runtime.mcp.stdio import StdioSpawn, measure_executable, resolve_executable
from cmcp_runtime.provenance import ProvenanceOutcome
from tests.unit.test_mcp_proxy import _make_proxy
from tests.unit.test_upstream_catalog_drift import _advertise, _catalog

_SERVER_INFO = {"name": "server_info", "description": "server information", "inputSchema": {}}
_CURSOR = "  next/%2F+雪==  "
_RESPONSE = "customer found"

_STDIO_SERVER = """
    import json
    import sys

    with open(sys.argv[1], encoding="utf-8") as handle:
        pages = json.load(handle)
    for line in sys.stdin:
        request = json.loads(line)
        with open(sys.argv[2], "a", encoding="utf-8") as handle:
            handle.write(json.dumps(request) + "\\n")
        if request["method"] == "tools/list":
            reply = pages["second" if "cursor" in request["params"] else "first"]
        elif request["method"] == "tools/call":
            reply = {"result": {"content": [{"type": "text", "text": "customer found"}]}}
        else:
            raise AssertionError("unexpected method")
        body = {"jsonrpc": "2.0", "id": request["id"], **reply}
        sys.stdout.write(json.dumps(body) + "\\n")
        sys.stdout.flush()
"""


def _signed_catalog(tmp_path):
    key = generate_key()
    record = build_record(
        kind="publisher-asserted",
        publisher="did:web:crm.example",
        tools=[_SERVER_INFO, *_advertise()],
        artifact={"package": "pkg:npm/crm@1.0.0", "digest": "sha256:" + "a" * 64},
    )
    record_path = tmp_path / "provenance.json"
    record_path.write_text(json.dumps(sign_record(record, key)), encoding="utf-8")
    catalog = _catalog()
    entry = catalog.entries["lookup_customer"]
    entry.server.provenance_record_path = str(record_path)
    entry.server.publisher_jwk = key_to_jwk(key)
    return catalog, entry


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["json", "sse", "stdio"])
@pytest.mark.parametrize(
    "case,outcome,required,allowed",
    [
        ("matching", ProvenanceOutcome.VERIFIED, "publisher-asserted", True),
        ("changed", ProvenanceOutcome.CATALOG_MISMATCH, None, True),
        ("incomplete", ProvenanceOutcome.UNCHECKED, None, True),
        ("incomplete", ProvenanceOutcome.UNCHECKED, "publisher-asserted", False),
    ],
)
async def test_cold_tool_call_shares_paginated_discovery_between_drift_and_provenance(
    tmp_path, monkeypatch, transport, case, outcome, required, allowed
):
    catalog, entry = _signed_catalog(tmp_path)
    pages = {
        "first": {"result": {"tools": [_SERVER_INFO], "nextCursor": _CURSOR}},
        "second": {"result": {"tools": _advertise()}},
    }
    if case == "changed":
        pages["second"] = {"result": {"tools": _advertise("changed description")}}
    elif case == "incomplete":
        pages["second"] = {"error": {"code": -32603, "message": "listing failed"}}

    request_log = tmp_path / "requests.jsonl"
    if transport == "stdio":
        script = tmp_path / "upstream.py"
        script.write_text(textwrap.dedent(_STDIO_SERVER), encoding="utf-8")
        page_path = tmp_path / "pages.json"
        page_path.write_text(json.dumps(pages), encoding="utf-8")
        entry.server.transport = "stdio"
        entry.server.spawn = StdioSpawn(
            command=sys.executable,
            args=(str(script), str(page_path), str(request_log)),
            measure_target=str(script),
            binary_digest=measure_executable(resolve_executable(str(script))),
        )

    proxy, session, chain = _make_proxy(catalog=catalog)
    # The helper normally stubs forwarding. Restore the class method so this
    # test exercises the exact drift -> forwarding -> provenance cold path.
    del proxy._forward_to_upstream
    proxy._mcp_gateway.intercept_tool_response.side_effect = lambda **kwargs: SimpleNamespace(
        allowed=True, content=kwargs["response_content"], threats=[], action="allowed"
    )
    proxy._config.attestation.required_provenance_kind = required
    proxy._config.catalog.drift_policy = (
        DriftPolicy.WARN_ONLY if case == "changed" else DriftPolicy.FAIL_CLOSED
    )
    requests = []

    def respond(request):
        payload = json.loads(request.content)
        requests.append(payload)
        assert request.headers["Mcp-Method"] == payload["method"]
        if payload["method"] == "tools/list":
            reply = pages["second" if "cursor" in payload["params"] else "first"]
        else:
            assert payload["method"] == "tools/call"
            reply = {"result": {"content": [{"type": "text", "text": _RESPONSE}]}}
        body = {"jsonrpc": "2.0", "id": payload["id"], **reply}
        if transport == "sse":
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                text=f"data: {json.dumps(body)}\n\n",
            )
        return httpx.Response(200, json=body)

    def observed_requests():
        if transport == "stdio":
            return [json.loads(line) for line in request_log.read_text().splitlines()]
        return requests

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        if transport != "stdio":
            monkeypatch.setattr(proxy, "_client_for_upstream", lambda entry: client)
        try:
            result = await proxy.call_tool("cold", "lookup_customer", {"id": "customer-1"})

            assert result.allowed is allowed
            assert result.response == (_RESPONSE if allowed else None)
            assert (await proxy._check_provenance(entry)).outcome is outcome
            assert session.catalog_drift is False
            assert session.upstream_drift_tools == (
                ["lookup_customer"] if case == "changed" else []
            )
            assert any(item.entry_type == "catalog_drift" for item in chain.entries) is (
                case == "changed"
            )
            cold_requests = observed_requests()
            discovery_requests = [item for item in cold_requests if item["method"] == "tools/list"]
            assert len(discovery_requests) == 2
            assert "cursor" not in discovery_requests[0]["params"]
            assert discovery_requests[1]["params"]["cursor"] == _CURSOR
            tool_requests = [item for item in cold_requests if item["method"] == "tools/call"]
            assert len(tool_requests) == int(allowed)
            if allowed:
                assert tool_requests[0]["params"]["name"] == "lookup_customer"
                assert tool_requests[0]["params"]["arguments"] == {"id": "customer-1"}
            else:
                assert result.deny_reason == "upstream_error:UPSTREAM_UNAVAILABLE"

            # The shared acquisition is session-scoped, not a one-call shortcut.
            repeated = await proxy.call_tool("warm", "lookup_customer", {"id": "customer-2"})
            assert repeated.allowed is allowed
            all_requests = observed_requests()
            assert sum(item["method"] == "tools/list" for item in all_requests) == 2
            assert sum(item["method"] == "tools/call" for item in all_requests) == 2 * int(allowed)
        finally:
            await proxy.aclose()
