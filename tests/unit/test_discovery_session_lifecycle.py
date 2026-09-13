"""Public calls compose paginated discovery with session draining and cleanup.

HTTP uses real owned httpx clients with MockTransport; stdio uses a measured
Python child and a loopback gate. Acquisition, lifecycle, audit finalization,
and signed TRACE provenance verification are not replaced. The existing proxy
helper supplies only unrelated policy/scanner seams.
"""

from __future__ import annotations

import asyncio
import json
import sys
import textwrap
from contextlib import asynccontextmanager, suppress
from types import SimpleNamespace

import httpx
import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.mcp.stdio import StdioSpawn, measure_executable, resolve_executable
from cmcp_runtime.provenance import ProvenanceOutcome
from cmcp_runtime.session.state import SessionState
from tests.unit.test_mcp_proxy import _make_proxy
from tests.unit.test_shared_discovery_transports import (
    _CURSOR,
    _RESPONSE,
    _SERVER_INFO,
    _signed_catalog,
)
from tests.unit.test_upstream_catalog_drift import _advertise

_CHILD = """
    import json
    import socket
    import sys

    with open(sys.argv[1], encoding="utf-8") as handle:
        pages = json.load(handle)
    for line in sys.stdin:
        request = json.loads(line)
        with open(sys.argv[2], "a", encoding="utf-8") as handle:
            handle.write(json.dumps(request) + "\\n")
        if request["method"] == "tools/list":
            second = "cursor" in request["params"]
            if second:
                with socket.create_connection(("127.0.0.1", int(sys.argv[3]))) as gate:
                    if gate.recv(1) != b"x":
                        raise RuntimeError("test gate closed")
            reply = pages["second" if second else "first"]
        else:
            assert request["method"] == "tools/call"
            reply = {"result": {"content": [{"type": "text", "text": "customer found"}]}}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request["id"], **reply}) + "\\n")
        sys.stdout.flush()
"""


@asynccontextmanager
async def _gateway(tmp_path, monkeypatch, transport):
    catalog, entry = _signed_catalog(tmp_path)
    pages = {
        "first": {"result": {"tools": [_SERVER_INFO], "nextCursor": _CURSOR}},
        "second": {"result": {"tools": _advertise()}},
    }
    entered, release = asyncio.Event(), asyncio.Event()
    gate_tasks = set()

    async def gate_connection(reader, writer):
        task = asyncio.current_task()
        gate_tasks.add(task)
        try:
            entered.set()
            await release.wait()
            writer.write(b"x")
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass  # A cancelled discovery deliberately terminates the child.
        finally:
            writer.close()
            # Windows reports the deliberately terminated child's reset here too.
            with suppress(ConnectionResetError, BrokenPipeError):
                await writer.wait_closed()
            gate_tasks.discard(task)

    gate = None
    request_log = tmp_path / "requests.jsonl"
    if transport == "stdio":
        gate = await asyncio.start_server(gate_connection, "127.0.0.1", 0)
        port = gate.sockets[0].getsockname()[1]
        script = tmp_path / "upstream.py"
        script.write_text(textwrap.dedent(_CHILD), encoding="utf-8")
        page_path = tmp_path / "pages.json"
        page_path.write_text(json.dumps(pages), encoding="utf-8")
        entry.server.transport = "stdio"
        entry.server.spawn = StdioSpawn(
            command=sys.executable,
            args=(str(script), str(page_path), str(request_log), str(port)),
            measure_target=str(script),
            binary_digest=measure_executable(resolve_executable(str(script))),
        )

    proxy, session, chain = _make_proxy(catalog=catalog)
    del proxy._forward_to_upstream
    proxy._mcp_gateway.intercept_tool_response.side_effect = lambda **kwargs: SimpleNamespace(
        allowed=True, content=kwargs["response_content"], threats=[], action="allowed"
    )
    proxy._config.attestation.required_provenance_kind = "publisher-asserted"
    requests, clients = [], []

    async def respond(request):
        payload = json.loads(request.content)
        requests.append(payload)
        assert request.headers["Mcp-Method"] == payload["method"]
        if payload["method"] == "tools/list":
            second = "cursor" in payload["params"]
            if second:
                entered.set()
                await release.wait()
            reply = pages["second" if second else "first"]
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

    if transport != "stdio":
        entry.server.url = "http://upstream.example/mcp"
        real_client = httpx.AsyncClient

        def local_client(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(respond)
            client = real_client(*args, **kwargs)
            clients.append(client)
            return client

        # Keep production resource ownership/keying/cleanup; replace only I/O.
        monkeypatch.setattr("cmcp_runtime.mcp.proxy.httpx.AsyncClient", local_client)

    def observed_requests():
        if transport == "stdio":
            return [json.loads(line) for line in request_log.read_text().splitlines()]
        return list(requests)

    def owned_resource():
        if transport == "stdio":
            return next(iter(proxy._stdio_servers.values()))._proc
        return clients[-1]

    try:
        yield SimpleNamespace(
            proxy=proxy,
            session=session,
            chain=chain,
            entered=entered,
            release=release,
            requests=observed_requests,
            resource=owned_resource,
        )
    finally:
        release.set()
        await proxy.shutdown(drain_timeout=0)
        if gate is not None:
            gate.close()
            await gate.wait_closed()
            if gate_tasks:
                await asyncio.gather(*tuple(gate_tasks))


@pytest.mark.parametrize("transport", ["json", "sse", "stdio"])
@pytest.mark.parametrize("cancel", [False, True], ids=["normal-drain", "deadline-cancellation"])
async def test_paginated_calls_drain_before_rebind_and_successor_discovers_fresh(
    tmp_path, monkeypatch, transport, cancel
):
    async with _gateway(tmp_path, monkeypatch, transport) as gateway:
        proxy = gateway.proxy
        calls = [asyncio.create_task(proxy.call_tool("old-owner", "lookup_customer", {}))]
        await asyncio.wait_for(gateway.entered.wait(), timeout=5)
        old_resource = gateway.resource()
        old_cache = proxy._advertised
        old_locks = proxy._discovery_locks
        assert not old_cache
        assert not proxy._drift_checked
        assert not proxy._provenance

        if cancel:
            admitted = asyncio.Event()
            enter_call = proxy._enter_call

            async def observed_enter():
                await enter_call()
                admitted.set()

            monkeypatch.setattr(proxy, "_enter_call", observed_enter)
            calls.append(asyncio.create_task(proxy.call_tool("old-waiter", "lookup_customer", {})))
            await asyncio.wait_for(admitted.wait(), timeout=5)
            assert proxy._active_calls == 2
            assert not calls[-1].done()

        draining = asyncio.Event()
        drain_calls = proxy._drain_calls

        async def observed_drain(timeout):
            draining.set()
            await drain_calls(timeout)

        monkeypatch.setattr(proxy, "_drain_calls", observed_drain)
        next_session = SessionState(session_id="successor")
        next_chain = AuditChain(next_session.session_id)
        next_genesis = list(next_chain.entries)

        async def rotate():
            async with proxy.session_rotation(drain_timeout=0 if cancel else 5) as acquired:
                assert acquired
                assert proxy._active_calls == 0
                if cancel:
                    assert not old_cache
                    assert not proxy._drift_checked
                    assert not proxy._provenance
                    faults = [e for e in gateway.chain.entries if e.entry_type == "fault"]
                    assert {e.call_id for e in faults} == {"old-owner", "old-waiter"}
                    assert all(e.detail["exception_type"] == "CancelledError" for e in faults)
                else:
                    assert (
                        next(iter(proxy._provenance.values())).outcome is ProvenanceOutcome.VERIFIED
                    )
                await proxy.rebind_session(next_session, next_chain)

        rotation = asyncio.create_task(rotate())
        try:
            await asyncio.wait_for(draining.wait(), timeout=5)
            assert proxy._session is gateway.session
            assert not rotation.done()
            if not cancel:
                assert not calls[0].done()
                if transport == "stdio":
                    assert old_resource.returncode is None
                else:
                    assert not old_resource.is_closed
                gateway.release.set()
            results = await asyncio.wait_for(
                asyncio.gather(*calls, return_exceptions=True), timeout=10
            )
            await asyncio.wait_for(rotation, timeout=10)
        finally:
            gateway.release.set()
            for task in [*calls, rotation]:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*calls, rotation, return_exceptions=True)

        if cancel:
            assert all(isinstance(result, asyncio.CancelledError) for result in results)
        else:
            assert results[0].allowed
            assert results[0].response == _RESPONSE
        assert proxy._active_calls == 0
        assert proxy._session is next_session
        assert proxy._advertised is not old_cache
        assert proxy._discovery_locks is not old_locks
        assert not proxy._advertised and not proxy._discovery_locks
        assert not proxy._drift_checked and not proxy._provenance
        assert next_chain.entries == next_genesis
        if transport == "stdio":
            assert old_resource.returncode is not None
        else:
            assert old_resource.is_closed

        old_entries = list(gateway.chain.entries)
        for call_id in ("next-cold", "next-warm"):
            result = await proxy.call_tool(call_id, "lookup_customer", {})
            assert result.allowed
            assert result.response == _RESPONSE
        assert gateway.resource() is not old_resource
        assert gateway.chain.entries == old_entries
        assert {e.call_id for e in next_chain.entries if e.call_id} == {"next-cold", "next-warm"}
        assert next(iter(proxy._provenance.values())).outcome is ProvenanceOutcome.VERIFIED
        requests = gateway.requests()
        listings = [request for request in requests if request["method"] == "tools/list"]
        assert ["cursor" in request["params"] for request in listings] == [False, True, False, True]
        assert [request["params"].get("cursor") for request in listings] == [
            None,
            _CURSOR,
            None,
            _CURSOR,
        ]
        assert sum(request["method"] == "tools/call" for request in requests) == (
            2 if cancel else 3
        )
