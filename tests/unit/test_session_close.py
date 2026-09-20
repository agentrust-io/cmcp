"""Tests for POST /sessions/{id}/close - claim issuance and session rotation."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from starlette.requests import Request
from starlette.testclient import TestClient

from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.cli import build_server
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.mcp.stdio import StdioSpawn, measure_executable
from cmcp_runtime.policy.bundle import PolicyStore
from cmcp_runtime.policy.evaluator import PolicyDecision
from cmcp_runtime.startup import RuntimeContext


@pytest.fixture
def server():
    config = Config(attestation=AttestationConfig(), dev_mode=True)

    attestation_report = MagicMock()
    attestation_report.provider = "software-only"
    attestation_report.attestation_generated_at = datetime.now(UTC)
    attestation_report.attestation_validity_seconds = 86400
    attestation_report.measurement = "0" * 64
    attestation_report.report_data = "0" * 64
    attestation_report.measurement_note = None
    attestation_report.raw_evidence = None

    bundle = MagicMock()
    bundle.bundle_hash = "sha256:" + "0" * 64
    bundle.policy_files = {"allow.cedar": "permit (principal, action, resource);"}
    bundle.manifest = MagicMock()
    bundle.manifest.version = "test-v1"
    policy_store = MagicMock(spec=PolicyStore)
    policy_store.bundle = bundle
    bundle.signing_key_id = None
    policy_store.revoked_key_ids = []

    catalog = MagicMock()
    catalog.entries = {}
    catalog.catalog_hash = "sha256:" + "1" * 64
    catalog.exceptions = []

    ctx = RuntimeContext(
        config=config,
        tee_provider=MagicMock(),
        attestation_report=attestation_report,
        signing_key=SigningKey(),
        policy_bundle=policy_store,
        catalog=catalog,
    )
    return build_server(ctx)


def test_close_returns_signed_claim_and_rotates(server):
    client = TestClient(server.app)
    old_session_id = server._session.session_id

    resp = client.post(f"/sessions/{old_session_id}/close")
    assert resp.status_code == 200
    claim = resp.json()
    assert claim["gateway"]["session_id"] == old_session_id
    assert claim["signature"]  # signed claim

    # Session rotated: new id, proxy rebound.
    assert server._session.session_id != old_session_id
    assert server._proxy._session.session_id == server._session.session_id
    assert server._audit_chain is server._proxy._audit


def test_closed_claim_retrievable_via_trace_claim_endpoint(server):
    client = TestClient(server.app)
    session_id = server._session.session_id
    client.post(f"/sessions/{session_id}/close")

    resp = client.get(f"/sessions/{session_id}/trace-claim")
    assert resp.status_code == 200
    assert resp.json()["gateway"]["session_id"] == session_id


def test_close_unknown_session_404(server):
    client = TestClient(server.app)
    resp = client.post("/sessions/not-a-real-session/close")
    assert resp.status_code == 404


def test_close_twice_404_on_second(server):
    client = TestClient(server.app)
    session_id = server._session.session_id
    assert client.post(f"/sessions/{session_id}/close").status_code == 200
    assert client.post(f"/sessions/{session_id}/close").status_code == 404


def test_audit_export_serves_closed_session(server):
    client = TestClient(server.app)
    session_id = server._session.session_id
    client.post(f"/sessions/{session_id}/close")

    resp = client.get(f"/audit/export?session_id={session_id}")
    assert resp.status_code == 200
    bundle = resp.json()
    assert bundle["session_id"] == session_id
    entry_types = [e["entry_type"] for e in bundle["entries"]]
    assert "session_start" in entry_types
    assert "session_end" in entry_types


def _stateful_stdio_catalog(script: str) -> ToolCatalog:
    entry = CatalogEntry(
        tool_name="stateful.tool",
        server=ServerIdentity(
            display_name="Stateful test server",
            url="",
            tls_fingerprint="",
            spiffe_id=None,
            transport="stdio",
            rotation_mode="key-pinned",
            spawn=StdioSpawn(
                command=sys.executable,
                args=(script,),
                binary_digest=measure_executable(script),
                measure_target=script,
            ),
        ),
        approved_definition=ApprovedDefinition(
            description="stateful test tool",
            input_schema={},
            output_schema=None,
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="public",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-09-09T00:00:00Z",
        approved_by="test",
    )
    return ToolCatalog(
        entries={entry.tool_name: entry},
        catalog_hash="sha256:" + "2" * 64,
    )


def _assert_process_exited(pid: int) -> None:
    """Check the PID without signalling it; Windows kill(pid, 0) terminates."""
    if sys.platform != "win32":
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        return

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE only
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: PID no longer exists
            return
        raise ctypes.WinError(error)
    try:
        # A retained handle can keep an exited process object addressable.
        status = kernel32.WaitForSingleObject(handle, 0)
        if status == 0xFFFFFFFF:  # WAIT_FAILED
            raise ctypes.WinError(ctypes.get_last_error())
        assert status == 0, f"process {pid} is still running (wait status {status})"
    finally:
        kernel32.CloseHandle(handle)


def _allow_proxy_call(server) -> None:
    """Keep this integration test focused on transport/session lifetime."""
    decision = PolicyDecision(
        allowed=True,
        enforcement_mode=EnforcementMode.ENFORCING,
        rule_matched=None,
        advice={},
        evaluation_ms=0.0,
    )
    server._proxy._policy.evaluate = MagicMock(return_value=decision)
    server._proxy._mcp_gateway = MagicMock()
    server._proxy._mcp_gateway.intercept_tool_call.return_value = (True, "ok")
    server._proxy._mcp_gateway.intercept_tool_response.return_value = SimpleNamespace(
        allowed=True,
        content=None,
        threats=[],
        action="allowed",
    )


_STATEFUL_UPSTREAM = """
import json
import os
import sys

count = 0
for line in sys.stdin:
    request = json.loads(line)
    if request["method"] == "tools/list":
        result = {"tools": [{"name": "stateful.tool", "description": "stateful test tool", "inputSchema": {}}]}
    else:
        count += 1
        result = {"content": [{"type": "text", "text": f"{os.getpid()}:{count}"}]}
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
""".strip()


@pytest.fixture
async def stateful_gateway(server, tmp_path, monkeypatch):
    """Configure one real upstream; reap children even when tests mock close()."""
    from cmcp_runtime.mcp.stdio import StdioServer

    script = tmp_path / "stateful_server.py"
    script.write_text(_STATEFUL_UPSTREAM)
    catalog = _stateful_stdio_catalog(str(script))
    server._proxy._catalog = catalog
    server._proxy._catalog_hash = catalog.catalog_hash
    _allow_proxy_call(server)
    children = []
    original_start = StdioServer.start

    async def start(child):
        children.append(child)
        await original_start(child)

    monkeypatch.setattr(StdioServer, "start", start)
    try:
        yield
    finally:
        for child in children:
            await StdioServer.close(child)


async def _tool_call(client, rpc_id="call"):
    return await client.post("/mcp", json={
        "jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
        "params": {"name": "stateful.tool", "arguments": {}},
    })


@pytest.mark.asyncio
async def test_close_endpoint_terminates_stateful_child_and_resets_session_caches(
    server, stateful_gateway
):
    """A real close rotates away the child and all one-session upstream caches."""
    http_client = AsyncMock()
    server._proxy._http_clients["test-client"] = http_client

    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        first = await _tool_call(client, 'before-close')
        assert first.status_code == 200
        assert first.json()["result"]["content"][0]["text"].endswith(":1")

        old_child = next(iter(server._proxy._stdio_servers.values()))
        old_process = old_child._proc
        assert old_process is not None

        assert server._proxy._provenance
        assert server._proxy._drift_checked
        old_session_id = server._session.session_id
        assert server._proxy._session.session_id == old_session_id

        closed = await client.post(f"/sessions/{old_session_id}/close")
        assert closed.status_code == 200, closed.text
        assert old_child._proc is None
        assert old_process.returncode is not None
        _assert_process_exited(old_process.pid)
        assert server._proxy._stdio_servers == {}
        assert http_client.aclose.await_count == 1
        assert server._proxy._http_clients == {}
        assert server._proxy._provenance == {}
        assert server._proxy._drift_checked == set()

        second = await _tool_call(client, 'after-close')
        assert second.status_code == 200
        assert second.json()["result"]["content"][0]["text"].endswith(":1")
        assert next(iter(server._proxy._stdio_servers.values())) is not old_child

    await server._proxy.aclose()


@pytest.mark.asyncio
async def test_reset_endpoint_terminates_stateful_child_and_resets_session_caches(
    server, stateful_gateway
):
    """Reset ends a session and opens a successor, so it releases what close does."""
    http_client = AsyncMock()
    server._proxy._http_clients["test-client"] = http_client

    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        first = await _tool_call(client, 'before-reset')
        assert first.status_code == 200
        assert first.json()["result"]["content"][0]["text"].endswith(":1")

        old_child = next(iter(server._proxy._stdio_servers.values()))
        old_process = old_child._proc
        assert old_process is not None

        assert server._proxy._provenance
        assert server._proxy._drift_checked
        old_session_id = server._session.session_id

        reset = await client.post(f"/sessions/{old_session_id}/reset")
        assert reset.status_code == 200, reset.text
        assert reset.json()["new_session_id"] != old_session_id
        assert old_child._proc is None
        assert old_process.returncode is not None
        _assert_process_exited(old_process.pid)
        assert server._proxy._stdio_servers == {}
        assert http_client.aclose.await_count == 1
        assert server._proxy._http_clients == {}
        assert server._proxy._provenance == {}
        assert server._proxy._drift_checked == set()

        second = await _tool_call(client, 'after-reset')
        assert second.status_code == 200
        assert second.json()["result"]["content"][0]["text"].endswith(":1")
        assert next(iter(server._proxy._stdio_servers.values())) is not old_child

    await server._proxy.aclose()



@pytest.mark.asyncio
async def test_a_stuck_transition_times_admission_out_instead_of_hanging(server, monkeypatch):
    """A call waits out a rotation, but a stuck one must not hold it forever.

    Waiting is right while the transition can still resolve. When it cannot,
    an unbounded wait turns a failed close into an unreachable gateway with no
    signal, so the caller is told what needs fixing instead.
    """
    from cmcp_runtime.errors import SessionCloseIncomplete

    monkeypatch.setattr(server._proxy, "_admission_wait_s", lambda: 0.05)
    sid = server._session.session_id
    monkeypatch.setattr(
        server._session_manager,
        "create_session",
        MagicMock(side_effect=RuntimeError("successor")),
    )
    api_transport = httpx.ASGITransport(app=server.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=api_transport, base_url="http://test") as api:
        assert (await api.post(f"/sessions/{sid}/close")).status_code == 500
        assert server._proxy._close_committed

        with pytest.raises(SessionCloseIncomplete, match="no successor was adopted"):
            await asyncio.wait_for(server._proxy._enter_call(), 1)
        assert server._proxy._active_calls == 0


@pytest.mark.asyncio
async def test_real_httpx_client_close_failure_is_dropped(server):
    """The best-effort path against real httpx machinery, not a mocked client."""

    class FailingTransport(httpx.AsyncHTTPTransport):
        async def aclose(self) -> None:
            raise OSError("injected transport close failure")

    server._proxy._http_clients["upstream"] = httpx.AsyncClient(transport=FailingTransport())
    sid = server._session.session_id

    api_transport = httpx.ASGITransport(app=server.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=api_transport, base_url="http://test") as api:
        resp = await api.post(f"/sessions/{sid}/close")

    assert resp.status_code == 200, resp.text
    assert server._proxy._http_clients == {}
    assert not server._proxy._cleanup_incomplete
    assert server._session.session_id != sid


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["close", "reset"])
async def test_failed_http_client_close_is_dropped_not_retained(server, endpoint, caplog):
    """HTTP close is best-effort: a failure drops the client instead of sealing.

    AsyncClient marks itself closed and HTTPcore empties its pool before the
    underlying streams are released, so nothing a retry could reach survives a
    failed close. Retaining the client would advertise a recovery that does not
    exist. Dropping it is what stops the successor reusing it, which is the
    guarantee #625 is actually about.
    """
    proxy = server._proxy
    sid = server._session.session_id
    failing = AsyncMock(spec=httpx.AsyncClient)
    failing.aclose.side_effect = OSError("injected client close failure")
    proxy._http_clients["loopback"] = failing

    api_transport = httpx.ASGITransport(app=server.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=api_transport, base_url="http://test") as api:
        with caplog.at_level(logging.ERROR, logger="cmcp_runtime.mcp.proxy"):
            resp = await api.post(f"/sessions/{sid}/{endpoint}")

    assert resp.status_code == 200, resp.text
    assert failing.aclose.await_count == 1
    assert proxy._http_clients == {}
    # A child would have sealed here; a socket does not.
    assert not proxy._cleanup_incomplete
    assert not proxy._session_rotation_in_progress
    assert any("failed to close and was dropped" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["close", "reset"])
async def test_cancelling_cleanup_recovery_keeps_admission_sealed(server, monkeypatch, endpoint):
    proxy = server._proxy
    sid = server._session.session_id
    resource = SimpleNamespace(close=AsyncMock(side_effect=[OSError("close failed"), None]))
    proxy._stdio_servers[("retained",)] = resource
    api_transport = httpx.ASGITransport(app=server.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=api_transport, base_url="http://test") as api:
        first = await api.post(f"/sessions/{sid}/reset")
        assert first.status_code == 500
        assert proxy._cleanup_incomplete
        assert proxy._session_rotation_in_progress

        drain_entered = asyncio.Event()
        original_drain = proxy._drain_calls

        async def pause_drain(timeout):
            drain_entered.set()
            await asyncio.Event().wait()
            await original_drain(timeout)

        monkeypatch.setattr(proxy, "_drain_calls", pause_drain)
        handler = server._session_close if endpoint == "close" else server._session_reset
        request = Request({"type": "http", "path_params": {"session_id": sid}})
        retry = asyncio.create_task(handler(request))
        try:
            await asyncio.wait_for(drain_entered.wait(), 1)
            retry.cancel()
            await asyncio.gather(retry, return_exceptions=True)
            assert retry.cancelled()
        finally:
            retry.cancel()
            await asyncio.gather(retry, return_exceptions=True)
            monkeypatch.setattr(proxy, "_drain_calls", original_drain)

        assert proxy._cleanup_incomplete
        assert proxy._session_rotation_in_progress
        assert proxy._stdio_servers[("retained",)] is resource
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(proxy._enter_call(), .02)
        assert proxy._active_calls == 0

        recovered = await api.post(f"/sessions/{sid}/reset")
        assert recovered.status_code == 200
        assert resource.close.await_count == 2
        assert not proxy._cleanup_incomplete
        assert not proxy._session_rotation_in_progress


@pytest.mark.asyncio
async def test_reset_endpoint_waits_for_an_inflight_call(server):
    """Reset drains first; a live call never has its child closed underneath it."""
    entered = asyncio.Event()
    release = asyncio.Event()
    drain_started = asyncio.Event()
    cleanup_started = asyncio.Event()
    allow_cleanup = asyncio.Event()

    async def slow_call(*args, **kwargs):
        entered.set()
        await release.wait()
        return SimpleNamespace(
            allowed=False,
            deny_reason="test",
            would_have_denied=False,
            response=None,
            latency_us=0,
            audit_entry_hash=server._proxy._audit.chain_tip,
            advice=None,
        )

    server._proxy._call_tool_impl = slow_call
    async def close_resource():
        cleanup_started.set()
        await allow_cleanup.wait()

    resource = SimpleNamespace(close=AsyncMock(side_effect=close_resource))
    server._proxy._stdio_servers[("held-resource",)] = resource
    original_close = server._proxy.aclose

    async def close_after_drain():
        # Observe ordering at cleanup entry, before gather schedules resource
        # coroutines. An event checked by the test task can miss that window.
        assert server._proxy._active_calls == 0
        await original_close()

    server._proxy.aclose = close_after_drain
    original_seal = server._proxy._seal_and_drain

    async def seal(drain_timeout):
        drain_started.set()
        return await original_seal(drain_timeout)

    server._proxy._seal_and_drain = seal
    old_session_id = server._session.session_id
    call_task = asyncio.create_task(server._proxy.call_tool("call-1", "test.tool", {}))
    await entered.wait()

    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        reset_task = asyncio.create_task(client.post(f"/sessions/{old_session_id}/reset"))
        try:
            await asyncio.wait_for(drain_started.wait(), timeout=1)
            # These are the boundary assertions: the request must not start
            # cleanup or mutate the session while an admitted call is running.
            assert server._proxy._active_calls == 1
            assert not cleanup_started.is_set()
            assert server._session.session_id == old_session_id

            release.set()
            await call_task
            await asyncio.wait_for(cleanup_started.wait(), timeout=1)
            assert server._session.session_id == old_session_id
            allow_cleanup.set()
            reset = await reset_task
        finally:
            release.set()
            allow_cleanup.set()
            # Surface the cleanup-entry assertion if ordering is broken.
            await asyncio.gather(call_task, reset_task)

    assert reset.status_code == 200
    assert server._proxy._active_calls == 0


@pytest.mark.asyncio
async def test_stale_reset_does_not_drain_calls_in_successor_session(server, monkeypatch):
    """A reset queued behind close checks its id before draining the successor."""
    proxy = server._proxy
    server._session_close_drain_s = 0.01
    old_session_id = server._session.session_id
    cleanup_started = asyncio.Event()
    allow_cleanup = asyncio.Event()
    request_waiting_for_transition = asyncio.Event()
    allow_stale_reset_to_acquire = asyncio.Event()
    successor_call_started = asyncio.Event()
    release_successor_call = asyncio.Event()
    original_exclude = proxy.exclude_session_transition
    original_call = proxy._call_tool_impl

    async def close_resource():
        cleanup_started.set()
        await allow_cleanup.wait()

    proxy._stdio_servers[("held-resource",)] = SimpleNamespace(
        close=AsyncMock(side_effect=close_resource)
    )

    async def successor_call(*args, **kwargs):
        successor_call_started.set()
        await release_successor_call.wait()
        return await original_call(*args, **kwargs)

    @asynccontextmanager
    async def delay_transition(**kwargs):
        request_waiting_for_transition.set()
        await allow_stale_reset_to_acquire.wait()
        async with original_exclude(**kwargs) as acquired:
            yield acquired

    monkeypatch.setattr(proxy, "_call_tool_impl", successor_call)
    monkeypatch.setattr(proxy, "exclude_session_transition", delay_transition)

    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        close_task = asyncio.create_task(
            client.post(f"/sessions/{old_session_id}/close")
        )
        await cleanup_started.wait()
        stale_reset_task = asyncio.create_task(
            client.post(f"/sessions/{old_session_id}/reset")
        )
        try:
            await request_waiting_for_transition.wait()
            allow_cleanup.set()
            closed = await close_task
            assert closed.status_code == 200
            assert server._session.session_id != old_session_id

            call_task = asyncio.create_task(
                proxy.call_tool("successor-call", "unknown.tool", {})
            )
            await successor_call_started.wait()
            successor_id = server._session.session_id

            allow_stale_reset_to_acquire.set()
            stale_reset = await stale_reset_task
            assert stale_reset.status_code == 404
            assert server._session.session_id == successor_id
            assert not call_task.done()
            assert proxy._active_calls == 1
        finally:
            allow_cleanup.set()
            allow_stale_reset_to_acquire.set()
            release_successor_call.set()
            await asyncio.gather(close_task, stale_reset_task, return_exceptions=True)
            if "call_task" in locals():
                await asyncio.gather(call_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_reset_drain_retry_recovers_after_cancelled_call_finishes(server, monkeypatch):
    from cmcp_runtime.mcp import proxy as proxy_module

    old_session_id = server._session.session_id
    entered = asyncio.Event()
    cancellation_seen = asyncio.Event()
    release = asyncio.Event()
    server._session_close_drain_s = 0.01
    monkeypatch.setattr(proxy_module, "SESSION_CANCELLATION_GRACE_SECONDS", 0.01)

    async def delayed_hydrate():
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancellation_seen.set()
            await release.wait()
            raise

    monkeypatch.setattr(server._session, "hydrate", delayed_hydrate)
    call_task = asyncio.create_task(
        server._proxy.call_tool("reset-drain-call", "unknown.tool", {})
    )
    await entered.wait()

    transport = httpx.ASGITransport(app=server.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        first_reset = await client.post(f"/sessions/{old_session_id}/reset")
        assert first_reset.status_code == 500
        assert cancellation_seen.is_set()
        assert server._session.session_id == old_session_id
        assert server._proxy._drain_incomplete

        release.set()
        await asyncio.gather(call_task, return_exceptions=True)
        assert call_task.cancelled()
        terminals = [
            entry for entry in server._audit_chain.entries
            if entry.call_id == "reset-drain-call"
        ]
        assert len(terminals) == 1
        assert terminals[0].entry_type == "fault"

        retry = await client.post(f"/sessions/{old_session_id}/reset")

    assert retry.status_code == 200
    assert server._session.session_id != old_session_id
    assert not server._proxy._drain_incomplete
    assert not server._proxy._session_rotation_in_progress


@pytest.mark.asyncio
async def test_close_endpoint_waits_for_an_inflight_call(server):
    """The close claim waits until an admitted call has reached a terminal outcome."""
    entered = asyncio.Event()
    release = asyncio.Event()
    rotation_started = asyncio.Event()

    async def slow_call(*args, **kwargs):
        entered.set()
        await release.wait()
        return SimpleNamespace(
            allowed=False,
            deny_reason="test",
            would_have_denied=False,
            response=None,
            latency_us=0,
            audit_entry_hash=server._proxy._audit.chain_tip,
            advice=None,
        )

    server._proxy._call_tool_impl = slow_call
    original_begin = server._proxy._begin_session_rotation

    async def begin_rotation(expected_session_id, *, drain_timeout):
        rotation_started.set()
        return await original_begin(expected_session_id, drain_timeout=drain_timeout)

    server._proxy._begin_session_rotation = begin_rotation
    old_session_id = server._session.session_id
    call_task = asyncio.create_task(server._proxy.call_tool("call-1", "test.tool", {}))
    await entered.wait()

    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        close_task = asyncio.create_task(client.post(f"/sessions/{old_session_id}/close"))
        await rotation_started.wait()
        assert not close_task.done()

        release.set()
        await call_task
        closed = await close_task

    assert closed.status_code == 200
    assert server._proxy._active_calls == 0


@pytest.mark.asyncio
async def test_drain_deadline_cancels_a_stuck_call_and_records_its_fault(server):
    entered = asyncio.Event()
    never_releases = asyncio.Event()

    async def stuck_call(*args, **kwargs):
        entered.set()
        await never_releases.wait()  # never happens
        raise AssertionError("unreachable")

    server._proxy._call_tool_impl = stuck_call
    old_chain = server._proxy._audit
    call_task = asyncio.create_task(server._proxy.call_tool("call-1", "test.tool", {}))
    await entered.wait()

    server._session_close_drain_s = 0.05
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server.app), base_url="http://testserver"
    ) as client:
        closed = await client.post(f"/sessions/{server._session.session_id}/close")
    assert closed.status_code == 200
    assert closed.json()["gateway"]["audit_chain"]["length"] == old_chain.length
    assert old_chain.entries[-1].entry_type == "session_end"

    assert call_task.cancelled() or isinstance(
        call_task.exception(), asyncio.CancelledError
    )
    assert server._proxy._active_calls == 0
    fault_entries = [e for e in old_chain.entries if e.entry_type == "fault"]
    assert fault_entries, "the cancelled call's terminal outcome must be in the claim"
    assert fault_entries[-1].detail["exception_type"] == "CancelledError"


@pytest.mark.asyncio
async def test_cancelled_hydration_is_recorded_before_close_signs(server, monkeypatch):
    from cmcp_runtime.session.store import InMemorySessionStateStore

    proxy = server._proxy
    chain = server._audit_chain
    sid = server._session.session_id
    store = InMemorySessionStateStore()
    server._session.state_store = store
    server._session_close_drain_s = 0.01
    entered = asyncio.Event()
    original_hydrate = server._session.hydrate

    async def hydrate():
        entered.set()
        return await original_hydrate()

    monkeypatch.setattr(server._session, "hydrate", hydrate)
    async with store.exclusive(sid):
        call = asyncio.create_task(proxy.call_tool("hydrating-call", "test.tool", {}))
        try:
            await asyncio.wait_for(entered.wait(), 1)
            assert proxy._active_calls == 1
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=server.app), base_url="http://test"
            ) as client:
                closed = await client.post(f"/sessions/{sid}/close")
        finally:
            call.cancel()
            await asyncio.gather(call, return_exceptions=True)

    assert call.cancelled()
    assert closed.status_code == 200
    terminals = [e for e in chain.entries if e.call_id == "hydrating-call"]
    assert len(terminals) == 1
    assert terminals[0].entry_type == "fault"
    assert terminals[0].detail["exception_type"] == "CancelledError"
    assert chain.entries[-1].entry_type == "session_end"
    assert closed.json()["gateway"]["audit_chain"]["length"] == chain.length


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_at_deadline", [True, False])
async def test_failed_terminal_write_blocks_close_and_reset(
    server, monkeypatch, cancel_at_deadline
):
    from cmcp_runtime.errors import SessionCloseIncomplete

    proxy = server._proxy
    chain = server._audit_chain
    sid = server._session.session_id
    entered = asyncio.Event()
    resource = SimpleNamespace(close=AsyncMock())
    proxy._stdio_servers[("retained-child",)] = resource

    async def failing_call(*args, **kwargs):
        entered.set()
        if cancel_at_deadline:
            await asyncio.Event().wait()
        raise RuntimeError("call failed before close")

    original_append = chain.append

    def append(entry_type, *args, **kwargs):
        if entry_type == "fault":
            raise OSError("injected terminal persistence failure")
        return original_append(entry_type, *args, **kwargs)

    monkeypatch.setattr(proxy, "_call_tool_impl", failing_call)
    monkeypatch.setattr(chain, "append", append)
    close_session = MagicMock(wraps=server._session_manager.close_session)
    monkeypatch.setattr(server._session_manager, "close_session", close_session)
    call = asyncio.create_task(proxy.call_tool("lost-terminal", "test.tool", {}))
    try:
        await asyncio.wait_for(entered.wait(), 1)
        if not cancel_at_deadline:
            await asyncio.gather(call, return_exceptions=True)
        server._session_close_drain_s = 0.01
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=server.app, raise_app_exceptions=False),
            base_url="http://test",
        ) as client:
            assert (await client.post(f"/sessions/{sid}/close")).status_code == 500
            # Restoring the writer cannot reconstruct the missing outcome.
            monkeypatch.setattr(chain, "append", original_append)
            assert (await client.post(f"/sessions/{sid}/close")).status_code == 500
            assert (await client.post(f"/sessions/{sid}/reset")).status_code == 500
        with pytest.raises(SessionCloseIncomplete):
            await asyncio.wait_for(proxy.call_tool("new-call", "test.tool", {}), 1)
        assert proxy._active_calls == 0
        close_session.assert_not_called()
        assert server._session.session_id == sid
        assert server._audit_chain is chain
        assert not server._pending_close
        assert not any(e.entry_type == "session_end" for e in chain.entries)
        resource.close.assert_not_awaited()
    finally:
        call.cancel()
        await asyncio.gather(call, return_exceptions=True)
        # Shutdown can release resources without issuing an incomplete claim.
        await proxy.shutdown(drain_timeout=0.1)
    resource.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_drain_raises_an_explicit_failure_when_cancellation_is_not_honored(server):
    from cmcp_runtime.errors import SessionDrainIncomplete

    entered = asyncio.Event()
    stop_ignoring_cancellation = asyncio.Event()

    async def uncooperative_call(*args, **kwargs):
        entered.set()
        while not stop_ignoring_cancellation.is_set():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                continue  # does not honor cancellation, until told to stop
        raise asyncio.CancelledError

    server._proxy._call_tool_impl = uncooperative_call
    call_task = asyncio.create_task(server._proxy.call_tool("call-1", "test.tool", {}))
    await entered.wait()

    with pytest.raises(SessionDrainIncomplete):
        async with server._proxy.session_rotation(drain_timeout=0.02):
            pytest.fail("must not proceed into the close body with the call still active")

    # No claim committed, but admitting more work after failed cancellation is unsafe.
    assert server._proxy._session_rotation_in_progress is True
    assert server._proxy._close_committed is False
    admission = asyncio.create_task(server._proxy._enter_call())
    await asyncio.sleep(0)
    assert not admission.done()
    with pytest.raises(SessionDrainIncomplete):
        async with server._proxy.exclude_session_transition():
            pytest.fail("reset must not bypass the failed drain")

    # Teardown: only now let the call actually stop, so nothing is left
    # running past the test for pytest-asyncio's loop teardown to hang on.
    stop_ignoring_cancellation.set()
    call_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call_task
    assert not admission.done()
    async with server._proxy.session_rotation(drain_timeout=0.1):
        new_session, new_chain = server._session_manager.create_session()
        await server._proxy.rebind_session(new_session, new_chain)
    await asyncio.wait_for(admission, 1)
    await server._proxy._leave_call()


@pytest.mark.asyncio
async def test_gateway_shutdown_terminates_spawned_children(server, stateful_gateway):

    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await _tool_call(client, '1')
        assert resp.status_code == 200
    live_child = next(iter(server._proxy._stdio_servers.values()))
    process = live_child._proc
    assert process is not None

    # Drive the ASGI lifespan protocol directly: startup then shutdown, the
    # same sequence uvicorn runs around the process's actual lifetime.
    async with server.app.router.lifespan_context(server.app):
        pass

    assert live_child._proc is None
    assert process.returncode is not None
    _assert_process_exited(process.pid)
    assert server._proxy._stdio_servers == {}


@pytest.mark.asyncio
async def test_close_retry_after_rebind_failure_reuses_the_committed_claim(server, stateful_gateway):

    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        first_call = await _tool_call(client, 'before-close')
        assert first_call.status_code == 200
        old_session_id = server._session.session_id
        old_chain = server._audit_chain

        real_close_session = server._session_manager.close_session
        close_session_calls = []

        def counting_close_session(*args, **kwargs):
            close_session_calls.append(1)
            return real_close_session(*args, **kwargs)

        server._session_manager.close_session = MagicMock(side_effect=counting_close_session)

        # Fail the first close attempt's rebind (aclose() on the live child).
        live_child = next(iter(server._proxy._stdio_servers.values()))
        live_child.close = AsyncMock(
            side_effect=[RuntimeError("close failed"), None]
        )

        with pytest.raises(RuntimeError, match="close failed"):
            await client.post(f"/sessions/{old_session_id}/close")

        assert len(close_session_calls) == 1
        assert server._pending_close is not None
        assert server._pending_close[0] == old_session_id
        assert old_session_id in server._closed_chains
        assert server._session.session_id == server._proxy._session.session_id
        assert server._audit_chain is server._proxy._audit
        assert server._proxy._session_rotation_in_progress
        assert server._proxy._close_committed
        assert server._proxy._active_calls == 0
        session_end_count = sum(
            1 for e in old_chain.entries if e.entry_type == "session_end"
        )
        assert session_end_count == 1
        cached_new_session_id = server._pending_close[2].session_id

        assert live_child.close.await_count == 1
        assert server._proxy._stdio_servers, "failed close must not drop the untracked child"

        second = await client.post(f"/sessions/{old_session_id}/close")
        assert second.status_code == 200, second.text
        assert len(close_session_calls) == 1  # still just the one real call
        assert server._pending_close is None
        session_end_count = sum(
            1 for e in old_chain.entries if e.entry_type == "session_end"
        )
        assert session_end_count == 1  # not doubled

        assert live_child.close.await_count == 2, "retry must actually re-attempt the failed close"
        assert server._proxy._stdio_servers == {}, "the child must be gone from tracking once closed"
        assert server._session.session_id == cached_new_session_id
        assert server._proxy._session.session_id == cached_new_session_id

    await server._proxy.aclose()


@pytest.mark.asyncio
async def test_close_failure_before_rebind_preserves_the_old_session(server, stateful_gateway):

    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        first = await _tool_call(client, 'before-close')
        assert first.status_code == 200
        live_child = next(iter(server._proxy._stdio_servers.values()))
        old_session_id = server._session.session_id

        server._session_manager.close_session = MagicMock(
            side_effect=RuntimeError("audit chain write failed")
        )
        with pytest.raises(RuntimeError, match="audit chain write failed"):
            await client.post(f"/sessions/{old_session_id}/close")

        # The close never committed: nothing was rotated or torn down.
        assert server._session.session_id == old_session_id
        assert server._proxy._session.session_id == old_session_id
        assert next(iter(server._proxy._stdio_servers.values())) is live_child
        assert live_child._proc is not None
        assert server._proxy._provenance
        assert server._proxy._drift_checked

        # The barrier released: the old session keeps serving calls.
        assert server._proxy._session_rotation_in_progress is False
        assert server._proxy._active_calls == 0
        second = await _tool_call(client, 'after-failed-close')
        assert second.status_code == 200
        assert second.json()["result"]["content"][0]["text"].endswith(":2")

    await server._proxy.aclose()


@pytest.mark.asyncio
async def test_committed_close_blocks_new_mcp_calls_until_rebind_resolves(server, stateful_gateway):

    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await _tool_call(client, '1')
        old_session_id = server._session.session_id
        live_child = next(iter(server._proxy._stdio_servers.values()))
        live_child.close = AsyncMock(side_effect=RuntimeError("close failed"))

        with pytest.raises(RuntimeError, match="close failed"):
            await client.post(f"/sessions/{old_session_id}/close")

        # The claim committed; the barrier must stay sealed rather than
        # reopen admission to the old (already-signed) session.
        assert server._pending_close is not None
        assert server._pending_close[0] == old_session_id
        assert server._proxy._session_rotation_in_progress is True

        blocked_call = asyncio.create_task(
            _tool_call(client, '2')
        )
        await asyncio.sleep(0.05)
        assert not blocked_call.done(), "a call must not be admitted to a committed, unresolved close"

        # Resolve the close: retry succeeds once the child actually closes.
        live_child.close = AsyncMock()
        retried = await client.post(f"/sessions/{old_session_id}/close")
        assert retried.status_code == 200, retried.text

        # The previously blocked call is now admitted, to the NEW session.
        result = await blocked_call
        assert result.status_code == 200
        assert server._proxy._session_rotation_in_progress is False


@pytest.mark.asyncio
async def test_reset_cannot_run_between_a_committed_close_and_its_rebind(server, stateful_gateway):

    close_may_finish = asyncio.Event()

    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await _tool_call(client, '1')
        old_session_id = server._session.session_id
        old_chain = server._audit_chain
        live_child = next(iter(server._proxy._stdio_servers.values()))

        async def blocked_close(*args, **kwargs):
            await close_may_finish.wait()

        live_child.close = blocked_close

        close_task = asyncio.create_task(client.post(f"/sessions/{old_session_id}/close"))
        # Wait for close to commit (session_end appended) and enter rebind,
        # where it is now blocked inside aclose() -> live_child.close().
        deadline = asyncio.get_running_loop().time() + 2
        while server._pending_close is None or server._pending_close[0] != old_session_id:
            assert asyncio.get_running_loop().time() < deadline, "close never committed"
            await asyncio.sleep(0.01)

        reset_task = asyncio.create_task(client.post(f"/sessions/{old_session_id}/reset"))
        await asyncio.sleep(0.05)
        assert not reset_task.done(), "reset must not interleave with a committed, unresolved close"

        chain_length_while_blocked = len(old_chain.entries)
        close_may_finish.set()
        closed = await close_task
        reset_resp = await reset_task

        assert closed.status_code == 200, closed.text
        # The chain gained nothing between commit and rebind resolving: no
        # session_reset entry landed on the already-closed chain.
        entry_types_after = [e.entry_type for e in old_chain.entries]
        assert entry_types_after.count("session_reset") == 0, (
            "a concurrent reset must not mutate a chain whose claim already signed"
        )
        assert chain_length_while_blocked == len(old_chain.entries)
        assert reset_resp.status_code in (200, 404)
    assert server._proxy._session_rotation_in_progress is False


@pytest.mark.asyncio
async def test_committed_rotation_has_one_owner(server):
    proxy = server._proxy
    entered = asyncio.Event()

    async def contender():
        async with proxy.session_rotation():
            entered.set()

    async with proxy.session_rotation():
        proxy.mark_close_committed()
        task = asyncio.create_task(contender())
        await asyncio.sleep(0)
        assert not entered.is_set()
    await asyncio.wait_for(task, 1)
    assert entered.is_set()


@pytest.mark.asyncio
async def test_successor_failure_seals_claim_and_retry_recovers(server, monkeypatch):
    sid = server._session.session_id
    original = server._session_manager.create_session
    monkeypatch.setattr(server._session_manager, 'create_session', MagicMock(side_effect=RuntimeError('successor')))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app, raise_app_exceptions=False), base_url='http://test') as client:
        assert (await client.post(f'/sessions/{sid}/close')).status_code == 500
        claim = server._session_manager.get_trace_claim(sid)
        assert claim is not None
        admission = asyncio.create_task(server._proxy._enter_call())
        await asyncio.sleep(0)
        assert not admission.done()
        monkeypatch.setattr(server._session_manager, 'create_session', original)
        response = await client.post(f'/sessions/{sid}/close')
        assert response.status_code == 200
        assert response.json() == claim
        await asyncio.wait_for(admission, 1)
        await server._proxy._leave_call()


@pytest.mark.asyncio
async def test_cancelled_stdio_close_retains_process_for_retry():
    from cmcp_runtime.mcp.stdio import StdioServer

    # Real close implementation, controlled process wait at the cancellation boundary.
    child = object.__new__(StdioServer)
    waiting = asyncio.Event()
    released = asyncio.Event()

    async def wait():
        waiting.set()
        await released.wait()
        return 0

    proc = SimpleNamespace(returncode=None, stdin=None, terminate=MagicMock(), wait=AsyncMock(side_effect=wait))
    child._proc = proc
    task = asyncio.create_task(child.close())
    await waiting.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert child._proc is proc
    released.set()
    await child.close()
    assert proc.wait.await_count == 2
    assert child._proc is None


@pytest.mark.asyncio
async def test_partial_claim_failure_seals_calls_and_rejects_reset(server):
    sid = server._session.session_id
    server._session_manager._ctx.attestation_report.provider = 'hardware'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app, raise_app_exceptions=False), base_url='http://test') as client:
        assert (await client.post(f'/sessions/{sid}/close')).status_code == 500
        assert server._session_manager.is_closing(sid)
        admission = asyncio.create_task(server._proxy._enter_call())
        await asyncio.sleep(0)
        assert not admission.done()
        reset = await asyncio.wait_for(client.post(f'/sessions/{sid}/reset'), 1)
        assert reset.status_code == 500
        assert (await client.post(f'/sessions/{sid}/close')).status_code == 500
        assert server._session.session_id == sid
        assert sum(e.entry_type == 'session_end' for e in server._audit_chain.entries) == 1
        assert not any(e.entry_type == 'session_reset' for e in server._audit_chain.entries)
        admission.cancel()
        with pytest.raises(asyncio.CancelledError):
            await admission


@pytest.mark.asyncio
async def test_overlapping_close_during_cleanup_does_not_close_resource_twice(server):
    sid = server._session.session_id
    entered = asyncio.Event()
    release = asyncio.Event()

    async def close():
        entered.set()
        await release.wait()

    resource = SimpleNamespace(close=AsyncMock(side_effect=close))
    server._proxy._stdio_servers[('controlled-child',)] = resource
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app), base_url='http://test') as client:
        first = asyncio.create_task(client.post(f'/sessions/{sid}/close'))
        await entered.wait()
        second = asyncio.create_task(client.post(f'/sessions/{sid}/close'))
        await asyncio.sleep(0)
        release.set()
        responses = await asyncio.wait_for(asyncio.gather(first, second), 2)
    assert [response.status_code for response in responses] == [200, 404]
    assert resource.close.await_count == 1


@pytest.mark.asyncio
async def test_shutdown_waits_for_cancelled_spawn_and_rejects_new_resources(server, monkeypatch):
    from cmcp_runtime.errors import UpstreamUnavailable
    from cmcp_runtime.mcp import proxy as proxy_module

    entered = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()
    children = []

    class Child:
        def __init__(self, *args, **kwargs):
            self.close = AsyncMock()
            children.append(self)

        async def start(self):
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                cancelled.set()
                await release.wait()

    monkeypatch.setattr(proxy_module, 'StdioServer', Child)
    entry = next(iter(_stateful_stdio_catalog(__file__).entries.values()))

    async def call(*args, **kwargs):
        await server._proxy._stdio_for(entry)
        return SimpleNamespace()

    monkeypatch.setattr(server._proxy, '_call_tool_impl', call)
    lifetime = server._lifespan(server.app)
    await lifetime.__aenter__()
    task = asyncio.create_task(server._proxy.call_tool('spawn', 'stateful.tool', {}))
    await entered.wait()
    server._session_close_drain_s = 0.01
    shutdown = asyncio.create_task(lifetime.__aexit__(None, None, None))
    await cancelled.wait()
    assert not shutdown.done()
    with pytest.raises(UpstreamUnavailable):
        await server._proxy._enter_call()
    with pytest.raises(UpstreamUnavailable):
        server._proxy._client_for_upstream(entry)
    with pytest.raises(UpstreamUnavailable):
        await server._proxy._stdio_for(entry)
    release.set()
    await asyncio.wait_for(asyncio.gather(task, shutdown), 1)
    assert children[0].close.await_count == 1
    assert not server._proxy._stdio_servers
    with pytest.raises(UpstreamUnavailable):
        await server._proxy._enter_call()


@pytest.mark.asyncio
async def test_shutdown_incomplete_drain_is_explicit_and_retryable(server, monkeypatch):
    from cmcp_runtime.errors import SessionDrainIncomplete, UpstreamUnavailable
    from cmcp_runtime.mcp import proxy as proxy_module

    entered = asyncio.Event()
    release = asyncio.Event()
    resource = SimpleNamespace(close=AsyncMock())
    server._proxy._stdio_servers[('child',)] = resource
    monkeypatch.setattr(proxy_module, 'SESSION_CANCELLATION_GRACE_SECONDS', 0.01)

    async def call(*args, **kwargs):
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()
        return SimpleNamespace()

    monkeypatch.setattr(server._proxy, '_call_tool_impl', call)
    task = asyncio.create_task(server._proxy.call_tool('stuck', 'tool', {}))
    await entered.wait()
    with pytest.raises(SessionDrainIncomplete):
        await server._proxy.shutdown(drain_timeout=0.01)
    assert resource.close.await_count == 0
    with pytest.raises(UpstreamUnavailable):
        await server._proxy._enter_call()
    release.set()
    await task
    await server._proxy.shutdown(drain_timeout=0.1)
    assert resource.close.await_count == 1
    assert not server._proxy._stdio_servers


@pytest.mark.asyncio
async def test_a_sealed_gateway_answers_tool_calls_instead_of_hanging(server, monkeypatch):
    """Assert the bound where a caller actually feels it, not at the guard.

    Every other admission test drives `_enter_call` directly, which proves the
    guard exists but not that a client is ever answered by it. An unresolvable
    close used to leave real tool calls parked on an open socket with no signal,
    so this drives the endpoint and requires a response.
    """
    monkeypatch.setattr(server._proxy, "_admission_wait_s", lambda: 0.05)
    sid = server._session.session_id
    monkeypatch.setattr(
        server._session_manager,
        "create_session",
        MagicMock(side_effect=RuntimeError("successor")),
    )
    api_transport = httpx.ASGITransport(app=server.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=api_transport, base_url="http://test") as api:
        assert (await api.post(f"/sessions/{sid}/close")).status_code == 500
        assert server._proxy._close_committed, "the close must be sealed for this to mean anything"

        response = await asyncio.wait_for(
            api.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": "after-seal",
                    "method": "tools/call",
                    "params": {"name": "stateful.tool", "arguments": {}},
                },
            ),
            5,
        )

    assert response.status_code == 500
    assert response.json()["error"]["code"] == -32000
