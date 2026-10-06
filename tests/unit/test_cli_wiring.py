"""
Regression tests for cli.build_server() - the production composition path.

These exist because the previous cli.start() body constructed MCPServer without
the bearer token (AUTH-001 dead in production), built AuditChain without the
SQLite store and TEE anchor (AUDIT-001/AUDIT-002 inert), and never passed
attestation timestamps to the proxy (staleness check dead). Unit tests that
construct MCPServer directly cannot catch wiring gaps in the entrypoint.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from starlette.testclient import TestClient

from cmcp_runtime.audit.store import SqliteAuditStore
from cmcp_runtime.cli import build_server
from cmcp_runtime.config import AttestationConfig, Config
from cmcp_runtime.policy.bundle import PolicyStore
from cmcp_runtime.startup import RuntimeContext

BEARER = "test-secret-token"


@pytest.fixture
def ctx(tmp_path) -> RuntimeContext:
    config = Config(
        attestation=AttestationConfig(),
        bearer_token=BEARER,
        dev_mode=True,
    )

    attestation_report = MagicMock()
    attestation_report.provider = "software-only"
    attestation_report.attestation_generated_at = datetime.now(UTC)
    attestation_report.attestation_validity_seconds = 86400

    bundle = MagicMock()
    bundle.bundle_hash = "sha256:" + "0" * 64
    bundle.policy_files = {"allow.cedar": "permit (principal, action, resource);"}
    policy_store = MagicMock(spec=PolicyStore)
    policy_store.bundle = bundle
    bundle.signing_key_id = None
    policy_store.revoked_key_ids = []
    policy_store.reload_if_stale = MagicMock()

    catalog = MagicMock()
    catalog.entries = {}
    catalog.catalog_hash = "sha256:" + "1" * 64
    catalog.exceptions = []

    return RuntimeContext(
        config=config,
        tee_provider=MagicMock(),
        attestation_report=attestation_report,
        signing_key=MagicMock(),
        policy_bundle=policy_store,
        catalog=catalog,
        audit_store=SqliteAuditStore(tmp_path / "audit.db"),
    )


def test_bearer_token_reaches_server(ctx):
    """AUTH-001: a request without the token must get 401, with it not-401."""
    server = build_server(ctx)
    client = TestClient(server.app)

    unauthenticated = client.get("/tools/list")
    assert unauthenticated.status_code == 401

    authenticated = client.get(
        "/tools/list", headers={"Authorization": f"Bearer {BEARER}"}
    )
    assert authenticated.status_code != 401


def test_health_exempt_from_auth(ctx):
    server = build_server(ctx)
    client = TestClient(server.app)
    assert client.get("/health").status_code != 401


def test_production_build_does_not_open_execution_registry(ctx, monkeypatch):
    """The unfinished state store must stay disconnected from production startup."""
    def unexpected_registry(*args, **kwargs):
        pytest.fail("production constructed the non-operational execution registry")

    monkeypatch.setattr("cmcp_runtime.execution.ExecutionRegistry", unexpected_registry)
    monkeypatch.setattr("cmcp_runtime.execution.registry.ExecutionRegistry", unexpected_registry)
    build_server(ctx)


def test_audit_chain_persists_to_store(ctx, tmp_path):
    """AUDIT-001: the session_start entry must land in the SQLite DB."""
    build_server(ctx)
    conn = sqlite3.connect(tmp_path / "audit.db")
    rows = conn.execute(
        "SELECT entry_type FROM audit_entries"
    ).fetchall()
    conn.close()
    assert ("session_start",) in rows


def test_audit_chain_is_tee_anchored(ctx):
    """AUDIT-002: the chain created by the entrypoint must have its anchor set."""
    server = build_server(ctx)
    chain = server._audit_chain
    assert chain is not None
    assert chain.tee_anchor == chain.chain_root


def test_proxy_receives_attestation_timestamps(ctx):
    """Staleness enforcement requires attestation_generated_at to be wired."""
    server = build_server(ctx)
    proxy = server._proxy
    assert proxy._attestation_generated_at is not None
    assert proxy._attestation_validity_seconds == 86400


@pytest.fixture
def durable_ctx(ctx, tmp_path):
    from cmcp_runtime.audit.keys import SigningKey
    from cmcp_runtime.kill_switch import KillSwitchBlockStore
    from cmcp_runtime.session.store import SqliteSessionStateStore

    ctx.signing_key = SigningKey()
    ctx.kill_switch_store = KillSwitchBlockStore(tmp_path / "blocks.db")
    ctx.session_state_store = SqliteSessionStateStore(tmp_path / "sessions.db")
    yield ctx
    for store in (ctx.audit_store, ctx.kill_switch_store, ctx.session_state_store):
        store.close()


def test_shutdown_closes_production_stores(durable_ctx, monkeypatch):
    stores = (durable_ctx.audit_store, durable_ctx.kill_switch_store, durable_ctx.session_state_store)
    closes = [MagicMock(wraps=store.close) for store in stores]
    for store, close in zip(stores, closes, strict=True):
        monkeypatch.setattr(store, "close", close)
    server = build_server(durable_ctx)
    with TestClient(server.app):
        assert not any(close.called for close in closes)
    for store, close in zip(stores, closes, strict=True):
        close.assert_called_once_with()
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            store._conn.execute("SELECT 1")


@pytest.mark.asyncio
async def test_shutdown_retries_only_failed_store_closes(durable_ctx, monkeypatch):
    server = build_server(durable_ctx)
    stores = (durable_ctx.audit_store, durable_ctx.kill_switch_store, durable_ctx.session_state_store)
    closes = [MagicMock(wraps=store.close) for store in stores]
    failure = RuntimeError("audit close failed")
    closes[0].side_effect = failure
    for store, close in zip(stores, closes, strict=True):
        monkeypatch.setattr(store, "close", close)
    with pytest.raises(RuntimeError) as caught:
        await server.shutdown()
    assert caught.value is failure
    assert [close.call_count for close in closes] == [1, 1, 1]
    closes[0].side_effect = None
    await server.shutdown()
    await server.shutdown()
    assert [close.call_count for close in closes] == [2, 1, 1]


@pytest.mark.asyncio
async def test_shutdown_preserves_cleanup_error_and_attempts_all_stores(durable_ctx, monkeypatch):
    from unittest.mock import AsyncMock

    server = build_server(durable_ctx)
    failure = RuntimeError("upstream cleanup failed")
    monkeypatch.setattr(server._proxy, "aclose", AsyncMock(side_effect=failure))
    close = MagicMock(side_effect=RuntimeError("audit close failed"))
    original_close = durable_ctx.audit_store.close
    monkeypatch.setattr(durable_ctx.audit_store, "close", close)
    try:
        with pytest.raises(RuntimeError) as caught:
            await server.shutdown()
        assert caught.value is failure
        close.assert_called_once_with()
        for store in (durable_ctx.kill_switch_store, durable_ctx.session_state_store):
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                store._conn.execute("SELECT 1")
    finally:
        monkeypatch.setattr(durable_ctx.audit_store, "close", original_close)


@pytest.mark.asyncio
async def test_incomplete_shutdown_retains_stores_for_outcome_and_retry(durable_ctx, monkeypatch, tmp_path):
    import asyncio
    from types import SimpleNamespace

    from cmcp_runtime.errors import SessionDrainIncomplete, UpstreamUnavailable
    from cmcp_runtime.mcp import proxy as proxy_module
    from cmcp_runtime.session.store import StoredSensitivity

    server = build_server(durable_ctx)
    server._session_close_drain_s = 0.01
    monkeypatch.setattr(proxy_module, "SESSION_CANCELLATION_GRACE_SECONDS", 0.01)
    entered, release = asyncio.Event(), asyncio.Event()
    stores = (durable_ctx.audit_store, durable_ctx.kill_switch_store, durable_ctx.session_state_store)
    closes = [MagicMock(wraps=store.close) for store in stores]
    for store, close in zip(stores, closes, strict=True):
        monkeypatch.setattr(store, "close", close)

    async def call(*args, **kwargs):
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()
        server._audit_chain.append("fault", call_id="late-outcome", detail={"outcome": "finished"})
        durable_ctx.kill_switch_store.block("late-agent", reason="test outcome")
        durable_ctx.session_state_store.save(
            "late-session", StoredSensitivity("PUBLIC", None, "late-outcome", 0)
        )
        return SimpleNamespace()

    monkeypatch.setattr(server._proxy, "_call_tool_impl", call)
    task = asyncio.create_task(server._proxy.call_tool("late-outcome", "test.tool", {}))
    await entered.wait()
    try:
        async with server._lifespan(server.app):
            pass
    except SessionDrainIncomplete:
        assert not any(close.called for close in closes)
        with pytest.raises(UpstreamUnavailable):
            await server._proxy._enter_call()
    else:
        pytest.fail("shutdown claimed success while a writer remained")
    finally:
        release.set()
        await asyncio.wait_for(task, 1)

    assert durable_ctx.kill_switch_store.is_blocked("late-agent")
    assert durable_ctx.session_state_store.load("late-session").sensitivity_raised_by_call == "late-outcome"
    with sqlite3.connect(tmp_path / "audit.db") as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_entries WHERE payload LIKE '%late-outcome%'").fetchone()[0] >= 1
    await server.shutdown()
    await server.shutdown()
    assert [close.call_count for close in closes] == [1, 1, 1]


@pytest.mark.asyncio
async def test_embedded_server_does_not_close_borrowed_stores(durable_ctx):
    from cmcp_runtime.mcp.server import MCPServer

    owner = build_server(durable_ctx)
    embedded = MCPServer(owner._proxy, audit_chain=owner._audit_chain)
    await embedded.shutdown()
    for store in (durable_ctx.audit_store, durable_ctx.kill_switch_store, durable_ctx.session_state_store):
        assert store._conn.execute("SELECT 1").fetchone() == (1,)
    await owner.shutdown()
