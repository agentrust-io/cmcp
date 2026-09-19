"""Kill switch blocks survive a restart, stop the gateway cleanly, and lift only by operator action."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import MagicMock

import httpx
import pytest

from cmcp_runtime.agent_manifest import AgentManifestBinding
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.cli import build_server
from cmcp_runtime.config import AttestationConfig, Config, KillSwitchConfig
from cmcp_runtime.kill_switch import KillSwitchBlockStore, KillSwitchEvaluator
from cmcp_runtime.policy.bundle import PolicyStore
from cmcp_runtime.startup import RuntimeContext

_AGENT_ID = "spiffe://example.com/agent/rogue-bot"
_OPERATOR_TOKEN = "operator-secret"
_BEARER_TOKEN = "bearer-secret"


def _ks_config() -> KillSwitchConfig:
    return KillSwitchConfig(enabled=True, window_seconds=300, deny_rate_threshold=0.9, min_calls=5)


def _manifest() -> AgentManifestBinding:
    return AgentManifestBinding(
        manifest_id="0197739a-8c00-7000-8000-000000000001",
        agent_id=_AGENT_ID,
        authenticated_subject=_AGENT_ID,
        subject_source="config",
        issuer="spiffe://example.com/signing-authority/prod",
        issuer_key_id="a" * 64,
        policy_bundle_hash="sha256:" + "0" * 64,
        tool_catalog_hash="sha256:" + "1" * 64,
    )


def _ctx(store: KillSwitchBlockStore) -> RuntimeContext:
    config = Config(
        attestation=AttestationConfig(),
        dev_mode=True,
        kill_switch=_ks_config(),
        bearer_token=_BEARER_TOKEN,
        operator_token=_OPERATOR_TOKEN,
    )
    report = MagicMock()
    report.provider = "software-only"
    report.attestation_generated_at = datetime.now(UTC)
    report.attestation_validity_seconds = 86400
    report.measurement = "0" * 64
    report.report_data = "0" * 64
    report.measurement_note = None
    report.raw_evidence = None

    bundle = MagicMock()
    bundle.signing_key_id = None
    bundle.revoked_signing_key_ids = ()
    bundle.bundle_hash = "sha256:" + "0" * 64
    bundle.policy_files = {"allow.cedar": "permit (principal, action, resource);"}
    bundle.manifest = MagicMock()
    bundle.manifest.version = "test-v1"
    policy_store = MagicMock(spec=PolicyStore)
    policy_store.bundle = bundle

    catalog = MagicMock()
    catalog.entries = {}
    catalog.catalog_hash = "sha256:" + "1" * 64
    catalog.exceptions = []

    return RuntimeContext(
        config=config,
        tee_provider=MagicMock(),
        attestation_report=report,
        signing_key=SigningKey(),
        policy_bundle=policy_store,
        catalog=catalog,
        agent_manifest=_manifest(),
        kill_switch_store=store,
    )


def _client(server) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server.app, raise_app_exceptions=False),
        base_url="http://test",
    )


def _bearer() -> dict[str, str]:
    return {"Authorization": f"Bearer {_BEARER_TOKEN}"}


def _operator() -> dict[str, str]:
    return {"Authorization": f"Bearer {_OPERATOR_TOKEN}"}


def _tool_call_body(rpc_id: str = "1") -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "tools/call",
        "params": {"name": "any.tool", "arguments": {}},
    }


def _unblock_body() -> dict[str, str]:
    return {"agent_id": _AGENT_ID, "reason": "false positive", "authorized_by": "oncall"}


async def _trip_by_close(server, client: httpx.AsyncClient) -> str:
    """Seed a denying window, then close: the close is what trips the switch."""
    server._session_manager._kill_switch.record_calls(_AGENT_ID, allowed=0, denied=10)
    sid = server._session.session_id
    resp = await client.post(f"/sessions/{sid}/close", headers=_bearer())
    assert resp.status_code == 200, resp.text
    assert resp.json()["gateway"]["kill_switch_triggered"] is True
    return sid


# ── The store ────────────────────────────────────────────────────────────────


def test_block_survives_a_new_store_on_the_same_file(tmp_path):
    db = tmp_path / "audit.db"
    KillSwitchBlockStore(db).block(_AGENT_ID, reason="deny_rate_threshold")

    reopened = KillSwitchBlockStore(db)
    assert reopened.is_blocked(_AGENT_ID)
    assert reopened.blocked_at(_AGENT_ID) is not None


def test_a_block_written_by_one_instance_is_seen_by_another(tmp_path):
    db = tmp_path / "audit.db"
    first, second = KillSwitchBlockStore(db), KillSwitchBlockStore(db)
    first.block(_AGENT_ID, reason="deny_rate_threshold")
    assert second.is_blocked(_AGENT_ID)


def test_unblock_reports_whether_anything_changed(tmp_path):
    store = KillSwitchBlockStore(tmp_path / "audit.db")
    assert store.unblock(_AGENT_ID) is False
    store.block(_AGENT_ID, reason="deny_rate_threshold")
    assert store.unblock(_AGENT_ID) is True
    assert not store.is_blocked(_AGENT_ID)


def test_evaluator_trip_is_still_blocked_after_a_restart(tmp_path):
    db = tmp_path / "audit.db"
    before = KillSwitchEvaluator(_ks_config(), store=KillSwitchBlockStore(db))
    before.record_calls(_AGENT_ID, allowed=0, denied=10)
    assert before.evaluate(_AGENT_ID) is True

    # A fresh process: new evaluator, empty rolling window, same file.
    after = KillSwitchEvaluator(_ks_config(), store=KillSwitchBlockStore(db))
    assert after.is_blocked(_AGENT_ID)


# ── A close that trips the switch ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_tripping_close_returns_the_claim_and_later_calls_are_refused(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        await _trip_by_close(server, client)

        # Refused at once with the documented code, not held waiting for a
        # successor session that the kill switch will not allow.
        resp = await asyncio.wait_for(
            client.post("/mcp", json=_tool_call_body(), headers=_bearer()), 5
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["data"]["error_code"] == "KILL_SWITCH_TRIPPED"

        ready = await client.get("/readyz")
        assert ready.status_code == 503
        assert ready.json()["checks"]["kill_switch"].startswith("failed:")


@pytest.mark.asyncio
async def test_close_and_reset_are_refused_while_halted(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        sid = await _trip_by_close(server, client)
        close = await client.post(f"/sessions/{sid}/close", headers=_bearer())
        reset = await client.post(f"/sessions/{sid}/reset", headers=_operator())
        assert close.status_code == 409
        assert reset.status_code == 409
        assert close.json()["error_code"] == "KILL_SWITCH_TRIPPED"


# ── Operator unblock ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unblock_resumes_on_a_new_session_and_records_who_did_it(tmp_path):
    store = KillSwitchBlockStore(tmp_path / "audit.db")
    server = build_server(_ctx(store))
    async with _client(server) as client:
        tripped_sid = await _trip_by_close(server, client)

        resp = await client.post("/kill-switch/unblock", json=_unblock_body(), headers=_operator())
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "unblocked"
        assert body["gateway_halted"] is False
        assert body["session_id"] != tripped_sid
        assert not store.is_blocked(_AGENT_ID)

        entry = server._audit_chain.entries[-1]
        assert entry.entry_type == "break_glass_used"
        assert entry.detail["reason"] == "kill_switch_unblocked"
        assert entry.detail["authorized_by"] == "oncall"
        assert entry.detail["credential_verified"] == "operator_token"

        # Admission is open again, on the successor.
        await asyncio.wait_for(server._proxy._enter_call(), 1)
        await server._proxy._leave_call()
        assert server._proxy._session.session_id == body["session_id"]


@pytest.mark.asyncio
async def test_unblock_requires_the_operator_token(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        await _trip_by_close(server, client)
        resp = await client.post("/kill-switch/unblock", json=_unblock_body(), headers=_bearer())
        assert resp.status_code == 401
        assert server._proxy.halted_identity == _AGENT_ID


@pytest.mark.asyncio
async def test_unblock_of_an_identity_that_is_not_blocked_is_404(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        resp = await client.post("/kill-switch/unblock", json=_unblock_body(), headers=_operator())
        assert resp.status_code == 404
        assert resp.json()["error_code"] == "NOT_BLOCKED"


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["agent_id", "reason", "authorized_by"])
async def test_unblock_requires_every_field(tmp_path, missing):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    body = _unblock_body()
    del body[missing]
    async with _client(server) as client:
        resp = await client.post("/kill-switch/unblock", json=body, headers=_operator())
        assert resp.status_code == 422


@pytest.mark.asyncio
async def test_unblock_retry_resumes_after_a_failed_resume(tmp_path, monkeypatch):
    store = KillSwitchBlockStore(tmp_path / "audit.db")
    server = build_server(_ctx(store))
    async with _client(server) as client:
        await _trip_by_close(server, client)

        original = server._session_manager.create_session
        monkeypatch.setattr(
            server._session_manager, "create_session", MagicMock(side_effect=RuntimeError("tee"))
        )
        failed = await client.post("/kill-switch/unblock", json=_unblock_body(), headers=_operator())
        assert failed.status_code == 500
        # The block is already gone, but the gateway is still stopped.
        assert not store.is_blocked(_AGENT_ID)
        assert server._proxy.halted_identity == _AGENT_ID

        monkeypatch.setattr(server._session_manager, "create_session", original)
        retried = await client.post("/kill-switch/unblock", json=_unblock_body(), headers=_operator())
        assert retried.status_code == 200, retried.text
        assert server._proxy.halted_identity is None


# ── A block already in force at startup ─────────────────────────────────────


@pytest.mark.asyncio
async def test_gateway_starts_halted_when_its_identity_is_already_blocked(tmp_path):
    store = KillSwitchBlockStore(tmp_path / "audit.db")
    store.block(_AGENT_ID, reason="deny_rate_threshold")

    # Before the fix this raised KillSwitchTripped out of build_server, so a
    # blocked gateway could not start and could not be unblocked.
    server = build_server(_ctx(store))
    assert server._proxy.halted_identity == _AGENT_ID
    first = server._audit_chain.entries[1]
    assert first.entry_type == "break_glass_used"
    assert first.detail["reason"] == "kill_switch_block_active_at_start"

    async with _client(server) as client:
        refused = await client.post("/mcp", json=_tool_call_body(), headers=_bearer())
        assert refused.status_code == 403

        startup_sid = server._session.session_id
        resp = await client.post("/kill-switch/unblock", json=_unblock_body(), headers=_operator())
        assert resp.status_code == 200, resp.text
        # The startup session never served anything, so it simply begins to.
        assert resp.json()["session_id"] == startup_sid
        assert server._proxy.halted_identity is None
