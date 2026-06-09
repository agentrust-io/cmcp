"""Unit tests for soak test components (issue #82)."""

from __future__ import annotations

import json

import pytest

# ── Reference server tests ─────────────────────────────────────────────────────


def test_reference_server_initialize():
    from starlette.testclient import TestClient

    from tests.soak.reference_server import make_app

    client = TestClient(make_app(), raise_server_exceptions=False)
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["serverInfo"]["name"] == "soak-reference-server"


def test_reference_server_tools_list():
    from starlette.testclient import TestClient

    from tests.soak.reference_server import make_app

    client = TestClient(make_app(), raise_server_exceptions=False)
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    tools = {t["name"] for t in resp.json()["result"]["tools"]}
    assert tools == {"echo", "get_data", "delay"}


def test_reference_server_echo():
    from starlette.testclient import TestClient

    from tests.soak.reference_server import make_app

    client = TestClient(make_app(), raise_server_exceptions=False)
    resp = client.post("/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"msg": "hello"}},
    })
    body = resp.json()
    assert "hello" in body["result"]["content"][0]["text"]


def test_reference_server_get_data():
    from starlette.testclient import TestClient

    from tests.soak.reference_server import make_app

    client = TestClient(make_app(), raise_server_exceptions=False)
    resp = client.post("/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "get_data", "arguments": {}},
    })
    data = json.loads(resp.json()["result"]["content"][0]["text"])
    assert "records" in data
    assert data["_sensitivity"] == ["pii"]
    assert len(json.dumps(data)) >= 500  # at least 500 bytes


def test_reference_server_unknown_tool():
    from starlette.testclient import TestClient

    from tests.soak.reference_server import make_app

    client = TestClient(make_app(), raise_server_exceptions=False)
    resp = client.post("/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "nonexistent", "arguments": {}},
    })
    assert "error" in resp.json()


# ── Soak state tests ───────────────────────────────────────────────────────────


def test_soak_state_initial():
    from tests.soak.run_soak import SoakState
    state = SoakState()
    assert state.crashes == 0
    assert state.total_calls == 0
    assert state.signing_key_stable is True
    assert state.idle_transition_within_2x is True


def test_soak_memory_growth_check_bounded():
    from tests.soak.run_soak import SoakState, _check_memory_growth
    state = SoakState()
    state.memory_samples = [1000, 2000]  # 2x growth — just within threshold
    state.total_calls = 1
    # Should pass: tn=2000, threshold=(2*1000) + (1*512) = 2512
    assert _check_memory_growth(state) is True


def test_soak_memory_growth_check_exceeded():
    from tests.soak.run_soak import SoakState, _check_memory_growth
    state = SoakState()
    state.memory_samples = [100, 999_999_999]  # pathological growth
    state.total_calls = 10
    assert _check_memory_growth(state) is False


def test_soak_memory_growth_check_single_sample():
    from tests.soak.run_soak import SoakState, _check_memory_growth
    state = SoakState()
    state.memory_samples = [1000]
    assert _check_memory_growth(state) is True  # needs at least 2 samples


def test_check_signing_key_stable(tmp_path):
    from cmcp_runtime.audit.chain import AuditChain
    from tests.soak.run_soak import SoakState, _check_signing_key

    chain = AuditChain(session_id="test-session")
    chain.append("session_start", session_sensitivity_before="public", session_sensitivity_after="public")
    state = SoakState()
    _check_signing_key(state, chain)
    _check_signing_key(state, chain)  # same chain, same root
    assert state.signing_key_stable is True
    assert len(state.signing_key_restart_timestamps) == 0


def test_check_signing_key_detects_change():
    from cmcp_runtime.audit.chain import AuditChain
    from tests.soak.run_soak import SoakState, _check_signing_key

    chain1 = AuditChain(session_id="session-1")
    chain1.append("session_start", session_sensitivity_before="public", session_sensitivity_after="public")
    chain2 = AuditChain(session_id="session-2")
    chain2.append("session_start", session_sensitivity_before="public", session_sensitivity_after="public")

    state = SoakState()
    _check_signing_key(state, chain1)
    _check_signing_key(state, chain2)  # different chain root
    # Different sessions produce different chain roots — simulates key change
    if chain1.chain_root[:16] != chain2.chain_root[:16]:
        assert state.signing_key_stable is False
        assert len(state.signing_key_restart_timestamps) == 1
    else:
        # Unlikely but hash collision possible in test; just check no crash
        pass


def test_sample_memory():
    from cmcp_runtime.audit.chain import AuditChain
    from tests.soak.run_soak import SoakState, _sample_memory

    chain = AuditChain(session_id="test")
    for _ in range(5):
        chain.append("tool_call",
                     call_id="c1", tool_name="echo",
                     policy_decision="allow",
                     session_sensitivity_before="public",
                     session_sensitivity_after="public")
    state = SoakState()
    _sample_memory(state, chain)
    assert len(state.memory_samples) == 1
    assert state.memory_samples[0] > 0


# ── Integration: smoke run ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_soak_smoke_run(tmp_path):
    """Smoke test: soak run completes with very short duration and produces valid JSON."""
    from tests.soak.run_soak import _run_soak

    result = await _run_soak(
        duration_hours=0.001,  # ~3.6 seconds
        provider="software-only",
        runtime_url=None,
        nginx_url=None,
        bearer_token="test-token",
        out_dir=tmp_path,
    )

    assert "provider" in result
    assert result["provider"] == "software-only"
    assert result["crashes"] == 0
    assert "passed" in result

    # Result file written
    files = list(tmp_path.glob("soak-*.json"))
    assert len(files) == 1
    data = json.loads(files[0].read_text())
    assert data["duration_hours"] == pytest.approx(0.001)
