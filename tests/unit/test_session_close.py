"""Tests for POST /sessions/{id}/close - claim issuance and session rotation."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from starlette.testclient import TestClient

from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.cli import build_server
from cmcp_runtime.config import AttestationConfig, Config
from cmcp_runtime.policy.bundle import PolicyStore
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
