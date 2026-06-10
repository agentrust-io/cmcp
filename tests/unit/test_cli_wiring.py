"""
Regression tests for cli.build_server() — the production composition path.

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
