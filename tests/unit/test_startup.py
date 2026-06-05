"""Tests for startup sequence and failure handling (issue #66)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from cmcp_gateway.startup import GatewayContext, run_startup


MANIFEST = {
    "version": "1.0.0",
    "authored_at": "2026-06-04T00:00:00Z",
    "author_identity": "test@example.com",
    "commit_sha": "abc123",
}

CEDAR_POLICY = 'permit(principal, action, resource) when { true };'
SCHEMA = '{"cMCP": {}}'

CATALOG_ENTRY = {
    "tool_name": "test.tool",
    "server": {
        "display_name": "Test",
        "url": "https://test.example.com/mcp",
        "tls_fingerprint": "SHA256:AAAA/BBBB/CCCC/DDDD/EEEE/FFFF/GGGG/HHHH/IIII/JJJJ/KK==",
        "transport": "http-sse",
    },
    "approved_definition": {"description": "test", "input_schema": {}},
    "compliance_domain": "external",
    "requires_baa": False,
    "sensitivity_level": "public",
    "added_at": "2026-06-01T00:00:00Z",
    "approved_by": "test",
}


@pytest.fixture
def complete_setup(tmp_path: Path, monkeypatch):
    """Set up a complete valid config + policy + catalog for startup tests."""
    monkeypatch.setenv("CMCP_DEV_MODE", "1")

    # Config
    config_path = tmp_path / "cmcp-config.yaml"
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    catalog_path = tmp_path / "catalog.json"

    config_path.write_text(
        f"policy_bundle_path: {policy_dir}\ncatalog_path: {catalog_path}\n"
    )
    (policy_dir / "manifest.json").write_text(json.dumps(MANIFEST))
    (policy_dir / "allow.cedar").write_text(CEDAR_POLICY)
    (policy_dir / "schema.cedarschema").write_text(SCHEMA)
    catalog_path.write_text(json.dumps([CATALOG_ENTRY]))

    return str(config_path)


def test_startup_succeeds_in_dev_mode(complete_setup):
    ctx = run_startup(complete_setup)
    assert isinstance(ctx, GatewayContext)
    assert ctx.config.dev_mode is True
    assert ctx.signing_key is not None
    assert ctx.policy_bundle is not None
    assert ctx.catalog is not None


def test_startup_returns_gateway_context_with_all_fields(complete_setup):
    ctx = run_startup(complete_setup)
    assert ctx.tee_provider is not None
    assert ctx.attestation_report is not None
    assert ctx.attestation_report.provider == "software-only"


def test_startup_fails_on_missing_config(tmp_path):
    """Conformance: startup exits on invalid config."""
    with pytest.raises(SystemExit) as exc_info:
        run_startup(str(tmp_path / "nonexistent.yaml"))
    assert exc_info.value.code == 1


def test_startup_fails_on_no_tee_no_dev_mode(tmp_path):
    """Conformance: ATTEST-001 — no hardware TEE + no dev mode → exit 1."""
    config_path = tmp_path / "cmcp-config.yaml"
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    catalog_path = tmp_path / "catalog.json"
    config_path.write_text(f"policy_bundle_path: {policy_dir}\ncatalog_path: {catalog_path}\n")
    (policy_dir / "manifest.json").write_text(json.dumps(MANIFEST))
    (policy_dir / "allow.cedar").write_text(CEDAR_POLICY)
    (policy_dir / "schema.cedarschema").write_text(SCHEMA)
    catalog_path.write_text("[]")

    # No CMCP_DEV_MODE, no hardware TEE → should exit 1
    with patch("cmcp_gateway.tee.detect._get_provider_impl", return_value=None):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SystemExit) as exc_info:
                run_startup(str(config_path))
    assert exc_info.value.code == 1


def test_startup_fails_on_policy_hash_mismatch(complete_setup, monkeypatch):
    """Conformance: POLICY_HASH_MISMATCH → exit 1."""
    monkeypatch.setenv("CMCP_POLICY_HASH", "sha256:" + "0" * 64)
    with pytest.raises(SystemExit) as exc_info:
        run_startup(complete_setup)
    assert exc_info.value.code == 1


def test_startup_fails_on_catalog_hash_mismatch(complete_setup, monkeypatch):
    """Conformance: CATALOG_HASH_MISMATCH → exit 1."""
    monkeypatch.setenv("CMCP_CATALOG_HASH", "sha256:" + "0" * 64)
    with pytest.raises(SystemExit) as exc_info:
        run_startup(complete_setup)
    assert exc_info.value.code == 1
