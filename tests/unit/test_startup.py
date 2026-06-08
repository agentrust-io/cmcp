"""Tests for startup sequence and failure handling (issue #66)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

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
        "tls_fingerprint": "SHA256:AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        "transport": "http-sse",
    },
    "approved_definition": {"description": "test", "input_schema": {}},
    "definition_hash": "sha256:17e2f3382a5c3582d0ed6ba64511ce791a242051319529d810ff2b4fe499821a",
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
    # TEE-002: DEV_MODE is frozen at import; patch the constant directly so
    # load_config() sees True even though the module was already imported.
    import cmcp_gateway.config as _cfg
    monkeypatch.setattr(_cfg, "DEV_MODE", True)

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
    with patch("cmcp_gateway.tee.detect._get_provider_impl", return_value=None), \
         patch.dict(os.environ, {}, clear=True), \
         pytest.raises(SystemExit) as exc_info:
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


def test_startup_fails_when_policy_hash_unset_and_not_dev_mode(tmp_path):
    """POLICY-001 (CRITICAL): CMCP_POLICY_HASH must be set outside dev mode."""
    config_path = tmp_path / "cmcp-config.yaml"
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    catalog_path = tmp_path / "catalog.json"
    config_path.write_text(f"policy_bundle_path: {policy_dir}\ncatalog_path: {catalog_path}\n")
    (policy_dir / "manifest.json").write_text(json.dumps(MANIFEST))
    (policy_dir / "allow.cedar").write_text(CEDAR_POLICY)
    (policy_dir / "schema.cedarschema").write_text(SCHEMA)
    catalog_path.write_text(json.dumps([CATALOG_ENTRY]))

    env = {"CMCP_DEV_MODE": "0"}
    with patch.dict(os.environ, env, clear=True), pytest.raises(SystemExit) as exc_info:
        run_startup(str(config_path))
    assert exc_info.value.code == 1


def test_startup_fails_when_catalog_hash_unset_and_not_dev_mode(tmp_path, monkeypatch):
    """POLICY-002 (CRITICAL): CMCP_CATALOG_HASH must be set outside dev mode."""
    config_path = tmp_path / "cmcp-config.yaml"
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    catalog_path = tmp_path / "catalog.json"
    config_path.write_text(f"policy_bundle_path: {policy_dir}\ncatalog_path: {catalog_path}\n")
    (policy_dir / "manifest.json").write_text(json.dumps(MANIFEST))
    (policy_dir / "allow.cedar").write_text(CEDAR_POLICY)
    (policy_dir / "schema.cedarschema").write_text(SCHEMA)
    catalog_path.write_text(json.dumps([CATALOG_ENTRY]))

    import json as _json

    from cmcp_gateway.policy.bundle import _canonical_bundle_hash
    manifest_raw = _json.loads((policy_dir / "manifest.json").read_text())
    policy_files = {"allow.cedar": CEDAR_POLICY}
    computed = _canonical_bundle_hash(manifest_raw, policy_files, SCHEMA)
    policy_hash = f"sha256:{computed}"

    env = {"CMCP_DEV_MODE": "0", "CMCP_POLICY_HASH": policy_hash}
    with patch.dict(os.environ, env, clear=True), pytest.raises(SystemExit) as exc_info:
        run_startup(str(config_path))
    assert exc_info.value.code == 1


def test_startup_fails_on_unknown_tee_provider_name(complete_setup):
    """HW-001: a provider that returns an unknown platform string must cause exit 1.

    The mock bypasses AttestationReport.__post_init__ by returning a plain
    MagicMock, simulating a custom or misconfigured provider that injects an
    arbitrary string before the startup boundary check can catch it.
    """
    fake_report = MagicMock()
    fake_report.provider = "evil-custom-tee"
    fake_report.measurement = "aabbcc" * 8

    with patch(
        "cmcp_gateway.tee.base.SoftwareOnlyProvider.get_attestation_report",
        return_value=fake_report,
    ), pytest.raises(SystemExit) as exc_info:
        run_startup(complete_setup)

    assert exc_info.value.code == 1
