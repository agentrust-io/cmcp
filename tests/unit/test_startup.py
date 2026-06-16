"""Tests for startup sequence and failure handling (issue #66)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cmcp_runtime.agent_manifest import SIGNED_FIELDS, signing_pre_image
from cmcp_runtime.catalog.loader import load_catalog
from cmcp_runtime.policy.bundle import load_policy_bundle
from cmcp_runtime.startup import RuntimeContext, run_startup

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

AGENT_ID = "spiffe://factory.example/agent/material-movement/dev"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _write_agent_manifest_files(
    tmp_path: Path,
    *,
    policy_hash: str,
    catalog_hash: str,
) -> tuple[Path, Path]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = hashlib.sha256(pub).hexdigest()
    manifest = {
        "@context": "https://agentmanifest.agentrust.io/v0.1/context.json",
        "@type": "AgentManifest",
        "manifest_id": "0197739a-8c00-7000-8000-000000000001",
        "agent_id": AGENT_ID,
        "version": "0.1",
        "issued_at": "2026-06-12T00:00:00Z",
        "expires_at": "2099-09-10T00:00:00Z",
        "issuer": "spiffe://factory.example/signing-authority/development",
        "crypto_profile": "standard",
        "artifacts": {
            "policy_bundle": {"hash": policy_hash, "policy_language": "cedar"},
            "tool_manifest": {"catalog_hash": catalog_hash, "tools": []},
        },
        "delegation_chain": [],
    }
    manifest["signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "key_type": "software",
        "signed_at": "2026-06-12T00:00:00Z",
        "signed_fields": list(SIGNED_FIELDS),
        "signature_value": _b64url(priv.sign(signing_pre_image(manifest))),
    }

    manifest_path = tmp_path / "agent-manifest.json"
    key_path = tmp_path / "manifest-public-key.json"
    manifest_path.write_text(json.dumps(manifest))
    key_path.write_text(
        json.dumps({
            "algorithm": "Ed25519",
            "key_id": key_id,
            "public_key_base64url": _b64url(pub),
        })
    )
    return manifest_path, key_path


@pytest.fixture
def complete_setup(tmp_path: Path, monkeypatch):
    """Set up a complete valid config + policy + catalog for startup tests."""
    monkeypatch.setenv("CMCP_DEV_MODE", "1")
    # TEE-002: DEV_MODE is frozen at import; patch the constant directly so
    # load_config() sees True even though the module was already imported.
    import cmcp_runtime.config as _cfg
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
    assert isinstance(ctx, RuntimeContext)
    assert ctx.config.dev_mode is True
    assert ctx.signing_key is not None
    assert ctx.policy_bundle is not None
    assert ctx.catalog is not None


def test_startup_returns_gateway_context_with_all_fields(complete_setup):
    ctx = run_startup(complete_setup)
    assert ctx.tee_provider is not None
    assert ctx.attestation_report is not None
    assert ctx.attestation_report.provider == "software-only"


def test_startup_binds_configured_agent_manifest(complete_setup):
    config_path = Path(complete_setup)
    tmp_path = config_path.parent
    policy_hash = load_policy_bundle(str(tmp_path / "policy")).bundle_hash
    catalog_hash = load_catalog(str(tmp_path / "catalog.json")).catalog_hash
    manifest_path, key_path = _write_agent_manifest_files(
        tmp_path,
        policy_hash=policy_hash,
        catalog_hash=catalog_hash,
    )
    config_path.write_text(
        config_path.read_text()
        + "\nagent_manifest:\n"
        + f"  path: {manifest_path}\n"
        + f"  trust_anchor_path: {key_path}\n"
        + f"  authenticated_subject: {AGENT_ID}\n"
    )

    ctx = run_startup(str(config_path))
    assert ctx.agent_manifest is not None
    assert ctx.agent_manifest.agent_id == AGENT_ID


def test_startup_fails_on_agent_manifest_subject_mismatch(complete_setup):
    config_path = Path(complete_setup)
    tmp_path = config_path.parent
    policy_hash = load_policy_bundle(str(tmp_path / "policy")).bundle_hash
    catalog_hash = load_catalog(str(tmp_path / "catalog.json")).catalog_hash
    manifest_path, key_path = _write_agent_manifest_files(
        tmp_path,
        policy_hash=policy_hash,
        catalog_hash=catalog_hash,
    )
    config_path.write_text(
        config_path.read_text()
        + "\nagent_manifest:\n"
        + f"  path: {manifest_path}\n"
        + f"  trust_anchor_path: {key_path}\n"
        + "  authenticated_subject: spiffe://factory.example/agent/other/dev\n"
    )

    with pytest.raises(SystemExit) as exc_info:
        run_startup(str(config_path))
    assert exc_info.value.code == 1


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
    with patch("cmcp_runtime.tee.detect._get_provider_impl", return_value=None), \
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
    """POLICY-002 (CRITICAL, issue #137): CMCP_CATALOG_HASH must be set outside dev mode."""
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

    from cmcp_runtime.policy.bundle import _canonical_bundle_hash
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
        "cmcp_runtime.tee.base.SoftwareOnlyProvider.get_attestation_report",
        return_value=fake_report,
    ), pytest.raises(SystemExit) as exc_info:
        run_startup(complete_setup)

    assert exc_info.value.code == 1
