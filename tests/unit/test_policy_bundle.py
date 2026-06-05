"""Tests for Cedar policy bundle loading and hash verification (issue #63)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cmcp_gateway.errors import ConfigError, PolicyHashMismatch
from cmcp_gateway.policy.bundle import PolicyBundle, load_policy_bundle, _canonical_bundle_hash


MANIFEST = {
    "version": "1.0.0",
    "authored_at": "2026-06-04T00:00:00Z",
    "author_identity": "test@example.com",
    "commit_sha": "abc123",
}

CEDAR_POLICY = 'permit(principal, action, resource) when { true };'
SCHEMA = '{"cMCP": {"entityTypes": {}, "actions": {}}}'


@pytest.fixture
def bundle_dir(tmp_path: Path) -> Path:
    (tmp_path / "manifest.json").write_text(json.dumps(MANIFEST))
    (tmp_path / "allow-all.cedar").write_text(CEDAR_POLICY)
    (tmp_path / "schema.cedarschema").write_text(SCHEMA)
    return tmp_path


def test_load_valid_bundle(bundle_dir):
    bundle = load_policy_bundle(str(bundle_dir))
    assert isinstance(bundle, PolicyBundle)
    assert bundle.manifest.version == "1.0.0"
    assert "allow-all.cedar" in bundle.policy_files
    assert bundle.bundle_hash.startswith("sha256:")


def test_load_bundle_hash_is_deterministic(bundle_dir):
    b1 = load_policy_bundle(str(bundle_dir))
    b2 = load_policy_bundle(str(bundle_dir))
    assert b1.bundle_hash == b2.bundle_hash


def test_load_bundle_verifies_hash(bundle_dir):
    bundle = load_policy_bundle(str(bundle_dir))
    # Should succeed with correct hash
    bundle2 = load_policy_bundle(str(bundle_dir), expected_hash=bundle.bundle_hash)
    assert bundle2.bundle_hash == bundle.bundle_hash


def test_load_bundle_raises_on_hash_mismatch(bundle_dir):
    with pytest.raises(PolicyHashMismatch, match="mismatch"):
        load_policy_bundle(str(bundle_dir), expected_hash="sha256:" + "0" * 64)


def test_load_bundle_hash_prefix_optional(bundle_dir):
    bundle = load_policy_bundle(str(bundle_dir))
    hex_only = bundle.bundle_hash.removeprefix("sha256:")
    # Should work with or without prefix
    load_policy_bundle(str(bundle_dir), expected_hash=hex_only)


def test_load_bundle_missing_manifest(tmp_path):
    (tmp_path / "allow.cedar").write_text(CEDAR_POLICY)
    (tmp_path / "schema.cedarschema").write_text(SCHEMA)
    with pytest.raises(ConfigError, match="manifest.json"):
        load_policy_bundle(str(tmp_path))


def test_load_bundle_missing_cedar_files(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps(MANIFEST))
    (tmp_path / "schema.cedarschema").write_text(SCHEMA)
    with pytest.raises(ConfigError, match=".cedar"):
        load_policy_bundle(str(tmp_path))


def test_load_bundle_missing_schema(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps(MANIFEST))
    (tmp_path / "allow.cedar").write_text(CEDAR_POLICY)
    with pytest.raises(ConfigError, match="schema.cedarschema"):
        load_policy_bundle(str(tmp_path))


def test_load_bundle_missing_manifest_fields(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"version": "1.0"}))
    (tmp_path / "allow.cedar").write_text(CEDAR_POLICY)
    (tmp_path / "schema.cedarschema").write_text(SCHEMA)
    with pytest.raises(ConfigError, match="missing required fields"):
        load_policy_bundle(str(tmp_path))


def test_load_bundle_not_a_directory(tmp_path):
    f = tmp_path / "not-a-dir.yaml"
    f.write_text("x: 1")
    with pytest.raises(ConfigError, match="not a directory"):
        load_policy_bundle(str(f))


def test_load_bundle_hash_changes_when_policy_changes(bundle_dir):
    b1 = load_policy_bundle(str(bundle_dir))
    (bundle_dir / "allow-all.cedar").write_text("forbid(principal, action, resource);")
    b2 = load_policy_bundle(str(bundle_dir))
    assert b1.bundle_hash != b2.bundle_hash


def test_load_bundle_manifest_approval_chain(bundle_dir):
    manifest_with_approval = dict(MANIFEST)
    manifest_with_approval["approval_chain"] = [
        {"approver": "security@example.com", "approved_at": "2026-06-04T01:00:00Z"}
    ]
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest_with_approval))
    bundle = load_policy_bundle(str(bundle_dir))
    assert len(bundle.manifest.approval_chain) == 1
