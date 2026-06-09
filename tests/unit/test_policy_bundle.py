"""Tests for Cedar policy bundle loading and hash verification (issue #63)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cmcp_runtime.errors import ConfigError, PolicyHashMismatch
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyManifest, PolicyStore, load_policy_bundle

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


# ── PolicyStore tests (POLICY-001 hot-reload) ─────────────────────────────────

def _make_bundle(hash_suffix: str = "0" * 64) -> PolicyBundle:
    return PolicyBundle(
        manifest=PolicyManifest(
            version="1.0.0",
            authored_at="2026-06-07T00:00:00Z",
            author_identity="test",
            commit_sha="abc",
        ),
        policy_files={"allow.cedar": "permit(principal, action, resource);"},
        schema_content='{"cMCP": {}}',
        bundle_hash=f"sha256:{hash_suffix}",
    )


def test_policy_store_no_reload_when_interval_zero():
    """reload_if_stale() must return False immediately when interval is 0."""
    store = PolicyStore(bundle=_make_bundle(), bundle_path="", reload_interval_seconds=0)
    result = store.reload_if_stale()
    assert result is False


def test_policy_store_no_reload_before_interval_elapsed():
    """reload_if_stale() must return False if interval has not elapsed yet."""
    store = PolicyStore(bundle=_make_bundle(), bundle_path="/some/path", reload_interval_seconds=60)
    # Time has just been set to monotonic() in __init__, so interval hasn't elapsed.
    result = store.reload_if_stale()
    assert result is False


def test_policy_store_reloads_after_interval(bundle_dir):
    """reload_if_stale() reloads from disk once interval has elapsed."""
    bundle = load_policy_bundle(str(bundle_dir))
    store = PolicyStore(
        bundle=bundle,
        bundle_path=str(bundle_dir),
        reload_interval_seconds=30,
    )

    # Simulate time advancing past the interval by patching monotonic so that
    # the elapsed check passes on the next call.
    start = store._last_reload_at
    with patch("cmcp_runtime.policy.bundle.time") as mock_time:
        # First call returns a value past the interval; subsequent calls (inside
        # reload_if_stale to update _last_reload_at) return the same advanced value.
        mock_time.monotonic.return_value = start + 31
        result = store.reload_if_stale()

    assert result is True


def test_policy_store_bundle_swap_on_hash_change(bundle_dir):
    """After a reload where the hash changes, store.bundle returns the new bundle."""
    old_bundle = load_policy_bundle(str(bundle_dir))
    store = PolicyStore(
        bundle=old_bundle,
        bundle_path=str(bundle_dir),
        reload_interval_seconds=1,
    )

    # Mutate the on-disk policy to produce a different hash.
    (bundle_dir / "allow-all.cedar").write_text("forbid(principal, action, resource);")

    start = store._last_reload_at
    with patch("cmcp_runtime.policy.bundle.time") as mock_time:
        mock_time.monotonic.return_value = start + 2
        store.reload_if_stale()

    assert store.bundle.bundle_hash != old_bundle.bundle_hash


def test_policy_store_keeps_current_on_reload_failure():
    """If reload raises, store keeps the existing bundle and returns False."""
    bundle = _make_bundle()
    store = PolicyStore(
        bundle=bundle,
        bundle_path="/nonexistent/path",
        reload_interval_seconds=1,
    )

    start = store._last_reload_at
    with patch("cmcp_runtime.policy.bundle.time") as mock_time:
        mock_time.monotonic.return_value = start + 2
        result = store.reload_if_stale()

    # Should return False (failure path) and preserve the original bundle.
    assert result is False
    assert store.bundle.bundle_hash == bundle.bundle_hash


# ── POLICY-007: agent_os_version pinning ─────────────────────────────────────

def test_load_bundle_accepts_manifest_without_agent_os_version(bundle_dir):
    """POLICY-007: agent_os_version is optional — bundles without it still load."""
    bundle = load_policy_bundle(str(bundle_dir))
    assert bundle.manifest.agent_os_version is None


def test_load_bundle_records_pinned_agent_os_version(bundle_dir):
    """POLICY-007: agent_os_version from manifest is stored in PolicyManifest."""
    manifest_with_version = dict(MANIFEST)
    manifest_with_version["agent_os_version"] = "3.7.0"
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest_with_version))
    bundle = load_policy_bundle(str(bundle_dir))
    assert bundle.manifest.agent_os_version == "3.7.0"


def test_load_bundle_warns_on_agent_os_version_mismatch(bundle_dir, caplog):
    """POLICY-007: version mismatch emits a WARNING but does not raise."""
    import logging
    manifest_with_old = dict(MANIFEST)
    manifest_with_old["agent_os_version"] = "0.0.0-definitely-not-installed"
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest_with_old))
    with caplog.at_level(logging.WARNING):
        bundle = load_policy_bundle(str(bundle_dir))
    assert bundle is not None
    assert any("POLICY-007" in r.message for r in caplog.records)


def test_load_bundle_no_warning_when_versions_match(bundle_dir, caplog):
    """POLICY-007: no warning when pinned version matches installed version."""
    import logging

    from cmcp_runtime.policy.bundle import _AGENT_OS_VERSION
    manifest_with_match = dict(MANIFEST)
    manifest_with_match["agent_os_version"] = _AGENT_OS_VERSION
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest_with_match))
    with caplog.at_level(logging.WARNING):
        load_policy_bundle(str(bundle_dir))
    assert not any("POLICY-007" in r.message for r in caplog.records)
