"""POLICY-004: signed policy bundles, the anchor that survives the bundle changing.

A pinned hash (`CMCP_POLICY_HASH`) says *this exact artifact*, decided before the
process started, and therefore cannot authorise a bundle that changed. A pinned
signing key says *anything this authority approves*, which can. That is the whole
reason this exists; see `docs/spec/policy-hot-reload.md`.

The load-bearing test is `test_a_replayed_older_signed_bundle_is_refused`. Without
the monotonic version check, the signing-key model *is* a downgrade attack:
everything about a replayed older bundle is genuine, the signature really
verifies, and the gateway would install a policy the operator already retired.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cmcp_runtime.errors import ConfigError, PolicySignatureInvalid
from cmcp_runtime.policy import bundle as bundle_module
from cmcp_runtime.policy.bundle import PolicyStore, load_policy_bundle

MANIFEST = {
    "version": "1.0.0",
    "authored_at": "2026-06-04T00:00:00Z",
    "author_identity": "test@example.com",
    "commit_sha": "abc123",
}
CEDAR_POLICY = "permit(principal, action, resource) when { true };"
SCHEMA = '{"cMCP": {"entityTypes": {}, "actions": {}}}'


@pytest.fixture
def bundle_dir(tmp_path: Path) -> Path:
    (tmp_path / "manifest.json").write_text(json.dumps(MANIFEST))
    (tmp_path / "allow-all.cedar").write_text(CEDAR_POLICY)
    (tmp_path / "schema.cedarschema").write_text(SCHEMA)
    return tmp_path


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return private, public


def _write_manifest(bundle_dir: Path, **changes: object) -> None:
    """Rewrite manifest.json with ``changes`` applied and any signature dropped."""
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    manifest.pop("signature", None)
    manifest.update(changes)
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest))


def _sign(bundle_dir: Path, private: Ed25519PrivateKey) -> str:
    """Sign the bundle in place. Returns the bundle hash that was signed."""
    unsigned = load_policy_bundle(str(bundle_dir))
    signature = private.sign(bundle_module.signing_pre_image(unsigned.bundle_hash))
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    manifest["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest))
    return unsigned.bundle_hash


def _store(bundle_dir: Path, public: bytes) -> PolicyStore:
    return PolicyStore(
        bundle=load_policy_bundle(str(bundle_dir), None, public),
        bundle_path=str(bundle_dir),
        reload_interval_seconds=1,
        signing_key=public,
    )


def _reload_now(store: PolicyStore) -> bool:
    start = store._last_reload_at
    with patch("cmcp_runtime.policy.bundle.time") as mock_time:
        mock_time.monotonic.return_value = start + 2
        return store.reload_if_stale()


# --------------------------------------------------------------------------
# The signature, and what it covers
# --------------------------------------------------------------------------


def test_signature_is_excluded_from_the_bundle_hash(bundle_dir: Path) -> None:
    """Otherwise the signature would have to cover itself.

    This is also why every bundle hash issued before signing existed is
    unchanged: stripping a key that was never present is a no-op.
    """
    before = load_policy_bundle(str(bundle_dir)).bundle_hash
    _sign(bundle_dir, _keypair()[0])
    assert load_policy_bundle(str(bundle_dir)).bundle_hash == before


def test_signing_pre_image_is_domain_separated() -> None:
    """A signature over some other cMCP structure must not be replayable here."""
    digest = "sha256:" + "ab" * 32
    pre = bundle_module.signing_pre_image(digest)
    assert pre.startswith(b"cmcp-policy-bundle-v1|")
    assert pre.endswith(digest.encode())


def test_a_signed_bundle_loads_under_its_key(bundle_dir: Path) -> None:
    private, public = _keypair()
    _sign(bundle_dir, private)
    assert load_policy_bundle(str(bundle_dir), None, public).manifest.signature


def test_an_unsigned_bundle_is_refused_when_a_key_is_pinned(bundle_dir: Path) -> None:
    """Having asked for signed policy, being handed unsigned policy is a refusal,
    not a downgrade to the unsigned path."""
    _, public = _keypair()
    with pytest.raises(PolicySignatureInvalid, match="no signature"):
        load_policy_bundle(str(bundle_dir), None, public)


def test_an_unsigned_bundle_still_loads_with_no_key_pinned(bundle_dir: Path) -> None:
    """Signing is opt-in. A deployment pinning a hash needs none of this."""
    assert load_policy_bundle(str(bundle_dir)).manifest.signature is None


def test_a_signature_from_the_wrong_key_is_refused(bundle_dir: Path) -> None:
    private, _ = _keypair()
    _sign(bundle_dir, private)
    with pytest.raises(PolicySignatureInvalid, match="does not verify"):
        load_policy_bundle(str(bundle_dir), None, _keypair()[1])


def test_editing_policy_after_signing_is_refused(bundle_dir: Path) -> None:
    """The signature covers the bundle hash, so content edits break it."""
    private, public = _keypair()
    _sign(bundle_dir, private)
    (bundle_dir / "allow-all.cedar").write_text("forbid(principal, action, resource);")
    with pytest.raises(PolicySignatureInvalid, match="does not verify"):
        load_policy_bundle(str(bundle_dir), None, public)


@pytest.mark.parametrize("signature", ["not base64url!!", "", "AAAA"])
def test_a_malformed_or_short_signature_is_refused(
    bundle_dir: Path, signature: str
) -> None:
    _, public = _keypair()
    _write_manifest(bundle_dir, signature=signature)
    with pytest.raises(PolicySignatureInvalid):
        load_policy_bundle(str(bundle_dir), None, public)


# --------------------------------------------------------------------------
# Runtime change, which is the point
# --------------------------------------------------------------------------


def test_signed_reload_installs_a_newer_bundle(bundle_dir: Path) -> None:
    """What the whole model exists for: policy changes with no restart."""
    private, public = _keypair()
    _sign(bundle_dir, private)
    store = _store(bundle_dir, public)
    original_hash = store.bundle.bundle_hash

    # The authority issues a tighter policy at a higher version, and signs it.
    (bundle_dir / "allow-all.cedar").write_text("forbid(principal, action, resource);")
    _write_manifest(bundle_dir, version="1.0.1")
    _sign(bundle_dir, private)

    assert _reload_now(store) is True
    assert store.bundle.bundle_hash != original_hash
    assert store.bundle.manifest.version == "1.0.1"
    assert "forbid" in next(iter(store.bundle.policy_files.values()))


def test_reload_with_a_key_survives_a_pinned_hash_being_absent(bundle_dir: Path) -> None:
    """The signing key is the anchor; no hash pin is needed alongside it."""
    private, public = _keypair()
    _sign(bundle_dir, private)
    store = _store(bundle_dir, public)
    assert store._expected_hash is None
    _write_manifest(bundle_dir, version="9.0.0")
    _sign(bundle_dir, private)
    assert _reload_now(store) is True
    assert store.bundle.manifest.version == "9.0.0"


# --------------------------------------------------------------------------
# Downgrade
# --------------------------------------------------------------------------


def test_a_replayed_older_signed_bundle_is_refused(bundle_dir: Path) -> None:
    """The downgrade attack, and the reason the version must increase.

    Everything about the replayed bundle is genuine: the authority really signed
    it and the signature really verifies on its own terms. Without this check the
    gateway installs a policy the operator already retired, and anyone who can
    write the bundle directory can make that happen.
    """
    private, public = _keypair()
    _write_manifest(bundle_dir, version="2.0.0")
    _sign(bundle_dir, private)
    store = _store(bundle_dir, public)

    # Yesterday's genuinely signed, more permissive bundle reappears on disk.
    _write_manifest(bundle_dir, version="1.9.0")
    (bundle_dir / "allow-all.cedar").write_text("permit(principal, action, resource);")
    _sign(bundle_dir, private)

    # It verifies on its own terms: a signature check alone would accept it.
    assert load_policy_bundle(str(bundle_dir), None, public).manifest.version == "1.9.0"

    assert _reload_now(store) is False
    assert store.bundle.manifest.version == "2.0.0", "a downgrade was installed"


def test_the_same_version_is_also_refused(bundle_dir: Path) -> None:
    """Equal is not greater. A same-version content swap is a policy change that
    nothing records the authority as having intended."""
    private, public = _keypair()
    _sign(bundle_dir, private)
    store = _store(bundle_dir, public)
    original_hash = store.bundle.bundle_hash

    (bundle_dir / "allow-all.cedar").write_text("forbid(principal, action, resource);")
    _write_manifest(bundle_dir)  # version unchanged
    _sign(bundle_dir, private)

    assert _reload_now(store) is False
    assert store.bundle.bundle_hash == original_hash


def test_version_comparison_is_numeric_not_lexicographic(bundle_dir: Path) -> None:
    """1.10.0 is newer than 1.9.0, which string comparison gets backwards."""
    private, public = _keypair()
    _write_manifest(bundle_dir, version="1.9.0")
    _sign(bundle_dir, private)
    store = _store(bundle_dir, public)

    _write_manifest(bundle_dir, version="1.10.0")
    (bundle_dir / "allow-all.cedar").write_text("forbid(principal, action, resource);")
    _sign(bundle_dir, private)

    assert _reload_now(store) is True
    assert store.bundle.manifest.version == "1.10.0"


@pytest.mark.parametrize("version", ["not-a-version", "1.0.0-rc1", "", "1.0.x"])
def test_an_unorderable_version_is_refused_at_load(bundle_dir: Path, version: str) -> None:
    """Unparseable must not be a way past the monotonic check, and finding out at
    the first reload is worse than refusing to start."""
    private, public = _keypair()
    _write_manifest(bundle_dir, version=version)
    _sign(bundle_dir, private)
    with pytest.raises(ConfigError, match="orderable"):
        load_policy_bundle(str(bundle_dir), None, public)


def test_unsigned_reload_does_not_enforce_monotonicity(bundle_dir: Path) -> None:
    """Without a pinned key there is no authority whose intent could be replayed,
    so the dev-mode path keeps its existing behaviour."""
    _write_manifest(bundle_dir, version="2.0.0")
    store = PolicyStore(
        bundle=load_policy_bundle(str(bundle_dir)),
        bundle_path=str(bundle_dir),
        reload_interval_seconds=1,
    )
    _write_manifest(bundle_dir, version="1.0.0")
    (bundle_dir / "allow-all.cedar").write_text("forbid(principal, action, resource);")
    assert _reload_now(store) is True
    assert store.bundle.manifest.version == "1.0.0"
