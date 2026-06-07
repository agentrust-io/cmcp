"""Cedar policy bundle loading and hash verification — implements issue #63."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cmcp_gateway.errors import ConfigError, PolicyHashMismatch

logger = logging.getLogger(__name__)


@dataclass
class PolicyManifest:
    """Provenance metadata embedded in the policy bundle (policy provenance, issue #26)."""

    version: str
    authored_at: str
    author_identity: str
    commit_sha: str
    approval_chain: list[dict[str, str]] = field(default_factory=list)


@dataclass
class PolicyBundle:
    """Loaded, verified Cedar policy bundle."""

    manifest: PolicyManifest
    policy_files: dict[str, str]  # filename → file content
    schema_content: str
    bundle_hash: str  # sha256:<hex> — what gets measured into the TEE report


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bundle_hash(
    manifest: dict[str, Any],
    policy_files: dict[str, str],
    schema_content: str,
) -> str:
    """
    Compute bundle hash as defined in docs/spec/cedar-policy.md §1:

    SHA-256 of canonical_json({
        manifest: <manifest contents>,
        policy_files: {<filename>: <sha256 of file bytes>},  # sorted by filename
        schema_hash: <sha256 of schema bytes>
    })
    """
    policy_hashes = {
        name: _sha256_hex(content.encode())
        for name, content in sorted(policy_files.items())
    }
    canonical = json.dumps(
        {
            "manifest": manifest,
            "policy_files": policy_hashes,
            "schema_hash": _sha256_hex(schema_content.encode()),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return _sha256_hex(canonical.encode())


def load_policy_bundle(bundle_path: str, expected_hash: str | None = None) -> PolicyBundle:
    """
    Load a Cedar policy bundle from disk and verify its hash.

    bundle_path is a directory containing:
    - manifest.json  (provenance metadata)
    - *.cedar        (Cedar policy files)
    - schema.cedarschema  (Cedar schema)

    expected_hash is "sha256:<hex>" — must match the computed bundle hash.
    If expected_hash is None, the hash is computed but not verified (dev convenience).

    Raises PolicyHashMismatch if hashes do not match.
    Raises ConfigError if the bundle directory is malformed.
    """
    path = Path(bundle_path)
    if not path.is_dir():
        raise ConfigError(f"Policy bundle path is not a directory: {bundle_path}")

    # Load manifest
    manifest_path = path / "manifest.json"
    if not manifest_path.exists():
        raise ConfigError(f"Policy bundle missing manifest.json in {bundle_path}")
    try:
        raw_manifest: dict[str, Any] = json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise ConfigError(f"Cannot load manifest.json: {exc}") from exc

    required = {"version", "authored_at", "author_identity", "commit_sha"}
    missing = required - raw_manifest.keys()
    if missing:
        raise ConfigError(f"manifest.json missing required fields: {missing}")

    manifest = PolicyManifest(
        version=raw_manifest["version"],
        authored_at=raw_manifest["authored_at"],
        author_identity=raw_manifest["author_identity"],
        commit_sha=raw_manifest["commit_sha"],
        approval_chain=raw_manifest.get("approval_chain", []),
    )

    # Load Cedar policy files
    cedar_files = sorted(path.glob("**/*.cedar"))
    if not cedar_files:
        raise ConfigError(f"Policy bundle contains no .cedar files in {bundle_path}")

    policy_files: dict[str, str] = {}
    for cedar_file in cedar_files:
        rel = cedar_file.relative_to(path).as_posix()
        try:
            policy_files[rel] = cedar_file.read_text()
        except OSError as exc:
            raise ConfigError(f"Cannot read policy file {rel}: {exc}") from exc

    # Load schema
    schema_path = path / "schema.cedarschema"
    if not schema_path.exists():
        raise ConfigError(f"Policy bundle missing schema.cedarschema in {bundle_path}")
    try:
        schema_content = schema_path.read_text()
    except OSError as exc:
        raise ConfigError(f"Cannot read schema.cedarschema: {exc}") from exc

    # Compute and verify hash
    computed = _canonical_bundle_hash(raw_manifest, policy_files, schema_content)

    if expected_hash is not None:
        expected_hex = expected_hash.removeprefix("sha256:")
        if computed != expected_hex:
            raise PolicyHashMismatch(
                "Policy bundle hash mismatch — gateway will not start",
                detail=f"expected=sha256:{expected_hex} actual=sha256:{computed}",
            )

    return PolicyBundle(
        manifest=manifest,
        policy_files=policy_files,
        schema_content=schema_content,
        bundle_hash=f"sha256:{computed}",
    )


class PolicyStore:
    """Thread-safe holder for the active policy bundle with optional hot-reload.

    When reload_interval_seconds > 0, calls to reload_if_stale() will re-read
    the bundle from disk once the interval has elapsed and swap it in atomically
    under a reentrant lock so that concurrent evaluate() calls never see a torn
    state.  When reload_interval_seconds is 0 (the default), reloads are disabled
    and the store behaves like a simple immutable wrapper.
    """

    def __init__(
        self,
        bundle: PolicyBundle,
        bundle_path: str,
        reload_interval_seconds: int = 0,
        expected_hash: str | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._bundle = bundle
        self._bundle_path = bundle_path
        self._reload_interval = reload_interval_seconds
        self._expected_hash = expected_hash
        self._last_reload_at = time.monotonic()

    @property
    def bundle(self) -> PolicyBundle:
        with self._lock:
            return self._bundle

    def reload_if_stale(self) -> bool:
        """Reload from disk if the configured interval has elapsed.

        Returns True if a reload attempt was made (regardless of whether the
        bundle hash changed).  Thread-safe; uses an RLock so nested calls from
        the same thread are safe.
        """
        if self._reload_interval <= 0:
            return False
        with self._lock:
            if time.monotonic() - self._last_reload_at < self._reload_interval:
                return False
            try:
                new_bundle = load_policy_bundle(self._bundle_path, self._expected_hash)
                if new_bundle.bundle_hash != self._bundle.bundle_hash:
                    self._bundle = new_bundle
                    logger.info("Policy bundle reloaded: hash=%s", new_bundle.bundle_hash)
                self._last_reload_at = time.monotonic()
                return True
            except Exception as exc:
                logger.warning("Policy bundle reload failed (keeping current): %s", exc)
                return False
