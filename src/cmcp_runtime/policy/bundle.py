"""Cedar policy bundle loading and hash verification: implements issue #63."""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib.metadata
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cmcp_runtime.errors import ConfigError, PolicyHashMismatch, PolicySignatureInvalid

# POLICY-007: version of the Cedar evaluation library bundled in agent-os-kernel.
# Pinned in manifest.json as agent_os_version; mismatch is logged as a warning.
try:
    _AGENT_OS_VERSION: str = importlib.metadata.version("agent-os-kernel")
except importlib.metadata.PackageNotFoundError:
    _AGENT_OS_VERSION = "unknown"

logger = logging.getLogger(__name__)


@dataclass
class PolicyManifest:
    """Provenance metadata embedded in the policy bundle (policy provenance, issue #26)."""

    version: str
    authored_at: str
    author_identity: str
    commit_sha: str
    approval_chain: list[dict[str, str]] = field(default_factory=list)
    agent_os_version: str | None = None  # POLICY-007: expected agent-os-kernel version
    #: POLICY-004: base64url Ed25519 signature over the bundle's signing pre-image.
    #: Absent on an unsigned bundle, which stays valid: signing is opt-in and a
    #: deployment that pins a hash instead needs none of this.
    signature: str | None = None


#: POLICY-004: domain separation for the policy-bundle signature, so a signature
#: over some other cMCP structure can never be replayed as a policy authorisation.
_SIGNATURE_DOMAIN = b"cmcp-policy-bundle-v1|"

#: Keys excluded from the hashed manifest. ``signature`` cannot be inside the
#: pre-image it signs, so it is stripped before hashing. Existing manifests carry
#: no such key, which is why every bundle hash issued to date is unchanged by
#: this: stripping an absent key is a no-op. Same idiom the delegation credential
#: uses, where ``body()`` omits the signature it is signed by.
_UNHASHED_MANIFEST_KEYS = frozenset({"signature"})


@dataclass
class PolicyBundle:
    """Loaded, verified Cedar policy bundle."""

    manifest: PolicyManifest
    policy_files: dict[str, str]  # filename → file content
    schema_content: str
    bundle_hash: str  # sha256:<hex>: what gets measured into the TEE report


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64url_decode(value: str) -> bytes:
    padding = 4 - (len(value) % 4)
    return base64.urlsafe_b64decode(value + ("=" * padding if padding != 4 else ""))


def signing_pre_image(bundle_hash: str) -> bytes:
    """The bytes a policy-bundle signature covers (POLICY-004).

    The signature is over the **bundle hash**, not the whole bundle, so signing
    reuses the hash the gateway already computes and measures. ``bundle_hash`` is
    the ``sha256:``-prefixed form, and the domain prefix keeps this signature from
    being interchangeable with any other signature in the system.
    """
    return _SIGNATURE_DOMAIN + bundle_hash.encode("utf-8")


def parse_bundle_version(version: str) -> tuple[int, ...]:
    """Parse a manifest ``version`` into a comparable tuple.

    Monotonicity is what stops a replayed older bundle, so the version has to be
    orderable. A version that cannot be parsed is refused rather than treated as
    equal-or-newer, because "unparseable" must not be a way past the check.
    """
    parts = version.split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError as exc:
        raise ConfigError(
            f"policy manifest version {version!r} is not a dotted sequence of integers; "
            "a runtime policy change is authorised by an increasing version, so the "
            "version must be orderable"
        ) from exc


def verify_bundle_signature(
    raw_manifest: dict[str, Any], bundle_hash: str, public_key: bytes
) -> None:
    """Verify a bundle's manifest signature against a pinned public key.

    Raises :class:`PolicySignatureInvalid` when the signature is absent, malformed,
    or does not verify. Absence is a failure *here* because this is only called
    when a deployment has pinned a key: having asked for signed policy, being
    handed unsigned policy is a refusal, not a downgrade.
    """
    signature = raw_manifest.get("signature")
    if not isinstance(signature, str) or not signature:
        raise PolicySignatureInvalid(
            "policy bundle manifest carries no signature",
            detail="a signing key is pinned, so an unsigned bundle is refused",
        )
    try:
        signature_bytes = _b64url_decode(signature)
    except (binascii.Error, ValueError) as exc:
        raise PolicySignatureInvalid(
            "policy bundle signature is not valid base64url", detail=str(exc)
        ) from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature_bytes, signing_pre_image(bundle_hash)
        )
    except InvalidSignature as exc:
        raise PolicySignatureInvalid(
            "policy bundle signature does not verify under the pinned signing key",
            detail=f"bundle_hash={bundle_hash}",
        ) from exc
    except ValueError as exc:
        raise PolicySignatureInvalid(
            "policy bundle signature could not be checked", detail=str(exc)
        ) from exc


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
    hashed_manifest = {k: v for k, v in manifest.items() if k not in _UNHASHED_MANIFEST_KEYS}
    canonical = json.dumps(
        {
            "manifest": hashed_manifest,
            "policy_files": policy_hashes,
            "schema_hash": _sha256_hex(schema_content.encode()),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return _sha256_hex(canonical.encode())


def load_policy_bundle(
    bundle_path: str,
    expected_hash: str | None = None,
    signing_key: bytes | None = None,
) -> PolicyBundle:
    """
    Load a Cedar policy bundle from disk and verify its hash.

    bundle_path is a directory containing:
    - manifest.json  (provenance metadata)
    - *.cedar        (Cedar policy files)
    - schema.cedarschema  (Cedar schema)

    expected_hash is "sha256:<hex>": must match the computed bundle hash.
    If expected_hash is None, the hash is computed but not verified (dev convenience).

    signing_key is a raw Ed25519 public key (POLICY-004). When supplied, the
    manifest's ``signature`` must verify over :func:`signing_pre_image` of the
    bundle hash. The two pins answer different questions and are usable together:
    ``expected_hash`` says *this exact artifact*, ``signing_key`` says *anything
    this authority approves*. Only the latter can authorise a bundle that changes,
    which is why runtime reload requires it.

    Raises PolicyHashMismatch if hashes do not match.
    Raises PolicySignatureInvalid if a key is pinned and the signature does not verify.
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

    pinned_agent_os = raw_manifest.get("agent_os_version")
    if pinned_agent_os is not None and pinned_agent_os != _AGENT_OS_VERSION:
        # POLICY-007: mismatch is a warning, not a hard failure, because the
        # gateway cannot know in advance whether a newer agent_os is semantically
        # compatible. Operators must review changelogs and re-pin after upgrade.
        logger.warning(
            "POLICY-007: agent_os_version mismatch: bundle pinned %s, installed %s. "
            "Cedar policy semantics may have changed; review the agent-os-kernel changelog.",
            pinned_agent_os,
            _AGENT_OS_VERSION,
        )

    manifest = PolicyManifest(
        version=raw_manifest["version"],
        authored_at=raw_manifest["authored_at"],
        author_identity=raw_manifest["author_identity"],
        commit_sha=raw_manifest["commit_sha"],
        approval_chain=raw_manifest.get("approval_chain", []),
        agent_os_version=pinned_agent_os,
        signature=raw_manifest.get("signature"),
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
                "Policy bundle hash mismatch: gateway will not start",
                detail=f"expected=sha256:{expected_hex} actual=sha256:{computed}",
            )

    if signing_key is not None:
        # POLICY-004. After the hash, because the signature is over the hash: a
        # signature can only mean anything once we know what was hashed.
        verify_bundle_signature(raw_manifest, f"sha256:{computed}", signing_key)
        # Refuse a version we cannot order, even on first load. Discovering at the
        # first reload that the running bundle's version was never comparable is
        # worse than refusing to start with it.
        parse_bundle_version(manifest.version)

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
        signing_key: bytes | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._bundle = bundle
        self._bundle_path = bundle_path
        self._reload_interval = reload_interval_seconds
        self._expected_hash = expected_hash
        self._signing_key = signing_key
        self._last_reload_at = time.monotonic()

    @property
    def bundle(self) -> PolicyBundle:
        with self._lock:
            return self._bundle

    def _check_not_a_downgrade(self, new_bundle: PolicyBundle) -> None:
        """Refuse a signed bundle whose version did not increase (POLICY-004).

        **Without this the signing-key model is a downgrade attack.** Anyone who
        can write the bundle directory replays yesterday's more permissive
        bundle: it is genuinely signed, the signature verifies, and the gateway
        installs a policy the operator already retired. Monotonicity is what makes
        "signed by the authority" mean "the authority's current intent".

        Only enforced where a key is pinned. Without one, reload is the dev-mode
        path and there is no authority whose intent could be replayed.
        """
        if self._signing_key is None:
            return
        current = parse_bundle_version(self._bundle.manifest.version)
        incoming = parse_bundle_version(new_bundle.manifest.version)
        if incoming <= current:
            raise PolicySignatureInvalid(
                "policy bundle version did not increase; refusing a possible downgrade",
                detail=(
                    f"running={self._bundle.manifest.version} "
                    f"offered={new_bundle.manifest.version}"
                ),
            )

    def reload_if_stale(self) -> bool:
        """Reload from disk if the configured interval has elapsed.

        Returns True if a reload attempt was made (regardless of whether the
        bundle hash changed).  Thread-safe; uses an RLock so nested calls from
        the same thread are safe.

        This runs on the enforcement path, once per policy evaluation, so the
        interval is a load bound and not only a freshness knob: the attempt is
        timestamped whether it succeeded or failed. Advancing it only on success
        meant a failing reload left the staleness check true, so every subsequent
        tool call re-read every policy file and recomputed the bundle hash. A
        reload that keeps failing must cost one attempt per interval, not one per
        request.
        """
        if self._reload_interval <= 0:
            return False
        with self._lock:
            if time.monotonic() - self._last_reload_at < self._reload_interval:
                return False
            # Stamped before the attempt, so an exception cannot skip it.
            self._last_reload_at = time.monotonic()
            try:
                new_bundle = load_policy_bundle(
                    self._bundle_path, self._expected_hash, self._signing_key
                )
                if new_bundle.bundle_hash != self._bundle.bundle_hash:
                    self._check_not_a_downgrade(new_bundle)
                    self._bundle = new_bundle
                    logger.info(
                        "Policy bundle reloaded: hash=%s version=%s",
                        new_bundle.bundle_hash,
                        new_bundle.manifest.version,
                    )
                return True
            except Exception as exc:
                logger.warning(
                    "Policy bundle reload failed (keeping current, retrying in %ds): %s",
                    self._reload_interval,
                    exc,
                )
                return False
