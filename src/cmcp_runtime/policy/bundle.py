"""Cedar policy bundle loading and hash verification: implements issue #63."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cmcp_runtime.errors import (
    ConfigError,
    PolicyHashMismatch,
    PolicyKeyRevocationInvalid,
    PolicySignatureInvalid,
    PolicySigningKeyRevoked,
)

logger = logging.getLogger(__name__)


@dataclass
class PolicyManifest:
    """Provenance metadata embedded in the policy bundle (policy provenance, issue #26)."""

    version: str
    authored_at: str
    author_identity: str
    commit_sha: str
    approval_chain: list[dict[str, str]] = field(default_factory=list)
    agent_os_version: str | None = None  # Legacy metadata, retained for bundle compatibility
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
    #: :func:`policy_key_id` of the key the signature verified under, or None when
    #: no key was pinned and the bundle was not signature-checked.
    signing_key_id: str | None = None


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


#: Domain separation for a key revocation statement, so a policy-bundle signature
#: can never be read as a revocation, or the reverse.
_REVOCATION_DOMAIN = b"cmcp-policy-key-revocation-v1|"

#: Revocation statements are read from this file in the bundle directory. It is
#: not part of the bundle hash (only manifest.json, *.cedar and the schema are),
#: so adding it does not change the measured policy.
REVOCATION_FILE = "signing-key-revocations.json"


def policy_key_id(public_key: bytes) -> str:
    """Stable identifier for a raw Ed25519 policy signing key: ``sha256:<hex>``
    of the 32 raw public key bytes."""
    return "sha256:" + _sha256_hex(public_key)


def revocation_pre_image(revoked_key_id: str) -> bytes:
    """The bytes a key revocation statement's signature covers."""
    return _REVOCATION_DOMAIN + revoked_key_id.encode("utf-8")


def _verifies(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


class PolicySigningKeys:
    """The policy signing keys a gateway trusts, and the ones it has revoked.

    ``current`` signs policy bundles. ``successor`` is optional, is pinned at
    startup next to ``current``, and signs no bundle until it is promoted. Its one
    use before then is to sign a revocation of ``current``, which is how a gateway
    stops trusting a compromised key without a restart: the successor's private
    key is kept apart from the current one, so whoever holds a stolen current key
    does not hold it.

    A revocation of ``current`` may also be signed by ``current`` itself. That
    gives a holder of the stolen key nothing: revoking a key hands policy to the
    successor, or leaves no trusted key at all, and it cannot be undone.

    State only moves one way. A revoked key never becomes trusted again in this
    process, no statement un-revokes, and the successor is promoted at most once.
    Replaying a statement that was already applied is a no-op.
    """

    def __init__(self, current: bytes, successor: bytes | None = None) -> None:
        if successor is not None and successor == current:
            raise ConfigError(
                "the successor policy signing key must differ from the current one"
            )
        self._current: bytes | None = current
        self._successor = successor
        self._revoked: list[bytes] = []

    @property
    def current(self) -> bytes | None:
        """The key bundles must be signed by, or None once every key is revoked."""
        return self._current

    @property
    def successor(self) -> bytes | None:
        return self._successor

    @property
    def revoked(self) -> tuple[bytes, ...]:
        return tuple(self._revoked)

    @property
    def revoked_key_ids(self) -> list[str]:
        return [policy_key_id(k) for k in self._revoked]

    def is_revoked(self, key_id: str | None) -> bool:
        return key_id is not None and key_id in self.revoked_key_ids

    def apply(self, statement: object) -> str | None:
        """Apply one revocation statement.

        Returns the revoked key id when the statement changed state, or None when
        it had already been applied. Raises :class:`PolicyKeyRevocationInvalid`
        when the statement is refused; state is then unchanged.
        """
        if not isinstance(statement, dict):
            raise PolicyKeyRevocationInvalid("revocation statement is not a JSON object")
        revoked_id = statement.get("revoked_key_id")
        signature = statement.get("signature")
        if not isinstance(revoked_id, str) or not isinstance(signature, str) or not signature:
            raise PolicyKeyRevocationInvalid(
                "revocation statement needs string revoked_key_id and signature"
            )
        if self.is_revoked(revoked_id):
            return None
        current = self._current
        if current is None or revoked_id != policy_key_id(current):
            raise PolicyKeyRevocationInvalid(
                "only the key currently trusted to sign policy can be revoked",
                detail=f"revoked_key_id={revoked_id}",
            )
        try:
            signature_bytes = _b64url_decode(signature)
        except (binascii.Error, ValueError) as exc:
            raise PolicyKeyRevocationInvalid(
                "revocation signature is not valid base64url", detail=str(exc)
            ) from exc
        message = revocation_pre_image(revoked_id)
        signers = [k for k in (self._successor, current) if k is not None]
        signer = next((k for k in signers if _verifies(k, signature_bytes, message)), None)
        if signer is None:
            raise PolicyKeyRevocationInvalid(
                "revocation signature verifies under neither the current nor the "
                "successor policy signing key",
                detail=f"revoked_key_id={revoked_id}",
            )
        self._revoked.append(current)
        self._current, self._successor = self._successor, None
        logger.warning(
            "POLICY_SIGNING_KEY_REVOKED: revoked=%s signed_by=%s now_trusted=%s",
            revoked_id,
            policy_key_id(signer),
            policy_key_id(self._current) if self._current is not None else "none",
        )
        return revoked_id

    def apply_file(self, bundle_path: str) -> list[str]:
        """Apply every statement in the bundle directory's revocation file.

        Never raises. A statement that is refused is logged and skipped, and the
        rest are still applied: anyone who can write the bundle directory can
        write a bad statement, and that must not be able to block a good one, or
        block the reload of a bundle signed by a still-trusted key.
        """
        if not bundle_path:
            return []
        path = Path(bundle_path) / REVOCATION_FILE
        if not path.is_file():
            return []
        try:
            statements = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("POLICY_KEY_REVOCATION_INVALID: cannot read %s: %s", path, exc)
            return []
        if not isinstance(statements, list):
            logger.warning(
                "POLICY_KEY_REVOCATION_INVALID: %s must hold a JSON array of statements",
                path,
            )
            return []
        applied: list[str] = []
        for statement in statements:
            try:
                revoked = self.apply(statement)
            except PolicyKeyRevocationInvalid as exc:
                logger.warning(
                    "POLICY_KEY_REVOCATION_INVALID: %s (%s)", exc, exc.detail or ""
                )
                continue
            if revoked is not None:
                applied.append(revoked)
        return applied


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
    raw_manifest: dict[str, Any],
    bundle_hash: str,
    public_key: bytes,
    revoked_keys: Iterable[bytes] = (),
) -> None:
    """Verify a bundle's manifest signature against a pinned public key.

    Raises :class:`PolicySignatureInvalid` when the signature is absent, malformed,
    or does not verify. Absence is a failure *here* because this is only called
    when a deployment has pinned a key: having asked for signed policy, being
    handed unsigned policy is a refusal, not a downgrade.

    Raises :class:`PolicySigningKeyRevoked` instead when the signature does not
    verify under ``public_key`` but does under one of ``revoked_keys``, so a
    bundle signed by a revoked key is reported as that and not as a bad signature.
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
        pre_image = signing_pre_image(bundle_hash)
        for revoked in revoked_keys:
            if _verifies(revoked, signature_bytes, pre_image):
                raise PolicySigningKeyRevoked(
                    "policy bundle is signed by a revoked policy signing key",
                    detail=f"bundle_hash={bundle_hash} key_id={policy_key_id(revoked)}",
                ) from exc
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
    # docs/spec/cedar-policy.md section 1 defines canonical_json as RFC 8785
    # (JCS), so this uses a JCS implementation rather than approximating one.
    #
    # json.dumps(sort_keys=True, ensure_ascii=True) agrees with JCS for
    # ASCII-only, integer-only bundles, which is why the divergence went
    # unnoticed. It differs on two input classes the spec explicitly allows:
    #
    #   non-ASCII strings   JCS emits raw UTF-8; ensure_ascii emits an escape
    #   float-typed numbers JCS 3.2.2.3 requires the ES6 shortest form (1),
    #                       json.dumps emits 1.0
    #
    # Section 1 defines author_identity as a SPIFFE SVID or git identity, and
    # git identities routinely carry non-ASCII names, so this is ordinary input
    # rather than an adversarial edge case. Two implementations following the
    # written spec would have computed different hashes for the same bundle.
    canonical = rfc8785.dumps(
        {
            "manifest": hashed_manifest,
            "policy_files": policy_hashes,
            "schema_hash": _sha256_hex(schema_content.encode()),
        }
    )
    return _sha256_hex(canonical)


def load_policy_bundle(
    bundle_path: str,
    expected_hash: str | None = None,
    signing_key: bytes | None = None,
    revoked_keys: Iterable[bytes] = (),
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
    revoked_keys are policy signing keys revoked in this process. They are only
    consulted to name the refusal: a bundle whose signature verifies under one of
    them, and not under ``signing_key``, raises PolicySigningKeyRevoked.

    Raises PolicySignatureInvalid if a key is pinned and the signature does not verify.
    Raises PolicySigningKeyRevoked if it verifies only under a revoked key.
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
    if pinned_agent_os is not None:
        logger.warning(
            "POLICY-007: agent_os_version=%s is legacy metadata and is not enforced; "
            "cMCP no longer has an AGT runtime dependency.",
            pinned_agent_os,
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
        verify_bundle_signature(
            raw_manifest, f"sha256:{computed}", signing_key, revoked_keys
        )
        # Refuse a version we cannot order, even on first load. Discovering at the
        # first reload that the running bundle's version was never comparable is
        # worse than refusing to start with it.
        parse_bundle_version(manifest.version)

    return PolicyBundle(
        manifest=manifest,
        policy_files=policy_files,
        schema_content=schema_content,
        bundle_hash=f"sha256:{computed}",
        signing_key_id=policy_key_id(signing_key) if signing_key is not None else None,
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
        signing_keys: PolicySigningKeys | None = None,
    ) -> None:
        """``signing_key`` pins one key. ``signing_keys`` pins a current key with an
        optional successor and carries any revocations already applied (startup
        applies the revocation file before the first load); pass one or neither."""
        if signing_key is not None and signing_keys is not None:
            raise ValueError("pass signing_key or signing_keys, not both")
        if signing_keys is None and signing_key is not None:
            signing_keys = PolicySigningKeys(signing_key)
        self._lock = threading.RLock()
        self._bundle = bundle
        self._bundle_path = bundle_path
        self._reload_interval = reload_interval_seconds
        self._expected_hash = expected_hash
        self._keys = signing_keys
        self._last_reload_at = time.monotonic()

    @property
    def bundle(self) -> PolicyBundle:
        with self._lock:
            return self._bundle

    @property
    def _signing_key(self) -> bytes | None:
        """The key a new bundle must be signed by; None when no key is pinned."""
        return self._keys.current if self._keys is not None else None

    @property
    def revoked_key_ids(self) -> list[str]:
        """Policy signing keys revoked in this process, in the order revoked."""
        with self._lock:
            return self._keys.revoked_key_ids if self._keys is not None else []

    def require_trusted(self) -> None:
        """Refuse to evaluate under a policy whose signing key has been revoked.

        Fail closed. The installed bundle was accepted because the key verified
        it; once that key is revoked, the bundle is only as trustworthy as
        whoever held the key, and the reason to revoke is that someone else may.
        Keeping it in force would be keeping the attacker's last policy. Calls are
        refused until a bundle signed by a still-trusted key is installed.
        """
        with self._lock:
            if self._keys is None:
                return
            key_id = self._bundle.signing_key_id
            if self._keys.is_revoked(key_id):
                raise PolicySigningKeyRevoked(
                    "the policy in force is signed by a revoked policy signing key; "
                    "refusing until a bundle signed by a trusted key is installed",
                    detail=f"bundle_hash={self._bundle.bundle_hash} key_id={key_id}",
                )

    def _check_not_a_downgrade(self, new_bundle: PolicyBundle) -> None:
        """Refuse a signed bundle whose version did not increase (POLICY-004).

        **Without this the signing-key model is a downgrade attack.** Anyone who
        can write the bundle directory replays yesterday's more permissive
        bundle: it is genuinely signed, the signature verifies, and the gateway
        installs a policy the operator already retired. Monotonicity is what makes
        "signed by the authority" mean "the authority's current intent".

        Only enforced where a key is pinned. Without one, reload is the dev-mode
        path and there is no authority whose intent could be replayed.

        The floor is the running bundle's version even when its key has since
        been revoked, so the version floor never goes down: the bundle that
        replaces a revoked-key policy must carry a higher version than it.
        """
        if self._keys is None:
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
            if self._keys is not None:
                # Before the bundle, so a bundle signed by a key revoked in this
                # same pass is already refused. Never raises: a bad statement is
                # logged and skipped, and cannot block the bundle reload below.
                self._keys.apply_file(self._bundle_path)
            try:
                if self._keys is not None and self._keys.current is None:
                    # Every pinned key is revoked. Loading with no key would skip
                    # the signature check entirely, which is the opposite of what
                    # revoking asked for.
                    raise PolicySigningKeyRevoked(
                        "every pinned policy signing key is revoked; no bundle can "
                        "be accepted until the gateway is restarted with a new key"
                    )
                # With a key pinned, the key authorises what changes after startup,
                # and the pinned hash has done its job: it fixed the artifact the
                # process started with. Re-checking it here refuses every bundle
                # that actually changed, which made reload inert in the one shape
                # production runs (a hash is required outside dev mode).
                new_bundle = load_policy_bundle(
                    self._bundle_path,
                    None if self._signing_key is not None else self._expected_hash,
                    self._signing_key,
                    self._keys.revoked if self._keys is not None else (),
                )
                if new_bundle.bundle_hash != self._bundle.bundle_hash:
                    self._check_not_a_downgrade(new_bundle)
                    self._bundle = new_bundle
                    logger.info(
                        "Policy bundle reloaded: hash=%s version=%s signing_key_id=%s",
                        new_bundle.bundle_hash,
                        new_bundle.manifest.version,
                        new_bundle.signing_key_id,
                    )
                return True
            except Exception as exc:
                logger.warning(
                    "Policy bundle reload failed (keeping current, retrying in %ds): %s",
                    self._reload_interval,
                    exc,
                )
                return False
