"""Agent Manifest binding helpers for session identity evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

import agent_manifest as agent_manifest_sdk

from cmcp_runtime.config import EnforcementMode
from cmcp_runtime.errors import ConfigError

SIGNED_FIELDS: tuple[str, ...] = tuple(agent_manifest_sdk.SIGNED_FIELDS)

_B64URL_RE = re.compile(r"^[A-Za-z0-9\-_]*$")
_HASH_RE = re.compile(r"^(sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96})$")
_SUBJECT_SOURCES: frozenset[str] = frozenset({"config", "svid", "manifest-dev"})

SubjectSource = Literal["config", "svid", "manifest-dev"]

# Spec 6.2: cMCP's own enforcement modes ("enforcing"/"advisory"/"silent",
# cmcp_runtime.config.EnforcementMode) and the Agent Manifest spec's
# ("enforce"/"advisory"/"audit-only") name the same three states differently.
# This is the single place that mapping is defined -- see
# agentrust-io/cmcp#576 and agentrust-io/agent-manifest#178.
_ENFORCEMENT_MODE_TO_MANIFEST: dict[EnforcementMode, str] = {
    EnforcementMode.ENFORCING: "enforce",
    EnforcementMode.ADVISORY: "advisory",
    EnforcementMode.SILENT: "audit-only",
}


def enforcement_mode_for_manifest(mode: EnforcementMode) -> str:
    """Map cMCP's enforcement mode to the Agent Manifest spec's vocabulary."""
    return _ENFORCEMENT_MODE_TO_MANIFEST[mode]

@dataclass(frozen=True)
class AgentManifestBinding:
    """Session-ready Agent Manifest identity binding."""

    manifest_id: str
    agent_id: str
    authenticated_subject: str
    subject_source: SubjectSource
    issuer: str
    issuer_key_id: str
    policy_bundle_hash: str
    tool_catalog_hash: str
    #: AARM R2. sha256 digest of the manifest's signed `intent` object, or None
    #: when the issuer declared none. Derived via agent_manifest.intent_hash
    #: rather than recomputed here, so the digest a receipt carries is the one
    #: the specification defines (agent-manifest spec 3.9).
    #:
    #: The digest travels, not the statement. Every other identity field in the
    #: claim is a hash for the same reason: the claim is meant to be shareable,
    #: and an intent statement is business context. A verifier that wants the
    #: text fetches the manifest it already has to fetch to check the signature.
    intent_hash: str | None = None
    #: Spec 6.2. The runtime's own enforcement mode (cmcp_runtime.config.
    #: EnforcementMode), present only when verify_agent_manifest_binding was
    #: given one -- which, by the time this object exists, means it has
    #: already been cross-checked against the manifest's declared
    #: artifacts.policy_bundle.enforcement_mode. A mismatch raises before this
    #: object is constructed, so a populated value here is an attested match,
    #: not merely "what the caller asked for".
    enforcement_mode: EnforcementMode | None = None


def _b64url_decode(value: str) -> bytes:
    if not _B64URL_RE.match(value):
        raise ConfigError("Agent Manifest signature/key must use base64url encoding")
    padding = 4 - (len(value) % 4)
    return base64.urlsafe_b64decode(value + ("=" * padding if padding != 4 else ""))


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def signing_pre_image(manifest: dict[str, Any]) -> bytes:
    """Return the Agent Manifest SDK signing pre-image."""
    return agent_manifest_sdk.signing_pre_image(manifest)


@dataclass(frozen=True)
class LoadedAgentManifest:
    """A manifest document plus the envelope it arrived in, if any.

    Both are needed because the two spec versions put the signature in
    different places (ADR-0011). In v0.1 the signature is a detached block
    inside the JSON document, so the document is the whole story. In v0.2 the
    COSE_Sign1 structure *is* the signature, so a v0.2 document handed over as
    a bare dict has no signature at all and the SDK reports SIGNATURE_MISSING.
    Carrying the envelope bytes alongside the decoded document is what lets the
    verifier be given the artifact it can actually appraise.
    """

    manifest: dict[str, Any]
    envelope: bytes | None = None


def load_agent_manifest_document(path: str) -> LoadedAgentManifest:
    """Load a manifest from *path*, JSON or COSE envelope.

    The file is sniffed rather than switched on its extension: a COSE envelope
    is CBOR and never parses as JSON, so trying JSON first and falling back is
    unambiguous, and an operator does not have to name the file correctly for
    the gateway to read it.
    """
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ConfigError(f"Cannot read Agent Manifest: {exc}") from exc

    try:
        manifest = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return LoadedAgentManifest(manifest=_decode_cose_envelope(raw), envelope=raw)

    if not isinstance(manifest, dict):
        raise ConfigError("Agent Manifest must be a JSON object")
    # A v0.2 document without an envelope is the one failure worth naming
    # precisely: the SDK would report a missing signature, which reads as a
    # malformed manifest rather than a manifest handed over in the wrong form.
    if manifest.get("version") == agent_manifest_sdk.COSE_MANIFEST_VERSION and (
        "signature" not in manifest
    ):
        raise ConfigError(
            "Agent Manifest declares version "
            f"{agent_manifest_sdk.COSE_MANIFEST_VERSION} but was supplied as bare "
            "JSON. From v0.2 the COSE_Sign1 envelope is the signature "
            "(agent-manifest ADR-0011); supply the envelope, not its payload."
        )
    return LoadedAgentManifest(manifest=manifest)


def _decode_cose_envelope(raw: bytes) -> dict[str, Any]:
    """Structurally decode a COSE envelope. No signature appraisal happens
    here: that is the verifier's job, and doing it in a loader would invite a
    caller to treat a decoded manifest as a verified one."""
    try:
        decoded = agent_manifest_sdk.decode_cose_manifest(raw)
    except Exception as exc:  # noqa: BLE001 - CoseError and friends -> ConfigError
        raise ConfigError(
            f"Cannot read Agent Manifest: not JSON and not a COSE envelope ({exc})"
        ) from exc
    if not isinstance(decoded.manifest, dict):
        raise ConfigError("Agent Manifest COSE payload must be a JSON object")
    return decoded.manifest


def load_agent_manifest(path: str) -> dict[str, Any]:
    """Backwards-compatible loader returning the document only.

    Callers that verify a signature want load_agent_manifest_document, because
    a v0.2 envelope cannot be verified from the document alone.
    """
    return load_agent_manifest_document(path).manifest


def load_agent_manifest_trust_anchor(path: str) -> dict[str, bytes]:
    """Load issuer public keys from a JSON trust anchor file."""
    try:
        with Path(path).open() as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot read Agent Manifest trust anchor: {exc}") from exc

    anchors: dict[str, bytes] = {}
    if isinstance(raw, dict) and "public_key_base64url" in raw:
        public_key = _b64url_decode(str(raw["public_key_base64url"]))
        key_id = str(raw.get("key_id") or _key_id(public_key))
        anchors[key_id] = public_key
        return anchors
    if isinstance(raw, dict) and "keys" in raw and isinstance(raw["keys"], list):
        for item in raw["keys"]:
            if not isinstance(item, dict):
                raise ConfigError("Agent Manifest trust anchor keys must be objects")
            public_key = _b64url_decode(str(item.get("public_key_base64url", "")))
            key_id = str(item.get("key_id") or _key_id(public_key))
            anchors[key_id] = public_key
        return anchors
    raise ConfigError(
        "Agent Manifest trust anchor must contain public_key_base64url or keys[]"
    )


def _trusted_keys_for_sdk(trusted_keys: dict[str, bytes]) -> dict[str, str]:
    sdk_keys: dict[str, str] = {}
    for key_id, public_key in trusted_keys.items():
        if len(public_key) != 32:
            raise ConfigError("Agent Manifest trust anchor contains an invalid Ed25519 key")
        if _key_id(public_key) != key_id:
            raise ConfigError("Agent Manifest trust anchor key_id does not match public key")
        sdk_keys[key_id] = _b64url_encode(public_key)
    return sdk_keys


def _result_value(value: Any) -> str:
    return str(getattr(value, "value", value))


def _raise_for_sdk_result(result: Any, *, require_runtime_artifacts: bool) -> None:
    if result.result == agent_manifest_sdk.OverallResult.VALID:
        if result.signature_verified is not True:
            raise ConfigError("Agent Manifest signature verification failed")
        if require_runtime_artifacts:
            fields = result.fields_verified
            if fields.policy_bundle != agent_manifest_sdk.FieldResult.MATCH:
                raise ConfigError(
                    "Agent Manifest policy bundle hash does not match runtime policy"
                )
            if fields.tool_manifest != agent_manifest_sdk.FieldResult.MATCH:
                raise ConfigError(
                    "Agent Manifest tool catalog hash does not match runtime catalog"
                )
        return

    mismatch_fields = {str(detail.field) for detail in result.mismatch_details}
    # Checked before the plain "policy_bundle" case: the hash can match while
    # only the enforcement mode disagrees (spec 6.2), and that deserves its
    # own message rather than being reported as a hash mismatch.
    if "policy_bundle.enforcement_mode" in mismatch_fields:
        raise ConfigError(  # pragma: no cover -- exercised by
            # test_enforcement_mode_mismatch_fails_closed /
            # test_enforcement_mode_not_provided_fails_closed, currently
            # skipped pending agentrust-io/agent-manifest#345 (see
            # tests/unit/test_agent_manifest.py). Remove this pragma
            # alongside the skip markers once that ships.
            "Agent Manifest policy bundle enforcement_mode does not match the "
            "runtime's attested enforcement mode"
        )
    if "policy_bundle" in mismatch_fields:
        raise ConfigError("Agent Manifest policy bundle hash does not match runtime policy")
    if "tool_manifest" in mismatch_fields:
        raise ConfigError("Agent Manifest tool catalog hash does not match runtime catalog")
    if "signature" in mismatch_fields:
        raise ConfigError("Agent Manifest signature verification failed")
    if result.result == agent_manifest_sdk.OverallResult.EXPIRED:
        raise ConfigError("Agent Manifest has expired")
    if result.result == agent_manifest_sdk.OverallResult.SIGNATURE_MISSING:
        raise ConfigError("Agent Manifest signature block is missing")
    if result.result == agent_manifest_sdk.OverallResult.UNVERIFIABLE:
        # UNVERIFIABLE is not a failed signature: the verifier could not appraise
        # the signature at all, because it lacks the trusted key or (since
        # agent-manifest 0.6.1) the algorithm. Both reject, but an operator needs
        # to know which, so surface the verifier's own reason when it gives one.
        reason = "; ".join(getattr(result, "warnings", None) or [])
        detail = f": {reason}" if reason else ""
        raise ConfigError(
            f"Agent Manifest signature could not be verified{detail}"
        )
    if result.result == agent_manifest_sdk.OverallResult.INCOMPATIBLE_VERSION:
        raise ConfigError("Agent Manifest version is not supported by the SDK verifier")
    if result.result == agent_manifest_sdk.OverallResult.INCOMPLETE:
        raise ConfigError("Agent Manifest SDK verification is incomplete")
    raise ConfigError(f"Agent Manifest SDK verification failed: {_result_value(result.result)}")


def _verify_with_sdk(
    manifest: dict[str, Any],
    trusted_keys: dict[str, bytes],
    *,
    policy_bundle_hash: str | None = None,
    tool_catalog_hash: str | None = None,
    enforcement_mode: EnforcementMode | None = None,
    require_runtime_artifacts: bool = False,
    envelope: bytes | None = None,
) -> None:
    # The envelope is handed to the verifier when there is one, because for a
    # v0.2 manifest the envelope is the signature. Passing the decoded payload
    # instead would ask the SDK to appraise a document with nothing to appraise.
    result = agent_manifest_sdk.verify_manifest(
        envelope if envelope is not None else manifest,
        agent_manifest_sdk.VerificationContext(
            policy_bundle_hash=policy_bundle_hash,
            tool_catalog_hash=tool_catalog_hash,
            enforcement_mode=(
                enforcement_mode_for_manifest(enforcement_mode)
                if enforcement_mode is not None
                else None
            ),
            trusted_keys=_trusted_keys_for_sdk(trusted_keys),
        ),
        agent_manifest_sdk.RevocationStore(),
    )
    _raise_for_sdk_result(result, require_runtime_artifacts=require_runtime_artifacts)


def verify_agent_manifest_signature(
    manifest: dict[str, Any],
    trusted_keys: dict[str, bytes],
    *,
    envelope: bytes | None = None,
) -> None:
    _verify_with_sdk(manifest, trusted_keys, envelope=envelope)


def _require_hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.match(value):
        raise ConfigError(f"Agent Manifest {field} must be a sha-prefixed hash")
    return value


def _parse_manifest_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"Agent Manifest {field} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConfigError(f"Agent Manifest {field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ConfigError(f"Agent Manifest {field} must include a timezone")
    return parsed.astimezone(UTC)


def _manifest_binding_fields(manifest: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    manifest_id = manifest.get("manifest_id")
    agent_id = manifest.get("agent_id")
    issuer = manifest.get("issuer")
    if not isinstance(manifest_id, str) or not manifest_id:
        raise ConfigError("Agent Manifest manifest_id is missing")
    if not isinstance(agent_id, str) or not agent_id.startswith("spiffe://"):
        raise ConfigError("Agent Manifest agent_id must be a SPIFFE URI")
    if not isinstance(issuer, str) or not issuer.startswith("spiffe://"):
        raise ConfigError("Agent Manifest issuer must be a SPIFFE URI")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ConfigError("Agent Manifest artifacts object is missing")
    policy = artifacts.get("policy_bundle")
    tools = artifacts.get("tool_manifest")
    if not isinstance(policy, dict) or not isinstance(tools, dict):
        raise ConfigError("Agent Manifest must bind policy_bundle and tool_manifest")
    policy_hash = _require_hash(policy.get("hash"), "artifacts.policy_bundle.hash")
    catalog_hash = _require_hash(
        tools.get("catalog_hash"), "artifacts.tool_manifest.catalog_hash"
    )
    signature = manifest.get("signature")
    key_id = str(signature.get("key_id") or "") if isinstance(signature, dict) else ""
    return manifest_id, agent_id, issuer, key_id, policy_hash, catalog_hash


def verify_agent_manifest_binding(
    manifest: dict[str, Any],
    trusted_keys: dict[str, bytes],
    *,
    authenticated_subject: str | None,
    policy_bundle_hash: str,
    tool_catalog_hash: str,
    enforcement_mode: EnforcementMode | None = None,
    authenticated_subject_source: str | None = None,
    allow_dev_subject_from_manifest: bool = False,
    now: datetime | None = None,
    envelope: bytes | None = None,
) -> AgentManifestBinding:
    """Verify manifest signature and bind it to runtime session inputs.

    *envelope* carries the COSE bytes for a v0.2 manifest. The binding fields
    are read from the decoded document either way: what the envelope changes is
    which artifact the signature is checked over, not where identity lives.
    """
    manifest_id, agent_id, issuer, key_id, manifest_policy, manifest_catalog = (
        _manifest_binding_fields(manifest)
    )

    _parse_manifest_time(manifest.get("issued_at"), "issued_at")
    expires_at = _parse_manifest_time(manifest.get("expires_at"), "expires_at")
    current_time = now or datetime.now(UTC)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=UTC)
    if expires_at <= current_time.astimezone(UTC):
        raise ConfigError("Agent Manifest has expired")
    _verify_with_sdk(
        manifest,
        trusted_keys,
        policy_bundle_hash=policy_bundle_hash,
        tool_catalog_hash=tool_catalog_hash,
        enforcement_mode=enforcement_mode,
        require_runtime_artifacts=True,
        envelope=envelope,
    )

    subject = authenticated_subject
    subject_source = authenticated_subject_source
    if subject is None and allow_dev_subject_from_manifest:
        subject = agent_id
        subject_source = "manifest-dev"
    if subject_source is None:
        subject_source = "config"
    if subject_source not in _SUBJECT_SOURCES:
        raise ConfigError("Agent Manifest subject_source is not supported")
    if subject_source == "manifest-dev" and not allow_dev_subject_from_manifest:
        raise ConfigError("Agent Manifest manifest-dev subject_source requires dev mode")
    subject_source = cast(SubjectSource, subject_source)
    if not isinstance(subject, str) or not subject.startswith("spiffe://"):
        raise ConfigError("Authenticated agent subject must be a SPIFFE URI")
    if subject != agent_id:
        raise ConfigError(
            "Agent Manifest agent_id does not match authenticated session subject"
        )

    return AgentManifestBinding(
        manifest_id=manifest_id,
        agent_id=agent_id,
        authenticated_subject=subject,
        subject_source=subject_source,
        issuer=issuer,
        issuer_key_id=key_id,
        policy_bundle_hash=manifest_policy,
        tool_catalog_hash=manifest_catalog,
        # Read after the signature has been verified above, never before: an
        # intent taken from an unverified manifest is an intent anyone could
        # have written, which is the failure the field exists to prevent.
        intent_hash=agent_manifest_sdk.intent_hash(manifest),
        enforcement_mode=enforcement_mode,
    )
