"""Agent Manifest binding helpers for session identity evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cmcp_runtime.errors import ConfigError

SIGNED_FIELDS: tuple[str, ...] = (
    "@context",
    "@type",
    "manifest_id",
    "previous_manifest_id",
    "agent_id",
    "version",
    "min_verifier_version",
    "issued_at",
    "expires_at",
    "issuer",
    "crypto_profile",
    "artifacts",
    "delegation_chain",
    "hitl_record",
    "prior_transparency_log_entry",
    "log_retention",
    "data_scope",
    "operational_lifecycle",
)

_B64URL_RE = re.compile(r"^[A-Za-z0-9\-_]*$")
_HASH_RE = re.compile(r"^(sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96})$")
_SUBJECT_SOURCES: frozenset[str] = frozenset({"config", "svid", "manifest-dev"})
_SMALL_ORDER_POINTS: frozenset[bytes] = frozenset({
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
})

SubjectSource = Literal["config", "svid", "manifest-dev"]


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


def _b64url_decode(value: str) -> bytes:
    if not _B64URL_RE.match(value):
        raise ConfigError("Agent Manifest signature/key must use base64url encoding")
    padding = 4 - (len(value) % 4)
    return base64.urlsafe_b64decode(value + ("=" * padding if padding != 4 else ""))


def _key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def _quote(value: str) -> str:
    parts = ['"']
    for ch in value:
        cp = ord(ch)
        if ch == '"':
            parts.append('\\"')
        elif ch == "\\":
            parts.append("\\\\")
        elif ch == "\b":
            parts.append("\\b")
        elif ch == "\f":
            parts.append("\\f")
        elif ch == "\n":
            parts.append("\\n")
        elif ch == "\r":
            parts.append("\\r")
        elif ch == "\t":
            parts.append("\\t")
        elif cp <= 0x001F:
            parts.append(f"\\u{cp:04x}")
        else:
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def _serialize_json(value: Any, *, depth: int = 0) -> str:
    if depth > 64:
        raise ConfigError("Agent Manifest JSON nesting is too deep")
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ConfigError("Agent Manifest JSON contains non-finite number")
        if value == math.floor(value) and abs(value) < 1e15:
            return str(int(value))
        text = repr(value)
        if "e" in text and "e+" not in text and "e-" not in text:
            text = text.replace("e", "e+")
        return text
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize_json(v, depth=depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        items = []
        for key in sorted(value, key=lambda item: _utf16_sort_key(str(item))):
            nested = value[key]
            if nested is None:
                continue
            items.append(f"{_quote(str(key))}:{_serialize_json(nested, depth=depth + 1)}")
        return "{" + ",".join(items) + "}"
    raise ConfigError(f"Agent Manifest JSON contains unsupported value {type(value).__name__}")


def _canonicalize(value: dict[str, Any]) -> bytes:
    return _serialize_json(value).encode("utf-8")


def signing_pre_image(manifest: dict[str, Any]) -> bytes:
    """Return the Agent Manifest RFC 8785 signing pre-image."""
    subset = {key: manifest[key] for key in SIGNED_FIELDS if key in manifest}
    hitl_record = subset.get("hitl_record")
    if isinstance(hitl_record, dict):
        normalized = dict(hitl_record)
        normalized["approvals"] = []
        subset["hitl_record"] = normalized
    return _canonicalize(subset)


def load_agent_manifest(path: str) -> dict[str, Any]:
    try:
        with Path(path).open() as f:
            manifest = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot read Agent Manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ConfigError("Agent Manifest must be a JSON object")
    return manifest


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


def verify_agent_manifest_signature(
    manifest: dict[str, Any],
    trusted_keys: dict[str, bytes],
) -> None:
    sig = manifest.get("signature")
    if not isinstance(sig, dict):
        raise ConfigError("Agent Manifest signature block is missing")
    if sig.get("algorithm") != "Ed25519":
        raise ConfigError("Agent Manifest signature algorithm must be Ed25519")

    key_id = str(sig.get("key_id") or "")
    public_key = trusted_keys.get(key_id)
    if public_key is None:
        raise ConfigError(f"Agent Manifest issuer key_id {key_id!r} is not trusted")
    if len(public_key) != 32 or public_key in _SMALL_ORDER_POINTS:
        raise ConfigError("Agent Manifest trust anchor contains an invalid Ed25519 key")
    if _key_id(public_key) != key_id:
        raise ConfigError("Agent Manifest trust anchor key_id does not match public key")

    signature = _b64url_decode(str(sig.get("signature_value") or ""))
    if len(signature) != 64:
        raise ConfigError("Agent Manifest Ed25519 signature must be 64 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, signing_pre_image(manifest)
        )
    except InvalidSignature as exc:
        raise ConfigError("Agent Manifest signature verification failed") from exc


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
    key_id = str((manifest.get("signature") or {}).get("key_id") or "")
    return manifest_id, agent_id, issuer, key_id, policy_hash, catalog_hash


def verify_agent_manifest_binding(
    manifest: dict[str, Any],
    trusted_keys: dict[str, bytes],
    *,
    authenticated_subject: str | None,
    policy_bundle_hash: str,
    tool_catalog_hash: str,
    authenticated_subject_source: str | None = None,
    allow_dev_subject_from_manifest: bool = False,
    now: datetime | None = None,
) -> AgentManifestBinding:
    """Verify manifest signature and bind it to runtime session inputs."""
    verify_agent_manifest_signature(manifest, trusted_keys)
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
    if manifest_policy != policy_bundle_hash:
        raise ConfigError("Agent Manifest policy bundle hash does not match runtime policy")
    if manifest_catalog != tool_catalog_hash:
        raise ConfigError("Agent Manifest tool catalog hash does not match runtime catalog")

    return AgentManifestBinding(
        manifest_id=manifest_id,
        agent_id=agent_id,
        authenticated_subject=subject,
        subject_source=subject_source,
        issuer=issuer,
        issuer_key_id=key_id,
        policy_bundle_hash=manifest_policy,
        tool_catalog_hash=manifest_catalog,
    )
