"""Explicit, signed correspondence between cMCP catalog and Agent Manifest tool root.

This is a separate protocol: it does not extend the Agent Manifest schema.
The caller must independently verify the Agent Manifest and runtime catalog.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from cmcp_runtime.errors import ConfigError

DOMAIN = b"cmcp.catalog-authority-bridge.v1\x00"
FIELDS = frozenset({"version", "manifest_id", "manifest_digest", "agent_id", "policy_hash", "runtime_catalog_hash", "manifest_catalog_root", "not_before", "expires_at", "key_id"})


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _message(payload: dict[str, Any]) -> bytes:
    return DOMAIN + _canonical(payload)


def _time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ConfigError("Invalid catalog bridge timestamp") from exc
    if result.tzinfo is None:
        raise ConfigError("Catalog bridge timestamp lacks timezone")
    return result.astimezone(UTC)


def sign_bridge(payload: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Issuer-side signing; never called automatically during gateway startup."""
    if set(payload) != FIELDS:
        raise ConfigError("Catalog bridge fields are not canonical")
    signature = private_key.sign(_message(payload))
    return {"payload": payload, "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")}


def verify_bridge(receipt: dict[str, Any], trusted_keys: dict[str, bytes], *,
                  manifest_id: str, manifest_digest: str, agent_id: str,
                  policy_hash: str, runtime_catalog_hash: str,
                  manifest_catalog_root: str, now: datetime | None = None) -> None:
    if not isinstance(receipt, dict) or set(receipt) != {"payload", "signature"}:
        raise ConfigError("Invalid catalog bridge envelope")
    p = receipt["payload"]
    if not isinstance(p, dict) or set(p) != FIELDS or p["version"] != 1:
        raise ConfigError("Unsupported catalog bridge payload")
    expected = {"manifest_id": manifest_id, "manifest_digest": manifest_digest,
                "agent_id": agent_id, "policy_hash": policy_hash,
                "runtime_catalog_hash": runtime_catalog_hash,
                "manifest_catalog_root": manifest_catalog_root}
    if any(p.get(k) != v for k, v in expected.items()):
        raise ConfigError("Catalog bridge measurement or identity mismatch")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if not _time(p["not_before"]) <= current < _time(p["expires_at"]):
        raise ConfigError("Catalog bridge outside validity window")
    key = trusted_keys.get(p["key_id"])
    if not isinstance(key, bytes) or len(key) != 32:
        raise ConfigError("Catalog bridge signing key not trusted")
    sig = receipt["signature"]
    if not isinstance(sig, str) or not sig or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in sig):
        raise ConfigError("Invalid catalog bridge signature encoding")
    try:
        raw = base64.urlsafe_b64decode(sig + '=' * (-len(sig) % 4))
        if len(raw) != 64:
            raise ValueError("Signature length")
        Ed25519PublicKey.from_public_bytes(key).verify(raw, _message(p))
    except (ValueError, InvalidSignature, TypeError) as exc:
        raise ConfigError("Catalog bridge signature invalid") from exc
