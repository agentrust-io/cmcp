"""Tests for Agent Manifest identity binding (#302)."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cmcp_runtime.agent_manifest import (
    SIGNED_FIELDS,
    load_agent_manifest_trust_anchor,
    signing_pre_image,
    verify_agent_manifest_binding,
)
from cmcp_runtime.errors import ConfigError

POLICY_HASH = "sha256:" + "a" * 64
CATALOG_HASH = "sha256:" + "b" * 64
AGENT_ID = "spiffe://factory.example/agent/material-movement/dev"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _keypair() -> tuple[Ed25519PrivateKey, bytes, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub, hashlib.sha256(pub).hexdigest()


def _signed_manifest(
    priv: Ed25519PrivateKey,
    key_id: str,
    *,
    agent_id: str = AGENT_ID,
    policy_hash: str = POLICY_HASH,
    catalog_hash: str = CATALOG_HASH,
) -> dict:
    manifest = {
        "@context": "https://agentmanifest.agentrust.io/v0.1/context.json",
        "@type": "AgentManifest",
        "manifest_id": "0197739a-8c00-7000-8000-000000000001",
        "agent_id": agent_id,
        "version": "0.1",
        "issued_at": "2026-06-12T00:00:00Z",
        "expires_at": "2099-09-10T00:00:00Z",
        "issuer": "spiffe://factory.example/signing-authority/development",
        "crypto_profile": "standard",
        "artifacts": {
            "policy_bundle": {
                "hash": policy_hash,
                "policy_language": "cedar",
                "version": "0.1.0",
                "enforcement_mode": "enforce",
            },
            "tool_manifest": {
                "catalog_hash": catalog_hash,
                "tools": [],
                "allow_dynamic_registration": False,
                "rug_pull_policy": "deny-and-alert",
            },
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
    return manifest


def test_valid_manifest_binds_subject_policy_and_catalog() -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    binding = verify_agent_manifest_binding(
        manifest,
        {key_id: pub},
        authenticated_subject=AGENT_ID,
        policy_bundle_hash=POLICY_HASH,
        tool_catalog_hash=CATALOG_HASH,
    )
    assert binding.manifest_id == manifest["manifest_id"]
    assert binding.agent_id == AGENT_ID
    assert binding.issuer_key_id == key_id


def test_subject_mismatch_fails_closed() -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    with pytest.raises(ConfigError, match="authenticated session subject"):
        verify_agent_manifest_binding(
            manifest,
            {key_id: pub},
            authenticated_subject="spiffe://factory.example/agent/other/dev",
            policy_bundle_hash=POLICY_HASH,
            tool_catalog_hash=CATALOG_HASH,
        )


def test_tampered_manifest_signature_fails_closed() -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    manifest["agent_id"] = "spiffe://factory.example/agent/other/dev"
    with pytest.raises(ConfigError, match="signature verification failed"):
        verify_agent_manifest_binding(
            manifest,
            {key_id: pub},
            authenticated_subject=AGENT_ID,
            policy_bundle_hash=POLICY_HASH,
            tool_catalog_hash=CATALOG_HASH,
        )


def test_policy_hash_drift_fails_closed() -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    with pytest.raises(ConfigError, match="policy bundle hash"):
        verify_agent_manifest_binding(
            manifest,
            {key_id: pub},
            authenticated_subject=AGENT_ID,
            policy_bundle_hash="sha256:" + "0" * 64,
            tool_catalog_hash=CATALOG_HASH,
        )


def test_catalog_hash_drift_fails_closed() -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    with pytest.raises(ConfigError, match="tool catalog hash"):
        verify_agent_manifest_binding(
            manifest,
            {key_id: pub},
            authenticated_subject=AGENT_ID,
            policy_bundle_hash=POLICY_HASH,
            tool_catalog_hash="sha256:" + "0" * 64,
        )


def test_trust_anchor_loader_accepts_single_public_key(tmp_path: Path) -> None:
    _, pub, key_id = _keypair()
    path = tmp_path / "manifest-public-key.json"
    path.write_text(
        json.dumps({
            "algorithm": "Ed25519",
            "key_id": key_id,
            "public_key_base64url": _b64url(pub),
        })
    )
    assert load_agent_manifest_trust_anchor(str(path)) == {key_id: pub}
