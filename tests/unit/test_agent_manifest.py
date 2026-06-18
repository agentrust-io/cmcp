"""Tests for Agent Manifest identity binding (#302)."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cmcp_runtime import agent_manifest as cmcp_agent_manifest
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
    expires_at: str = "2099-09-10T00:00:00Z",
) -> dict:
    manifest = {
        "@context": "https://agentmanifest.agentrust.io/v0.1/context.json",
        "@type": "AgentManifest",
        "manifest_id": "0197739a-8c00-7000-8000-000000000001",
        "agent_id": agent_id,
        "version": "0.1",
        "issued_at": "2026-06-12T00:00:00Z",
        "expires_at": expires_at,
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
    assert binding.subject_source == "config"
    assert binding.issuer_key_id == key_id


def test_binding_verification_delegates_to_sdk_with_encoded_keys(monkeypatch) -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    captured = {}

    def fake_verify_manifest(manifest_arg, context, revocation_store):
        captured["manifest"] = manifest_arg
        captured["trusted_keys"] = context.trusted_keys
        captured["policy_bundle_hash"] = context.policy_bundle_hash
        captured["tool_catalog_hash"] = context.tool_catalog_hash
        assert isinstance(revocation_store, cmcp_agent_manifest.agent_manifest_sdk.RevocationStore)
        return cmcp_agent_manifest.agent_manifest_sdk.VerificationResult(
            manifest_id=manifest_arg["manifest_id"],
            result=cmcp_agent_manifest.agent_manifest_sdk.OverallResult.VALID,
            signature_verified=True,
            fields_verified=cmcp_agent_manifest.agent_manifest_sdk.FieldsVerified(
                policy_bundle=cmcp_agent_manifest.agent_manifest_sdk.FieldResult.MATCH,
                tool_manifest=cmcp_agent_manifest.agent_manifest_sdk.FieldResult.MATCH,
            ),
        )

    monkeypatch.setattr(
        cmcp_agent_manifest.agent_manifest_sdk,
        "verify_manifest",
        fake_verify_manifest,
    )

    binding = verify_agent_manifest_binding(
        manifest,
        {key_id: pub},
        authenticated_subject=AGENT_ID,
        policy_bundle_hash=POLICY_HASH,
        tool_catalog_hash=CATALOG_HASH,
    )

    assert binding.manifest_id == manifest["manifest_id"]
    assert captured == {
        "manifest": manifest,
        "trusted_keys": {key_id: _b64url(pub)},
        "policy_bundle_hash": POLICY_HASH,
        "tool_catalog_hash": CATALOG_HASH,
    }


def test_dev_subject_fallback_is_marked_as_manifest_dev() -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    binding = verify_agent_manifest_binding(
        manifest,
        {key_id: pub},
        authenticated_subject=None,
        policy_bundle_hash=POLICY_HASH,
        tool_catalog_hash=CATALOG_HASH,
        allow_dev_subject_from_manifest=True,
    )
    assert binding.authenticated_subject == AGENT_ID
    assert binding.subject_source == "manifest-dev"


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


def test_expired_manifest_fails_closed() -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id, expires_at="2026-06-16T00:00:00Z")
    with pytest.raises(ConfigError, match="expired"):
        verify_agent_manifest_binding(
            manifest,
            {key_id: pub},
            authenticated_subject=AGENT_ID,
            policy_bundle_hash=POLICY_HASH,
            tool_catalog_hash=CATALOG_HASH,
            now=datetime(2026, 6, 17, tzinfo=UTC),
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


def test_signing_pre_image_delegates_to_agent_manifest_sdk(monkeypatch) -> None:
    manifest = {"manifest_id": "0197739a-8c00-7000-8000-000000000001"}

    def fake_signing_pre_image(manifest_arg):
        assert manifest_arg is manifest
        return b"sdk-pre-image"

    monkeypatch.setattr(
        cmcp_agent_manifest.agent_manifest_sdk,
        "signing_pre_image",
        fake_signing_pre_image,
    )

    assert cmcp_agent_manifest.signing_pre_image(manifest) == b"sdk-pre-image"
