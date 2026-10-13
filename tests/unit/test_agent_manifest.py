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
    load_agent_manifest_issuer_policy,
    load_agent_manifest_trust_anchor,
    load_agent_manifest_trust_policy,
    signing_pre_image,
    verify_agent_manifest_binding,
)
from cmcp_runtime.config import EnforcementMode
from cmcp_runtime.errors import ConfigError

POLICY_HASH = "sha256:" + "a" * 64
CATALOG_HASH = "sha256:" + "b" * 64
AGENT_ID = "spiffe://factory.example/agent/material-movement/dev"
ISSUER = "spiffe://factory.example/signing-authority/development"


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
        "@context": "https://agentmanifest.agentrust-io.com/v0.1/context.json",
        "@type": "AgentManifest",
        "manifest_id": "0197739a-8c00-7000-8000-000000000001",
        "agent_id": agent_id,
        "version": "0.1",
        "issued_at": "2026-06-12T00:00:00Z",
        "expires_at": expires_at,
        "issuer": ISSUER,
        "crypto_profile": "standard",
        "artifacts": {
            # agent-manifest 0.12.0 (GHSA-6hjj-gh3c-r6wv) enforces the
            # full-binding requirement independently of the model validator, so
            # a manifest with no profile must carry all three required
            # artifacts. This fixture previously omitted two and still verified,
            # because a nested omission was suppressing the check.
            "system_prompt": {"hash": "sha256:" + "a" * 64},
            "model_identity": {"version": "example-model", "deployment_type": "api"},
            "policy_bundle": {
                "hash": policy_hash,
                "policy_language": "cedar",
                "version": "0.1.0",
                "enforcement_mode": "enforce",
            },
            "tool_manifest": {
                "catalog_hash": catalog_hash,
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
        trusted_key_issuers={key_id: [ISSUER]},
        authenticated_subject=AGENT_ID,
        policy_bundle_hash=POLICY_HASH,
        tool_catalog_hash=CATALOG_HASH,
        enforcement_mode=EnforcementMode.ENFORCING,
    )
    assert binding.manifest_id == manifest["manifest_id"]
    assert binding.agent_id == AGENT_ID
    assert binding.enforcement_mode == EnforcementMode.ENFORCING


def test_binding_verification_delegates_to_sdk_with_encoded_keys(monkeypatch) -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    captured = {}

    def fake_verify_manifest(manifest_arg, context, revocation_store):
        captured["manifest"] = manifest_arg
        captured["trusted_keys"] = context.trusted_keys
        captured["policy_bundle_hash"] = context.policy_bundle_hash
        captured["tool_catalog_hash"] = context.tool_catalog_hash
        captured["trusted_key_issuers"] = context.trusted_key_issuers
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
        trusted_key_issuers={key_id: [ISSUER]},
        authenticated_subject=AGENT_ID,
        policy_bundle_hash=POLICY_HASH,
        tool_catalog_hash=CATALOG_HASH,
        enforcement_mode=EnforcementMode.ENFORCING,
    )

    assert binding.manifest_id == manifest["manifest_id"]
    assert captured == {
        "manifest": manifest,
        "trusted_keys": {key_id: _b64url(pub)},
        "policy_bundle_hash": POLICY_HASH,
        "tool_catalog_hash": CATALOG_HASH,
        "trusted_key_issuers": {key_id: [ISSUER]},
    }


def test_dev_subject_fallback_is_marked_as_manifest_dev() -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    binding = verify_agent_manifest_binding(
        manifest,
        {key_id: pub},
        trusted_key_issuers={key_id: [ISSUER]},
        authenticated_subject=None,
        policy_bundle_hash=POLICY_HASH,
        tool_catalog_hash=CATALOG_HASH,
        enforcement_mode=EnforcementMode.ENFORCING,
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
            trusted_key_issuers={key_id: [ISSUER]},
            authenticated_subject="spiffe://factory.example/agent/other/dev",
            policy_bundle_hash=POLICY_HASH,
            tool_catalog_hash=CATALOG_HASH,
            enforcement_mode=EnforcementMode.ENFORCING,
        )



def test_enforcement_mode_mismatch_fails_closed() -> None:
    # The manifest's policy_bundle declares "enforce" (see _signed_manifest);
    # a runtime that is only attested as running in advisory mode must not
    # bind, even though the policy_bundle hash itself matches.
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    with pytest.raises(ConfigError, match="enforcement_mode"):
        verify_agent_manifest_binding(
            manifest,
            {key_id: pub},
            trusted_key_issuers={key_id: [ISSUER]},
            authenticated_subject=AGENT_ID,
            policy_bundle_hash=POLICY_HASH,
            tool_catalog_hash=CATALOG_HASH,
            enforcement_mode=EnforcementMode.ADVISORY,
        )


def test_enforcement_mode_not_provided_fails_closed() -> None:
    # A runtime that can't or doesn't attest its enforcement mode must not be
    # treated as matching a manifest that declares one -- unattested is not
    # evidence of compliance.
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    with pytest.raises(ConfigError, match="enforcement_mode"):
        verify_agent_manifest_binding(
            manifest,
            {key_id: pub},
            trusted_key_issuers={key_id: [ISSUER]},
            authenticated_subject=AGENT_ID,
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
            trusted_key_issuers={key_id: [ISSUER]},
            authenticated_subject=AGENT_ID,
            policy_bundle_hash=POLICY_HASH,
            tool_catalog_hash=CATALOG_HASH,
            enforcement_mode=EnforcementMode.ENFORCING,
        )


def test_policy_hash_drift_fails_closed() -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    with pytest.raises(ConfigError, match="policy bundle hash"):
        verify_agent_manifest_binding(
            manifest,
            {key_id: pub},
            trusted_key_issuers={key_id: [ISSUER]},
            authenticated_subject=AGENT_ID,
            policy_bundle_hash="sha256:" + "0" * 64,
            tool_catalog_hash=CATALOG_HASH,
            enforcement_mode=EnforcementMode.ENFORCING,
        )


def test_catalog_hash_drift_fails_closed() -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    with pytest.raises(ConfigError, match="tool catalog hash"):
        verify_agent_manifest_binding(
            manifest,
            {key_id: pub},
            trusted_key_issuers={key_id: [ISSUER]},
            authenticated_subject=AGENT_ID,
            policy_bundle_hash=POLICY_HASH,
            tool_catalog_hash="sha256:" + "0" * 64,
            enforcement_mode=EnforcementMode.ENFORCING,
        )


def test_expired_manifest_fails_closed() -> None:
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id, expires_at="2026-06-16T00:00:00Z")
    with pytest.raises(ConfigError, match="expired"):
        verify_agent_manifest_binding(
            manifest,
            {key_id: pub},
            trusted_key_issuers={key_id: [ISSUER]},
            authenticated_subject=AGENT_ID,
            policy_bundle_hash=POLICY_HASH,
            tool_catalog_hash=CATALOG_HASH,
            enforcement_mode=EnforcementMode.ENFORCING,
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


def test_issuer_policy_is_read_from_the_trust_anchor(tmp_path: Path) -> None:
    _, pub, key_id = _keypair()
    _, other_pub, other_id = _keypair()
    path = tmp_path / "anchor.json"
    path.write_text(json.dumps({"keys": [
        {"key_id": key_id, "public_key_base64url": _b64url(pub), "issuers": [ISSUER]},
        {"key_id": other_id, "public_key_base64url": _b64url(other_pub)},
    ]}))
    assert load_agent_manifest_issuer_policy(str(path)) == {key_id: [ISSUER]}


def test_trust_anchor_without_issuers_yields_no_policy(tmp_path: Path) -> None:
    _, pub, key_id = _keypair()
    path = tmp_path / "anchor.json"
    path.write_text(json.dumps({"key_id": key_id, "public_key_base64url": _b64url(pub)}))
    assert load_agent_manifest_issuer_policy(str(path)) is None


def test_trust_anchor_issuers_must_be_spiffe_uris(tmp_path: Path) -> None:
    _, pub, key_id = _keypair()
    path = tmp_path / "anchor.json"
    path.write_text(json.dumps({
        "key_id": key_id, "public_key_base64url": _b64url(pub), "issuers": "not-a-list",
    }))
    with pytest.raises(ConfigError, match="SPIFFE"):
        load_agent_manifest_issuer_policy(str(path))


def _write_anchor(tmp_path: Path, keys: list[dict]) -> str:
    path = tmp_path / "anchor.json"
    path.write_text(json.dumps({"keys": keys}))
    return str(path)


@pytest.mark.parametrize(
    "issuer",
    [
        "spiffe://",
        "spiffe:///signing-authority",
        "spiffe://factory.example/signing-authority?env=dev",
        "spiffe://factory.example/signing-authority#dev",
        "spiffe://admin@factory.example/signing-authority",
        "spiffe://factory.example:443/signing-authority",
        "spiffe://Factory.example/signing-authority",
        "spiffe://factory.example/",
        "spiffe://factory.example//signing-authority",
        "spiffe://factory.example/signing-authority/../other",
        "https://factory.example/signing-authority",
        "spiffe://factory.example/" + "a" * 2040,
    ],
)
def test_trust_anchor_refuses_a_malformed_spiffe_issuer(tmp_path: Path, issuer: str) -> None:
    _, pub, key_id = _keypair()
    path = _write_anchor(
        tmp_path, [{"key_id": key_id, "public_key_base64url": _b64url(pub), "issuers": [issuer]}]
    )
    with pytest.raises(ConfigError, match="SPIFFE"):
        load_agent_manifest_trust_policy(path)


@pytest.mark.parametrize("issuer", [ISSUER, "spiffe://factory.example"])
def test_trust_anchor_accepts_a_well_formed_spiffe_issuer(tmp_path: Path, issuer: str) -> None:
    _, pub, key_id = _keypair()
    path = _write_anchor(
        tmp_path, [{"key_id": key_id, "public_key_base64url": _b64url(pub), "issuers": [issuer]}]
    )
    assert load_agent_manifest_trust_policy(path) == ({key_id: pub}, {key_id: [issuer]})


def test_trust_anchor_refuses_a_repeated_key_id(tmp_path: Path) -> None:
    _, pub, key_id = _keypair()
    _, other_pub, _ = _keypair()
    path = _write_anchor(
        tmp_path,
        [
            {"key_id": key_id, "public_key_base64url": _b64url(pub), "issuers": [ISSUER]},
            {"key_id": key_id, "public_key_base64url": _b64url(other_pub), "issuers": [ISSUER]},
        ],
    )
    with pytest.raises(ConfigError, match="repeats key_id"):
        load_agent_manifest_trust_policy(path)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "Cannot read"),
        ("{not json", "Cannot read"),
        ('{"keys": "not-a-list"}', "public_key_base64url or keys"),
        ('{"keys": ["not-an-object"]}', "must be objects"),
    ],
)
def test_trust_anchor_refuses_an_unreadable_or_misshapen_file(
    tmp_path: Path, content: str | None, message: str
) -> None:
    path = tmp_path / "anchor.json"
    if content is not None:
        path.write_text(content)
    with pytest.raises(ConfigError, match=message):
        load_agent_manifest_trust_policy(str(path))


def _bind(manifest: dict, keys: dict[str, bytes], issuers: dict[str, list[str]] | None):
    return verify_agent_manifest_binding(
        manifest,
        keys,
        trusted_key_issuers=issuers,
        authenticated_subject=AGENT_ID,
        policy_bundle_hash=POLICY_HASH,
        tool_catalog_hash=CATALOG_HASH,
        enforcement_mode=EnforcementMode.ENFORCING,
    )


def test_a_key_may_be_authorized_for_several_issuers() -> None:
    priv, pub, key_id = _keypair()
    binding = _bind(
        _signed_manifest(priv, key_id),
        {key_id: pub},
        {key_id: ["spiffe://factory.example/other-authority", ISSUER]},
    )
    assert binding.manifest_id == "0197739a-8c00-7000-8000-000000000001"


def test_an_empty_issuers_list_authorizes_nothing(tmp_path: Path) -> None:
    priv, pub, key_id = _keypair()
    keys, issuers = load_agent_manifest_trust_policy(
        _write_anchor(tmp_path, [{"key_id": key_id, "public_key_base64url": _b64url(pub), "issuers": []}])
    )
    assert issuers == {key_id: []}
    with pytest.raises(ConfigError, match="not authorized for the manifest issuer"):
        _bind(_signed_manifest(priv, key_id), keys, issuers)


def test_an_empty_issuer_policy_authorizes_nothing() -> None:
    priv, pub, key_id = _keypair()
    with pytest.raises(ConfigError, match="not authorized for the manifest issuer"):
        _bind(_signed_manifest(priv, key_id), {key_id: pub}, {})


def test_another_keys_authorization_does_not_cover_the_signer() -> None:
    _, pub, key_id = _keypair()
    signer_priv, signer_pub, signer_id = _keypair()
    with pytest.raises(ConfigError, match="not authorized for the manifest issuer"):
        _bind(
            _signed_manifest(signer_priv, signer_id),
            {key_id: pub, signer_id: signer_pub},
            {key_id: [ISSUER], signer_id: ["spiffe://factory.example/other-authority"]},
        )


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


def test_a_mislabelled_post_quantum_manifest_fails_closed_cleanly() -> None:
    # A peer can present a manifest declaring any registered algorithm. Before
    # agent-manifest 0.6.1 an ML-DSA-65 declaration crashed the verifier with an
    # uncaught RuntimeError on installs without the optional [pq] extra, so this
    # path answered with a crash rather than a rejection. Not crashing is still
    # the property under test.
    #
    # What changed at agent-manifest 0.11: the [pq] extra no longer names a
    # liboqs package, because ML-DSA-65 now comes from `cryptography` (>=47),
    # which is already a required dependency. So ML-DSA is always available and
    # this scenario is no longer a capability gap - the algorithm can be
    # attempted, and an Ed25519 signature relabelled as ML-DSA-65 is simply a
    # signature that does not verify. The message therefore says verification
    # failed rather than could not be verified, and that is the more accurate
    # of the two: nothing here is missing.
    #
    # The capability-gap branch still exists for a build whose linked OpenSSL is
    # too old, and it belongs to agent-manifest, which owns the backend dispatch.
    # Reaching into that from here would test somebody else's internals.
    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    manifest["crypto_profile"] = "post-quantum"
    manifest["signature"]["algorithm"] = "ML-DSA-65"

    with pytest.raises(ConfigError, match="verification failed"):
        verify_agent_manifest_binding(
            manifest,
            {key_id: pub},
            trusted_key_issuers={key_id: [ISSUER]},
            authenticated_subject=AGENT_ID,
            policy_bundle_hash=POLICY_HASH,
            tool_catalog_hash=CATALOG_HASH,
            enforcement_mode=EnforcementMode.ENFORCING,
        )


# --- authoritative revocation state -------------------------------------


def _revocation_line(manifest_id: str) -> str:
    return json.dumps({
        "manifest_id": manifest_id,
        "revoked_at": "2026-09-20T00:00:00Z",
        "reason": "key_compromise",
        "revoked_by": "spiffe://factory.example/signing-authority/development",
    })


def test_manifest_listed_in_revocation_list_is_rejected(tmp_path: Path) -> None:
    from cmcp_runtime.agent_manifest import load_agent_manifest_revocations

    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    crl = tmp_path / "revocations.jsonl"
    crl.write_text(_revocation_line(manifest["manifest_id"]) + "\n")

    with pytest.raises(ConfigError, match="revoked"):
        verify_agent_manifest_binding(
            manifest,
            {key_id: pub},
            trusted_key_issuers={key_id: [ISSUER]},
            authenticated_subject=AGENT_ID,
            policy_bundle_hash=POLICY_HASH,
            tool_catalog_hash=CATALOG_HASH,
            enforcement_mode=EnforcementMode.ENFORCING,
            revocations=load_agent_manifest_revocations(str(crl)),
        )


def test_revocation_list_naming_another_manifest_still_binds(tmp_path: Path) -> None:
    from cmcp_runtime.agent_manifest import load_agent_manifest_revocations

    priv, pub, key_id = _keypair()
    manifest = _signed_manifest(priv, key_id)
    crl = tmp_path / "revocations.jsonl"
    crl.write_text(_revocation_line("00000000-0000-7000-8000-000000000000") + "\n\n")

    binding = verify_agent_manifest_binding(
        manifest,
        {key_id: pub},
        trusted_key_issuers={key_id: [ISSUER]},
        authenticated_subject=AGENT_ID,
        policy_bundle_hash=POLICY_HASH,
        tool_catalog_hash=CATALOG_HASH,
        enforcement_mode=EnforcementMode.ENFORCING,
        revocations=load_agent_manifest_revocations(str(crl)),
    )
    assert binding.manifest_id == manifest["manifest_id"]


def test_missing_revocation_list_fails_closed(tmp_path: Path) -> None:
    from cmcp_runtime.agent_manifest import load_agent_manifest_revocations

    with pytest.raises(ConfigError, match="Cannot read"):
        load_agent_manifest_revocations(str(tmp_path / "absent.jsonl"))


@pytest.mark.parametrize(
    "line",
    [
        "not json",
        "[1, 2]",
        json.dumps({"revoked_at": "2026-09-20T00:00:00Z", "reason": "x", "revoked_by": "y"}),
        json.dumps({"manifest_id": "m", "revoked_at": "yesterday", "reason": "x", "revoked_by": "y"}),
        json.dumps({"manifest_id": "m", "revoked_at": "2026-09-20T00:00:00Z"}),
    ],
)
def test_malformed_revocation_line_fails_closed(tmp_path: Path, line: str) -> None:
    from cmcp_runtime.agent_manifest import load_agent_manifest_revocations

    crl = tmp_path / "revocations.jsonl"
    crl.write_text(_revocation_line("ok-entry") + "\n" + line + "\n")
    with pytest.raises(ConfigError, match="line 2"):
        load_agent_manifest_revocations(str(crl))
