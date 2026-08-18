"""cMCP consuming a v0.2 COSE manifest (agent-manifest #315, phase 4 of #243).

cmcp pinned `agent-manifest>=0.11`, so the COSE verifier was available, and
nothing here had ever presented a v0.2 manifest to it. It could not have
worked: `_verify_with_sdk` passed the manifest as a dict, and from v0.2 the
COSE_Sign1 structure *is* the signature (ADR-0011), so a v0.2 document handed
over as a dict has nothing to appraise and the SDK reports SIGNATURE_MISSING.

These are the end-to-end cases: a real signed envelope through cmcp's own
binding path, a v0.1 manifest still working unchanged, and the two ways the
wrong artifact can be supplied.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import agent_manifest as sdk
import pytest
from agent_manifest import _cose as sdk_cose

from cmcp_runtime.agent_manifest import (
    load_agent_manifest,
    load_agent_manifest_document,
    verify_agent_manifest_binding,
)
from cmcp_runtime.errors import ConfigError

POLICY_HASH = "sha256:" + "a" * 64
CATALOG_HASH = "sha256:" + "b" * 64
AGENT_ID = "spiffe://factory.example/agent/material-movement/dev"
ISSUER = "spiffe://factory.example/signing-authority/development"


def _manifest(version: str = "0.2") -> dict:
    return {
        "@context": "https://manifest.agentrust-io.com/v0.2/context.json",
        "@type": "AgentManifest",
        "manifest_id": "0197739a-8c00-7000-8000-000000000001",
        "agent_id": AGENT_ID,
        "version": version,
        "issued_at": "2026-06-12T00:00:00Z",
        "expires_at": "2099-09-10T00:00:00Z",
        "issuer": ISSUER,
        "crypto_profile": "standard",
        "artifacts": {
            "policy_bundle": {
                "hash": POLICY_HASH,
                "policy_language": "cedar",
                "version": "0.1.0",
                "enforcement_mode": "enforce",
            },
            "tool_manifest": {
                "catalog_hash": CATALOG_HASH,
                "tools": [],
                "allow_dynamic_registration": False,
                "rug_pull_policy": "deny-and-alert",
            },
        },
        "delegation_chain": [],
    }


def _cose_envelope() -> tuple[bytes, dict, str, bytes]:
    """A genuinely signed v0.2 COSE envelope, plus its trust anchor."""
    keypair = sdk.generate_ed25519()
    manifest = _manifest("0.2")
    envelope = sdk.sign_manifest_cose(manifest, keypair)
    public_key = keypair.public_bytes
    return envelope, manifest, keypair.key_id, public_key


def _v01_manifest() -> tuple[dict, str, bytes]:
    keypair = sdk.generate_ed25519()
    manifest = _manifest("0.1")
    manifest["@context"] = "https://agentmanifest.agentrust-io.com/v0.1/context.json"
    # The SDK signer owns the pre-image, so the v0.1 arm of this test cannot
    # drift from the canonical byte sequence the verifier will recompute.
    manifest["signature"] = sdk.Ed25519Signer(keypair).sign(manifest)
    public_key = keypair.public_bytes
    return manifest, keypair.key_id, public_key


def _bind(loaded, trusted_keys):
    return verify_agent_manifest_binding(
        loaded.manifest,
        trusted_keys,
        authenticated_subject=AGENT_ID,
        policy_bundle_hash=POLICY_HASH,
        tool_catalog_hash=CATALOG_HASH,
        envelope=loaded.envelope,
    )


# ---------------------------------------------------------------------------
# The v0.2 path, end to end
# ---------------------------------------------------------------------------


def test_cose_envelope_binds_end_to_end(tmp_path: Path) -> None:
    envelope, manifest, key_id, public_key = _cose_envelope()
    path = tmp_path / "manifest.cose"
    path.write_bytes(envelope)

    loaded = load_agent_manifest_document(str(path))
    assert loaded.envelope == envelope
    assert loaded.manifest["manifest_id"] == manifest["manifest_id"]

    binding = _bind(loaded, {key_id: public_key})
    assert binding.manifest_id == manifest["manifest_id"]
    assert binding.agent_id == AGENT_ID
    assert binding.policy_bundle_hash == POLICY_HASH
    assert binding.tool_catalog_hash == CATALOG_HASH


def test_cose_envelope_under_an_untrusted_key_is_rejected(tmp_path: Path) -> None:
    envelope, _manifest_doc, _key_id, _public_key = _cose_envelope()
    path = tmp_path / "manifest.cose"
    path.write_bytes(envelope)
    other = sdk.generate_ed25519()
    other_key = other.public_bytes

    loaded = load_agent_manifest_document(str(path))
    with pytest.raises(ConfigError):
        _bind(loaded, {other.key_id: other_key})


def test_tampered_cose_payload_is_rejected(tmp_path: Path) -> None:
    """The property the envelope exists for: the signed bytes travel with the
    signature, so there is no re-serialization step to disagree about."""
    envelope, _doc, key_id, public_key = _cose_envelope()
    tampered = bytearray(envelope)
    # Flip a byte inside the payload region rather than the header, so the
    # structure still decodes and only the signature can catch it.
    tampered[len(tampered) // 2] ^= 0x01
    path = tmp_path / "manifest.cose"
    path.write_bytes(bytes(tampered))

    try:
        loaded = load_agent_manifest_document(str(path))
    except ConfigError:
        return  # structural rejection at decode is also a rejection
    with pytest.raises(ConfigError):
        _bind(loaded, {key_id: public_key})


# ---------------------------------------------------------------------------
# The v0.1 path is unchanged
# ---------------------------------------------------------------------------


def test_v01_json_manifest_still_binds(tmp_path: Path) -> None:
    manifest, key_id, public_key = _v01_manifest()
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    loaded = load_agent_manifest_document(str(path))
    assert loaded.envelope is None
    binding = _bind(loaded, {key_id: public_key})
    assert binding.agent_id == AGENT_ID


def test_legacy_loader_still_returns_a_dict(tmp_path: Path) -> None:
    manifest, _key_id, _public_key = _v01_manifest()
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    assert load_agent_manifest(str(path))["agent_id"] == AGENT_ID


# ---------------------------------------------------------------------------
# Supplying the wrong artifact
# ---------------------------------------------------------------------------


def test_v02_payload_as_bare_json_names_the_real_problem(tmp_path: Path) -> None:
    """Without this the operator gets "signature block is missing", which reads
    as a malformed manifest rather than a manifest supplied in the wrong form."""
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(_manifest("0.2")), encoding="utf-8")
    with pytest.raises(ConfigError, match="COSE"):
        load_agent_manifest_document(str(path))


def test_v01_payload_inside_v02_envelope_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AM-VEC-COSE-012 at the cMCP boundary: route on the signed payload's
    version, not merely on the outer envelope being valid COSE_Sign1."""
    keypair = sdk.generate_ed25519()
    manifest = _manifest("0.1")
    manifest["@context"] = "https://agentmanifest.agentrust-io.com/v0.1/context.json"

    # Production issuance correctly refuses to construct this downgrade. Bypass
    # only that producer guard to build the adversarial, correctly signed wire
    # artifact; the consumer decoder and verifier remain unmodified.
    monkeypatch.setattr(sdk_cose, "_require_v02", lambda _manifest: None)
    envelope = sdk.sign_manifest_cose(manifest, keypair)
    path = tmp_path / "v01-in-v02.cose"
    path.write_bytes(envelope)

    with pytest.raises(ConfigError, match="payload declares manifest version 0.1"):
        load_agent_manifest_document(str(path))


def test_neither_json_nor_cose_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "manifest.bin"
    path.write_bytes(b"\xff\xfe not json and not cbor \x00\x01")
    with pytest.raises(ConfigError, match="not JSON and not a COSE envelope"):
        load_agent_manifest_document(str(path))


def test_missing_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Cannot read Agent Manifest"):
        load_agent_manifest_document(str(tmp_path / "absent.json"))


def test_json_scalar_is_not_a_manifest(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text("42", encoding="utf-8")
    with pytest.raises(ConfigError, match="must be a JSON object"):
        load_agent_manifest_document(str(path))


def test_cose_envelope_digest_is_stable(tmp_path: Path) -> None:
    """The envelope is bytes on disk, so a deployment can pin it by digest.
    Re-reading must not renormalize anything."""
    envelope, _doc, _key_id, _public_key = _cose_envelope()
    path = tmp_path / "manifest.cose"
    path.write_bytes(envelope)
    loaded = load_agent_manifest_document(str(path))
    assert loaded.envelope is not None
    assert hashlib.sha256(loaded.envelope).digest() == hashlib.sha256(envelope).digest()
