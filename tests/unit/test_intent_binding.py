"""AARM R2: the declared intent reaches the claim, as a digest, after verification.

The gateway does not invent intent and does not accept it from the caller. It
reads the `intent` object out of an Agent Manifest whose issuer signature it has
already verified (agent-manifest spec 3.9), and carries the digest into the TRACE
claim beside the other identity hashes.

Three properties are worth holding onto:

1. **The digest travels, not the statement.** The claim is built to be shared and
   an intent statement is business context.
2. **It is read after signature verification.** An intent from an unverified
   manifest is an intent anyone could have written.
3. **Absence is not failure.** Almost no manifest declares an intent yet, so a
   manifest without one must bind and serve exactly as before.
"""

from __future__ import annotations

import base64
import json

import pytest
from agent_manifest import SIGNED_FIELDS, intent_hash
from agent_manifest import signing_pre_image as sdk_pre_image
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cmcp_runtime.agent_manifest import verify_agent_manifest_binding
from cmcp_runtime.errors import ConfigError

AGENT_ID = "spiffe://factory.example/agent/reconciler/prod"
POLICY_HASH = "sha256:" + "ab" * 32
CATALOG_HASH = "sha256:" + "cd" * 32
STATEMENT = "Reconcile supplier invoices against the general ledger."


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _signed_manifest(intent: dict | None = None) -> tuple[dict, dict[str, bytes]]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    import hashlib

    key_id = hashlib.sha256(public).hexdigest()

    manifest: dict = {
        "@context": "https://manifest.agentrust-io.com/v0.2/context.json",
        "@type": "AgentManifest",
        "manifest_id": "0197739a-8c00-7000-8000-000000000001",
        "agent_id": AGENT_ID,
        "version": "0.1",
        "issued_at": "2026-08-11T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "issuer": "spiffe://factory.example/manifest-authority",
        "crypto_profile": "standard",
        "artifacts": {
            "policy_bundle": {"hash": POLICY_HASH, "policy_language": "cedar"},
            "tool_manifest": {"catalog_hash": CATALOG_HASH, "tools": []},
        },
        "delegation_chain": [],
    }
    if intent is not None:
        manifest["intent"] = intent
    manifest["signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "key_type": "software",
        "signed_at": "2026-08-11T00:00:00Z",
        "signed_fields": list(SIGNED_FIELDS),
        "signature_value": _b64url(private.sign(sdk_pre_image(manifest))),
    }
    return manifest, {key_id: public}


def _bind(manifest: dict, keys: dict[str, bytes]):
    return verify_agent_manifest_binding(
        manifest,
        keys,
        authenticated_subject=AGENT_ID,
        policy_bundle_hash=POLICY_HASH,
        tool_catalog_hash=CATALOG_HASH,
    )


def test_a_declared_intent_reaches_the_binding_as_a_digest() -> None:
    manifest, keys = _signed_manifest({"statement": STATEMENT})
    binding = _bind(manifest, keys)
    assert binding.intent_hash == intent_hash(manifest)
    assert binding.intent_hash is not None
    assert binding.intent_hash.startswith("sha256:")


def test_the_statement_text_is_not_carried(monkeypatch) -> None:
    """The digest travels, not the business context."""
    manifest, keys = _signed_manifest({"statement": STATEMENT})
    binding = _bind(manifest, keys)
    assert STATEMENT not in json.dumps(binding.__dict__, default=str)


def test_a_manifest_without_intent_still_binds() -> None:
    """The common case. Absence is not a failure and must not become one."""
    manifest, keys = _signed_manifest()
    binding = _bind(manifest, keys)
    assert binding.intent_hash is None
    assert binding.agent_id == AGENT_ID


def test_a_tampered_intent_is_refused_rather_than_recorded() -> None:
    """The point of putting intent in the signature.

    Broadening the intent after issuance must fail the binding outright, not
    produce a binding carrying the broadened intent's digest.
    """
    manifest, keys = _signed_manifest({"statement": STATEMENT})
    manifest["intent"] = {"statement": "Do anything the operator asks."}
    with pytest.raises(ConfigError):
        _bind(manifest, keys)


def test_an_intent_added_after_issuance_is_refused() -> None:
    """A manifest signed without an intent cannot have one bolted on."""
    manifest, keys = _signed_manifest()
    manifest["intent"] = {"statement": "Do anything."}
    with pytest.raises(ConfigError):
        _bind(manifest, keys)


def test_intent_hash_reaches_the_emitted_claim() -> None:
    """End of the path: binding -> AgentIdentityInfo -> the claim's identity block."""
    from cmcp_runtime.audit.trace_claim import AgentIdentityInfo, AgentIdentityOut

    manifest, keys = _signed_manifest({"statement": STATEMENT})
    binding = _bind(manifest, keys)

    info = AgentIdentityInfo(
        manifest_id=binding.manifest_id,
        agent_id=binding.agent_id,
        authenticated_subject=binding.authenticated_subject,
        subject_source=binding.subject_source,
        issuer=binding.issuer,
        issuer_key_id=binding.issuer_key_id,
        policy_bundle_hash=binding.policy_bundle_hash,
        tool_catalog_hash=binding.tool_catalog_hash,
        intent_hash=binding.intent_hash,
    )
    out = AgentIdentityOut(**info.__dict__)
    assert out.intent_hash == binding.intent_hash


def test_the_claim_rejects_an_intent_hash_that_is_not_a_digest() -> None:
    """Same pattern as the other hash fields: shape is enforced, not assumed."""
    from cmcp_runtime.audit.trace_claim import AgentIdentityOut

    fields = {
        "manifest_id": "m1",
        "agent_id": AGENT_ID,
        "authenticated_subject": AGENT_ID,
        "subject_source": "config",
        "issuer": "spiffe://factory.example/manifest-authority",
        "issuer_key_id": "k1",
        "policy_bundle_hash": POLICY_HASH,
        "tool_catalog_hash": CATALOG_HASH,
    }
    assert AgentIdentityOut(**fields, intent_hash=None).intent_hash is None
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError
        AgentIdentityOut(**fields, intent_hash="not-a-digest")
