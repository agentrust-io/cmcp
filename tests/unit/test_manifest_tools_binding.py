"""A manifest that lists its tools binds through their Merkle root, not the sealed digest.

agent-manifest 0.13 (agentrust-io/agent-manifest#418) recomputes
``tool_manifest.catalog_hash`` from ``tools`` when the member is present. cMCP
used to hand the SDK its sealed catalog digest for that comparison, a
different construction, so a manifest that honestly listed its tools could
never bind. These cases run through real signed v0.2 envelopes.
"""

from __future__ import annotations

import copy
from typing import Any

import agent_manifest as sdk
import pytest

from cmcp_runtime.agent_manifest import verify_agent_manifest_binding
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.config import EnforcementMode
from cmcp_runtime.errors import ConfigError
from cmcp_runtime.manifest_catalog import manifest_catalog_binding

POLICY_HASH = "sha256:" + "a" * 64
SEALED_HASH = "sha256:" + "b" * 64
AGENT_ID = "spiffe://factory.example/agent/material-movement/dev"
ISSUER = "spiffe://factory.example/signing-authority/development"
MISMATCH = "tool catalog hash does not match runtime catalog"


def _entry(name: str, description: str) -> CatalogEntry:
    return CatalogEntry(
        tool_name=name,
        server=ServerIdentity(
            display_name="Fixture",
            url="https://fixture.invalid/mcp",
            tls_fingerprint="SHA256:" + "A" * 43 + "=",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description=description, input_schema={"type": "object"}, output_schema=None
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="public",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-09-30T00:00:00Z",
        approved_by="test",
    )


def _catalog(**descriptions: str) -> ToolCatalog:
    return ToolCatalog(
        entries={name: _entry(name, text) for name, text in descriptions.items()},
        catalog_hash=SEALED_HASH,
    )


SERVED = {"inventory.read": "Read stock levels", "inventory.move": "Move a pallet"}


def _manifest(tool_manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "@context": "https://manifest.agentrust-io.com/v0.2/context.json",
        "@type": "AgentManifest",
        "manifest_id": "0197739a-8c00-7000-8000-000000000002",
        "agent_id": AGENT_ID,
        "version": "0.2",
        "issued_at": "2026-09-30T00:00:00Z",
        "expires_at": "2099-09-10T00:00:00Z",
        "issuer": ISSUER,
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": "sha256:" + "a" * 64},
            "model_identity": {"version": "example-model", "deployment_type": "api"},
            "policy_bundle": {
                "hash": POLICY_HASH,
                "policy_language": "cedar",
                "version": "0.1.0",
                "enforcement_mode": "enforce",
            },
            "tool_manifest": {
                **tool_manifest,
                "allow_dynamic_registration": False,
                "rug_pull_policy": "deny-and-alert",
            },
        },
        "delegation_chain": [],
    }


def _bind(
    tool_manifest: dict[str, Any],
    runtime: ToolCatalog | None,
    *,
    sealed: str = SEALED_HASH,
) -> Any:
    keypair = sdk.generate_ed25519()
    manifest = _manifest(tool_manifest)
    envelope = sdk.sign_manifest_cose(manifest, keypair)
    return verify_agent_manifest_binding(
        manifest,
        {keypair.key_id: keypair.public_bytes},
        authenticated_subject=AGENT_ID,
        policy_bundle_hash=POLICY_HASH,
        tool_catalog_hash=sealed,
        runtime_catalog=runtime,
        enforcement_mode=EnforcementMode.ENFORCING,
        envelope=envelope,
    )


def _listed(catalog: ToolCatalog) -> dict[str, Any]:
    return copy.deepcopy(manifest_catalog_binding(catalog))


def test_manifest_listing_the_served_tools_binds() -> None:
    served = _catalog(**SERVED)
    listed = _listed(served)
    binding = _bind(listed, served)
    assert binding.tool_catalog_hash == listed["catalog_hash"]
    assert binding.tool_catalog_hash != SEALED_HASH


def test_legacy_manifest_without_tools_binds_to_the_sealed_digest() -> None:
    binding = _bind({"catalog_hash": SEALED_HASH}, _catalog(**SERVED))
    assert binding.tool_catalog_hash == SEALED_HASH


def test_legacy_manifest_still_binds_when_no_runtime_catalog_is_given() -> None:
    assert _bind({"catalog_hash": SEALED_HASH}, None).tool_catalog_hash == SEALED_HASH


@pytest.mark.parametrize(
    "listed_tools",
    [
        {"inventory.read": "Read stock levels"},
        {**SERVED, "inventory.delete": "Delete a pallet"},
        {"inventory.read": "Read stock levels", "inventory.scrap": "Move a pallet"},
    ],
    ids=["subset", "superset", "renamed"],
)
def test_manifest_listing_a_different_tool_set_fails(listed_tools: dict[str, str]) -> None:
    with pytest.raises(ConfigError, match=MISMATCH):
        _bind(_listed(_catalog(**listed_tools)), _catalog(**SERVED))


def test_tampered_description_in_the_served_catalog_fails() -> None:
    listed = _listed(_catalog(**SERVED))
    tampered = _catalog(**{**SERVED, "inventory.read": "Read stock levels and post them"})
    with pytest.raises(ConfigError, match=MISMATCH):
        _bind(listed, tampered)


def test_explicit_empty_list_is_an_empty_catalog_not_the_legacy_form() -> None:
    empty = _listed(_catalog())
    with pytest.raises(ConfigError, match=MISMATCH):
        _bind(empty, _catalog(**SERVED))
    assert _bind(empty, _catalog()).tool_catalog_hash == empty["catalog_hash"]


def test_sealed_digest_next_to_a_tool_list_fails() -> None:
    """The pre-fix fixture shape: tools listed, sealed digest declared as the root."""
    listed = _listed(_catalog(**SERVED))
    listed["catalog_hash"] = SEALED_HASH
    with pytest.raises(ConfigError, match=MISMATCH):
        _bind(listed, _catalog(**SERVED))


def test_listed_tools_must_match_even_if_the_root_does() -> None:
    """cMCP checks the list itself, so the result does not depend on the SDK release."""
    served = _catalog(**SERVED)
    listed = _listed(served)
    listed["tools"][0]["description_hash"] = "sha256:" + "d" * 64
    with pytest.raises(ConfigError, match=MISMATCH):
        _bind(listed, served)


def test_tool_list_without_the_runtime_catalog_does_not_bind() -> None:
    with pytest.raises(ConfigError, match="needs the runtime catalog"):
        _bind(_listed(_catalog(**SERVED)), None)


def test_runtime_catalog_must_be_the_one_behind_the_sealed_digest() -> None:
    served = _catalog(**SERVED)
    with pytest.raises(ConfigError, match="needs the runtime catalog"):
        _bind(_listed(served), served, sealed="sha256:" + "c" * 64)
