"""Paired experimental signed-catalog admission/refusal at cMCP's real binding boundary."""

import copy
from datetime import UTC, datetime, timedelta

import agent_manifest as sdk
import pytest

from cmcp_runtime.agent_manifest import verify_agent_manifest_binding
from cmcp_runtime.catalog.loader import ToolCatalog
from cmcp_runtime.config import EnforcementMode
from cmcp_runtime.errors import ConfigError
from cmcp_runtime.manifest_catalog import manifest_catalog_binding

SEALED = "sha256:" + "c" * 64
POLICY = "sha256:" + "b" * 64


@pytest.fixture
def binding_packet():
    now = datetime.now(UTC)
    key = sdk.generate_ed25519()
    catalog = ToolCatalog(entries={}, catalog_hash=SEALED)
    projection = manifest_catalog_binding(catalog)
    manifest = {
        "manifest_id": "01993f2c-8000-7000-8000-000000000001",
        "agent_id": "spiffe://example.test/agent/one",
        "version": "0.2",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        "issuer": "spiffe://example.test/issuer",
        "crypto_profile": "standard",
        "profile": "evidence-requirements-experimental-v1",
        "artifacts": {
            "system_prompt": {
                "hash": "sha256:" + "a" * 64,
                "version": "1",
                "classification": "public",
                "bound_at": now.isoformat(),
            },
            "policy_bundle": {
                "hash": POLICY,
                "version": "1",
                "policy_language": "cedar",
                "enforcement_mode": "enforce",
                "bound_at": now.isoformat(),
            },
            "model_identity": {
                "provider": "test",
                "model_id": "test",
                "version": "test-model",
                "deployment_type": "api",
                "model_attestation_type": "provider-asserted",
                "bound_at": now.isoformat(),
            },
            "tool_manifest": {
                **projection,
                "rug_pull_policy": "deny-and-alert",
                "allow_dynamic_registration": False,
                "bound_at": now.isoformat(),
            },
        },
        "evidence_requirements": {
            "components": [
                {
                    "component_id": "runtime.cpu",
                    "component_type": "runtime",
                    "required": True,
                    "accepted_profiles": ["urn:example:snp:v1"],
                    "accepted_appraisal_authorities": ["https://verifier.example"],
                    "maximum_age_seconds": 120,
                },
                {
                    "component_id": "served-catalog",
                    "component_type": "tool-catalog",
                    "required": True,
                    "artifact_ref": "artifacts.tool_manifest",
                    "expected_observed_digest": SEALED,
                    "accepted_profiles": ["test-v1"],
                    "accepted_appraisal_authorities": ["https://verifier.example"],
                    "maximum_age_seconds": 300,
                },
            ],
            "required_bindings": [],
            "combination_policy_ref": "urn:example:policy:v1",
        },
    }
    return manifest, key, catalog


def bind(packet, *, manifest=None, catalog=None, policy=POLICY):
    base_manifest, key, base_catalog = packet
    actual_manifest = manifest if manifest is not None else base_manifest
    actual_catalog = catalog if catalog is not None else base_catalog
    signed = sdk.sign_cose_sign1(actual_manifest, key)
    return verify_agent_manifest_binding(
        actual_manifest,
        {key.key_id: key.public_bytes},
        authenticated_subject=actual_manifest["agent_id"],
        policy_bundle_hash=policy,
        tool_catalog_hash=actual_catalog.catalog_hash,
        runtime_catalog=actual_catalog,
        envelope=signed,
        enforcement_mode=EnforcementMode.ENFORCING,
    )


def test_signed_experimental_profile_accepts_matching_actual_catalog(binding_packet):
    assert bind(binding_packet).tool_catalog_hash == SEALED


@pytest.mark.parametrize("case", ["wrong_signed_seal", "missing_seal", "wrong_policy"])
def test_signed_experimental_profile_refuses_changes_after_good_twin(binding_packet, case):
    assert bind(binding_packet).tool_catalog_hash == SEALED
    manifest = copy.deepcopy(binding_packet[0])
    if case == "wrong_signed_seal":
        manifest["evidence_requirements"]["components"][1]["expected_observed_digest"] = (
            "sha256:" + "d" * 64
        )
        with pytest.raises(ConfigError, match="does not bind the sealed runtime catalog"):
            bind(binding_packet, manifest=manifest)
    elif case == "missing_seal":
        manifest["evidence_requirements"]["components"][1].pop("expected_observed_digest")
        with pytest.raises(ConfigError, match="does not bind the sealed runtime catalog"):
            bind(binding_packet, manifest=manifest)
    else:
        with pytest.raises(ConfigError, match="policy bundle hash does not match runtime policy"):
            bind(binding_packet, policy="sha256:" + "e" * 64)


@pytest.fixture
def experimental_startup(tmp_path, monkeypatch, binding_packet):
    """Real startup configuration using the generated COSE profile fixture."""
    import base64
    import json
    from pathlib import Path

    from cmcp_runtime.catalog.loader import load_catalog
    from cmcp_runtime.policy.bundle import load_policy_bundle
    from tests.unit.test_startup import complete_setup as setup_fixture

    config_path = Path(setup_fixture.__wrapped__(tmp_path, monkeypatch))
    runtime_catalog = load_catalog(str(tmp_path / "catalog.json"))
    runtime_policy = load_policy_bundle(str(tmp_path / "policy"))
    manifest, key, _ = binding_packet
    manifest = copy.deepcopy(manifest)
    manifest["artifacts"]["policy_bundle"]["hash"] = runtime_policy.bundle_hash
    manifest["artifacts"]["tool_manifest"] = {
        **manifest_catalog_binding(runtime_catalog),
        "rug_pull_policy": "deny-and-alert",
        "allow_dynamic_registration": False,
        "bound_at": manifest["issued_at"],
    }
    manifest["evidence_requirements"]["components"][1]["expected_observed_digest"] = (
        runtime_catalog.catalog_hash
    )
    manifest_path = tmp_path / "experimental.cose"
    key_path = tmp_path / "experimental-trust.json"
    key_path.write_text(
        json.dumps(
            {
                "key_id": key.key_id,
                "public_key_base64url": base64.urlsafe_b64encode(key.public_bytes)
                .decode()
                .rstrip("="),
            }
        )
    )
    config_path.write_text(
        config_path.read_text()
        + "\nagent_manifest:\n"
        + f"  path: {manifest_path}\n"
        + f"  trust_anchor_path: {key_path}\n"
        + f"  authenticated_subject: {manifest['agent_id']}\n"
    )
    return config_path, manifest_path, manifest, key


@pytest.mark.parametrize("wrong_seal", [False, True])
def test_experimental_signed_catalog_is_enforced_by_real_startup(experimental_startup, wrong_seal):
    from cmcp_runtime.startup import run_startup

    config_path, manifest_path, manifest, key = experimental_startup
    if wrong_seal:
        manifest["evidence_requirements"]["components"][1]["expected_observed_digest"] = (
            "sha256:" + "d" * 64
        )
    manifest_path.write_bytes(sdk.sign_cose_sign1(manifest, key))
    if wrong_seal:
        with pytest.raises(SystemExit) as exc:
            run_startup(str(config_path))
        assert exc.value.code == 1
    else:
        ctx = run_startup(str(config_path))
        assert ctx.agent_manifest is not None
        assert ctx.agent_manifest.agent_id == manifest["agent_id"]
