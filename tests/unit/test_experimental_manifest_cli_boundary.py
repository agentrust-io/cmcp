"""Reviewer-only CLI composition controls; synthetic state and mocked transport."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import agent_manifest as sdk
import pytest
from click.testing import CliRunner

from cmcp_runtime import cli
from cmcp_runtime.mcp.proxy import CMCPProxy
from tests.unit.conftest import wire_mock_gateway

pytest_plugins = ("tests.unit.test_experimental_manifest_binding_edrg",)


@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "wrong_seal",
        "missing_seal",
        "wrong_policy",
        "wrong_subject",
        "expired",
        "unknown_key",
        "missing_requirements",
        "duplicate_component",
        "unknown_requirement_field",
        "signature_tamper",
        "catalog_server",
    ],
)
def test_cli_composition_boundary(experimental_startup, monkeypatch, case):
    config, manifest_path, manifest, key = experimental_startup
    if case == "wrong_seal":
        manifest["evidence_requirements"]["components"][1]["expected_observed_digest"] = (
            "sha256:" + "d" * 64
        )
    elif case == "missing_seal":
        manifest["evidence_requirements"]["components"][1].pop("expected_observed_digest")
    elif case == "wrong_policy":
        manifest["artifacts"]["policy_bundle"]["hash"] = "sha256:" + "e" * 64
    elif case == "wrong_subject":
        config.write_text(
            config.read_text().replace(manifest["agent_id"], "spiffe://example.test/agent/other")
        )
    elif case == "expired":
        manifest["issued_at"] = (datetime.now(UTC) - timedelta(hours=4)).isoformat()
        manifest["expires_at"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    elif case == "unknown_key":
        (config.parent / "experimental-trust.json").write_text("{}")
    elif case == "missing_requirements":
        manifest.pop("evidence_requirements")
    elif case == "duplicate_component":
        import copy

        manifest["evidence_requirements"]["components"].append(
            copy.deepcopy(manifest["evidence_requirements"]["components"][0])
        )
    elif case == "unknown_requirement_field":
        manifest["evidence_requirements"]["components"][0]["unknown_rule"] = True
    elif case == "catalog_server":
        p = config.parent / "catalog.json"
        catalog = json.loads(p.read_text())
        catalog[0]["server"]["url"] = "https://substituted.example.test/mcp"
        p.write_text(json.dumps(catalog))
    signed = sdk.sign_cose_sign1(manifest, key)
    if case == "signature_tamper":
        signed = signed[:-1] + bytes([signed[-1] ^ 1])
    manifest_path.write_bytes(signed)

    # Observe the production CLI's build_server call, rather than assigning a
    # negative counter ourselves. Successful composition uses the real builder.
    observed = []
    constructed = []
    forward = AsyncMock(return_value="synthetic response")
    original = cli.build_server
    original_init = CMCPProxy.__init__

    def construct(self, *args, **kwargs):
        constructed.append(self)
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(CMCPProxy, "__init__", construct)
    monkeypatch.setattr(CMCPProxy, "_forward_to_upstream", forward)

    def build(ctx):
        server = original(ctx)
        wire_mock_gateway(server._proxy)
        server._proxy._forward_to_upstream = forward
        observed.append(server)
        return server

    def serve(_app, **_kwargs):
        result = asyncio.run(observed[-1]._proxy.call_tool("review-control", "test.tool", {}))
        assert result.allowed

    monkeypatch.setattr(cli, "build_server", build)
    monkeypatch.setattr("uvicorn.run", serve)
    result = CliRunner().invoke(cli.main, ["start", "--config", str(config)])
    if case == "valid":
        assert result.exit_code == 0, repr(result.exception) + result.output
        assert len(observed) == 1
        assert len(constructed) == 1
        assert forward.await_count == 1
    else:
        assert result.exit_code == 1, repr(result.exception) + result.output
        assert observed == []
        assert constructed == []
        assert forward.await_count == 0
