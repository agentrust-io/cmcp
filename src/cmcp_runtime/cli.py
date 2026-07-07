"""cmcp CLI entry point."""

from __future__ import annotations

import contextlib
import sys
from typing import TYPE_CHECKING

import click

from cmcp_runtime import __version__

if TYPE_CHECKING:
    from cmcp_runtime.mcp.server import MCPServer
    from cmcp_runtime.startup import RuntimeContext


def build_server(ctx: RuntimeContext) -> MCPServer:
    """
    Compose the running gateway from a validated RuntimeContext.

    All components validated by run_startup() MUST be wired here - a component
    that is validated but not passed through is silently inert in production
    (the AUTH-001 bearer token and AUDIT-001 store were both lost this way).
    """
    from cmcp_runtime.audit.trace_claim import _PROVIDER_MAP
    from cmcp_runtime.mcp.proxy import CMCPProxy
    from cmcp_runtime.mcp.server import MCPServer
    from cmcp_runtime.policy.evaluator import PolicyEvaluator
    from cmcp_runtime.session.manager import SessionManager

    # Resolve provider string to canonical platform name for Cedar context.
    # Falls back to the raw provider string if not in the map (e.g. future providers).
    attestation_platform = _PROVIDER_MAP.get(
        ctx.attestation_report.provider, ctx.attestation_report.provider
    )

    # AUDIT-001/AUDIT-002: sessions MUST be created through SessionManager so the
    # chain is backed by the durable SQLite store and TEE-anchored at creation.
    session_manager = SessionManager(ctx)
    session, audit_chain = session_manager.create_session()
    policy_evaluator = PolicyEvaluator(bundle=ctx.policy_bundle, config=ctx.config)
    proxy = CMCPProxy(
        catalog=ctx.catalog,
        policy_evaluator=policy_evaluator,
        session=session,
        audit_chain=audit_chain,
        config=ctx.config,
        attestation_generated_at=ctx.attestation_report.attestation_generated_at,
        attestation_validity_seconds=ctx.attestation_report.attestation_validity_seconds,
        attestation_platform=attestation_platform,
    )
    # AUTH-001: the token validated in run_startup must reach the server, otherwise
    # every protected endpoint is reachable unauthenticated.
    return MCPServer(
        proxy=proxy,
        session_manager=session_manager,
        audit_chain=audit_chain,
        session=session,
        bearer_token=ctx.config.bearer_token,
    )


@click.group()
@click.version_option(__version__, prog_name="cmcp")
def main() -> None:
    """cMCP Runtime: hardware-attested MCP runtime."""
    # Ensure the CLI status glyphs print regardless of the ambient console
    # encoding (e.g. Windows cp1252, which cannot encode the check/cross
    # marks and would otherwise raise UnicodeEncodeError). See #396.
    for _stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            _stream.reconfigure(encoding="utf-8", errors="replace")


@main.command()
@click.option("--config", required=True, type=click.Path(exists=True), help="Path to cmcp-config.yaml")
@click.option("--enforcement", type=click.Choice(["enforcing", "advisory", "silent"]), default=None,
              help="Override attestation.enforcement_mode from config")
def start(config: str, enforcement: str | None) -> None:
    """Start the cMCP Runtime."""
    import uvicorn

    from cmcp_runtime.startup import run_startup

    ctx = run_startup(config)

    # Apply CLI override after loading config, before proxy is instantiated.
    if enforcement is not None:
        from cmcp_runtime.config import EnforcementMode
        ctx.config.attestation.enforcement_mode = EnforcementMode(enforcement)

    server = build_server(ctx)

    host, _, port_str = ctx.config.listen_addr.rpartition(":")
    port = int(port_str)

    click.echo(
        f"cMCP Runtime starting: TEE: {ctx.attestation_report.provider},"
        f" listen: {ctx.config.listen_addr}"
    )
    uvicorn.run(server.app, host=host, port=port)


@main.command()
@click.argument("claim_file", type=click.Path(exists=True))
@click.option("--policy-hash", default=None,
              help="Approved policy bundle hash (sha256:<hex>). Unpinned if omitted.")
@click.option("--catalog-hash", default=None,
              help="Approved tool catalog hash (sha256:<hex>). Unpinned if omitted.")
@click.option("--max-age", default=86400, type=int, show_default=True,
              help="Maximum attestation age in seconds.")
@click.option("--trusted-key", default=None,
              help="Out-of-band pinned Ed25519 public key (hex) to cross-check trace.cnf.jwk.")
@click.option("--audit-bundle", default=None, type=click.Path(exists=True),
              help="Also verify an exported audit bundle (GET /audit/export) against the claim.")
@click.option("--agent-manifest", default=None, type=click.Path(exists=True),
              help="Signed Agent Manifest to cross-check against the Trust Record.")
@click.option("--agent-manifest-trust-anchor", default=None, type=click.Path(exists=True),
              help="JSON issuer public key trust anchor for --agent-manifest.")
def verify(
    claim_file: str,
    policy_hash: str | None,
    catalog_hash: str | None,
    max_age: int,
    trusted_key: str | None,
    audit_bundle: str | None,
    agent_manifest: str | None,
    agent_manifest_trust_anchor: str | None,
) -> None:
    """Verify a signed TRACE Claim (and optionally its audit bundle).

    Checks the Ed25519 signature against the confirmation key in
    trace.cnf.jwk, the claim schema, attestation freshness, audit chain
    consistency, and (when pinned) the policy and catalog hashes.
    Exits 0 when verified, 1 otherwise.
    """
    import json as _json

    from cmcp_runtime.agent_manifest import (
        load_agent_manifest,
        load_agent_manifest_trust_anchor,
    )
    from cmcp_verify import ApprovedHashes, verify_audit_bundle, verify_trace_claim

    with open(claim_file) as f:
        claim = _json.load(f)

    pinned_policy = policy_hash is not None
    pinned_catalog = catalog_hash is not None
    # Unpinned hashes fall back to the claim's own values: the check passes
    # trivially and is reported as "not pinned" rather than verified.
    approved = ApprovedHashes(
        policy_bundle_hash=policy_hash
        or claim.get("trace", {}).get("policy", {}).get("bundle_hash", ""),
        tool_catalog_hash=catalog_hash
        or claim.get("gateway", {}).get("catalog", {}).get("hash", ""),
    )

    manifest_json = load_agent_manifest(agent_manifest) if agent_manifest is not None else None
    manifest_keys = (
        load_agent_manifest_trust_anchor(agent_manifest_trust_anchor)
        if agent_manifest_trust_anchor is not None
        else None
    )
    if agent_manifest is not None and agent_manifest_trust_anchor is None:
        click.echo(
            "[cmcp verify] agent_manifest       FAIL  pass --agent-manifest-trust-anchor",
            err=True,
        )
        raise SystemExit(1)

    result = verify_trace_claim(
        claim,
        approved,
        max_attestation_age_seconds=max_age,
        trusted_public_key_hex=trusted_key,
        agent_manifest=manifest_json,
        trusted_agent_manifest_keys=manifest_keys,
    )

    def _line(name: str, ok: bool, note: str = "") -> None:
        mark = "PASS" if ok else "FAIL"
        click.echo(f"[cmcp verify] {name:<24} {mark}{('  ' + note) if note else ''}")

    for field_name in result.verified_fields:
        note = ""
        if field_name == "policy_bundle.hash" and not pinned_policy:
            note = "(not pinned - pass --policy-hash to pin)"
        if field_name == "tool_catalog.hash" and not pinned_catalog:
            note = "(not pinned - pass --catalog-hash to pin)"
        _line(field_name, True, note)
    for field_name in result.unverified_fields:
        _line(field_name, False, result.details.get(field_name, ""))

    bundle_ok = True
    if audit_bundle is not None:
        with open(audit_bundle) as f:
            bundle = _json.load(f)
        bundle_result = verify_audit_bundle(bundle, claim)
        bundle_ok = bundle_result.verified
        _line(
            "audit_bundle",
            bundle_ok,
            f"({bundle_result.entry_count} entries)"
            if bundle_ok
            else "; ".join(bundle_result.failures),
        )

    overall = result.status.value == "verified" and bundle_ok
    if "hardware_attestation" in result.unverified_fields:
        click.echo(
            "[cmcp verify] note: "
            + result.details.get("hardware_attestation", "hardware attestation not verified")
        )
    click.echo(f"[cmcp verify] RESULT: {'PASS' if overall else 'FAIL'} ({result.status.value})")
    if not overall:
        raise SystemExit(1)


@main.command("validate-config")
@click.option("--config", required=True, type=click.Path(exists=True), help="Path to cmcp-config.yaml")
def validate_config(config: str) -> None:
    """Validate cmcp-config.yaml without starting the runtime."""
    from cmcp_runtime.config import load_config

    try:
        load_config(config)
        click.echo(f"✓ Config valid: {config}")
    except Exception as exc:
        click.echo(f"✗ Config invalid: {exc}", err=True)
        raise SystemExit(1) from exc


@main.command("validate-bundle")
@click.option("--bundle-path", required=True, type=click.Path(exists=True))
@click.option("--expected-hash", required=True, help="Expected SHA-256 hash (sha256:<hex>)")
def validate_bundle(bundle_path: str, expected_hash: str) -> None:
    """Validate a Cedar policy bundle hash before deployment."""
    from cmcp_runtime.policy.bundle import load_policy_bundle

    try:
        bundle = load_policy_bundle(bundle_path)
    except Exception as exc:
        click.echo(f"✗ Bundle load error: {exc}", err=True)
        raise SystemExit(1) from exc

    bundle_hash = bundle.bundle_hash
    # Normalise both sides to bare hex for comparison
    expected_hex = expected_hash.removeprefix("sha256:")
    actual_hex = bundle_hash.removeprefix("sha256:")

    if actual_hex == expected_hex:
        click.echo(f"✓ Bundle valid: {bundle_hash}")
    else:
        click.echo(
            f"✗ Bundle hash mismatch: expected {expected_hash}, got {bundle_hash}",
            err=True,
        )
        raise SystemExit(1)
