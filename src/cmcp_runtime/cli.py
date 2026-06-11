"""cmcp CLI entry point."""

from __future__ import annotations

from typing import TYPE_CHECKING

import click

from cmcp_runtime import __version__

if TYPE_CHECKING:
    from cmcp_runtime.mcp.server import MCPServer
    from cmcp_runtime.startup import RuntimeContext


def build_server(ctx: RuntimeContext) -> MCPServer:
    """
    Compose the running gateway from a validated RuntimeContext.

    All components validated by run_startup() MUST be wired here — a component
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
