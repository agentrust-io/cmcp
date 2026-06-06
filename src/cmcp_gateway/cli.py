"""cmcp CLI entry point."""

from __future__ import annotations

import click

from cmcp_gateway import __version__


@click.group()
@click.version_option(__version__, prog_name="cmcp")
def main() -> None:
    """cMCP Gateway — hardware-attested MCP gateway."""


@main.command()
@click.option("--config", required=True, type=click.Path(exists=True), help="Path to cmcp-config.yaml")
def start(config: str) -> None:
    """Start the cMCP Gateway."""
    import uvicorn
    from uuid import uuid4

    from cmcp_gateway.audit.chain import AuditChain
    from cmcp_gateway.mcp.proxy import CMCPProxy
    from cmcp_gateway.mcp.server import MCPServer
    from cmcp_gateway.policy.evaluator import PolicyEvaluator
    from cmcp_gateway.session.state import SessionState
    from cmcp_gateway.startup import run_startup

    ctx = run_startup(config)

    session = SessionState(session_id=str(uuid4()))
    audit_chain = AuditChain(session_id=session.session_id)
    policy_evaluator = PolicyEvaluator(bundle=ctx.policy_bundle, config=ctx.config)
    proxy = CMCPProxy(
        catalog=ctx.catalog,
        policy_evaluator=policy_evaluator,
        session=session,
        audit_chain=audit_chain,
        config=ctx.config,
    )
    server = MCPServer(proxy=proxy)

    host, _, port_str = ctx.config.listen_addr.rpartition(":")
    port = int(port_str)

    click.echo(
        f"cMCP Gateway starting — TEE: {ctx.attestation_report.provider},"
        f" listen: {ctx.config.listen_addr}"
    )
    uvicorn.run(server.app, host=host, port=port)


@main.command("validate-config")
@click.option("--config", required=True, type=click.Path(exists=True), help="Path to cmcp-config.yaml")
def validate_config(config: str) -> None:
    """Validate cmcp-config.yaml without starting the gateway."""
    from cmcp_gateway.config import load_config

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
    from cmcp_gateway.policy.bundle import load_policy_bundle

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
