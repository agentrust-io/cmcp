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
    click.echo(f"Starting cMCP Gateway with config: {config}")
    raise NotImplementedError("Gateway start implemented in track:assembly issues")


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
    raise NotImplementedError("Bundle validation implemented in track:policy issues")
