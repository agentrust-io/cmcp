"""Gateway startup sequence with fail-closed validation — implements issue #66."""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from typing import Any

from cmcp_gateway.audit.keys import SigningKey
from cmcp_gateway.catalog.loader import ToolCatalog, load_catalog
from cmcp_gateway.config import Config, load_config
from cmcp_gateway.errors import (
    AttestationProviderUnsupported,
    CatalogHashMismatch,
    CatalogToolNameCollision,
    ConfigError,
    PolicyHashMismatch,
)
from cmcp_gateway.policy.bundle import PolicyBundle, load_policy_bundle
from cmcp_gateway.tee.base import AttestationReport, TEEProvider
from cmcp_gateway.tee.detect import detect_provider

logger = logging.getLogger(__name__)


@dataclass
class GatewayContext:
    """All validated components ready for the gateway to use."""

    config: Config
    tee_provider: TEEProvider
    attestation_report: AttestationReport
    signing_key: SigningKey
    policy_bundle: PolicyBundle
    catalog: ToolCatalog


def _fatal(code: str, message: str, **fields: Any) -> None:
    """Log a FATAL structured entry and exit with code 1."""
    entry = {
        "level": "FATAL",
        "event": code,
        "message": message,
        **fields,
    }
    logger.critical("%s", entry)


def run_startup(config_path: str) -> GatewayContext:
    """
    Execute the ordered startup sequence. Any failure before step 6 (network bind)
    is fatal — the gateway exits with code 1.

    Startup order per docs/spec/failure-modes.md:
    1. Load and validate config
    2. Detect TEE provider and attest
    3. Generate ephemeral signing keypair
    4. Load and verify policy bundle hash
    5. Load and verify catalog hash
    (Step 6: bind network port — done by the caller after this returns)
    """
    # Step 1: config
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        _fatal("CONFIG_ERROR", str(exc))
        sys.exit(1)

    # Step 2: TEE detection and attestation
    try:
        tee_provider = detect_provider(config)
    except AttestationProviderUnsupported as exc:
        _fatal(
            "ATTESTATION_PROVIDER_UNSUPPORTED",
            str(exc),
            detail=exc.detail or "",
            action="startup_aborted",
        )
        sys.exit(1)

    # Step 3: signing key
    signing_key = SigningKey()
    logger.info("Signing key generated: %s...", signing_key.public_key_hex[:16])

    # CRYPTO-002: nonce must be session-unique. Use SHA-256(public_key || random_session_id)
    # so two gateways with different random bytes produce different nonces even if they
    # share the same keypair (e.g. during blue-green deploy).
    import hashlib
    import secrets
    session_id = secrets.token_bytes(32)
    nonce = hashlib.sha256(signing_key.public_key_bytes + session_id).digest()
    try:
        attestation_report = tee_provider.get_attestation_report(nonce)
    except Exception as exc:
        _fatal(
            "ATTESTATION_REPORT_UNAVAILABLE",
            f"TEE provider '{tee_provider.provider_name()}' failed to produce attestation report",
            error=str(exc),
            action="startup_aborted",
        )
        sys.exit(1)

    logger.info(
        "TEE attestation complete: provider=%s measurement=%s...",
        attestation_report.provider,
        attestation_report.measurement[:16],
    )

    # Step 4: policy bundle
    policy_expected_hash = os.environ.get("CMCP_POLICY_HASH")
    try:
        policy_bundle = load_policy_bundle(config.policy_bundle_path, expected_hash=policy_expected_hash)
    except PolicyHashMismatch as exc:
        _fatal(
            "POLICY_HASH_MISMATCH",
            str(exc),
            detail=exc.detail or "",
            action="startup_aborted",
        )
        sys.exit(1)
    except ConfigError as exc:
        _fatal("CONFIG_ERROR", f"Policy bundle invalid: {exc}")
        sys.exit(1)

    logger.info("Policy bundle loaded: hash=%s", policy_bundle.bundle_hash)

    # Step 5: catalog
    catalog_expected_hash = os.environ.get("CMCP_CATALOG_HASH")
    try:
        catalog = load_catalog(config.catalog_path, expected_hash=catalog_expected_hash)
    except CatalogHashMismatch as exc:
        _fatal(
            "CATALOG_HASH_MISMATCH",
            str(exc),
            detail=exc.detail or "",
            action="startup_aborted",
        )
        sys.exit(1)
    except CatalogToolNameCollision as exc:
        _fatal(
            "CATALOG_TOOL_NAME_COLLISION",
            str(exc),
            detail=exc.detail or "",
            action="startup_aborted",
        )
        sys.exit(1)
    except ConfigError as exc:
        _fatal("CONFIG_ERROR", f"Catalog invalid: {exc}")
        sys.exit(1)

    logger.info(
        "Catalog loaded: %d tools, hash=%s",
        len(catalog.entries),
        catalog.catalog_hash,
    )

    return GatewayContext(
        config=config,
        tee_provider=tee_provider,
        attestation_report=attestation_report,
        signing_key=signing_key,
        policy_bundle=policy_bundle,
        catalog=catalog,
    )
