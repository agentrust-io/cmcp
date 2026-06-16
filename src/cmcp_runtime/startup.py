"""Gateway startup sequence with fail-closed validation - implements issue #66."""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from typing import Any

from cmcp_runtime.agent_manifest import (
    AgentManifestBinding,
    load_agent_manifest,
    load_agent_manifest_trust_anchor,
    verify_agent_manifest_binding,
)
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.store import SqliteAuditStore
from cmcp_runtime.catalog.loader import ToolCatalog, load_catalog
from cmcp_runtime.config import Config, load_config
from cmcp_runtime.errors import (
    AttestationProviderUnsupported,
    CatalogHashMismatch,
    CatalogToolNameCollision,
    ConfigError,
    PolicyHashMismatch,
)
from cmcp_runtime.policy.bundle import PolicyStore, load_policy_bundle
from cmcp_runtime.tee.base import AttestationReport, TEEProvider
from cmcp_runtime.tee.detect import detect_provider
from cmcp_runtime.tee.nras import AppraisalResult, try_appraise
from cmcp_runtime.tee.spiffe import SpiffeClientResult, fetch_svid

logger = logging.getLogger(__name__)

# HW-001: allowlist of canonical TEE provider names that may appear in
# AttestationReport.provider.  Mirrors the keys of _PROVIDER_MAP in
# audit/trace_claim.py - kept as a local constant to avoid a circular import.
_VALID_PROVIDERS: frozenset[str] = frozenset({
    "sev-snp",
    "tdx",
    "opaque",
    "tpm",
    "software-only",
})


@dataclass
class RuntimeContext:
    """All validated components ready for the gateway to use."""

    config: Config
    tee_provider: TEEProvider
    attestation_report: AttestationReport
    signing_key: SigningKey
    policy_bundle: PolicyStore
    catalog: ToolCatalog
    audit_store: SqliteAuditStore | None = None
    spiffe: SpiffeClientResult | None = None
    nras_appraisal: AppraisalResult | None = None
    agent_manifest: AgentManifestBinding | None = None


def _fatal(code: str, message: str, **fields: Any) -> None:
    """Log a FATAL structured entry and exit with code 1."""
    entry = {
        "level": "FATAL",
        "event": code,
        "message": message,
        **fields,
    }
    logger.critical("%s", entry)


def run_startup(config_path: str) -> RuntimeContext:
    """
    Execute the ordered startup sequence. Any failure before step 6 (network bind)
    is fatal - the gateway exits with code 1.

    Startup order per docs/spec/failure-modes.md:
    1. Load and validate config
    2. Detect TEE provider and attest
    3. Generate ephemeral signing keypair
    4. Load and verify policy bundle hash
    5. Load and verify catalog hash
    (Step 6: bind network port - done by the caller after this returns)
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

    # CRYPTO-001 + CRYPTO-002: the first 32 bytes of the nonce are SHA-256(public_key_bytes)
    # so verifiers can re-derive the fingerprint from the public key in cnf.jwk and confirm
    # it matches report_data[:32] -- binding the attestation report to this specific keypair.
    # The remaining 32 bytes are a random salt so two gateways with different random bytes
    # produce different nonces even if they share the same keypair (blue-green deploy).
    import hashlib
    import secrets
    key_fingerprint = hashlib.sha256(signing_key.public_key_bytes).digest()
    random_salt = secrets.token_bytes(32)
    nonce = key_fingerprint + random_salt
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

    # HW-001: reject unknown provider strings before they can propagate into
    # TRACE Claims or Cedar policy context.  A custom or misconfigured provider
    # could set an arbitrary value in provider_name(); validate here at the
    # boundary rather than relying on downstream consumers to handle it.
    if attestation_report.provider not in _VALID_PROVIDERS:
        _fatal(
            "ATTESTATION_PROVIDER_INVALID",
            f"TEE provider returned unknown platform string '{attestation_report.provider}'. "
            f"Allowed values: {sorted(_VALID_PROVIDERS)}.",
            provider=attestation_report.provider,
            action="startup_aborted",
        )
        sys.exit(1)

    # AUTH-001 (CRITICAL): require a bearer token in production to authenticate
    # inbound MCP calls. Without it, any network client can invoke any tool.
    if config.bearer_token is None and not config.dev_mode:
        _fatal(
            "BEARER_TOKEN_REQUIRED",
            "CMCP_BEARER_TOKEN env var is not set. "
            "Set it to a secret token that agent hosts must present in the "
            "Authorization header. Set CMCP_DEV_MODE=1 only in development.",
        )
        sys.exit(1)

    # Step 4: policy bundle
    policy_expected_hash = os.environ.get("CMCP_POLICY_HASH")
    if policy_expected_hash is None and not config.dev_mode:
        # POLICY-001 (CRITICAL): without a pinned hash, a compromised policy bundle
        # loads silently. Require CMCP_POLICY_HASH in production; set CMCP_DEV_MODE=1
        # only for local development.
        _fatal(
            "POLICY_HASH_REQUIRED",
            "CMCP_POLICY_HASH env var is not set. "
            "Set it to the sha256:<hex> of the policy bundle to prevent policy tampering. "
            "Set CMCP_DEV_MODE=1 only in development to skip this check.",
        )
        sys.exit(1)
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

    policy_store = PolicyStore(
        bundle=policy_bundle,
        bundle_path=config.policy_bundle_path,
        reload_interval_seconds=config.policy_reload_interval_seconds,
        expected_hash=policy_expected_hash,
    )
    if config.policy_reload_interval_seconds > 0:
        logger.info(
            "Policy hot-reload enabled: interval=%ds",
            config.policy_reload_interval_seconds,
        )

    # Step 5: catalog
    catalog_expected_hash = os.environ.get("CMCP_CATALOG_HASH")
    if catalog_expected_hash is None and not config.dev_mode:
        # POLICY-002 (CRITICAL, closes #137): without a pinned hash, a compromised catalog
        # loads silently, allowing unauthorized tools or redirecting tool calls to attacker-
        # controlled servers. Require CMCP_CATALOG_HASH in production; fail closed here.
        _fatal(
            "CATALOG_HASH_REQUIRED",
            "CMCP_CATALOG_HASH env var is not set. "
            "Set it to the sha256:<hex> of the tool catalog to prevent catalog tampering. "
            "Set CMCP_DEV_MODE=1 only in development to skip this check.",
        )
        sys.exit(1)
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

    # Step 5b: optional Agent Manifest binding (#302). When configured, this is
    # fail-closed: signature, subject, policy hash, and catalog hash must agree
    # before any session can be created.
    agent_manifest: AgentManifestBinding | None = None
    if config.agent_manifest.path is not None and config.agent_manifest.trust_anchor_path is not None:
        try:
            manifest = load_agent_manifest(config.agent_manifest.path)
            trusted_keys = load_agent_manifest_trust_anchor(
                config.agent_manifest.trust_anchor_path
            )
            agent_manifest = verify_agent_manifest_binding(
                manifest,
                trusted_keys,
                authenticated_subject=config.agent_manifest.authenticated_subject,
                policy_bundle_hash=policy_bundle.bundle_hash,
                tool_catalog_hash=catalog.catalog_hash,
                allow_dev_subject_from_manifest=config.dev_mode,
            )
        except ConfigError as exc:
            _fatal("AGENT_MANIFEST_BINDING_FAILED", str(exc), action="startup_aborted")
            sys.exit(1)

        logger.info(
            "Agent Manifest bound: manifest_id=%s agent_id=%s",
            agent_manifest.manifest_id,
            agent_manifest.agent_id,
        )

    # Step 5c: SPIFFE/SPIRE SVID fetch (non-fatal - falls back to self-signed TLS)
    # SVID issuance is conditioned on TEE attestation succeeding (handled by the
    # SPIRE node attestation plugin on the SPIRE server side).
    spiffe_result = fetch_svid()
    if spiffe_result.has_svid:
        logger.info(
            "SPIFFE SVID obtained: spiffe_id=%s",
            spiffe_result.svid.spiffe_id,  # type: ignore[union-attr]
        )
    else:
        logger.warning(
            "SPIFFE SVID not available (%s) - gateway will use self-signed TLS for mTLS",
            spiffe_result.failure_reason,
        )

    # Step 5d: NRAS post-attestation appraisal (non-fatal, Phase 2 / v0.2 -- issue #125).
    # CMCP_NRAS_API_KEY missing -> skip with warning; any NRAS error -> skip with warning.
    nras_appraisal = try_appraise(attestation_report)

    # Step 5e: open durable audit store and warn on orphaned sessions (AUDIT-001).
    try:
        from pathlib import Path as _Path
        audit_store = SqliteAuditStore(_Path(config.audit_db_path))
        orphaned = audit_store.find_orphaned_sessions()
        if orphaned:
            logger.warning(
                "AUDIT-001: %d session(s) have no session_end entry in the audit DB - "
                "gateway may have restarted mid-session. Orphaned session IDs: %s",
                len(orphaned),
                orphaned,
            )
    except Exception as exc:
        _fatal(
            "AUDIT_STORE_UNAVAILABLE",
            f"Cannot open audit store at '{config.audit_db_path}': {exc}",
            action="startup_aborted",
        )
        sys.exit(1)

    return RuntimeContext(
        config=config,
        tee_provider=tee_provider,
        attestation_report=attestation_report,
        signing_key=signing_key,
        policy_bundle=policy_store,
        catalog=catalog,
        audit_store=audit_store,
        spiffe=spiffe_result,
        nras_appraisal=nras_appraisal,
        agent_manifest=agent_manifest,
    )
