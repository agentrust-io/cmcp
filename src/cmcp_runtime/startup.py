"""Gateway startup sequence with fail-closed validation - implements issue #66."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
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
from cmcp_runtime.tee.measurement import (
    ExtendResult,
    GatewayMeasurement,
    MeasurementUnavailable,
    certify_and_extend_gateway_measurement,
    extend_gateway_measurement,
    gateway_measurement,
)
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
    # #432: the gateway's own measurement, and the NV extend index state around it.
    # Both None when the platform has no TPM, or in dev mode where an editable
    # install makes the code digest uncomputable.
    gateway_measurement: GatewayMeasurement | None = None
    measurement_extend: ExtendResult | None = None
    # The signed TPM2_NV_Certify pair proving the measurement. None when the platform
    # provisions no certified attestation key to sign with; see cmcp_verify.nv_certify.
    measurement_evidence: bytes | None = None


def _jwk_thumbprint_sha256(x_b64url: str) -> bytes:
    """RFC 7638 §3 JWK Thumbprint: SHA-256(UTF-8(JSON of sorted required OKP members))."""
    canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": x_b64url},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).digest()


def _fatal(code: str, message: str, **fields: Any) -> None:
    """Log a FATAL structured entry and exit with code 1."""
    entry = {
        "level": "FATAL",
        "event": code,
        "message": message,
        **fields,
    }
    logger.critical("%s", entry)


def _measure_gateway(
    config: Config, tee_provider: TEEProvider, nonce: bytes
) -> tuple[GatewayMeasurement | None, ExtendResult | None, bytes | None]:
    """Measure the gateway into the TPM NV index and have the TPM certify it (#432).

    Returns ``(measurement, extend, evidence)``. ``evidence`` is the signed
    ``TPM2_NV_Certify`` pair, or None when the platform provisions no certified
    attestation key to sign with: the extend still happens and is still a local
    integrity control, but it is not remote-verifiable, so it is not presented as
    evidence. All three are None when the platform has no TPM at all, which is not a
    failure: SEV-SNP and TDX commit their own binding through the report's fields.

    A TPM platform that cannot be measured is fatal in production and a warning in
    dev mode, matching how ``CMCP_POLICY_HASH`` is handled. The dev-mode escape
    matters in practice because an editable install has no ``RECORD`` metadata, so
    the code digest is genuinely uncomputable there rather than merely inconvenient.
    """
    if tee_provider.provider_name() != "tpm":
        logger.debug(
            "Gateway measurement skipped: provider %s does not use an NV extend index",
            tee_provider.provider_name(),
        )
        return None, None, None

    def _degrade(exc: MeasurementUnavailable) -> tuple[None, None, None]:
        if config.dev_mode:
            logger.warning(
                "Gateway measurement unavailable (%s): %s. Continuing because "
                "CMCP_DEV_MODE is set; the TPM will not attest what code is running.",
                exc,
                exc.detail or "",
            )
            return None, None, None
        _fatal(
            "MEASUREMENT_UNAVAILABLE",
            f"the gateway could not be measured into the TPM: {exc}",
            detail=exc.detail or "",
            action="startup_aborted",
        )
        sys.exit(1)

    try:
        measurement = gateway_measurement(config)
    except MeasurementUnavailable as exc:
        return _degrade(exc)

    try:
        from tpm2_pytss.ESAPI import ESAPI
    except ImportError as exc:
        return _degrade(
            MeasurementUnavailable(
                "tpm2-pytss is required to extend the measurement NV index",
                detail=str(exc),
            )
        )

    evidence: bytes | None = None
    try:
        with ESAPI() as ectx:
            extend_result, evidence = _extend_and_certify(ectx, measurement, nonce)
    except MeasurementUnavailable as exc:
        return _degrade(exc)
    except Exception as exc:  # noqa: BLE001 - any TPM fault means unmeasured
        return _degrade(
            MeasurementUnavailable(
                "the TPM could not be opened to extend the measurement",
                detail=f"{type(exc).__name__}: {exc}",
            )
        )

    logger.info(
        "Gateway measured: %s (code=%s policy=%s config=%s) into NV %#x, certified=%s",
        measurement.digest_hex,
        measurement.components["code"][:12],
        measurement.components["policy"][:12],
        measurement.components["config"][:12],
        extend_result.index,
        evidence is not None,
    )
    return measurement, extend_result, evidence


def _extend_and_certify(
    ectx: Any, measurement: GatewayMeasurement, nonce: bytes
) -> tuple[ExtendResult, bytes | None]:
    """Extend the measurement, certifying it with the platform AK when there is one.

    The certify pair must be signed by a key whose certificate chains to a vendor
    root, otherwise the signature proves nothing about where the key lives. Only the
    platform attestation key qualifies; a transient key would produce a verifiable
    signature with no provenance, which is worse than an honest absence because it
    looks like evidence. So when no platform key is available this falls back to the
    unsigned extend and returns no evidence.
    """
    from cmcp_runtime.tee.tpm import TPMProvider
    from cmcp_verify.nv_certify import build_envelope

    platform_key = None
    try:
        platform_key = TPMProvider().platform_attestation_key(ectx)
    except Exception as exc:  # noqa: BLE001
        logger.warning("No attestation key available to certify the measurement: %s", exc)

    if platform_key is None:
        logger.warning(
            "The measurement will not be certified: this platform provisions no "
            "certified attestation key. The extend still happened and remains a local "
            "integrity control, but it is not remote-verifiable evidence."
        )
        return extend_gateway_measurement(ectx, measurement), None

    sign_handle, _chain_pem = platform_key
    certified = certify_and_extend_gateway_measurement(
        ectx, measurement, sign_handle=sign_handle, nonce=nonce
    )
    envelope = build_envelope(
        pre_attest=certified.pre_attest,
        pre_signature=certified.pre_signature,
        post_attest=certified.post_attest,
        post_signature=certified.post_signature,
        gateway_digest=measurement.digest,
        components=measurement.components,
    )
    return certified.extend, envelope


def run_startup(config_path: str) -> RuntimeContext:
    """
    Execute the ordered startup sequence. Any failure before step 6 (network bind)
    is fatal - the gateway exits with code 1.

    Startup order per docs/spec/failure-modes.md:
    1. Load and validate config
    2. Detect TEE provider
    3. Generate ephemeral signing keypair and derive the attestation nonce
    3b. Measure the gateway into the TPM NV index and certify it (#432)
    3c. Produce the attestation report
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

    # Step 3: signing key. Generated before the measurement (#432) because the
    # measurement's TPM2_NV_Certify calls commit the attestation nonce, which is
    # derived from this key. The key has no dependencies of its own, so producing it
    # earlier is ordering only, not a behaviour change.
    signing_key = SigningKey()
    logger.info("Signing key generated: %s...", signing_key.public_key_hex[:16])

    # CRYPTO-001 + CRYPTO-002: the first 32 bytes of the nonce are the RFC 7638 JWK Thumbprint
    # (SHA-256 of the sorted JSON OKP key members) so verifiers can re-derive the fingerprint
    # from cnf.jwk and confirm it matches report_data[:32] -- binding the attestation report
    # to this specific keypair.
    # The remaining 32 bytes are a random salt so two gateways with different random bytes
    # produce different nonces even if they share the same keypair (blue-green deploy).
    _x_b64 = base64.urlsafe_b64encode(signing_key.public_key_bytes).rstrip(b"=").decode()
    key_fingerprint = _jwk_thumbprint_sha256(_x_b64)
    random_salt = secrets.token_bytes(32)
    nonce = key_fingerprint + random_salt

    # Step 3b (#432): measure the gateway into the NV extend index BEFORE it serves
    # traffic, and have the TPM certify the value either side of the extend so the
    # measurement is signed evidence rather than a self-reported number. PCRs 0-7
    # cover firmware and the bootloader only, so without this the TPM enforced
    # nothing about the gateway itself and a swapped policy bundle measured
    # identically.
    measurement, extend_result, measurement_evidence = _measure_gateway(
        config, tee_provider, nonce
    )

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
        catalog = load_catalog(
            config.catalog_path,
            expected_hash=catalog_expected_hash,
            extra_sensitivity_levels=frozenset(config.sensitivity.vocabulary),
        )
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
        gateway_measurement=measurement,
        measurement_extend=extend_result,
        measurement_evidence=measurement_evidence,
    )
