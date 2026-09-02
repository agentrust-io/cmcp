"""Gateway startup sequence with fail-closed validation - implements issue #66."""

from __future__ import annotations

import base64
import binascii
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
    load_agent_manifest_document,
    load_agent_manifest_trust_anchor,
    verify_agent_manifest_binding,
)
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.store import SqliteAuditStore
from cmcp_runtime.catalog.loader import ToolCatalog, load_catalog
from cmcp_runtime.catalog.scanner import CatalogScanner
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
from cmcp_runtime.tee.report_binding import (
    binds_measurement_into_report_data,
    measurement_bound_nonce_for,
)
from cmcp_runtime.tee.spiffe import SpiffeClientResult, fetch_svid

logger = logging.getLogger(__name__)

# HW-001: allowlist of canonical TEE provider names that may appear in
# AttestationReport.provider.  Mirrors the keys of _PROVIDER_MAP in
# audit/trace_claim.py - kept as a local constant to avoid a circular import.
_VALID_PROVIDERS: frozenset[str] = frozenset({
    "sev-snp",
    "azure-cvm-sev-snp",
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
    # #521: carries the tool fingerprints registered at startup, which is what
    # lets check_drift classify a later mutation. None only in tests that build a
    # context by hand; the proxy treats that as "no classification available"
    # and still enforces via digest comparison.
    catalog_scanner: CatalogScanner | None = None
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


def _decode_ed25519_public_key(value: str) -> bytes:
    """Decode a raw Ed25519 public key given as base64url or hex.

    Both spellings are accepted because operators paste whichever their tooling
    emits, and a 32-byte key is unambiguous either way. Anything that is not
    exactly 32 bytes is refused rather than padded or truncated.
    """
    text = value.strip()
    raw: bytes | None = None
    if len(text) == 64:
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raw = None
    if raw is None:
        try:
            padding = 4 - (len(text) % 4)
            raw = base64.urlsafe_b64decode(text + ("=" * padding if padding != 4 else ""))
        except (binascii.Error, ValueError) as exc:
            raise ConfigError(
                "CMCP_POLICY_SIGNING_KEY must be a raw Ed25519 public key in "
                "base64url or hex"
            ) from exc
    if len(raw) != 32:
        raise ConfigError(
            "CMCP_POLICY_SIGNING_KEY must decode to exactly 32 bytes "
            f"(an Ed25519 public key); got {len(raw)}"
        )
    return raw


def _fatal(code: str, message: str, **fields: Any) -> None:
    """Log a FATAL structured entry and exit with code 1."""
    entry = {
        "level": "FATAL",
        "event": code,
        "message": message,
        **fields,
    }
    logger.critical("%s", entry)


def _degrade_measurement(config: Config, exc: MeasurementUnavailable) -> None:
    """Abort on an unmeasurable gateway, or warn and continue in dev mode.

    Fatal in production and a warning in dev mode, matching how ``CMCP_POLICY_HASH``
    is handled. The dev-mode escape matters in practice because an editable install
    has no ``RECORD`` metadata, so the code digest is genuinely uncomputable there
    rather than merely inconvenient.
    """
    if config.dev_mode:
        logger.warning(
            "Gateway measurement unavailable (%s): %s. Continuing because "
            "CMCP_DEV_MODE is set; the platform will not attest what code is running.",
            exc,
            exc.detail or "",
        )
        return
    _fatal(
        "MEASUREMENT_UNAVAILABLE",
        f"the gateway could not be measured: {exc}",
        detail=exc.detail or "",
        action="startup_aborted",
    )
    sys.exit(1)


def _measure_gateway(
    config: Config, tee_provider: TEEProvider
) -> GatewayMeasurement | None:
    """Compute the gateway measurement on platforms that commit it (#432, #552).

    Two tiers commit it, by two different mechanisms. The ``tpm`` tier extends it
    into a ``TPM_NT_EXTEND`` NV index and certifies it (#432). SEV-SNP, TDX and
    Azure CVM have no such index, so they bind the same digest into the attestation
    nonce and the hardware signs it as ``report_data`` (#552) -- their own report
    fields carry only a *launch* measurement, which does not move when the policy
    bundle reloads mid-session.

    Returns None where neither applies, which is not a failure. An unmeasurable
    gateway on a platform that does commit it is fatal in production; see
    :func:`_degrade_measurement`.
    """
    provider_name = tee_provider.provider_name()
    if provider_name != "tpm" and not binds_measurement_into_report_data(provider_name):
        logger.debug(
            "Gateway measurement skipped: provider %s commits no gateway measurement",
            provider_name,
        )
        return None

    try:
        return gateway_measurement(config)
    except MeasurementUnavailable as exc:
        _degrade_measurement(config, exc)
        return None


def _attestation_nonce(
    key_fingerprint: bytes,
    signing_key: SigningKey,
    tee_provider: TEEProvider,
    measurement: GatewayMeasurement | None,
) -> bytes:
    """Choose the 64-byte nonce the hardware will sign into ``report_data``.

    Default (CRYPTO-001 + CRYPTO-002): ``jwk_thumbprint(key) || random_salt``. The
    first 32 bytes let a verifier re-derive the fingerprint from ``cnf.jwk`` and
    confirm it matches ``report_data[:32]``, binding the report to this keypair. The
    salt makes two gateways sharing a keypair produce different nonces.

    On SEV-SNP, TDX and Azure CVM (#552) the salt is replaced by the gateway
    measurement digest, so the code, policy and config actually running are what the
    hardware signs. Freshness survives the change: the signing key is generated once
    per start, so ``report_data[:32]`` still differs between two starts of identical
    code, policy and config.

    The TPM tier keeps the salt. Its measurement is committed by the NV extend index
    instead, which keeps the history that ``report_data`` does not.
    """
    if measurement is not None and binds_measurement_into_report_data(
        tee_provider.provider_name()
    ):
        return measurement_bound_nonce_for(signing_key.public_key_bytes, measurement)
    return key_fingerprint + secrets.token_bytes(32)


def _extend_measurement(
    config: Config,
    tee_provider: TEEProvider,
    measurement: GatewayMeasurement | None,
    nonce: bytes,
) -> tuple[ExtendResult | None, bytes | None]:
    """Extend the measurement into the TPM NV index and have the TPM certify it (#432).

    Returns ``(extend, evidence)``. ``evidence`` is the signed ``TPM2_NV_Certify``
    pair, or None when the platform provisions no certified attestation key to sign
    with. The pair is retained in ``RuntimeContext`` for direct appraisal, but the
    current TRACE schema does not transport it and ``verify_trace_claim`` does not
    invoke its verifier; do not describe ordinary claims as carrying this property.
    Both are None on a platform with no TPM, where #552's ``report_data`` binding
    does this job instead.
    """
    if tee_provider.provider_name() != "tpm" or measurement is None:
        return None, None

    def _degrade(exc: MeasurementUnavailable) -> tuple[None, None]:
        _degrade_measurement(config, exc)
        return None, None

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
    return extend_result, evidence


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
    # What fills the remaining 32 bytes depends on the platform: a random salt, or the
    # gateway measurement on the providers that have no NV index to hold it (#552).
    # See _attestation_nonce.
    _x_b64 = base64.urlsafe_b64encode(signing_key.public_key_bytes).rstrip(b"=").decode()
    key_fingerprint = _jwk_thumbprint_sha256(_x_b64)

    # Step 3b (#432, #552): measure the gateway BEFORE it serves traffic. The
    # measurement is computed first because on SEV-SNP, TDX and Azure CVM it goes
    # into the nonce itself, so it has to exist before the nonce does.
    measurement = _measure_gateway(config, tee_provider)
    nonce = _attestation_nonce(key_fingerprint, signing_key, tee_provider, measurement)

    # On the TPM tier the measurement is committed by an NV extend index instead,
    # certified either side of the extend so it is signed evidence rather than a
    # self-reported number. PCRs 0-7 cover firmware and the bootloader only, so
    # without this the TPM authenticated no commitment to the gateway itself and a
    # swapped policy bundle measured identically.
    extend_result, measurement_evidence = _extend_measurement(
        config, tee_provider, measurement, nonce
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

    # POLICY-004: the pinned policy signing key. This is the anchor that survives
    # the bundle changing, and therefore the only one that can authorise runtime
    # policy change: a hash pins one artifact, a key approves any artifact the
    # authority signs. See docs/spec/policy-hot-reload.md.
    policy_signing_key: bytes | None = None
    raw_signing_key = os.environ.get("CMCP_POLICY_SIGNING_KEY")
    if raw_signing_key:
        try:
            policy_signing_key = _decode_ed25519_public_key(raw_signing_key)
        except ConfigError as exc:
            _fatal("POLICY_SIGNING_KEY_INVALID", str(exc), action="startup_aborted")
            sys.exit(1)

    # POLICY-003: a pinned hash and automatic reload cannot both be satisfied.
    # The pin says "the policy is exactly this artifact, decided before the
    # process started"; reload says "the policy may change while it runs". The
    # reload path re-validates against this same pinned hash, so a bundle that
    # actually changed is rejected and the old policy keeps being enforced --
    # silently, at WARNING, while the failed reload re-reads and re-hashes the
    # whole bundle on every subsequent tool call because the interval is only
    # advanced on success.
    #
    # That combination could never do what an operator setting it intends, so it
    # is refused here rather than discovered in production. Runtime policy change
    # needs a trust anchor that survives the bundle changing: a pinned signing
    # key, not a pinned artifact hash. See docs/spec/policy-hot-reload.md.
    if (
        policy_expected_hash is not None
        and config.policy_reload_interval_seconds > 0
        and policy_signing_key is None
    ):
        _fatal(
            "POLICY_RELOAD_PINNED_HASH",
            "policy_reload_interval_seconds > 0 cannot be combined with a pinned "
            "CMCP_POLICY_HASH: every reload is validated against that hash, so a "
            "changed bundle is always rejected and the policy never updates.",
            detail=(
                f"policy_reload_interval_seconds={config.policy_reload_interval_seconds}, "
                "CMCP_POLICY_HASH is set. Set policy_reload_interval_seconds to 0. "
                "Automatic reload currently works only under CMCP_DEV_MODE=1, where no "
                "hash is pinned; see docs/spec/policy-hot-reload.md."
            ),
            action="startup_aborted",
        )
        sys.exit(1)

    try:
        policy_bundle = load_policy_bundle(
            config.policy_bundle_path,
            expected_hash=policy_expected_hash,
            signing_key=policy_signing_key,
        )
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
        signing_key=policy_signing_key,
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

    # Step 5a (#521): scan the catalog and register every tool's fingerprint, which
    # is what makes CatalogScanner.check_drift able to classify a later mutation.
    # The scanner is cMCP-owned and records approved fingerprints for later drift
    # classification. The proxy independently enforces its canonical digest check.
    catalog_scanner = CatalogScanner()
    scan = catalog_scanner.scan_catalog(catalog)
    if scan.safe:
        logger.info("Catalog security scan clean: %d tools scanned", scan.tools_scanned)
    else:
        for threat in scan.threats:
            logger.error(
                "CATALOG_THREAT tool=%s type=%s severity=%s",
                threat.get("tool_name"),
                threat.get("threat_type"),
                threat.get("severity"),
            )

    # Step 5b: optional Agent Manifest binding (#302). When configured, this is
    # fail-closed: signature, subject, policy hash, and catalog hash must agree
    # before any session can be created.
    agent_manifest: AgentManifestBinding | None = None

    # AARM R6: every receipt MUST be bound to an agent identity. The developer
    # default leaves binding optional, because requiring it out of the box would
    # stop anyone trying cMCP in five minutes. A deployment claiming conformance
    # says so by name, and then the requirement is real rather than aspirational.
    if config.conformance_profile == "aarm" and (
        config.agent_manifest.path is None
        or config.agent_manifest.trust_anchor_path is None
    ):
        _fatal(
            "CONFORMANCE_PROFILE_UNSATISFIED",
            "conformance_profile 'aarm' requires an Agent Manifest binding: "
            "AARM R6 binds every receipt to an agent identity.",
            detail=(
                "set agent_manifest.path and agent_manifest.trust_anchor_path, "
                "or remove conformance_profile to run with the permissive default"
            ),
            action="startup_aborted",
        )
        sys.exit(1)

    if config.agent_manifest.path is not None and config.agent_manifest.trust_anchor_path is not None:
        try:
            loaded = load_agent_manifest_document(config.agent_manifest.path)
            trusted_keys = load_agent_manifest_trust_anchor(
                config.agent_manifest.trust_anchor_path
            )
            agent_manifest = verify_agent_manifest_binding(
                loaded.manifest,
                trusted_keys,
                envelope=loaded.envelope,
                authenticated_subject=config.agent_manifest.authenticated_subject,
                policy_bundle_hash=policy_bundle.bundle_hash,
                tool_catalog_hash=catalog.catalog_hash,
                enforcement_mode=config.attestation.enforcement_mode,
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
        catalog_scanner=catalog_scanner,
        audit_store=audit_store,
        spiffe=spiffe_result,
        nras_appraisal=nras_appraisal,
        agent_manifest=agent_manifest,
        gateway_measurement=measurement,
        measurement_extend=extend_result,
        measurement_evidence=measurement_evidence,
    )
