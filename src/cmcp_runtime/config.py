"""Configuration parser - cmcp-config.yaml. Implements issue #64."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

import yaml

from cmcp_runtime.errors import ConfigError

# TEE-002: read exactly once at import time so the value is immutable for the
# lifetime of the process. No code may call os.environ.get("CMCP_DEV_MODE")
# after this point.
DEV_MODE: bool = os.environ.get("CMCP_DEV_MODE", "0") == "1"


class TEEProvider(StrEnum):
    TPM = "tpm"
    SEV_SNP = "sev-snp"
    TDX = "tdx"
    OPAQUE = "opaque"
    AUTO = "auto"
    SOFTWARE_ONLY = "software-only"


class EnforcementMode(StrEnum):
    ENFORCING = "enforcing"
    ADVISORY = "advisory"
    SILENT = "silent"


class StalenessPolicy(StrEnum):
    FAIL_CLOSED = "fail_closed"
    WARN_ONLY = "warn_only"


@dataclass
class KillSwitchConfig:
    enabled: bool = False
    window_seconds: int = 300
    deny_rate_threshold: float = 0.9
    min_calls: int = 10


@dataclass
class AttestationConfig:
    provider: TEEProvider = TEEProvider.AUTO
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCING
    validity_seconds: int = 86400
    staleness_policy: StalenessPolicy = StalenessPolicy.FAIL_CLOSED
    expected_measurement: str | None = None


@dataclass
class AgentManifestConfig:
    path: str | None = None
    trust_anchor_path: str | None = None
    authenticated_subject: str | None = None


@dataclass
class Config:
    attestation: AttestationConfig = field(default_factory=AttestationConfig)
    agent_manifest: AgentManifestConfig = field(default_factory=AgentManifestConfig)
    kill_switch: KillSwitchConfig = field(default_factory=KillSwitchConfig)
    policy_bundle_path: str = "policies/"
    catalog_path: str = "catalog.json"
    listen_addr: str = "0.0.0.0:8443"
    max_response_size_bytes: int = 2 * 1024 * 1024  # 2MB
    policy_reload_interval_seconds: int = 0  # 0 = disabled (POLICY-001)
    audit_db_path: str = "audit.db"  # AUDIT-001: durable audit chain storage
    dev_mode: bool = False
    bearer_token: str | None = None


_KNOWN_TOP_KEYS = {
    "attestation",
    "agent_manifest",
    "kill_switch",
    "policy_bundle_path",
    "catalog_path",
    "listen_addr",
    "max_response_size_bytes",
    "policy_reload_interval_seconds",
    "audit_db_path",
}
_KNOWN_KILL_SWITCH_KEYS = {
    "enabled",
    "window_seconds",
    "deny_rate_threshold",
    "min_calls",
}
_KNOWN_ATTEST_KEYS = {
    "provider",
    "enforcement_mode",
    "validity_seconds",
    "staleness_policy",
    "expected_measurement",
}
_KNOWN_AGENT_MANIFEST_KEYS = {"path", "trust_anchor_path", "authenticated_subject"}


def _check_no_traversal(field_name: str, path_str: str) -> None:
    """Reject paths that contain '..' components to prevent directory traversal (CONF-004)."""
    for part in PurePosixPath(path_str).parts:
        if part == "..":
            raise ConfigError(
                f"'{field_name}' must not contain '..' path components: {path_str!r}"
            )
    for part in PureWindowsPath(path_str).parts:
        if part == "..":
            raise ConfigError(
                f"'{field_name}' must not contain '..' path components: {path_str!r}"
            )


def load_config(path: str) -> Config:
    """Load and validate cmcp-config.yaml. Raises ConfigError on invalid input."""
    raw: dict[str, Any]
    try:
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
    except OSError as exc:
        raise ConfigError(f"Cannot read config file: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Config YAML parse error: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("Config must be a YAML mapping at the top level")

    for key in raw:
        if key not in _KNOWN_TOP_KEYS:
            raise ConfigError(
                f"Unknown config key '{key}'. Valid keys: {sorted(_KNOWN_TOP_KEYS)}"
            )

    attest_raw = raw.get("attestation", {})
    if not isinstance(attest_raw, dict):
        raise ConfigError("'attestation' must be a mapping")

    for key in attest_raw:
        if key not in _KNOWN_ATTEST_KEYS:
            raise ConfigError(
                f"Unknown attestation key '{key}'. Valid keys: {sorted(_KNOWN_ATTEST_KEYS)}"
            )

    manifest_raw = raw.get("agent_manifest", {})
    if manifest_raw is None:
        manifest_raw = {}
    if not isinstance(manifest_raw, dict):
        raise ConfigError("'agent_manifest' must be a mapping")

    for key in manifest_raw:
        if key not in _KNOWN_AGENT_MANIFEST_KEYS:
            raise ConfigError(
                "Unknown agent_manifest key "
                f"'{key}'. Valid keys: {sorted(_KNOWN_AGENT_MANIFEST_KEYS)}"
            )

    ks_raw = raw.get("kill_switch", {})
    if ks_raw is None:
        ks_raw = {}
    if not isinstance(ks_raw, dict):
        raise ConfigError("'kill_switch' must be a mapping")
    for key in ks_raw:
        if key not in _KNOWN_KILL_SWITCH_KEYS:
            raise ConfigError(
                f"Unknown kill_switch key '{key}'. Valid keys: {sorted(_KNOWN_KILL_SWITCH_KEYS)}"
            )
    ks_enabled = ks_raw.get("enabled", False)
    if not isinstance(ks_enabled, bool):
        raise ConfigError("kill_switch.enabled must be a boolean")
    ks_window = ks_raw.get("window_seconds", 300)
    if not isinstance(ks_window, int) or ks_window <= 0:
        raise ConfigError("kill_switch.window_seconds must be a positive integer")
    ks_threshold = ks_raw.get("deny_rate_threshold", 0.9)
    if not isinstance(ks_threshold, int | float) or not (0.0 < ks_threshold <= 1.0):
        raise ConfigError("kill_switch.deny_rate_threshold must be a float in (0, 1]")
    ks_min_calls = ks_raw.get("min_calls", 10)
    if not isinstance(ks_min_calls, int) or ks_min_calls <= 0:
        raise ConfigError("kill_switch.min_calls must be a positive integer")

    try:
        provider = TEEProvider(attest_raw.get("provider", "auto"))
    except ValueError as err:
        valid = [p.value for p in TEEProvider]
        raise ConfigError(f"attestation.provider must be one of {valid}") from err

    try:
        enforcement_mode = EnforcementMode(attest_raw.get("enforcement_mode", "enforcing"))
    except ValueError as err:
        valid = [m.value for m in EnforcementMode]
        raise ConfigError(f"attestation.enforcement_mode must be one of {valid}") from err

    try:
        staleness_policy = StalenessPolicy(attest_raw.get("staleness_policy", "fail_closed"))
    except ValueError as err:
        valid = [s.value for s in StalenessPolicy]
        raise ConfigError(f"attestation.staleness_policy must be one of {valid}") from err

    validity_seconds = attest_raw.get("validity_seconds", 86400)
    if not isinstance(validity_seconds, int) or validity_seconds <= 0:
        raise ConfigError("attestation.validity_seconds must be a positive integer")

    expected_measurement = attest_raw.get("expected_measurement", None)
    if expected_measurement is not None and not isinstance(expected_measurement, str):
        raise ConfigError("attestation.expected_measurement must be a string")

    max_bytes = raw.get("max_response_size_bytes", 2 * 1024 * 1024)
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ConfigError("max_response_size_bytes must be a positive integer")

    policy_reload_interval = raw.get("policy_reload_interval_seconds", 0)
    if not isinstance(policy_reload_interval, int) or policy_reload_interval < 0:
        raise ConfigError("policy_reload_interval_seconds must be a non-negative integer")

    dev_mode = DEV_MODE  # TEE-002: use the frozen constant, never re-read from env
    bearer_token = os.environ.get("CMCP_BEARER_TOKEN") or None

    policy_bundle_path = raw.get("policy_bundle_path", "policy/")
    catalog_path = raw.get("catalog_path", "catalog.json")
    audit_db_path = raw.get("audit_db_path", "audit.db")
    _check_no_traversal("policy_bundle_path", policy_bundle_path)
    _check_no_traversal("catalog_path", catalog_path)
    _check_no_traversal("audit_db_path", audit_db_path)

    agent_manifest_path = manifest_raw.get("path")
    trust_anchor_path = manifest_raw.get("trust_anchor_path")
    authenticated_subject = manifest_raw.get("authenticated_subject")
    if agent_manifest_path is not None and not isinstance(agent_manifest_path, str):
        raise ConfigError("agent_manifest.path must be a string")
    if trust_anchor_path is not None and not isinstance(trust_anchor_path, str):
        raise ConfigError("agent_manifest.trust_anchor_path must be a string")
    if authenticated_subject is not None and not isinstance(authenticated_subject, str):
        raise ConfigError("agent_manifest.authenticated_subject must be a string")
    if authenticated_subject is not None and not authenticated_subject.startswith("spiffe://"):
        raise ConfigError("agent_manifest.authenticated_subject must be a SPIFFE URI")
    if bool(agent_manifest_path) != bool(trust_anchor_path):
        raise ConfigError(
            "agent_manifest.path and agent_manifest.trust_anchor_path must be set together"
        )
    if agent_manifest_path is not None:
        _check_no_traversal("agent_manifest.path", agent_manifest_path)
    if trust_anchor_path is not None:
        _check_no_traversal("agent_manifest.trust_anchor_path", trust_anchor_path)

    return Config(
        attestation=AttestationConfig(
            provider=provider,
            enforcement_mode=enforcement_mode,
            validity_seconds=validity_seconds,
            staleness_policy=staleness_policy,
            expected_measurement=expected_measurement,
        ),
        agent_manifest=AgentManifestConfig(
            path=agent_manifest_path,
            trust_anchor_path=trust_anchor_path,
            authenticated_subject=authenticated_subject,
        ),
        kill_switch=KillSwitchConfig(
            enabled=ks_enabled,
            window_seconds=ks_window,
            deny_rate_threshold=float(ks_threshold),
            min_calls=ks_min_calls,
        ),
        policy_bundle_path=policy_bundle_path,
        catalog_path=catalog_path,
        listen_addr=raw.get("listen_addr", "0.0.0.0:8443"),
        max_response_size_bytes=max_bytes,
        policy_reload_interval_seconds=policy_reload_interval,
        audit_db_path=audit_db_path,
        dev_mode=dev_mode,
        bearer_token=bearer_token,
    )
