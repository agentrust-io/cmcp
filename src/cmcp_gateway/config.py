"""Configuration parser — cmcp-config.yaml. Implements issue #64."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import yaml

from cmcp_gateway.errors import ConfigError


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
class AttestationConfig:
    provider: TEEProvider = TEEProvider.AUTO
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCING
    validity_seconds: int = 86400
    staleness_policy: StalenessPolicy = StalenessPolicy.FAIL_CLOSED


@dataclass
class Config:
    attestation: AttestationConfig = field(default_factory=AttestationConfig)
    policy_bundle_path: str = "policy/"
    catalog_path: str = "catalog.json"
    listen_addr: str = "0.0.0.0:8443"
    max_response_size_bytes: int = 2 * 1024 * 1024  # 2MB
    dev_mode: bool = False
    bearer_token: str | None = None


_KNOWN_TOP_KEYS = {"attestation", "policy_bundle_path", "catalog_path", "listen_addr", "max_response_size_bytes"}
_KNOWN_ATTEST_KEYS = {"provider", "enforcement_mode", "validity_seconds", "staleness_policy"}


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

    max_bytes = raw.get("max_response_size_bytes", 2 * 1024 * 1024)
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ConfigError("max_response_size_bytes must be a positive integer")

    dev_mode = os.environ.get("CMCP_DEV_MODE", "0") == "1"
    bearer_token = os.environ.get("CMCP_BEARER_TOKEN") or None

    return Config(
        attestation=AttestationConfig(
            provider=provider,
            enforcement_mode=enforcement_mode,
            validity_seconds=validity_seconds,
            staleness_policy=staleness_policy,
        ),
        policy_bundle_path=raw.get("policy_bundle_path", "policy/"),
        catalog_path=raw.get("catalog_path", "catalog.json"),
        listen_addr=raw.get("listen_addr", "0.0.0.0:8443"),
        max_response_size_bytes=max_bytes,
        dev_mode=dev_mode,
        bearer_token=bearer_token,
    )
