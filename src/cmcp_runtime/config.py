"""Configuration parser - cmcp-config.yaml. Implements issue #64."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import ip_address
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

import yaml

from cmcp_runtime.errors import ConfigError
from cmcp_runtime.session.state import SENSITIVITY_ORDER

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
class SensitivityConfig:
    """Deployment supplied additions to the built in sensitivity vocabulary (#479).

    Additive only: a key here must not collide with a built in SENSITIVITY_ORDER
    name (enforced when config loads), so a deployment can add new labels,
    including tiers above trade_secret, without ever being able to remove or
    rename a built in one. See session/state.py's effective_sensitivity_order().
    """

    vocabulary: dict[str, int] = field(default_factory=dict)


@dataclass
class AttestationConfig:
    provider: TEEProvider = TEEProvider.AUTO
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCING
    validity_seconds: int = 86400
    staleness_policy: StalenessPolicy = StalenessPolicy.FAIL_CLOSED
    expected_measurement: str | None = None
    allow_unmeasured_spawn: bool = False
    required_provenance_kind: str | None = None
    """Minimum server-provenance assurance to route a call. ``None`` records the
    outcome without enforcing it, which is the only default that works in an
    ecosystem where almost no server has a record: a gateway that refuses to route
    without one gets turned off on first contact and never turned back on."""
    """Permit spawning a stdio server whose binary the catalog does not pin.

    Default off. A child runs inside the enclave, in the same isolation domain as
    the policy evaluator and the audit chain, and the control that pays for that
    is refusing to spawn what cannot be checked. Turning this on does not make
    the spawn silent: every such call is recorded as ``spawn-unmeasured``.
    """


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
    sensitivity: SensitivityConfig = field(default_factory=SensitivityConfig)
    policy_bundle_path: str = "policies/"
    catalog_path: str = "catalog.json"
    listen_addr: str = "0.0.0.0:8443"
    max_response_size_bytes: int = 2 * 1024 * 1024  # 2MB
    policy_reload_interval_seconds: int = 0  # 0 = disabled (POLICY-001)
    audit_db_path: str = "audit.db"  # AUDIT-001: durable audit chain storage
    dev_mode: bool = False
    bearer_token: str | None = None
    #: AARM R6. A named conformance profile tightens defaults that stay
    #: permissive for developers. None is the default, and nothing changes.
    #: "aarm" requires an Agent Manifest binding, because R6 says every receipt
    #: MUST be bound to an agent identity while the developer default leaves
    #: binding optional. Naming the profile is what lets both be true.
    conformance_profile: str | None = None


_KNOWN_TOP_KEYS = {
    "attestation",
    "agent_manifest",
    "kill_switch",
    "sensitivity",
    "policy_bundle_path",
    "catalog_path",
    "listen_addr",
    "max_response_size_bytes",
    "policy_reload_interval_seconds",
    "audit_db_path",
    "conformance_profile",
}

# #495: catalog identity and routing are immutable for the process lifetime.
# Keep likely reload knobs in a separate denylist so merely adding one to the
# normal parser allowlist cannot silently enable mutation later.
_FORBIDDEN_CATALOG_MUTATION_KEYS = {
    "catalog_reload_interval_seconds",
    "catalog_reload_path",
}

#: Named conformance profiles. Deliberately a closed set: an unrecognised
#: profile name must be a config error rather than silently enforcing nothing,
#: which is how a deployment ends up believing it is conformant when it is not.
_KNOWN_CONFORMANCE_PROFILES = {"aarm"}
_KNOWN_KILL_SWITCH_KEYS = {
    "enabled",
    "window_seconds",
    "deny_rate_threshold",
    "min_calls",
}
_KNOWN_SENSITIVITY_KEYS = {"vocabulary"}
_KNOWN_ATTEST_KEYS = {
    "provider",
    "enforcement_mode",
    "validity_seconds",
    "staleness_policy",
    "expected_measurement",
    "allow_unmeasured_spawn",
    "required_provenance_kind",
}
_KNOWN_AGENT_MANIFEST_KEYS = {"path", "trust_anchor_path", "authenticated_subject"}


def parse_listen_addr(value: str) -> tuple[str, int]:
    """Parse a listen address into a host and port."""

    if not isinstance(value, str):
        raise ConfigError("listen_addr must be a string")

    address = value.strip()
    if not address:
        raise ConfigError("listen_addr must not be empty")

    if address.startswith("["):
        closing_bracket = address.find("]")
        if closing_bracket == -1 or address[closing_bracket + 1 : closing_bracket + 2] != ":":
            raise ConfigError(
                "listen_addr must use the format '[IPv6]:port'"
            )

        host = address[1:closing_bracket]
        port_text = address[closing_bracket + 2 :]
    else:
        host, separator, port_text = address.rpartition(":")
        if not separator:
            raise ConfigError(
                "listen_addr must use the format 'host:port'"
            )

    if not host:
        raise ConfigError("listen_addr host must not be empty")

    try:
        port = int(port_text)
    except ValueError as exc:
        raise ConfigError("listen_addr port must be an integer") from exc

    if not 1 <= port <= 65535:
        raise ConfigError("listen_addr port must be between 1 and 65535")

    return host, port


def _is_loopback_host(host: str) -> bool:
    """Return whether a host is explicitly local-only."""

    if host.casefold() == "localhost":
        return True

    try:
        return ip_address(host).is_loopback
    except ValueError:
        # Hostnames other than localhost are not guaranteed to remain local.
        return False


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

    forbidden_catalog_keys = set(raw) & _FORBIDDEN_CATALOG_MUTATION_KEYS
    if forbidden_catalog_keys:
        raise ConfigError(
            "CATALOG_RESTART_REQUIRED: runtime catalog mutation is unsupported; "
            f"remove {sorted(forbidden_catalog_keys)} and restart with a newly pinned catalog"
        )

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

    sens_raw = raw.get("sensitivity", {})
    if sens_raw is None:
        sens_raw = {}
    if not isinstance(sens_raw, dict):
        raise ConfigError("'sensitivity' must be a mapping")
    for key in sens_raw:
        if key not in _KNOWN_SENSITIVITY_KEYS:
            raise ConfigError(
                f"Unknown sensitivity key '{key}'. Valid keys: {sorted(_KNOWN_SENSITIVITY_KEYS)}"
            )
    vocab_raw = sens_raw.get("vocabulary", {})
    if vocab_raw is None:
        vocab_raw = {}
    if not isinstance(vocab_raw, dict):
        raise ConfigError("sensitivity.vocabulary must be a mapping")
    sensitivity_vocabulary: dict[str, int] = {}
    for label, rank in vocab_raw.items():
        if not isinstance(label, str) or not label:
            raise ConfigError("sensitivity.vocabulary keys must be non empty strings")
        if label in SENSITIVITY_ORDER:
            raise ConfigError(
                f"sensitivity.vocabulary key '{label}' collides with a built in "
                "sensitivity label. Custom labels may only add to the built in "
                "set, never rename or replace one."
            )
        if isinstance(rank, bool) or not isinstance(rank, int) or rank < 0:
            raise ConfigError(
                f"sensitivity.vocabulary['{label}'] must be a non negative integer"
            )
        sensitivity_vocabulary[label] = rank

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

    allow_unmeasured_spawn = attest_raw.get("allow_unmeasured_spawn", False)
    if not isinstance(allow_unmeasured_spawn, bool):
        raise ConfigError("attestation.allow_unmeasured_spawn must be a boolean")

    required_provenance_kind = attest_raw.get("required_provenance_kind", None)
    _KINDS = ("publisher-asserted", "observer-attested", "tee-attested")
    if required_provenance_kind is not None and required_provenance_kind not in _KINDS:
        raise ConfigError(
            "attestation.required_provenance_kind must be null or one of "
            + ", ".join(_KINDS)
        )

    max_bytes = raw.get("max_response_size_bytes", 2 * 1024 * 1024)
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ConfigError("max_response_size_bytes must be a positive integer")

    policy_reload_interval = raw.get("policy_reload_interval_seconds", 0)
    if not isinstance(policy_reload_interval, int) or policy_reload_interval < 0:
        raise ConfigError("policy_reload_interval_seconds must be a non-negative integer")

    dev_mode = DEV_MODE  # TEE-002: use the frozen constant, never re-read from env
    bearer_token = os.environ.get("CMCP_BEARER_TOKEN") or None

    default_listen_addr = (
        "127.0.0.1:8443"
        if dev_mode and bearer_token is None
        else "0.0.0.0:8443"
    )
    listen_addr = raw.get("listen_addr", default_listen_addr)
    listen_host, _ = parse_listen_addr(listen_addr)

    if dev_mode and bearer_token is None and not _is_loopback_host(listen_host):
        raise ConfigError(
            "Tokenless development mode may only bind to a loopback address. "
            "Use 127.0.0.1:<port>, localhost:<port>, or [::1]:<port>, "
            "or configure CMCP_BEARER_TOKEN for non-loopback access."
        )

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

    profile = raw.get("conformance_profile")
    if profile is not None and (
        not isinstance(profile, str) or profile not in _KNOWN_CONFORMANCE_PROFILES
    ):
        raise ConfigError(
            f"conformance_profile must be one of "
            f"{sorted(_KNOWN_CONFORMANCE_PROFILES)}, got {profile!r}"
        )

    return Config(
        attestation=AttestationConfig(
            provider=provider,
            enforcement_mode=enforcement_mode,
            validity_seconds=validity_seconds,
            staleness_policy=staleness_policy,
            expected_measurement=expected_measurement,
            allow_unmeasured_spawn=allow_unmeasured_spawn,
            required_provenance_kind=required_provenance_kind,
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
        sensitivity=SensitivityConfig(vocabulary=sensitivity_vocabulary),
        policy_bundle_path=policy_bundle_path,
        catalog_path=catalog_path,
        listen_addr=listen_addr,
        max_response_size_bytes=max_bytes,
        policy_reload_interval_seconds=policy_reload_interval,
        audit_db_path=audit_db_path,
        conformance_profile=profile,
        dev_mode=dev_mode,
        bearer_token=bearer_token,
    )
