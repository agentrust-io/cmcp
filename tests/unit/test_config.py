"""Tests for configuration parser (issue #64)."""

import textwrap
from pathlib import Path

import pytest

from cmcp_runtime.config import Config, EnforcementMode, TEEProvider, load_config
from cmcp_runtime.errors import ConfigError


@pytest.fixture
def config_file(tmp_path: Path):
    def _write(content: str) -> str:
        p = tmp_path / "cmcp-config.yaml"
        p.write_text(textwrap.dedent(content))
        return str(p)
    return _write


def test_load_minimal_config(config_file):
    path = config_file("""
        attestation:
          provider: tpm
          enforcement_mode: advisory
    """)
    cfg = load_config(path)
    assert cfg.attestation.provider == TEEProvider.TPM
    assert cfg.attestation.enforcement_mode == EnforcementMode.ADVISORY
    assert cfg.attestation.validity_seconds == 86400
    assert cfg.max_response_size_bytes == 2 * 1024 * 1024


def test_load_full_config(config_file):
    path = config_file("""
        attestation:
          provider: sev-snp
          enforcement_mode: enforcing
          validity_seconds: 3600
        policy_bundle_path: /etc/cmcp/policy/
        catalog_path: /etc/cmcp/catalog.json
        listen_addr: 127.0.0.1:9443
        max_response_size_bytes: 1048576
    """)
    cfg = load_config(path)
    assert cfg.attestation.provider == TEEProvider.SEV_SNP
    assert cfg.attestation.enforcement_mode == EnforcementMode.ENFORCING
    assert cfg.attestation.validity_seconds == 3600
    assert cfg.listen_addr == "127.0.0.1:9443"
    assert cfg.max_response_size_bytes == 1048576


def test_invalid_provider(config_file):
    path = config_file("attestation:\n  provider: quantum\n")
    with pytest.raises(ConfigError, match="provider"):
        load_config(path)


def test_invalid_enforcement_mode(config_file):
    path = config_file("attestation:\n  enforcement_mode: yolo\n")
    with pytest.raises(ConfigError, match="enforcement_mode"):
        load_config(path)


def test_invalid_validity_seconds(config_file):
    path = config_file("attestation:\n  validity_seconds: -1\n")
    with pytest.raises(ConfigError, match="validity_seconds"):
        load_config(path)


def test_unknown_key_raises(config_file):
    """CONF-001 — unknown config keys must fail closed, not silently ignore."""
    path = config_file("unknown_key: value\n")
    with pytest.raises(ConfigError, match="unknown_key"):
        load_config(path)


def test_empty_config_uses_defaults(config_file):
    path = config_file("")
    cfg = load_config(path)
    assert isinstance(cfg, Config)
    assert cfg.attestation.provider == TEEProvider.AUTO


def test_default_enforcement_mode_is_enforcing(config_file):
    """POLICY-003 — omitting enforcement_mode must default to enforcing, not advisory."""
    path = config_file("")
    cfg = load_config(path)
    assert cfg.attestation.enforcement_mode == EnforcementMode.ENFORCING


def test_non_mapping_config(config_file):
    path = config_file("- item1\n- item2\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(path)


def test_missing_file():
    with pytest.raises(ConfigError, match="Cannot read"):
        load_config("/nonexistent/path/config.yaml")


# ── CONF-004: path traversal rejection ───────────────────────────────────────

def test_policy_bundle_path_traversal_rejected(config_file):
    """CONF-004: '..' components in policy_bundle_path must be rejected."""
    path = config_file("policy_bundle_path: ../../etc/passwd\n")
    with pytest.raises(ConfigError, match=r"\.\."):
        load_config(path)


def test_catalog_path_traversal_rejected(config_file):
    """CONF-004: '..' components in catalog_path must be rejected."""
    path = config_file("catalog_path: ../../../etc/shadow\n")
    with pytest.raises(ConfigError, match=r"\.\."):
        load_config(path)


def test_embedded_traversal_in_policy_path_rejected(config_file):
    """CONF-004: embedded '..' (e.g. /safe/../etc) must also be rejected."""
    path = config_file("policy_bundle_path: /safe/../etc/passwd\n")
    with pytest.raises(ConfigError, match=r"\.\."):
        load_config(path)


def test_legitimate_absolute_path_accepted(config_file):
    """CONF-004: absolute paths without '..' remain valid."""
    path = config_file("policy_bundle_path: /opt/cmcp/policy\ncatalog_path: /opt/cmcp/catalog.json\n")
    cfg = load_config(path)
    assert cfg.policy_bundle_path == "/opt/cmcp/policy"
    assert cfg.catalog_path == "/opt/cmcp/catalog.json"


# ── POLICY-001: policy_reload_interval_seconds ────────────────────────────────

def test_policy_reload_interval_defaults_to_zero(config_file):
    """POLICY-001: omitting policy_reload_interval_seconds must default to 0 (disabled)."""
    path = config_file("")
    cfg = load_config(path)
    assert cfg.policy_reload_interval_seconds == 0


def test_policy_reload_interval_parsed(config_file):
    path = config_file("policy_reload_interval_seconds: 60\n")
    cfg = load_config(path)
    assert cfg.policy_reload_interval_seconds == 60


def test_policy_reload_interval_negative_rejected(config_file):
    path = config_file("policy_reload_interval_seconds: -1\n")
    with pytest.raises(ConfigError, match="policy_reload_interval_seconds"):
        load_config(path)


def test_policy_reload_interval_non_integer_rejected(config_file):
    path = config_file("policy_reload_interval_seconds: 30.5\n")
    with pytest.raises(ConfigError, match="policy_reload_interval_seconds"):
        load_config(path)


# ── HW-002: expected_measurement config field ─────────────────────────────────

def test_expected_measurement_loaded_from_config(config_file):
    """HW-002: attestation.expected_measurement is parsed and stored."""
    em = "sha384:" + "a" * 96
    path = config_file(f"attestation:\n  expected_measurement: {em}\n")
    cfg = load_config(path)
    assert cfg.attestation.expected_measurement == em


def test_expected_measurement_defaults_to_none(config_file):
    """HW-002: omitting expected_measurement leaves it as None."""
    path = config_file("attestation:\n  provider: auto\n")
    cfg = load_config(path)
    assert cfg.attestation.expected_measurement is None


def test_expected_measurement_non_string_rejected(config_file):
    """HW-002: a non-string expected_measurement is a config error."""
    path = config_file("attestation:\n  expected_measurement: 12345\n")
    with pytest.raises(ConfigError, match="expected_measurement"):
        load_config(path)
