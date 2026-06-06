"""Tests for configuration parser (issue #64)."""

import textwrap
from pathlib import Path

import pytest

from cmcp_gateway.config import Config, EnforcementMode, TEEProvider, load_config
from cmcp_gateway.errors import ConfigError


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


def test_non_mapping_config(config_file):
    path = config_file("- item1\n- item2\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(path)


def test_missing_file():
    with pytest.raises(ConfigError, match="Cannot read"):
        load_config("/nonexistent/path/config.yaml")
