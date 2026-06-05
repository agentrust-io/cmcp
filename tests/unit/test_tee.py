"""Tests for TEE provider abstraction and dev mode (issues #72, #77)."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from unittest.mock import patch

import pytest

from cmcp_gateway.config import Config, AttestationConfig, TEEProvider as TEEProviderEnum
from cmcp_gateway.errors import AttestationProviderUnsupported
from cmcp_gateway.tee.base import SoftwareOnlyProvider, make_nonce
from cmcp_gateway.tee.detect import detect_provider


@pytest.fixture
def dev_config() -> Config:
    cfg = Config()
    cfg.dev_mode = True
    return cfg


@pytest.fixture
def no_dev_config() -> Config:
    cfg = Config()
    cfg.dev_mode = False
    return cfg


# ── SoftwareOnlyProvider ─────────────────────────────────────────────────────

def test_software_only_detect():
    assert SoftwareOnlyProvider().detect() is True


def test_software_only_provider_name():
    assert SoftwareOnlyProvider().provider_name() == "software-only"


def test_software_only_report_fields():
    provider = SoftwareOnlyProvider()
    nonce = b"\x00" * 32
    report = provider.get_attestation_report(nonce)
    assert report.provider == "software-only"
    assert report.measurement == "DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION"
    assert report.report_data == nonce.hex()
    assert report.raw_evidence is None
    assert isinstance(report.attestation_generated_at, datetime)
    assert report.attestation_validity_seconds > 0


def test_software_only_report_note():
    report = SoftwareOnlyProvider().get_attestation_report(b"\x01" * 32)
    assert report.measurement_note is not None
    assert "software-only" in report.measurement_note


# ── make_nonce ────────────────────────────────────────────────────────────────

def test_make_nonce_deterministic():
    key = b"\xab" * 32
    sid = "session-123"
    nonce1 = make_nonce(key, sid)
    nonce2 = make_nonce(key, sid)
    assert nonce1 == nonce2


def test_make_nonce_sha256():
    key = b"\x01" * 32
    sid = "test"
    expected = hashlib.sha256(key + sid.encode()).digest()
    assert make_nonce(key, sid) == expected


def test_make_nonce_different_inputs():
    n1 = make_nonce(b"\x01" * 32, "a")
    n2 = make_nonce(b"\x02" * 32, "a")
    n3 = make_nonce(b"\x01" * 32, "b")
    assert n1 != n2
    assert n1 != n3


# ── detect_provider ───────────────────────────────────────────────────────────

def test_detect_returns_software_only_in_dev_mode(dev_config):
    with patch("cmcp_gateway.tee.detect._get_provider_impl", return_value=None):
        provider = detect_provider(dev_config)
    assert isinstance(provider, SoftwareOnlyProvider)


def test_detect_raises_when_no_hardware_and_no_dev_mode(no_dev_config):
    with patch("cmcp_gateway.tee.detect._get_provider_impl", return_value=None):
        with pytest.raises(AttestationProviderUnsupported):
            detect_provider(no_dev_config)


def test_detect_via_env_var(no_dev_config, monkeypatch):
    monkeypatch.setenv("CMCP_DEV_MODE", "1")
    with patch("cmcp_gateway.tee.detect._get_provider_impl", return_value=None):
        provider = detect_provider(no_dev_config)
    assert isinstance(provider, SoftwareOnlyProvider)


def test_detect_uses_first_available_provider(dev_config):
    """detect_provider picks the first provider whose detect() returns True."""
    mock_provider = SoftwareOnlyProvider()  # reuse as a stand-in

    def _mock_get(name: str):
        if name == "sev-snp":
            return mock_provider
        return None

    with patch("cmcp_gateway.tee.detect._get_provider_impl", side_effect=_mock_get):
        with patch.object(mock_provider, "detect", return_value=True):
            provider = detect_provider(dev_config)
    assert provider is mock_provider


def test_detect_explicit_software_only_requires_dev_mode(no_dev_config):
    no_dev_config.attestation.provider = TEEProviderEnum.SOFTWARE_ONLY
    with pytest.raises(AttestationProviderUnsupported, match="CMCP_DEV_MODE"):
        detect_provider(no_dev_config)


def test_detect_explicit_software_only_with_dev_mode(dev_config):
    dev_config.attestation.provider = TEEProviderEnum.SOFTWARE_ONLY
    provider = detect_provider(dev_config)
    assert isinstance(provider, SoftwareOnlyProvider)
