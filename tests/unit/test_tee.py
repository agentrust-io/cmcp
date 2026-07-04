"""Tests for TEE provider abstraction and dev mode (issues #72, #77)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from cmcp_runtime.config import Config
from cmcp_runtime.config import TEEProvider as TEEProviderEnum
from cmcp_runtime.errors import (
    AttestationProviderNotImplemented,
    AttestationProviderUnsupported,
)
from cmcp_runtime.tee.base import SoftwareOnlyProvider, jwk_thumbprint, make_nonce
from cmcp_runtime.tee.detect import detect_provider


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
    """Same key and salt produce the same 64-byte nonce."""
    key = b"\xab" * 32
    salt = b"\x07" * 32
    assert make_nonce(key, salt) == make_nonce(key, salt)


def test_make_nonce_structure():
    """Nonce is jwk_thumbprint(key)(32) || salt(32)."""
    key = b"\x01" * 32
    salt = b"\x09" * 32
    nonce = make_nonce(key, salt)
    assert len(nonce) == 64
    assert nonce[:32] == jwk_thumbprint(key)
    assert nonce[32:] == salt


def test_make_nonce_rejects_bad_salt():
    with pytest.raises(ValueError):
        make_nonce(b"\x01" * 32, b"\x00" * 16)


def test_make_nonce_different_inputs():
    salt = b"\x05" * 32
    n1 = make_nonce(b"\x01" * 32, salt)
    n2 = make_nonce(b"\x02" * 32, salt)
    n3 = make_nonce(b"\x01" * 32, b"\x06" * 32)
    assert n1 != n2  # different key -> different thumbprint
    assert n1 != n3  # different salt -> different nonce


# ── detect_provider ───────────────────────────────────────────────────────────

def test_detect_returns_software_only_in_dev_mode(dev_config):
    with patch("cmcp_runtime.tee.detect._get_provider_impl", return_value=None):
        provider = detect_provider(dev_config)
    assert isinstance(provider, SoftwareOnlyProvider)


def test_detect_raises_when_no_hardware_and_no_dev_mode(no_dev_config):
    with patch("cmcp_runtime.tee.detect._get_provider_impl", return_value=None), \
         pytest.raises(AttestationProviderUnsupported):
        detect_provider(no_dev_config)


def test_detect_env_var_alone_does_not_bypass_config(no_dev_config, monkeypatch):
    """CONF-002: CMCP_DEV_MODE in env after config load must not enable software-only."""
    monkeypatch.setenv("CMCP_DEV_MODE", "1")
    with patch("cmcp_runtime.tee.detect._get_provider_impl", return_value=None), \
         pytest.raises(AttestationProviderUnsupported):
        detect_provider(no_dev_config)


def test_detect_uses_first_available_provider(dev_config):
    """detect_provider picks the first provider whose detect() returns True."""
    mock_provider = SoftwareOnlyProvider()  # reuse as a stand-in

    def _mock_get(name, config=None):
        if name == "sev-snp":
            return mock_provider
        return None

    with patch("cmcp_runtime.tee.detect._get_provider_impl", side_effect=_mock_get), \
         patch.object(mock_provider, "detect", return_value=True):
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


def test_detect_explicit_opaque_raises_not_implemented(dev_config):
    """Explicitly selecting the opaque provider raises an explicit not-implemented error,
    not a silent fall-through or a generic 'unsupported'."""
    dev_config.attestation.provider = TEEProviderEnum.OPAQUE
    with pytest.raises(AttestationProviderNotImplemented):
        detect_provider(dev_config)


def test_opaque_excluded_from_auto_probe_order():
    """The not-yet-implemented opaque provider must never be in the auto-detect order."""
    from cmcp_runtime.tee.detect import _PROBE_ORDER

    assert "opaque" not in _PROBE_ORDER


# ── HW-001: AttestationReport provider validation ────────────────────────────

def test_attestation_report_unknown_provider_raises():
    """HW-001: unknown provider string must be rejected at AttestationReport construction."""

    from cmcp_runtime.tee.base import AttestationReport
    with pytest.raises(ValueError, match="not in the allowed set"):
        AttestationReport(
            provider="unknown-cloud-magic",
            measurement="sha256:" + "a" * 64,
            report_data="aa" * 32,
            raw_evidence=None,
            attestation_generated_at=datetime.now(tz=UTC),
            attestation_validity_seconds=86400,
        )


def test_attestation_report_known_providers_accepted():
    """HW-001: all known providers must be accepted."""

    from cmcp_runtime.tee.base import _ALLOWED_PROVIDERS, AttestationReport
    for provider in _ALLOWED_PROVIDERS:
        AttestationReport(
            provider=provider,
            measurement="sha256:" + "a" * 64,
            report_data="aa" * 32,
            raw_evidence=None,
            attestation_generated_at=datetime.now(tz=UTC),
            attestation_validity_seconds=86400,
        )


# ── HW-002: SEVSNPProvider expected_measurement validation ───────────────────

def test_sevsnp_no_expected_measurement_skips_check():
    """HW-002: when expected_measurement is None, attribute is None (check skipped)."""
    from cmcp_runtime.tee.sev_snp import SEVSNPProvider
    provider = SEVSNPProvider(expected_measurement=None)
    assert provider._expected_measurement is None


def test_sevsnp_stores_expected_measurement():
    """HW-002: SEVSNPProvider stores the configured expected_measurement."""
    from cmcp_runtime.tee.sev_snp import SEVSNPProvider
    em = "sha384:" + "a" * 96
    provider = SEVSNPProvider(expected_measurement=em)
    assert provider._expected_measurement == em


def test_sevsnp_rejects_mismatched_expected_measurement(monkeypatch):
    """HW-002: measurement mismatch raises RuntimeError before returning the report."""
    import struct
    import sys
    from unittest.mock import MagicMock

    from cmcp_runtime.tee.sev_snp import (
        _SNP_MEASUREMENT_END,
        _SNP_MEASUREMENT_OFFSET,
        _SNP_REPORT_SIZE,
        _SNP_RESP_HEADER_SIZE,
        SEVSNPProvider,
    )

    # Build a fake ioctl response with a known measurement
    measurement_bytes = b"\xab" * (_SNP_MEASUREMENT_END - _SNP_MEASUREMENT_OFFSET)
    raw_evidence = bytearray(_SNP_REPORT_SIZE)
    raw_evidence[_SNP_MEASUREMENT_OFFSET:_SNP_MEASUREMENT_END] = measurement_bytes

    resp_buf = bytearray(_SNP_RESP_HEADER_SIZE + _SNP_REPORT_SIZE)
    struct.pack_into("<I", resp_buf, 0, 0)  # status = 0
    resp_buf[_SNP_RESP_HEADER_SIZE:] = raw_evidence

    def fake_ioctl(fd, req, buf):
        buf[:] = resp_buf

    mock_fcntl = MagicMock()
    mock_fcntl.ioctl.side_effect = fake_ioctl
    monkeypatch.setitem(sys.modules, "fcntl", mock_fcntl)
    monkeypatch.setattr("cmcp_runtime.tee.sev_snp.sys.platform", "linux")

    wrong_expected = "sha384:" + "0" * 96
    provider = SEVSNPProvider(expected_measurement=wrong_expected)

    with patch("builtins.open", MagicMock(
        return_value=MagicMock(__enter__=lambda s: MagicMock(), __exit__=lambda s, *a: False)
    )), pytest.raises(RuntimeError, match="measurement mismatch"):
        provider.get_attestation_report(b"\x00" * 32)


def test_sevsnp_accepts_matching_expected_measurement(monkeypatch):
    """HW-002: when expected_measurement matches, report is returned without error."""
    import hashlib
    import struct
    import sys
    from unittest.mock import MagicMock

    from cmcp_runtime.tee.sev_snp import (
        _SNP_MEASUREMENT_END,
        _SNP_MEASUREMENT_OFFSET,
        _SNP_REPORT_SIZE,
        _SNP_RESP_HEADER_SIZE,
        SEVSNPProvider,
    )

    measurement_bytes = b"\xcd" * (_SNP_MEASUREMENT_END - _SNP_MEASUREMENT_OFFSET)
    expected = "sha384:" + hashlib.sha384(measurement_bytes).hexdigest()

    raw_evidence = bytearray(_SNP_REPORT_SIZE)
    raw_evidence[_SNP_MEASUREMENT_OFFSET:_SNP_MEASUREMENT_END] = measurement_bytes

    resp_buf = bytearray(_SNP_RESP_HEADER_SIZE + _SNP_REPORT_SIZE)
    struct.pack_into("<I", resp_buf, 0, 0)
    resp_buf[_SNP_RESP_HEADER_SIZE:] = raw_evidence

    def fake_ioctl(fd, req, buf):
        buf[:] = resp_buf

    mock_fcntl = MagicMock()
    mock_fcntl.ioctl.side_effect = fake_ioctl
    monkeypatch.setitem(sys.modules, "fcntl", mock_fcntl)
    monkeypatch.setattr("cmcp_runtime.tee.sev_snp.sys.platform", "linux")

    provider = SEVSNPProvider(expected_measurement=expected)

    with patch("builtins.open", MagicMock(
        return_value=MagicMock(__enter__=lambda s: MagicMock(), __exit__=lambda s, *a: False)
    )):
        report = provider.get_attestation_report(b"\x00" * 32)

    assert report.measurement == expected


def test_detect_provider_passes_expected_measurement_to_snp(dev_config):
    """HW-002: detect_provider threads attestation.expected_measurement into SEVSNPProvider."""
    from cmcp_runtime.tee.sev_snp import SEVSNPProvider

    dev_config.attestation.expected_measurement = "sha384:" + "f" * 96
    dev_config.attestation.provider = TEEProviderEnum.SEV_SNP

    created = []

    original_get = __import__(
        "cmcp_runtime.tee.detect", fromlist=["_get_provider_impl"]
    )._get_provider_impl

    def spy_get(name, config=None):
        impl = original_get(name, config)
        if isinstance(impl, SEVSNPProvider):
            created.append(impl)
        return impl

    with patch("cmcp_runtime.tee.detect._get_provider_impl", side_effect=spy_get), \
         patch.object(SEVSNPProvider, "detect", return_value=True):
        detect_provider(dev_config)

    assert created, "SEVSNPProvider was not instantiated"
    assert created[0]._expected_measurement == "sha384:" + "f" * 96
