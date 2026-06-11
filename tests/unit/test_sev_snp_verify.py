"""Unit tests for AMD SEV-SNP attestation verification (issue #67)."""
from __future__ import annotations

import ctypes
import hashlib
import struct

from cmcp_verify.sev_snp import _SnpAttestationReport, verify_sev_snp_measurement

_REPORT_DATA_OFFSET = _SnpAttestationReport.report_data.offset
_MEASUREMENT_OFFSET = _SnpAttestationReport.measurement.offset
_HOST_DATA_OFFSET   = _SnpAttestationReport.host_data.offset
_REPORT_SIZE        = ctypes.sizeof(_SnpAttestationReport)


def make_snp_report(
    version: int = 2,
    measurement_bytes: bytes | None = None,
    report_data: bytes | None = None,
) -> bytes:
    buf = bytearray(_REPORT_SIZE)
    struct.pack_into("<I", buf, 0x00, version)
    if report_data:
        buf[_REPORT_DATA_OFFSET : _REPORT_DATA_OFFSET + 64] = report_data[:64]
    if measurement_bytes:
        buf[_MEASUREMENT_OFFSET : _MEASUREMENT_OFFSET + 48] = measurement_bytes[:48]
    return bytes(buf)


def test_snp_struct_size() -> None:
    assert ctypes.sizeof(_SnpAttestationReport) == 0x4A0


def test_snp_struct_report_data_offset() -> None:
    assert _SnpAttestationReport.report_data.offset == 0x050


def test_snp_struct_measurement_offset() -> None:
    assert _SnpAttestationReport.measurement.offset == 0x090


def test_snp_struct_host_data_offset() -> None:
    assert _SnpAttestationReport.host_data.offset == 0x0C0


def test_snp_struct_round_trip() -> None:
    buf = bytearray(_REPORT_SIZE)
    struct.pack_into("<I", buf, 0x00, 2)
    pattern = bytes(range(48))
    buf[_MEASUREMENT_OFFSET : _MEASUREMENT_OFFSET + 48] = pattern
    host_pattern = bytes(range(32, 64))
    buf[_HOST_DATA_OFFSET : _HOST_DATA_OFFSET + 32] = host_pattern
    report = _SnpAttestationReport.from_buffer_copy(buf)
    assert report.version == 2
    assert bytes(report.measurement) == pattern
    assert bytes(report.host_data) == host_pattern


def test_valid_measurement_format_no_evidence_fails_closed():
    """A well-formed measurement string is not evidence."""
    good = "sha384:" + "a" * 96
    result = verify_sev_snp_measurement(good, raw_evidence=None)
    assert result.verified is False
    assert result.failure_reason == "no_raw_evidence"


def test_sha256_prefix_fails_format():
    bad = "sha256:" + "a" * 64
    result = verify_sev_snp_measurement(bad, raw_evidence=None)
    assert result.verified is False
    assert result.failure_reason == "invalid_measurement_format"


def test_short_hex_fails_format():
    bad = "sha384:" + "a" * 95
    result = verify_sev_snp_measurement(bad, raw_evidence=None)
    assert result.verified is False
    assert result.failure_reason == "invalid_measurement_format"


def test_long_hex_fails_format():
    bad = "sha384:" + "a" * 97
    result = verify_sev_snp_measurement(bad, raw_evidence=None)
    assert result.verified is False
    assert result.failure_reason == "invalid_measurement_format"


def test_version2_matching_measurement_verified():
    raw_m = b"\xab" * 48
    expected = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    report = make_snp_report(version=2, measurement_bytes=raw_m)
    result = verify_sev_snp_measurement(expected, raw_evidence=report)
    assert result.verified is True
    assert "measurement" in result.verified_fields
    assert result.details["snp_report_version"] == "2"


def test_version3_matching_measurement_verified():
    raw_m = b"\xcd" * 48
    expected = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    report = make_snp_report(version=3, measurement_bytes=raw_m)
    result = verify_sev_snp_measurement(expected, raw_evidence=report)
    assert result.verified is True
    assert "measurement" in result.verified_fields
    assert result.details["snp_report_version"] == "3"


def test_version5_report_fails():
    raw_m = b"\x00" * 48
    measurement = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    report = make_snp_report(version=5, measurement_bytes=raw_m)
    result = verify_sev_snp_measurement(measurement, raw_evidence=report)
    assert result.verified is False
    assert result.failure_reason == "invalid_snp_report_version"
    assert result.details["snp_report_version"] == "5"


def test_measurement_mismatch_fails():
    raw_m = b"\x11" * 48
    wrong_measurement = "sha384:" + "0" * 96
    report = make_snp_report(version=2, measurement_bytes=raw_m)
    result = verify_sev_snp_measurement(wrong_measurement, raw_evidence=report)
    assert result.verified is False
    assert result.failure_reason == "measurement_mismatch"


def test_report_data_match_adds_verified_field():
    raw_m = b"\x77" * 48
    nonce = b"\x44" * 64
    report = make_snp_report(version=2, measurement_bytes=raw_m, report_data=nonce)
    actual_rd = report[_REPORT_DATA_OFFSET : _REPORT_DATA_OFFSET + 64]
    measurement = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    result = verify_sev_snp_measurement(
        measurement, raw_evidence=report, report_data_hex=actual_rd.hex()
    )
    assert result.verified is True
    assert "report_data" in result.verified_fields


def test_report_data_mismatch_not_fatal():
    raw_m = b"\x55" * 48
    report = make_snp_report(version=2, measurement_bytes=raw_m, report_data=b"\x22" * 64)
    measurement = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    wrong_report_data = b"\x33" * 64
    result = verify_sev_snp_measurement(
        measurement, raw_evidence=report, report_data_hex=wrong_report_data.hex()
    )
    assert result.verified is True
    assert "report_data" not in result.verified_fields
    assert result.failure_reason is None


def test_truncated_report_is_parse_error():
    raw_m = b"\x22" * 48
    measurement = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    truncated = make_snp_report(version=2, measurement_bytes=raw_m)[:-100]
    result = verify_sev_snp_measurement(measurement, raw_evidence=truncated)
    assert result.verified is False
    assert result.failure_reason == "raw_evidence_parse_error"


def test_no_raw_evidence_fails_closed():
    """A hardware-platform claim with no evidence must not verify."""
    good = "sha384:" + "f" * 96
    result = verify_sev_snp_measurement(good, raw_evidence=None)
    assert result.verified is False
    assert result.failure_reason == "no_raw_evidence"
    assert "measurement" not in result.verified_fields


def test_vcek_cert_chain_always_unverified_no_evidence():
    good = "sha384:" + "e" * 96
    result = verify_sev_snp_measurement(good, raw_evidence=None)
    assert result.verified is False
    assert "vcek_cert_chain" in result.unverified_fields


def test_vcek_cert_chain_always_unverified_with_matching_report():
    raw_m = b"\x33" * 48
    measurement = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    report = make_snp_report(version=2, measurement_bytes=raw_m)
    result = verify_sev_snp_measurement(measurement, raw_evidence=report)
    assert "vcek_cert_chain" in result.unverified_fields
    assert result.details["vcek_chain"] == "requires_amd_kds_lookup"


def test_vcek_cert_chain_unverified_on_format_failure():
    bad = "sha256:" + "z" * 64
    result = verify_sev_snp_measurement(bad, raw_evidence=None)
    assert "vcek_cert_chain" in result.unverified_fields
