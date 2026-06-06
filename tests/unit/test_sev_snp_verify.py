"""Unit tests for AMD SEV-SNP attestation verification (issue #67)."""
from __future__ import annotations

import hashlib
import struct

from cmcp_verify.sev_snp import verify_sev_snp_measurement


def make_snp_report(
    version: int = 2,
    measurement_bytes: bytes | None = None,
    report_data: bytes | None = None,
) -> bytes:
    """Build a minimal fake SNP report of exactly 0x4A0 bytes.

    Write order: version, report_data (0x38, 64 bytes), measurement (0x60, 48 bytes).
    report_data ends at 0x78, measurement starts at 0x60 — they overlap at 0x60-0x78.
    Writing measurement last ensures it is not overwritten by report_data.
    """
    buf = bytearray(0x4A0)
    struct.pack_into("<I", buf, 0x00, version)
    if report_data:
        buf[0x38 : 0x38 + 64] = report_data
    if measurement_bytes:
        buf[0x60 : 0x60 + 48] = measurement_bytes
    return bytes(buf)


# ── Measurement string format ─────────────────────────────────────────────────


def test_valid_measurement_format_no_evidence():
    """Valid sha384:<96hex> with no raw evidence passes format check."""
    good = "sha384:" + "a" * 96
    result = verify_sev_snp_measurement(good, raw_evidence=None)
    assert result.verified is True
    assert result.failure_reason is None


def test_sha256_prefix_fails_format():
    bad = "sha256:" + "a" * 64
    result = verify_sev_snp_measurement(bad, raw_evidence=None)
    assert result.verified is False
    assert result.failure_reason == "invalid_measurement_format"


def test_short_hex_fails_format():
    """95-char hex part (one short) must fail."""
    bad = "sha384:" + "a" * 95
    result = verify_sev_snp_measurement(bad, raw_evidence=None)
    assert result.verified is False
    assert result.failure_reason == "invalid_measurement_format"


def test_long_hex_fails_format():
    """97-char hex part must also fail."""
    bad = "sha384:" + "a" * 97
    result = verify_sev_snp_measurement(bad, raw_evidence=None)
    assert result.verified is False
    assert result.failure_reason == "invalid_measurement_format"


# ── Report parsing ────────────────────────────────────────────────────────────


def test_version2_matching_measurement_verified():
    """Version 2 report with matching measurement is fully verified."""
    raw_m = b"\xab" * 48
    expected = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    report = make_snp_report(version=2, measurement_bytes=raw_m)
    result = verify_sev_snp_measurement(expected, raw_evidence=report)
    assert result.verified is True
    assert "measurement" in result.verified_fields
    assert result.details["snp_report_version"] == "2"


def test_version3_matching_measurement_verified():
    """Version 3 report is also accepted."""
    raw_m = b"\xcd" * 48
    expected = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    report = make_snp_report(version=3, measurement_bytes=raw_m)
    result = verify_sev_snp_measurement(expected, raw_evidence=report)
    assert result.verified is True
    assert "measurement" in result.verified_fields
    assert result.details["snp_report_version"] == "3"


def test_version5_report_fails():
    """Version 5 is not a valid SNP report version."""
    raw_m = b"\x00" * 48
    measurement = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    report = make_snp_report(version=5, measurement_bytes=raw_m)
    result = verify_sev_snp_measurement(measurement, raw_evidence=report)
    assert result.verified is False
    assert result.failure_reason == "invalid_snp_report_version"
    assert result.details["snp_report_version"] == "5"


def test_measurement_mismatch_fails():
    """Measurement field in report does not match claimed measurement."""
    raw_m = b"\x11" * 48
    wrong_measurement = "sha384:" + "0" * 96
    report = make_snp_report(version=2, measurement_bytes=raw_m)
    result = verify_sev_snp_measurement(wrong_measurement, raw_evidence=report)
    assert result.verified is False
    assert result.failure_reason == "measurement_mismatch"


# ── report_data (nonce) matching ──────────────────────────────────────────────


def test_report_data_match_adds_verified_field():
    """Matching report_data adds it to verified_fields.

    The SNP report_data field (0x38, 64 bytes) and measurement field (0x60, 48 bytes)
    overlap in bytes 0x60-0x77.  make_snp_report writes measurement last, so bytes
    0x60-0x77 in the buffer contain measurement_bytes, not the original nonce.
    We build the expected report_data by reading back what's actually in the buffer
    at offset 0x38 after both writes, so the comparison is consistent.
    """
    raw_m = b"\x77" * 48
    nonce_prefix = b"\x99" * 40  # bytes 0x38–0x5f (non-overlapping portion)
    # Build the report and read back the actual 64-byte report_data region
    report = make_snp_report(version=2, measurement_bytes=raw_m, report_data=nonce_prefix + b"\x00" * 24)
    actual_rd_in_report = report[0x38:0x38 + 64]
    measurement = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    result = verify_sev_snp_measurement(
        measurement, raw_evidence=report, report_data_hex=actual_rd_in_report.hex()
    )
    assert result.verified is True
    assert "report_data" in result.verified_fields


def test_report_data_mismatch_not_fatal():
    """Mismatched report_data is NOT fatal — verified stays True, field just absent."""
    raw_m = b"\x55" * 48
    # Use a 40-byte nonce prefix in the non-overlapping zone, then zeros
    nonce_prefix = b"\xaa" * 40
    report = make_snp_report(version=2, measurement_bytes=raw_m, report_data=nonce_prefix + b"\x00" * 24)
    measurement = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    wrong_report_data = b"\xbb" * 64
    result = verify_sev_snp_measurement(
        measurement, raw_evidence=report, report_data_hex=wrong_report_data.hex()
    )
    assert result.verified is True
    assert "report_data" not in result.verified_fields
    assert result.failure_reason is None


# ── Truncated / bad evidence ──────────────────────────────────────────────────


def test_truncated_report_is_parse_error():
    """A report shorter than 0x4A0 bytes must produce raw_evidence_parse_error."""
    raw_m = b"\x22" * 48
    measurement = "sha384:" + hashlib.sha384(raw_m).hexdigest()
    truncated = make_snp_report(version=2, measurement_bytes=raw_m)[:-100]
    result = verify_sev_snp_measurement(measurement, raw_evidence=truncated)
    assert result.verified is False
    assert result.failure_reason == "raw_evidence_parse_error"


def test_no_raw_evidence_hardware_unverified():
    """Without raw_evidence, measurement format is checked but nothing is hardware-verified."""
    good = "sha384:" + "f" * 96
    result = verify_sev_snp_measurement(good, raw_evidence=None)
    assert result.verified is True
    assert "measurement" not in result.verified_fields


# ── VCEK cert chain always unverified ────────────────────────────────────────


def test_vcek_cert_chain_always_unverified_no_evidence():
    good = "sha384:" + "e" * 96
    result = verify_sev_snp_measurement(good, raw_evidence=None)
    assert "vcek_cert_chain" in result.unverified_fields
    assert result.details["vcek_chain"] == "requires_amd_kds_lookup"


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
