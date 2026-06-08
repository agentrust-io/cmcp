"""Tests for TDX and Opaque attestation verification stubs (issue #70)."""
from __future__ import annotations

import ctypes
import hashlib
from unittest.mock import MagicMock, patch

from cmcp_verify.opaque import verify_opaque_measurement
from cmcp_verify.tdx import _TdReport, verify_tdx_measurement

_MRTD_OFFSET  = _TdReport.mrtd.offset
_REPORT_SIZE  = ctypes.sizeof(_TdReport)


def test_tdreport_struct_size() -> None:
    assert ctypes.sizeof(_TdReport) == 1024


def test_tdreport_mrtd_offset() -> None:
    assert _TdReport.mrtd.offset == 0x90


def test_tdreport_round_trip() -> None:
    buf = bytearray(_REPORT_SIZE)
    pattern = bytes(range(48))
    buf[_MRTD_OFFSET : _MRTD_OFFSET + 48] = pattern
    report = _TdReport.from_buffer_copy(buf)
    assert bytes(report.mrtd) == pattern


def _make_tdreport(mrtd_bytes: bytes) -> bytes:
    buf = bytearray(_REPORT_SIZE)
    buf[_MRTD_OFFSET : _MRTD_OFFSET + 48] = mrtd_bytes[:48]
    return bytes(buf)


def test_tdx_invalid_measurement_format():
    result = verify_tdx_measurement("bad-format", None)
    assert not result.verified
    assert result.failure_reason == "invalid_measurement_format"
    assert "dcap_quote_signature" in result.unverified_fields


def test_tdx_invalid_measurement_hex_length():
    result = verify_tdx_measurement("sha384:" + "a" * 95, None)
    assert not result.verified
    assert result.failure_reason == "invalid_measurement_format"


def test_tdx_no_raw_evidence_no_dcap(monkeypatch):
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    measurement = "sha384:" + "b" * 96
    result = verify_tdx_measurement(measurement, None)
    assert result.verified
    assert "dcap_quote_signature" in result.unverified_fields
    assert result.details.get("dcap_chain") == "dcap_service_unreachable"


def test_tdx_no_raw_evidence_dcap_reachable(monkeypatch):
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: True)
    measurement = "sha384:" + "c" * 96
    result = verify_tdx_measurement(measurement, None)
    assert result.verified
    assert "dcap_quote_signature" in result.unverified_fields
    assert "reachable" in result.details.get("dcap_qe_identity", "")


def test_tdx_measurement_matches_mrtd(monkeypatch):
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    mrtd = b"\xAB" * 48
    expected = "sha384:" + hashlib.sha384(mrtd).hexdigest()
    report = _make_tdreport(mrtd)
    result = verify_tdx_measurement(expected, report)
    assert result.verified
    assert "measurement" in result.verified_fields


def test_tdx_measurement_mismatch(monkeypatch):
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    mrtd = b"\xAB" * 48
    report = _make_tdreport(mrtd)
    wrong_measurement = "sha384:" + "0" * 96
    result = verify_tdx_measurement(wrong_measurement, report)
    assert not result.verified
    assert result.failure_reason == "measurement_mismatch"


def test_tdx_truncated_evidence(monkeypatch):
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    result = verify_tdx_measurement("sha384:" + "a" * 96, b"\x00" * 100)
    assert not result.verified
    assert result.failure_reason == "raw_evidence_parse_error"


def test_opaque_no_endpoint_configured(monkeypatch):
    monkeypatch.delenv("CMCP_OPAQUE_ATTESTATION_ENDPOINT", raising=False)
    result = verify_opaque_measurement("sha384:" + "a" * 96, None)
    assert not result.verified
    assert result.failure_reason == "opaque_endpoint_not_configured"
    assert "opaque_managed_attestation" in result.unverified_fields


def test_opaque_no_raw_evidence(monkeypatch):
    monkeypatch.setenv("CMCP_OPAQUE_ATTESTATION_ENDPOINT", "https://attest.opaque.co/v1/verify")
    result = verify_opaque_measurement("sha384:" + "a" * 96, None)
    assert result.verified
    assert "opaque_managed_attestation" in result.unverified_fields
    assert "raw_evidence not provided" in result.details.get("hint", "")


def test_opaque_endpoint_returns_verified(monkeypatch):
    monkeypatch.delenv("CMCP_OPAQUE_ATTESTATION_ENDPOINT", raising=False)
    with patch("cmcp_verify.opaque.urllib.request.urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"verified": true}'
        mock_open.return_value = mock_resp

        result = verify_opaque_measurement(
            "sha384:" + "a" * 96,
            b"\x00" * 64,
            opaque_endpoint="https://attest.opaque.co/v1/verify",
        )

    assert result.verified
    assert "opaque_managed_attestation" in result.verified_fields


def test_opaque_endpoint_returns_unverified(monkeypatch):
    monkeypatch.delenv("CMCP_OPAQUE_ATTESTATION_ENDPOINT", raising=False)
    with patch("cmcp_verify.opaque.urllib.request.urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"verified": false, "failure_reason": "measurement_unknown"}'
        mock_open.return_value = mock_resp

        result = verify_opaque_measurement(
            "sha384:" + "a" * 96,
            b"\x00" * 64,
            opaque_endpoint="https://attest.opaque.co/v1/verify",
        )

    assert not result.verified
    assert result.failure_reason == "measurement_unknown"
    assert "opaque_managed_attestation" in result.unverified_fields


def test_opaque_network_error(monkeypatch):
    monkeypatch.delenv("CMCP_OPAQUE_ATTESTATION_ENDPOINT", raising=False)
    with patch("cmcp_verify.opaque.urllib.request.urlopen", side_effect=OSError("timeout")):
        result = verify_opaque_measurement(
            "sha384:" + "a" * 96,
            b"\x00" * 64,
            opaque_endpoint="https://attest.opaque.co/v1/verify",
        )

    assert result.verified
    assert "opaque_managed_attestation" in result.unverified_fields
    assert result.details.get("opaque_error") == "OSError"
