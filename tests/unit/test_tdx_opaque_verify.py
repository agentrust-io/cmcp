"""Tests for TDX and Opaque attestation verification stubs (issue #70)."""
from __future__ import annotations

import ctypes
import hashlib
from unittest.mock import MagicMock, patch

from cmcp_runtime.tee.tdreport import (
    MRTD_OFFSET,
    MRTD_SIZE,
    REPORT_DATA_OFFSET,
    REPORT_DATA_SIZE,
    TDREPORT_SIZE,
    TdReport,
)
from cmcp_verify.opaque import verify_opaque_measurement
from cmcp_verify.tdx import verify_tdx_measurement

_MRTD_OFFSET = MRTD_OFFSET
_REPORT_SIZE = TDREPORT_SIZE

# The offsets this code read MRTD and REPORTDATA from before issue #371.
_OLD_MRTD_OFFSET = 0x90
_OLD_REPORT_DATA_OFFSET = 0x08


def test_tdreport_struct_size() -> None:
    assert ctypes.sizeof(TdReport) == 1024


def test_tdreport_abi_offsets() -> None:
    """The two offsets issue #371 is about, pinned to the Intel TDX Module ABI.

    MRTD was read at 0x90 and REPORTDATA at 0x08. 0x90 is inside
    REPORTMACSTRUCT.report_data and 0x08 is inside its leading RESERVED block,
    so neither field was where the code looked for it.
    """
    assert MRTD_OFFSET == 0x210
    assert MRTD_SIZE == 48
    assert REPORT_DATA_OFFSET == 0x80
    assert REPORT_DATA_SIZE == 64


def test_mrtd_is_not_inside_report_data() -> None:
    """The defect stated structurally: the guest supplies report_data, so an
    MRTD read from inside it measures the caller's own nonce."""
    report_data = range(REPORT_DATA_OFFSET, REPORT_DATA_OFFSET + REPORT_DATA_SIZE)
    assert _OLD_MRTD_OFFSET in report_data
    assert MRTD_OFFSET not in report_data


def test_tdreport_round_trip() -> None:
    buf = bytearray(_REPORT_SIZE)
    pattern = bytes(range(48))
    buf[_MRTD_OFFSET : _MRTD_OFFSET + 48] = pattern
    report = TdReport.from_buffer_copy(buf)
    assert bytes(report.td_info.mrtd) == pattern


def _make_tdreport(mrtd_bytes: bytes, report_data: bytes = b"") -> bytes:
    buf = bytearray(_REPORT_SIZE)
    buf[_MRTD_OFFSET : _MRTD_OFFSET + MRTD_SIZE] = mrtd_bytes[:MRTD_SIZE]
    if report_data:
        padded = report_data[:REPORT_DATA_SIZE]
        padded = padded + bytes(REPORT_DATA_SIZE - len(padded))
        buf[REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + REPORT_DATA_SIZE] = padded
    return bytes(buf)


def _mrtd(fill: int = 0xAB) -> bytes:
    return bytes([fill]) * MRTD_SIZE


def _measurement_of(mrtd: bytes) -> str:
    return "sha384:" + hashlib.sha384(mrtd).hexdigest()


def test_tdx_invalid_measurement_format():
    result = verify_tdx_measurement("bad-format", None)
    assert not result.verified
    assert result.failure_reason == "invalid_measurement_format"
    assert "dcap_quote_signature" in result.unverified_fields


def test_tdx_invalid_measurement_hex_length():
    result = verify_tdx_measurement("sha384:" + "a" * 95, None)
    assert not result.verified
    assert result.failure_reason == "invalid_measurement_format"


def test_tdx_no_raw_evidence_fails_closed(monkeypatch):
    """A hardware-platform claim with no evidence must not verify."""
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    measurement = "sha384:" + "b" * 96
    result = verify_tdx_measurement(measurement, None)
    assert result.verified is False
    assert result.failure_reason == "no_raw_evidence"
    assert "dcap_quote_signature" in result.unverified_fields


def test_tdx_no_raw_evidence_fails_closed_even_with_dcap(monkeypatch):
    """DCAP reachability cannot substitute for missing evidence."""
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: True)
    measurement = "sha384:" + "c" * 96
    result = verify_tdx_measurement(measurement, None)
    assert result.verified is False
    assert result.failure_reason == "no_raw_evidence"


def test_tdx_measurement_matches_mrtd(monkeypatch):
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    mrtd = _mrtd()
    result = verify_tdx_measurement(_measurement_of(mrtd), _make_tdreport(mrtd))
    assert result.verified
    assert "measurement" in result.verified_fields


def test_tdx_measurement_mismatch(monkeypatch):
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    report = _make_tdreport(_mrtd())
    wrong_measurement = "sha384:" + "0" * 96
    result = verify_tdx_measurement(wrong_measurement, report)
    assert not result.verified
    assert result.failure_reason == "measurement_mismatch"


def test_tdx_truncated_evidence(monkeypatch):
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    result = verify_tdx_measurement("sha384:" + "a" * 96, bytes(100))
    assert not result.verified
    assert result.failure_reason == "raw_evidence_parse_error"


# ---------------------------------------------------------------------------
# report_data binding and MRTD placement (issue #371)
# ---------------------------------------------------------------------------


def test_tdx_report_data_match_is_recorded(monkeypatch):
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    mrtd = _mrtd()
    nonce = bytes(range(32))
    result = verify_tdx_measurement(
        _measurement_of(mrtd),
        _make_tdreport(mrtd, nonce),
        report_data_hex=nonce.hex(),
    )
    assert result.verified
    assert "report_data" in result.verified_fields


def test_tdx_report_data_mismatch_is_fatal(monkeypatch):
    """Issue #371: advisory was the bug. A report that does not carry the
    expected binding is not a report about this key or this request."""
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    mrtd = _mrtd()
    result = verify_tdx_measurement(
        _measurement_of(mrtd),
        _make_tdreport(mrtd, bytes(range(32))),
        report_data_hex=(bytes([0x99]) * 32).hex(),
    )
    assert result.verified is False
    assert result.failure_reason == "report_data_mismatch"
    assert "dcap_quote_signature" in result.unverified_fields


def test_tdx_report_data_is_read_from_the_abi_offset(monkeypatch):
    """The old code read 0x08, inside REPORTMACSTRUCT's leading RESERVED block.

    A report carrying the binding at 0x80 and zeros at 0x08 verifies now and
    would have failed then, which is the defect in a single case.
    """
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    mrtd = _mrtd()
    nonce = bytes([0x5A]) * REPORT_DATA_SIZE
    report = _make_tdreport(mrtd, nonce)
    old_window = report[_OLD_REPORT_DATA_OFFSET:_OLD_REPORT_DATA_OFFSET + 64]
    assert old_window != nonce
    assert report[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET + 64] == nonce
    result = verify_tdx_measurement(
        _measurement_of(mrtd), report, report_data_hex=nonce.hex()
    )
    assert result.verified
    assert "report_data" in result.verified_fields


def test_tdx_short_report_data_is_zero_padded(monkeypatch):
    """The guest writes a short nonce into a 64-byte field, so the trailing
    zeros are part of what the TD signed."""
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    mrtd = _mrtd()
    nonce = bytes([1, 2, 3, 4])
    result = verify_tdx_measurement(
        _measurement_of(mrtd),
        _make_tdreport(mrtd, nonce),
        report_data_hex=nonce.hex(),
    )
    assert result.verified
    assert "report_data" in result.verified_fields


def test_measurement_does_not_move_with_the_nonce(monkeypatch):
    """The MRTD half of #371, as a property rather than an offset assertion.

    Two attestations of the same TD differing only in the nonce must produce
    the same measurement. Reading MRTD at 0x90 made them differ, which is how
    a measurement stops being one.
    """
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    mrtd = _mrtd()
    expected = _measurement_of(mrtd)
    first_report = _make_tdreport(mrtd, bytes([0x11]) * REPORT_DATA_SIZE)
    second_report = _make_tdreport(mrtd, bytes([0x22]) * REPORT_DATA_SIZE)
    assert verify_tdx_measurement(expected, first_report).verified
    assert verify_tdx_measurement(expected, second_report).verified

    # The old offset really was nonce-controlled, so this is not hypothetical:
    # the two reports differ over exactly the bytes it used to read.
    window = slice(_OLD_MRTD_OFFSET, _OLD_MRTD_OFFSET + MRTD_SIZE)
    assert first_report[window] != second_report[window]


def test_opaque_no_endpoint_configured(monkeypatch):
    monkeypatch.delenv("CMCP_OPAQUE_ATTESTATION_ENDPOINT", raising=False)
    result = verify_opaque_measurement("sha384:" + "a" * 96, None)
    assert not result.verified
    assert result.failure_reason == "opaque_endpoint_not_configured"
    assert "opaque_managed_attestation" in result.unverified_fields


def test_opaque_no_raw_evidence_fails_closed(monkeypatch):
    monkeypatch.setenv("CMCP_OPAQUE_ATTESTATION_ENDPOINT", "https://attest.example.com/v1/verify")
    result = verify_opaque_measurement("sha384:" + "a" * 96, None)
    assert result.verified is False
    assert result.failure_reason == "no_raw_evidence"
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
            bytes(64),
            opaque_endpoint="https://attest.example.com/v1/verify",
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
            bytes(64),
            opaque_endpoint="https://attest.example.com/v1/verify",
        )

    assert not result.verified
    assert result.failure_reason == "measurement_unknown"
    assert "opaque_managed_attestation" in result.unverified_fields


def test_opaque_network_error(monkeypatch):
    monkeypatch.delenv("CMCP_OPAQUE_ATTESTATION_ENDPOINT", raising=False)
    with patch("cmcp_verify.opaque.urllib.request.urlopen", side_effect=OSError("timeout")):
        result = verify_opaque_measurement(
            "sha384:" + "a" * 96,
            bytes(64),
            opaque_endpoint="https://attest.example.com/v1/verify",
        )

    assert result.verified
    assert "opaque_managed_attestation" in result.unverified_fields
    assert result.details.get("opaque_error") == "OSError"
