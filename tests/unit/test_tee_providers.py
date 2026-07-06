"""Tests for TPM, SEV-SNP, TDX, and Opaque TEE provider stubs."""

from __future__ import annotations

import ctypes
import struct
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cmcp_runtime.errors import AttestationProviderNotImplemented
from cmcp_runtime.tee.opaque import OpaqueProvider
from cmcp_runtime.tee.sev_snp import SEVSNPProvider, _SnpAttestationReport
from cmcp_runtime.tee.tdx import TDXProvider, _TdxReportReq
from cmcp_runtime.tee.tpm import TPMProvider

# ── OpaqueProvider ─────────────────────────────────────────────────────────────

def test_opaque_detect_raises_not_implemented() -> None:
    with pytest.raises(AttestationProviderNotImplemented):
        OpaqueProvider().detect()


def test_opaque_get_report_raises_not_implemented() -> None:
    with pytest.raises(AttestationProviderNotImplemented):
        OpaqueProvider().get_attestation_report(b"\x00" * 32)


def test_opaque_provider_name() -> None:
    assert OpaqueProvider().provider_name() == "opaque"


# ── SEVSNPProvider struct layout (HW-006) ─────────────────────────────────────

def test_snp_struct_size() -> None:
    """_SnpAttestationReport must be exactly 0x4A0 bytes."""
    assert ctypes.sizeof(_SnpAttestationReport) == 0x4A0


def test_snp_struct_measurement_field_round_trip() -> None:
    """Write a known pattern at the struct-derived measurement offset,
    parse with from_buffer_copy, assert the named field reads it back."""
    buf = bytearray(ctypes.sizeof(_SnpAttestationReport))
    struct.pack_into("<I", buf, 0, 2)
    pattern = bytes(range(48))
    offset = _SnpAttestationReport.measurement.offset
    buf[offset : offset + 48] = pattern
    report = _SnpAttestationReport.from_buffer_copy(buf)
    assert bytes(report.measurement) == pattern


def test_snp_struct_host_data_field_round_trip() -> None:
    """Write a known pattern at the host_data offset; read back via named field."""
    buf = bytearray(ctypes.sizeof(_SnpAttestationReport))
    struct.pack_into("<I", buf, 0, 2)
    pattern = bytes(range(32))
    offset = _SnpAttestationReport.host_data.offset
    buf[offset : offset + 32] = pattern
    report = _SnpAttestationReport.from_buffer_copy(buf)
    assert bytes(report.host_data) == pattern


# ── SEVSNPProvider ─────────────────────────────────────────────────────────────

def test_sev_snp_detect_returns_false_on_non_linux() -> None:
    with patch.object(sys, "platform", "win32"), \
         patch.object(Path, "exists", return_value=False):
        assert SEVSNPProvider().detect() is False


def test_sev_snp_detect_returns_false_when_device_missing() -> None:
    with patch.object(sys, "platform", "linux"), \
         patch.object(Path, "exists", return_value=False):
        assert SEVSNPProvider().detect() is False


def test_sev_snp_detect_returns_true_when_device_present() -> None:
    with patch.object(sys, "platform", "linux"), \
         patch.object(Path, "exists", return_value=True):
        assert SEVSNPProvider().detect() is True


def test_sev_snp_provider_name() -> None:
    assert SEVSNPProvider().provider_name() == "sev-snp"


def test_sev_snp_get_report_raises_on_ioctl_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """ioctl raising OSError must surface as RuntimeError."""
    mock_fcntl = MagicMock()
    mock_fcntl.ioctl = MagicMock(side_effect=OSError("ioctl failed"))
    monkeypatch.setitem(sys.modules, "fcntl", mock_fcntl)

    mock_fd = MagicMock()
    mock_fd.__enter__ = MagicMock(return_value=mock_fd)
    mock_fd.__exit__ = MagicMock(return_value=False)

    with patch("builtins.open", return_value=mock_fd), pytest.raises(RuntimeError, match="SEV-SNP attestation failed"):
        SEVSNPProvider().get_attestation_report(b"\x00" * 32)


def test_sev_snp_get_report_raises_when_fcntl_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When fcntl is absent (non-Linux), get_attestation_report must raise RuntimeError."""
    monkeypatch.setitem(sys.modules, "fcntl", None)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="SEV-SNP attestation failed"):
        SEVSNPProvider().get_attestation_report(b"\x00" * 32)


# ── TDXProvider struct layout (HW-007) ────────────────────────────────────────

def test_tdx_req_struct_size() -> None:
    """_TdxReportReq must be exactly 0x440 bytes."""
    assert ctypes.sizeof(_TdxReportReq) == 0x440


def test_tdx_req_struct_reportdata_round_trip() -> None:
    """Write a nonce into the reportdata field; read it back via named access."""
    req = _TdxReportReq()
    nonce = bytes(range(64))
    req.reportdata[:] = nonce
    assert bytes(req.reportdata) == nonce


def test_tdx_req_struct_tdreport_round_trip() -> None:
    """Write a pattern at the tdreport offset in a bytearray,
    parse with from_buffer_copy, assert named field reads it back."""
    buf = bytearray(ctypes.sizeof(_TdxReportReq))
    pattern = b"\xab" * 1024
    offset = _TdxReportReq.tdreport.offset
    buf[offset : offset + 1024] = pattern
    req = _TdxReportReq.from_buffer_copy(buf)
    assert bytes(req.tdreport) == pattern


# ── TDXProvider ────────────────────────────────────────────────────────────────

def test_tdx_detect_returns_false_when_device_missing() -> None:
    with patch.object(Path, "exists", return_value=False):
        assert TDXProvider().detect() is False


def test_tdx_detect_returns_false_on_non_linux() -> None:
    with patch.object(sys, "platform", "darwin"), \
         patch.object(Path, "exists", return_value=False):
        assert TDXProvider().detect() is False


def test_tdx_detect_returns_true_when_device_present() -> None:
    with patch.object(sys, "platform", "linux"), \
         patch.object(Path, "exists", return_value=True):
        assert TDXProvider().detect() is True


def test_tdx_provider_name() -> None:
    assert TDXProvider().provider_name() == "tdx"


def test_tdx_get_report_raises_on_ioctl_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """ioctl raising OSError must surface as RuntimeError."""
    mock_fcntl = MagicMock()
    mock_fcntl.ioctl = MagicMock(side_effect=OSError("ioctl failed"))
    monkeypatch.setitem(sys.modules, "fcntl", mock_fcntl)

    mock_fd = MagicMock()
    mock_fd.__enter__ = MagicMock(return_value=mock_fd)
    mock_fd.__exit__ = MagicMock(return_value=False)

    with patch("builtins.open", return_value=mock_fd), pytest.raises(RuntimeError, match="TDX attestation failed"):
        TDXProvider().get_attestation_report(b"\x00" * 32)


# ── TPMProvider ────────────────────────────────────────────────────────────────

def test_tpm_detect_returns_false_when_no_device() -> None:
    with patch.object(sys, "platform", "linux"), \
         patch.object(Path, "exists", return_value=False):
        assert TPMProvider().detect() is False


def test_tpm_detect_returns_false_on_non_linux() -> None:
    with patch.object(sys, "platform", "win32"):
        assert TPMProvider().detect() is False


def test_tpm_provider_name() -> None:
    assert TPMProvider().provider_name() == "tpm"


def test_tpm_get_report_raises_when_no_tss2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cmcp_runtime.tee.tpm._TSS2_AVAILABLE", False)

    failed_result = MagicMock(spec=subprocess.CompletedProcess)
    failed_result.returncode = 1
    failed_result.stderr = "error: cannot open /dev/tpm0"
    failed_result.stdout = ""

    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=failed_result))

    with pytest.raises(RuntimeError, match="TPM device found but could not read PCRs"):
        TPMProvider().get_attestation_report(b"\x00" * 32)


def test_tpm_detect_does_not_raise_on_exception() -> None:
    with patch.object(Path, "exists", side_effect=PermissionError("no access")):
        assert TPMProvider().detect() is False


def test_tpm_sha1_fallback_subprocess_produces_software_only_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SHA-1 fallback via subprocess must downgrade provider to software-only."""
    monkeypatch.setattr("cmcp_runtime.tee.tpm._TSS2_AVAILABLE", False)

    sha256_fail = MagicMock(spec=subprocess.CompletedProcess)
    sha256_fail.returncode = 1
    sha256_fail.stderr = "algorithm not supported"
    sha256_fail.stdout = ""

    sha1_pcr_output = "\n".join(
        [
            "sha1:",
            *[f"  {i} : 0x" + ("ab" * 20) for i in range(8)],
        ]
    )
    sha1_ok = MagicMock(spec=subprocess.CompletedProcess)
    sha1_ok.returncode = 0
    sha1_ok.stderr = ""
    sha1_ok.stdout = sha1_pcr_output

    monkeypatch.setattr(subprocess, "run", MagicMock(side_effect=[sha256_fail, sha1_ok]))

    report = TPMProvider().get_attestation_report(b"\x00" * 32)

    assert report.provider == "software-only"
    assert report.measurement_note == "sha1-bank-fallback"
    assert report.measurement.startswith("sha256:")


def test_tpm_sha256_success_subprocess_keeps_tpm_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When SHA-256 PCR bank is available, provider must remain 'tpm'."""
    monkeypatch.setattr("cmcp_runtime.tee.tpm._TSS2_AVAILABLE", False)

    sha256_pcr_output = "\n".join(
        [
            "sha256:",
            *[f"  {i} : 0x" + ("cd" * 32) for i in range(8)],
        ]
    )
    sha256_ok = MagicMock(spec=subprocess.CompletedProcess)
    sha256_ok.returncode = 0
    sha256_ok.stderr = ""
    sha256_ok.stdout = sha256_pcr_output

    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=sha256_ok))

    report = TPMProvider().get_attestation_report(b"\x00" * 32)

    assert report.provider == "tpm"
    assert report.measurement_note is None
