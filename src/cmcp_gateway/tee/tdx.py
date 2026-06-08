"""Intel TDX TEE provider -- implements issue #93."""

from __future__ import annotations

import ctypes
import hashlib
import sys
from datetime import UTC, datetime
from pathlib import Path

from cmcp_gateway.tee.base import AttestationReport, TEEProvider

_TDX_GUEST_DEVICE = Path("/dev/tdx_guest")

# TDX_CMD_GET_REPORT0 ioctl: 0xC0884000
# Derived from: _IOWR(0x40, 0x00, struct tdx_report_req) where req is 0x88 bytes.
_TDX_CMD_GET_REPORT0 = 0xC0884000

# MRTD field in TDREPORT: bytes 0x90..0xC0 (48 bytes)
_MRTD_OFFSET = 0x90
_MRTD_END = 0xC0


class _TdxReportReq(ctypes.LittleEndianStructure):
    """Mirror of struct tdx_report_req from the Linux kernel
    (arch/x86/include/uapi/asm/tdx.h).  The ioctl buffer is exactly
    this struct: a 64-byte REPORTDATA field followed by a 1024-byte
    TDREPORT output field.  Using ctypes ensures the split point is
    derived from the struct layout rather than a bare integer offset.

    Total size: 0x440 (1088) bytes.
    """

    _pack_ = 1
    _fields_ = [
        # Input: 64-byte nonce written by the caller before the ioctl.
        ("reportdata", ctypes.c_uint8 * 64),
        # Output: 1024-byte TDREPORT filled by the kernel driver.
        ("tdreport",   ctypes.c_uint8 * 1024),
    ]


# Compile-time assertion: struct must be exactly 0x440 (1088) bytes.
assert ctypes.sizeof(_TdxReportReq) == 0x440, (
    f"_TdxReportReq size mismatch: "
    f"got {ctypes.sizeof(_TdxReportReq):#x}, expected 0x440"
)

_TDX_REQ_SIZE = ctypes.sizeof(_TdxReportReq)
# Derived size -- never a hardcoded integer.
_REPORTDATA_SIZE: int = _TdxReportReq.reportdata.size   # 64


class TDXProvider(TEEProvider):
    """Intel TDX attestation provider using the /dev/tdx_guest ioctl interface."""

    def provider_name(self) -> str:
        return "tdx"

    def detect(self) -> bool:
        """Return True if /dev/tdx_guest exists."""
        try:
            if sys.platform != "linux":
                return False
            return _TDX_GUEST_DEVICE.exists()
        except Exception:  # noqa: BLE001
            return False

    def get_attestation_report(self, nonce: bytes) -> AttestationReport:
        """
        Request a TDREPORT via the TDX_CMD_GET_REPORT0 ioctl.

        The nonce is placed in the REPORTDATA field (first 64 bytes, zero-padded).
        """
        try:
            import fcntl  # available on Linux only
        except ImportError as exc:
            raise RuntimeError(f"TDX attestation failed: {exc}") from exc

        # Build the ioctl buffer via the ctypes struct (HW-007).
        # Serialise to a bytearray via bytes(req) so the ioctl receives a mutable
        # buffer of the correct size with the nonce already written in.
        req = _TdxReportReq()
        report_data_bytes = (nonce[:_REPORTDATA_SIZE] + b"\x00" * _REPORTDATA_SIZE)[
            :_REPORTDATA_SIZE
        ]
        req.reportdata[:] = report_data_bytes
        buf = bytearray(bytes(req))

        try:
            with open(_TDX_GUEST_DEVICE, "rb") as fd:
                fcntl.ioctl(fd, _TDX_CMD_GET_REPORT0, buf)  # type: ignore[attr-defined]
        except OSError as exc:
            raise RuntimeError(f"TDX attestation failed: {exc}") from exc

        # Parse response back into struct for named field access
        resp = _TdxReportReq.from_buffer_copy(buf)
        raw_evidence = bytes(resp.tdreport)

        # MRTD field is the TD measurement equivalent
        mrtd_bytes = raw_evidence[_MRTD_OFFSET:_MRTD_END]
        measurement = "sha384:" + hashlib.sha384(mrtd_bytes).hexdigest()

        return AttestationReport(
            provider=self.provider_name(),
            measurement=measurement,
            report_data=nonce.hex(),
            raw_evidence=raw_evidence,
            attestation_generated_at=datetime.now(tz=UTC),
            attestation_validity_seconds=86400,
        )
