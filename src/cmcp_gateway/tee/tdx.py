"""Intel TDX TEE provider — implements issue #93."""

from __future__ import annotations

import hashlib
import sys
from datetime import UTC, datetime
from pathlib import Path

from cmcp_gateway.tee.base import AttestationReport, TEEProvider

_TDX_GUEST_DEVICE = Path("/dev/tdx_guest")

# TDX_CMD_GET_REPORT0 ioctl: 0xC0884000
# Derived from: _IOWR(0x40, 0x00, struct tdx_report_req) where req is 0x88 bytes.
_TDX_CMD_GET_REPORT0 = 0xC0884000

# TDREPORT size: 1024 bytes
_TDREPORT_SIZE = 1024

# REPORTDATA input: 64 bytes (placed at start of ioctl buffer)
_REPORTDATA_SIZE = 64

# MRTD field in TDREPORT: bytes 0x90..0xC0 (48 bytes)
_MRTD_OFFSET = 0x90
_MRTD_END = 0xC0


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

        # Buffer layout: 64-byte REPORTDATA followed by 1024-byte TDREPORT output
        buf_size = _REPORTDATA_SIZE + _TDREPORT_SIZE
        buf = bytearray(buf_size)

        # Write nonce into REPORTDATA (truncate or pad to 64 bytes)
        report_data_bytes = (nonce[:_REPORTDATA_SIZE] + b"\x00" * _REPORTDATA_SIZE)[
            :_REPORTDATA_SIZE
        ]
        buf[:_REPORTDATA_SIZE] = report_data_bytes

        try:
            with open(_TDX_GUEST_DEVICE, "rb") as fd:
                fcntl.ioctl(fd, _TDX_CMD_GET_REPORT0, buf)
        except OSError as exc:
            raise RuntimeError(f"TDX attestation failed: {exc}") from exc

        # TDREPORT is in the second half of the buffer
        raw_evidence = bytes(buf[_REPORTDATA_SIZE : _REPORTDATA_SIZE + _TDREPORT_SIZE])

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
