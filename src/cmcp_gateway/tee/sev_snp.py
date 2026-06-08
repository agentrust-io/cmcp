"""AMD SEV-SNP TEE provider -- implements issue #89."""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import struct
import sys
from datetime import UTC, datetime
from pathlib import Path

from cmcp_gateway.tee.base import AttestationReport, TEEProvider

_SEV_GUEST_DEVICE = Path("/dev/sev-guest")

# SNP_GET_REPORT ioctl number: 0xC0A01181
# Derived from: _IOWR(0x11, 0x01, struct snp_report_req) where req is 0xA0 bytes.
_SNP_GET_REPORT = 0xC0A01181

# Request structure: 96-byte user_data + 4-byte vmpl + 28-byte reserved = 128 bytes total
_SNP_REQ_USER_DATA_SIZE = 96
_SNP_REQ_SIZE = 128

# Response structure: 4-byte status + 4-byte report_size + 24-byte reserved + report
_SNP_RESP_HEADER_SIZE = 32


class _SnpAttestationReport(ctypes.LittleEndianStructure):
    """Mirror of struct snp_attestation_report from the Linux kernel
    (include/uapi/linux/sev-guest.h).  Field offsets are computed by
    ctypes so magic numeric offsets are never needed in application code.

    Total size: 0x4A0 (1184) bytes.
    """

    _pack_ = 1
    _fields_ = [
        ("version",             ctypes.c_uint32),
        ("guest_svn",           ctypes.c_uint32),
        ("policy",              ctypes.c_uint64),
        ("family_id",           ctypes.c_uint8 * 16),
        ("image_id",            ctypes.c_uint8 * 16),
        ("vmpl",                ctypes.c_uint32),
        ("sig_algo",            ctypes.c_uint32),
        ("current_tcb",         ctypes.c_uint64),
        ("plat_info",           ctypes.c_uint64),
        ("author_key_en",       ctypes.c_uint32),
        ("rsvd1",               ctypes.c_uint32),
        ("report_data",         ctypes.c_uint8 * 64),
        ("measurement",         ctypes.c_uint8 * 48),
        ("host_data",           ctypes.c_uint8 * 32),
        ("id_key_digest",       ctypes.c_uint8 * 48),
        ("author_key_digest",   ctypes.c_uint8 * 48),
        ("report_id",           ctypes.c_uint8 * 32),
        ("report_id_ma",        ctypes.c_uint8 * 32),
        ("reported_tcb",        ctypes.c_uint64),
        ("rsvd2",               ctypes.c_uint8 * 24),
        ("chip_id",             ctypes.c_uint8 * 64),
        ("committed_svn",       ctypes.c_uint8 * 8),
        ("committed_version",   ctypes.c_uint8 * 8),
        ("launch_svn",          ctypes.c_uint8 * 8),
        ("rsvd3",               ctypes.c_uint8 * 168),
        ("signature",           ctypes.c_uint8 * 512),
    ]


# Compile-time assertion: struct must be exactly 0x4A0 (1184) bytes.
assert ctypes.sizeof(_SnpAttestationReport) == 0x4A0, (
    f"_SnpAttestationReport size mismatch: "
    f"got {ctypes.sizeof(_SnpAttestationReport):#x}, expected 0x4A0"
)

_SNP_REPORT_SIZE = ctypes.sizeof(_SnpAttestationReport)
_SNP_RESP_SIZE = _SNP_RESP_HEADER_SIZE + _SNP_REPORT_SIZE

# Byte range of the measurement field within the raw SNP report blob.
# Derived from the ctypes struct so they stay in sync with the field layout.
_SNP_MEASUREMENT_OFFSET: int = _SnpAttestationReport.measurement.offset
_SNP_MEASUREMENT_END: int = _SNP_MEASUREMENT_OFFSET + _SnpAttestationReport.measurement.size


class SEVSNPProvider(TEEProvider):
    """AMD SEV-SNP attestation provider using the /dev/sev-guest ioctl interface."""

    def __init__(self, expected_measurement: str | None = None) -> None:
        self._expected_measurement = expected_measurement

    def provider_name(self) -> str:
        return "sev-snp"

    def detect(self) -> bool:
        """Return True if /dev/sev-guest exists (Linux only)."""
        try:
            if sys.platform != "linux":
                return False
            return _SEV_GUEST_DEVICE.exists()
        except Exception:  # noqa: BLE001
            return False

    def get_attestation_report(self, nonce: bytes) -> AttestationReport:
        """
        Request an SNP attestation report via the SNP_GET_REPORT ioctl.

        The nonce is placed in the 96-byte user_data field (first 64 bytes used,
        zero-padded to 96).
        """
        try:
            import fcntl  # available on Linux only
        except ImportError as exc:
            raise RuntimeError(f"SEV-SNP attestation failed: {exc}") from exc

        # Build request: 96-byte user_data (nonce truncated/padded) + vmpl=0 + reserved
        user_data = (nonce[:64] + b"\x00" * 96)[:96]
        vmpl = 0
        # struct: 96s user_data, I vmpl, 28s reserved
        req = struct.pack("96sI28s", user_data, vmpl, b"\x00" * 28)

        buf = bytearray(max(len(req), _SNP_RESP_SIZE))
        buf[: len(req)] = req

        try:
            with open(_SEV_GUEST_DEVICE, "rb") as fd:
                fcntl.ioctl(fd, _SNP_GET_REPORT, buf)  # type: ignore[attr-defined]
        except OSError as exc:
            raise RuntimeError(f"SEV-SNP attestation failed: {exc}") from exc

        # Extract status (first 4 bytes)
        status = struct.unpack_from("<I", buf, 0)[0]
        if status != 0:
            raise RuntimeError(f"SEV-SNP attestation failed: ioctl status={status:#x}")

        # Report starts at offset _SNP_RESP_HEADER_SIZE
        raw_evidence = bytes(buf[_SNP_RESP_HEADER_SIZE : _SNP_RESP_HEADER_SIZE + _SNP_REPORT_SIZE])

        # Parse report via ctypes struct for named field access (HW-006)
        report = _SnpAttestationReport.from_buffer_copy(raw_evidence)

        # Measurement = SHA-384 of the measurement field within the SNP report
        measurement_bytes = bytes(report.measurement)
        measurement = "sha384:" + hashlib.sha384(measurement_bytes).hexdigest()

        # HW-002: reject reports whose measurement does not match the expected binary hash.
        if self._expected_measurement is not None and not hmac.compare_digest(measurement, self._expected_measurement):
            raise RuntimeError(
                "SEV-SNP measurement mismatch: the report measurement does not match "
                "attestation.expected_measurement from config. "
                "This report may be replayed from a different binary or build."
            )

        return AttestationReport(
            provider=self.provider_name(),
            measurement=measurement,
            report_data=nonce.hex(),
            raw_evidence=raw_evidence,
            attestation_generated_at=datetime.now(tz=UTC),
            attestation_validity_seconds=86400,
        )
