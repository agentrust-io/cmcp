"""AMD SEV-SNP TEE provider — implements issue #89."""

from __future__ import annotations

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

# SNP attestation report is 0x4A0 (1184) bytes.
_SNP_REPORT_SIZE = 0x4A0

# Request structure: 96-byte user_data + 4-byte vmpl + 28-byte reserved = 128 bytes total
_SNP_REQ_USER_DATA_SIZE = 96
_SNP_REQ_SIZE = 128

# Response structure: 4-byte status + 4-byte report_size + 24-byte reserved + report
_SNP_RESP_HEADER_SIZE = 32
_SNP_RESP_SIZE = _SNP_RESP_HEADER_SIZE + _SNP_REPORT_SIZE

# Measurement field offset and size in SNP report
_SNP_MEASUREMENT_OFFSET = 0x60
_SNP_MEASUREMENT_END = 0x90  # 48 bytes = SHA-384


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

        # Place request into response buffer (ioctl arg is a combined req/resp struct)
        # The kernel driver takes a pointer to snp_guest_request_ioctl which contains
        # pointers; however the simplified /dev/sev-guest interface accepts the request
        # directly.  We use a single buffer of max(req, resp) size.
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

        # Measurement = SHA-384 of the measurement field within the SNP report
        measurement_bytes = raw_evidence[_SNP_MEASUREMENT_OFFSET:_SNP_MEASUREMENT_END]
        measurement = "sha384:" + hashlib.sha384(measurement_bytes).hexdigest()

        # HW-002: reject reports whose measurement doesn't match the expected binary hash.
        # This prevents replay of a valid attestation report for a different binary.
        if self._expected_measurement is not None:
            if not hmac.compare_digest(measurement, self._expected_measurement):
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
