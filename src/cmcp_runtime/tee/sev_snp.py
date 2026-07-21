"""AMD SEV-SNP TEE provider -- implements issue #89.

Uses the kernel configfs-TSM interface (`/sys/kernel/config/tsm/report`,
Linux 6.7+) to obtain the SNP attestation report. This supersedes the earlier
`/dev/sev-guest` ioctl path, which used an incorrect ioctl number and an inline
request ABI and failed on real hardware with ENOTTY ("inappropriate ioctl for
device"); the live kernel ABI passes pointers to separate request/response
structs. The configfs-TSM interface was hardware-validated on a real
non-paravisor SEV-SNP guest (GCP N2D, AMD Milan): the guest-supplied nonce lands
in the report's REPORT_DATA field and the report verifies against the AMD VCEK.
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import hmac
import sys
from datetime import UTC, datetime
from pathlib import Path

from cmcp_runtime.tee.base import AttestationReport, TEEProvider

_SEV_GUEST_DEVICE = Path("/dev/sev-guest")

# Kernel configfs-TSM report interface (Linux 6.7+). A caller writes up to 64
# bytes of report data to `inblob` and reads the raw platform report back from
# `outblob`; `provider` names the backend (expected "sev_guest" here).
_TSM_REPORT_DIR = Path("/sys/kernel/config/tsm/report")
_TSM_ENTRY = "cmcp"


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


def _tsm_get_report(report_data: bytes) -> bytes:
    """Fetch a raw SNP attestation report via the configfs-TSM interface.

    Writes *report_data* (<=64 bytes) to a fresh report entry's ``inblob`` and
    reads the raw report from ``outblob``. Requires root (configfs) and a
    registered ``sev_guest`` TSM provider. Returns the raw report bytes.
    """
    if not _TSM_REPORT_DIR.is_dir():
        raise RuntimeError(
            f"SEV-SNP attestation failed: configfs-TSM interface not present at "
            f"{_TSM_REPORT_DIR} (needs Linux 6.7+ with the sev-guest driver loaded)."
        )
    entry = _TSM_REPORT_DIR / _TSM_ENTRY
    try:
        entry.mkdir(exist_ok=True)
    except OSError as exc:
        raise RuntimeError(
            f"SEV-SNP attestation failed: cannot create TSM report entry {entry}: {exc} "
            "(no TSM provider registered, or not root)."
        ) from exc
    try:
        (entry / "inblob").write_bytes(report_data)
        provider = (entry / "provider").read_text().strip()
        if provider and provider != "sev_guest":
            raise RuntimeError(
                f"SEV-SNP attestation failed: TSM provider is {provider!r}, not 'sev_guest'."
            )
        outblob = (entry / "outblob").read_bytes()
    finally:
        with contextlib.suppress(OSError):
            entry.rmdir()
    if len(outblob) < _SNP_REPORT_SIZE:
        raise RuntimeError(
            f"SEV-SNP attestation failed: TSM outblob too short ({len(outblob)} bytes)."
        )
    return outblob[:_SNP_REPORT_SIZE]


class SEVSNPProvider(TEEProvider):
    """AMD SEV-SNP attestation provider using the kernel configfs-TSM interface."""

    def __init__(self, expected_measurement: str | None = None) -> None:
        self._expected_measurement = expected_measurement

    def provider_name(self) -> str:
        return "sev-snp"

    def detect(self) -> bool:
        """Return True only on a genuine Linux SEV-SNP guest.

        Gate on the /dev/sev-guest device, which the sev-guest driver creates on
        a real SNP guest (and which also registers the configfs-TSM provider used
        for acquisition). The configfs-TSM report *directory* alone is NOT a valid
        signal: it exists whenever tsm.ko is loaded (e.g. on ordinary CI runners)
        with no provider registered, which would wrongly select this provider.
        """
        try:
            if sys.platform != "linux":
                return False
            return _SEV_GUEST_DEVICE.exists()
        except Exception:  # noqa: BLE001
            return False

    def get_attestation_report(self, nonce: bytes) -> AttestationReport:
        """
        Request an SNP attestation report via configfs-TSM.

        The nonce is placed in the guest-controlled REPORT_DATA field (up to 64
        bytes). On a genuine SNP guest the hardware signs it into the report, so
        a verifier can bind the report to this nonce.
        """
        report_data = (nonce[:64] + b"\x00" * 64)[:64]
        raw_evidence = _tsm_get_report(report_data)

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


# Retained for callers/tests that referenced the module-level constant.
_SNP_MEASUREMENT_OFFSET: int = _SnpAttestationReport.measurement.offset
_SNP_MEASUREMENT_END: int = _SNP_MEASUREMENT_OFFSET + _SnpAttestationReport.measurement.size
