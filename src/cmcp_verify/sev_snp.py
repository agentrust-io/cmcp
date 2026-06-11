"""AMD SEV-SNP attestation verification -- implements issue #67."""
from __future__ import annotations

import ctypes
import hashlib
from dataclasses import dataclass, field


class _SnpAttestationReport(ctypes.LittleEndianStructure):
    """Mirror of struct snp_attestation_report from the Linux kernel
    (include/uapi/linux/sev-guest.h).  Matches the layout defined in
    the gateway provider; kept in sync via the sizeof assertion below.

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


assert ctypes.sizeof(_SnpAttestationReport) == 0x4A0, (
    f"_SnpAttestationReport size mismatch: "
    f"got {ctypes.sizeof(_SnpAttestationReport):#x}, expected 0x4A0"
)

_SNP_REPORT_MIN_SIZE = ctypes.sizeof(_SnpAttestationReport)


@dataclass
class SNPVerificationResult:
    verified: bool
    verified_fields: list[str] = field(default_factory=list)
    unverified_fields: list[str] = field(default_factory=list)
    failure_reason: str | None = None
    details: dict[str, str] = field(default_factory=dict)


def verify_sev_snp_measurement(
    measurement: str,
    raw_evidence: bytes | None,
    report_data_hex: str | None = None,
) -> SNPVerificationResult:
    """
    Verify an AMD SEV-SNP attestation measurement.

    Checks:
    - measurement string format (sha384:<96 hex chars>)
    - SNP report version (must be 2 or 3)
    - measurement field in report matches the claimed measurement
    - report_data (nonce) if provided (mismatch is not fatal)

    Signature verification via AMD KDS VCEK/VLEK cert chain is out of scope
    and is always placed in unverified_fields.
    """
    result = SNPVerificationResult(verified=True)

    # Step 1: Format check
    if not measurement.startswith("sha384:"):
        result.verified = False
        result.failure_reason = "invalid_measurement_format"
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = "requires_amd_kds_lookup"
        return result

    hex_part = measurement[len("sha384:"):]
    if len(hex_part) != 96:
        result.verified = False
        result.failure_reason = "invalid_measurement_format"
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = "requires_amd_kds_lookup"
        return result

    # Step 2: raw evidence is mandatory — a claim asserting a hardware
    # platform with no evidence to check must fail closed, not pass on
    # string-format checks alone.
    if raw_evidence is None:
        result.verified = False
        result.failure_reason = "no_raw_evidence"
        result.unverified_fields.extend(["measurement", "vcek_cert_chain"])
        result.details["raw_evidence"] = "not provided; SNP report cannot be checked"
        return result

    if len(raw_evidence) >= _SNP_REPORT_MIN_SIZE:
        try:
            # Parse via ctypes struct for named field access (HW-006)
            report = _SnpAttestationReport.from_buffer_copy(raw_evidence[:_SNP_REPORT_MIN_SIZE])

            if report.version not in (2, 3):
                result.verified = False
                result.failure_reason = "invalid_snp_report_version"
                result.details["snp_report_version"] = str(report.version)
                result.unverified_fields.append("vcek_cert_chain")
                result.details["vcek_chain"] = "requires_amd_kds_lookup"
                return result

            result.details["snp_report_version"] = str(report.version)

            # Verify measurement field using named struct access
            m_bytes = bytes(report.measurement)
            computed = "sha384:" + hashlib.sha384(m_bytes).hexdigest()
            if computed == measurement:
                result.verified_fields.append("measurement")
            else:
                result.verified = False
                result.failure_reason = "measurement_mismatch"
                result.unverified_fields.append("vcek_cert_chain")
                result.details["vcek_chain"] = "requires_amd_kds_lookup"
                return result

            # Check report_data (nonce) using named struct access -- mismatch is not fatal
            if report_data_hex is not None:
                extracted_rd = bytes(report.report_data)
                expected_rd = bytes.fromhex(report_data_hex[:128])
                # Pad expected to 64 bytes if shorter
                if len(expected_rd) < 64:
                    expected_rd = expected_rd + b"\x00" * (64 - len(expected_rd))
                if extracted_rd == expected_rd:
                    result.verified_fields.append("report_data")

        except Exception:  # noqa: BLE001
            result.verified = False
            result.failure_reason = "raw_evidence_parse_error"
            result.unverified_fields.append("vcek_cert_chain")
            result.details["vcek_chain"] = "requires_amd_kds_lookup"
            return result

    else:
        # Truncated report -- treat as parse error
        result.verified = False
        result.failure_reason = "raw_evidence_parse_error"
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = "requires_amd_kds_lookup"
        return result

    # Step 3: VCEK/VLEK cert chain -- always out of scope
    result.unverified_fields.append("vcek_cert_chain")
    result.details["vcek_chain"] = "requires_amd_kds_lookup"

    return result
