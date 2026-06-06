"""AMD SEV-SNP attestation verification — implements issue #67."""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

_SNP_REPORT_MIN_SIZE = 0x4A0
_SNP_REPORT_DATA_OFFSET = 0x38
_SNP_MEASUREMENT_OFFSET = 0x60
_SNP_MEASUREMENT_SIZE = 48


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

    # Step 2: Parse raw_evidence if provided
    if raw_evidence is not None and len(raw_evidence) >= _SNP_REPORT_MIN_SIZE:
        try:
            version = struct.unpack_from("<I", raw_evidence, 0x00)[0]
            if version not in (2, 3):
                result.verified = False
                result.failure_reason = "invalid_snp_report_version"
                result.details["snp_report_version"] = str(version)
                result.unverified_fields.append("vcek_cert_chain")
                result.details["vcek_chain"] = "requires_amd_kds_lookup"
                return result

            result.details["snp_report_version"] = str(version)

            # Verify measurement field
            m_bytes = raw_evidence[_SNP_MEASUREMENT_OFFSET:_SNP_MEASUREMENT_OFFSET + _SNP_MEASUREMENT_SIZE]
            computed = "sha384:" + hashlib.sha384(m_bytes).hexdigest()
            if computed == measurement:
                result.verified_fields.append("measurement")
            else:
                result.verified = False
                result.failure_reason = "measurement_mismatch"
                result.unverified_fields.append("vcek_cert_chain")
                result.details["vcek_chain"] = "requires_amd_kds_lookup"
                return result

            # Check report_data (nonce) — mismatch is not fatal
            if report_data_hex is not None:
                extracted_rd = raw_evidence[_SNP_REPORT_DATA_OFFSET:_SNP_REPORT_DATA_OFFSET + 64]
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

    elif raw_evidence is not None and len(raw_evidence) < _SNP_REPORT_MIN_SIZE:
        # Truncated report — treat as parse error
        result.verified = False
        result.failure_reason = "raw_evidence_parse_error"
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = "requires_amd_kds_lookup"
        return result

    # Step 3: VCEK/VLEK cert chain — always out of scope
    result.unverified_fields.append("vcek_cert_chain")
    result.details["vcek_chain"] = "requires_amd_kds_lookup"

    return result
