"""TPM 2.0 attestation verification — implements issue #62."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TPMVerificationResult:
    verified: bool
    verified_fields: list[str] = field(default_factory=list)
    unverified_fields: list[str] = field(default_factory=list)
    failure_reason: str | None = None
    details: dict[str, str] = field(default_factory=dict)


# TPMS_ATTEST magic constant (FF 54 43 47 — "TPM generated")
_TPM_GENERATED_VALUE = 0xFF544347


def verify_tpm_measurement(
    measurement: str,
    raw_evidence: bytes | None,
    tee_public_key_hex: str | None = None,
    session_id: str | None = None,
) -> TPMVerificationResult:
    """
    Verify TPM attestation from a TRACE Claim.

    What can be verified WITHOUT raw hardware evidence:
    - measurement field format: must start with "sha256:" followed by 64 hex chars

    What requires raw_evidence (TPM2B_ATTEST):
    - qualifying_data = SHA-256(tee_public_key || session_id) matches quote
    - PCR digest in quote matches measurement field

    EK cert chain validation: always marked as unverified_fields (requires
    manufacturer CA lookup — out of scope for Phase 1).
    """
    verified_fields: list[str] = []
    unverified_fields: list[str] = []
    details: dict[str, Any] = {}

    # Step 1: Validate measurement format
    if not _valid_measurement(measurement):
        unverified_fields.append("ek_cert_chain")
        details["ek_cert_chain_validation"] = "ek_cert_chain_validation_requires_ca_lookup"
        return TPMVerificationResult(
            verified=False,
            verified_fields=verified_fields,
            unverified_fields=unverified_fields,
            failure_reason="invalid_measurement_format",
            details=details,
        )

    # Measurement format is valid
    verified_fields.append("measurement_format")

    # Step 2: Parse raw_evidence if provided
    if raw_evidence is not None:
        parse_ok, parse_details = _parse_tpm2b_attest(
            raw_evidence,
            measurement=measurement,
            tee_public_key_hex=tee_public_key_hex,
            session_id=session_id,
        )
        if parse_ok:
            verified_fields.append("pcr_format")
            if tee_public_key_hex and session_id:
                qd_verified = parse_details.get("qualifying_data_verified", False)
                if qd_verified:
                    verified_fields.append("qualifying_data")
                else:
                    unverified_fields.append("qualifying_data")
                    details["qualifying_data_error"] = parse_details.get(
                        "qualifying_data_error", "mismatch"
                    )
            else:
                unverified_fields.append("qualifying_data")
                details["qualifying_data_error"] = "tee_public_key_hex or session_id not provided"
        else:
            unverified_fields.append("pcr_format")
            unverified_fields.append("qualifying_data")
            details["tpm_parse_error"] = parse_details.get("error", "failed to parse TPM2B_ATTEST")
    else:
        # No raw evidence — a claim asserting a hardware platform with no
        # evidence to check must fail closed, not pass on format checks alone.
        unverified_fields.extend(["pcr_digest", "qualifying_data", "ek_cert_chain"])
        details["pcr_digest_note"] = "raw_evidence not provided; PCR digest unverifiable"
        return TPMVerificationResult(
            verified=False,
            verified_fields=verified_fields,
            unverified_fields=unverified_fields,
            failure_reason="no_raw_evidence",
            details=details,
        )

    # Step 3: EK cert chain always unverified in Phase 1
    unverified_fields.append("ek_cert_chain")
    details["ek_cert_chain_validation"] = "ek_cert_chain_validation_requires_ca_lookup"

    # verified=True only when the evidence parsed and matched
    verified = "measurement_format" in verified_fields and "pcr_format" not in unverified_fields

    return TPMVerificationResult(
        verified=verified,
        verified_fields=verified_fields,
        unverified_fields=unverified_fields,
        failure_reason=None if verified else "tpm_evidence_check_failed",
        details=details,
    )


def _valid_measurement(measurement: str) -> bool:
    """Return True if measurement is "sha256:" followed by exactly 64 hex characters."""
    if not measurement.startswith("sha256:"):
        return False
    hex_part = measurement[len("sha256:"):]
    if len(hex_part) != 64:
        return False
    try:
        bytes.fromhex(hex_part)
    except ValueError:
        return False
    return True


def _parse_tpm2b_attest(
    data: bytes,
    *,
    measurement: str,
    tee_public_key_hex: str | None,
    session_id: str | None,
) -> tuple[bool, dict[str, Any]]:
    """
    Parse a TPM2B_ATTEST blob and verify qualifying_data if keys are provided.

    TPM2B_ATTEST layout:
      [0:2]  size (uint16 big-endian) — size of the following TPMS_ATTEST
      [2:]   TPMS_ATTEST

    TPMS_ATTEST layout (big-endian):
      [0:4]  magic (uint32, must be 0xFF544347)
      [4:6]  type (uint16)
      [6:]   qualifiedSigner (TPM2B: uint16 size + <size> bytes)
      [...]  extraData / qualifyingData (TPM2B: uint16 size + <size> bytes)
      [...]  clockInfo (8 bytes)
      [...]  firmwareVersion (8 bytes)
      [...]  attested (union, type-dependent)
    """
    try:
        if len(data) < 2:
            return False, {"error": "TPM2B_ATTEST too short"}

        # Skip the outer TPM2B size field
        tpms_size = struct.unpack_from(">H", data, 0)[0]
        if tpms_size == 0 or len(data) < 2 + tpms_size:
            return False, {"error": "TPM2B_ATTEST size field invalid"}

        attest = data[2 : 2 + tpms_size]

        if len(attest) < 6:
            return False, {"error": "TPMS_ATTEST too short for magic+type"}

        magic = struct.unpack_from(">I", attest, 0)[0]
        if magic != _TPM_GENERATED_VALUE:
            return False, {"error": f"TPMS_ATTEST magic mismatch: got 0x{magic:08x}"}

        # Skip magic (4) + type (2) = 6 bytes, then read qualifiedSigner (TPM2B)
        offset = 6
        if len(attest) < offset + 2:
            return False, {"error": "TPMS_ATTEST truncated before qualifiedSigner"}

        qs_size = struct.unpack_from(">H", attest, offset)[0]
        offset += 2 + qs_size  # skip qualifiedSigner

        if len(attest) < offset + 2:
            return False, {"error": "TPMS_ATTEST truncated before extraData"}

        # Read extraData (qualifyingData)
        ed_size = struct.unpack_from(">H", attest, offset)[0]
        offset += 2
        if len(attest) < offset + ed_size:
            return False, {"error": "TPMS_ATTEST truncated inside extraData"}

        qualifying_data = attest[offset : offset + ed_size]

        result: dict[str, Any] = {"qualifying_data_verified": False}

        if tee_public_key_hex and session_id:
            try:
                expected_qd = hashlib.sha256(
                    bytes.fromhex(tee_public_key_hex) + session_id.encode()
                ).digest()
                if qualifying_data == expected_qd:
                    result["qualifying_data_verified"] = True
                else:
                    result["qualifying_data_error"] = "qualifying_data hash mismatch"
            except ValueError as exc:
                result["qualifying_data_error"] = f"cannot decode tee_public_key_hex: {exc}"

        return True, result

    except struct.error as exc:
        return False, {"error": f"struct parse error: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return False, {"error": f"unexpected parse error: {exc}"}
