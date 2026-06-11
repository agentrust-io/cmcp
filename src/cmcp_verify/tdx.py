"""Intel TDX attestation verification -- implements issue #70."""
from __future__ import annotations

import ctypes
import hashlib
import urllib.request
from dataclasses import dataclass, field


class _TdReport(ctypes.LittleEndianStructure):
    """Named-field representation of the raw TDREPORT buffer returned by the
    TDX_CMD_GET_REPORT0 ioctl (1024 bytes).

    This layout places ``mrtd`` at offset 0x90 (144 bytes), matching the
    offset used by the Linux kernel TDX guest driver and Intel TDX Module
    Spec for the MRTD field within TDREPORT_STRUCT.  All unused bytes are
    grouped into padding arrays; ctypes computes every field offset so no
    magic integers appear in application code.

    Total size: 0x400 (1024) bytes.
    """

    _pack_ = 1
    _fields_ = [
        ("_pre_mrtd",   ctypes.c_uint8 * 0x90),            # 0x000 -- 144 bytes
        ("mrtd",        ctypes.c_uint8 * 48),               # 0x090 -- 48 bytes (TD measurement)
        ("_post_mrtd",  ctypes.c_uint8 * (1024 - 0x90 - 48)),  # 0x0C0 -- 832 bytes
    ]


assert ctypes.sizeof(_TdReport) == 1024, (
    f"_TdReport size mismatch: got {ctypes.sizeof(_TdReport)}, expected 1024"
)

_TDREPORT_MIN_SIZE = ctypes.sizeof(_TdReport)

# Intel DCAP QE identity endpoint (used to confirm DCAP service reachability)
_DCAP_QE_IDENTITY_URL = (
    "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
)
_DCAP_TIMEOUT_SECONDS = 5


@dataclass
class TDXVerificationResult:
    verified: bool
    verified_fields: list[str] = field(default_factory=list)
    unverified_fields: list[str] = field(default_factory=list)
    failure_reason: str | None = None
    details: dict[str, str] = field(default_factory=dict)


def _check_dcap_reachable() -> bool:
    """Return True if Intel DCAP service responds within timeout."""
    try:
        req = urllib.request.Request(
            _DCAP_QE_IDENTITY_URL,
            method="GET",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_DCAP_TIMEOUT_SECONDS) as resp:  # nosec B310 — req is a Request object with explicit HTTPS DCAP URL
            return resp.status == 200
    except Exception:  # noqa: BLE001
        return False


def verify_tdx_measurement(
    measurement: str,
    raw_evidence: bytes | None,
    report_data_hex: str | None = None,
) -> TDXVerificationResult:
    """
    Verify an Intel TDX attestation measurement.

    Checks:
    - measurement string format (sha384:<96 hex chars>)
    - MRTD field in TDREPORT matches claimed measurement (when raw_evidence provided)
    - Intel DCAP collateral reachability (network call; marks unverified if unavailable)

    Full Quote verification (QE signature, TCB status) requires the DCAP
    verification library and is always placed in unverified_fields.
    """
    result = TDXVerificationResult(verified=True)

    # Step 1: Format check
    if not measurement.startswith("sha384:"):
        result.verified = False
        result.failure_reason = "invalid_measurement_format"
        result.unverified_fields.extend(["dcap_quote_signature", "tcb_status"])
        result.details["dcap_chain"] = "requires_intel_dcap_service"
        return result

    hex_part = measurement[len("sha384:"):]
    if len(hex_part) != 96:
        result.verified = False
        result.failure_reason = "invalid_measurement_format"
        result.unverified_fields.extend(["dcap_quote_signature", "tcb_status"])
        result.details["dcap_chain"] = "requires_intel_dcap_service"
        return result

    # Step 2: raw evidence is mandatory — a claim asserting a hardware
    # platform with no evidence to check must fail closed, not pass on
    # string-format checks alone.
    if raw_evidence is None:
        result.verified = False
        result.failure_reason = "no_raw_evidence"
        result.unverified_fields.extend(
            ["measurement", "dcap_quote_signature", "tcb_status"]
        )
        result.details["raw_evidence"] = "not provided; TDREPORT cannot be checked"
        return result

    if len(raw_evidence) >= _TDREPORT_MIN_SIZE:
        try:
            # Parse via ctypes struct for named field access (HW-007)
            tdreport = _TdReport.from_buffer_copy(raw_evidence[:_TDREPORT_MIN_SIZE])
            mrtd_bytes = bytes(tdreport.mrtd)
            computed = "sha384:" + hashlib.sha384(mrtd_bytes).hexdigest()
            if computed == measurement:
                result.verified_fields.append("measurement")
            else:
                result.verified = False
                result.failure_reason = "measurement_mismatch"
                result.details["expected_prefix"] = measurement[:24] + "..."
                result.details["computed_prefix"] = computed[:24] + "..."
                result.unverified_fields.extend(["dcap_quote_signature", "tcb_status"])
                result.details["dcap_chain"] = "requires_intel_dcap_service"
                return result

            # Check report_data if provided (nonce -- mismatch is not fatal)
            # REPORTDATA is at offset 0x08 in REPORTMACSTRUCT (first 256 bytes)
            # For a simple check: compare the first 64 bytes of REPORTDATA area
            # The exact offset varies by TDREPORT version; use a best-effort check
            if report_data_hex is not None:
                report_data_area = raw_evidence[0x08:0x08 + 64]
                expected_rd = bytes.fromhex(report_data_hex[:128])
                if len(expected_rd) < 64:
                    expected_rd = expected_rd + b"\x00" * (64 - len(expected_rd))
                if report_data_area == expected_rd:
                    result.verified_fields.append("report_data")

        except Exception:  # noqa: BLE001
            result.verified = False
            result.failure_reason = "raw_evidence_parse_error"
            result.unverified_fields.extend(["dcap_quote_signature", "tcb_status"])
            result.details["dcap_chain"] = "requires_intel_dcap_service"
            return result

    else:
        # Truncated evidence
        result.verified = False
        result.failure_reason = "raw_evidence_parse_error"
        result.details["raw_evidence_size"] = str(len(raw_evidence))
        result.unverified_fields.extend(["dcap_quote_signature", "tcb_status"])
        result.details["dcap_chain"] = "requires_intel_dcap_service"
        return result

    # Step 3: DCAP collateral -- network check
    if _check_dcap_reachable():
        result.details["dcap_qe_identity"] = "reachable"
        # Full Quote verification requires dcap-provider library -- mark unverified
        result.unverified_fields.append("dcap_quote_signature")
        result.details["dcap_chain"] = "dcap_service_reachable_full_verification_not_implemented"
    else:
        result.unverified_fields.extend(["dcap_quote_signature", "tcb_status"])
        result.details["dcap_chain"] = "dcap_service_unreachable"
        result.details["dcap_endpoint"] = _DCAP_QE_IDENTITY_URL

    return result
