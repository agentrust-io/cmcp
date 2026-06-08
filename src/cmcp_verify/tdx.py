"""Intel TDX attestation verification — implements issue #70."""
from __future__ import annotations

import hashlib
import urllib.request
from dataclasses import dataclass, field

_TDREPORT_MIN_SIZE = 1024

# MRTD field in TDREPORT_STRUCT (TD measurement, 48 bytes)
_MRTD_OFFSET = 0x90
_MRTD_END = 0xC0

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

    # Step 2: Parse TDREPORT if provided
    if raw_evidence is not None and len(raw_evidence) >= _TDREPORT_MIN_SIZE:
        try:
            mrtd_bytes = raw_evidence[_MRTD_OFFSET:_MRTD_END]
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

            # Check report_data if provided (nonce — mismatch is not fatal)
            if report_data_hex is not None:
                # REPORTDATA is at offset 0x08 in REPORTMACSTRUCT (first 256 bytes)
                # For a simple check: compare the first 64 bytes of REPORTDATA area
                # The exact offset varies by TDREPORT version; use a best-effort check
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

    elif raw_evidence is not None:
        # Truncated evidence
        result.verified = False
        result.failure_reason = "raw_evidence_parse_error"
        result.details["raw_evidence_size"] = str(len(raw_evidence))
        result.unverified_fields.extend(["dcap_quote_signature", "tcb_status"])
        result.details["dcap_chain"] = "requires_intel_dcap_service"
        return result

    # Step 3: DCAP collateral — network check
    if _check_dcap_reachable():
        result.details["dcap_qe_identity"] = "reachable"
        # Full Quote verification requires dcap-provider library — mark unverified
        result.unverified_fields.append("dcap_quote_signature")
        result.details["dcap_chain"] = "dcap_service_reachable_full_verification_not_implemented"
    else:
        result.unverified_fields.extend(["dcap_quote_signature", "tcb_status"])
        result.details["dcap_chain"] = "dcap_service_unreachable"
        result.details["dcap_endpoint"] = _DCAP_QE_IDENTITY_URL

    return result
