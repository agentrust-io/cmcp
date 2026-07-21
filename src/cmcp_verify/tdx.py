"""Intel TDX attestation verification -- implements issue #70."""
from __future__ import annotations

import ctypes
import hashlib
import urllib.request
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256


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
        with urllib.request.urlopen(req, timeout=_DCAP_TIMEOUT_SECONDS) as resp:  # nosec B310 - req is a Request object with explicit HTTPS DCAP URL
            return resp.status == 200
    except Exception:  # noqa: BLE001
        return False


def verify_tdx_measurement(
    measurement: str,
    raw_evidence: bytes | None,
    report_data_hex: str | None = None,
    raw_quote: bytes | None = None,
    trusted_intel_root_pem: bytes | None = None,
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

    # Step 2: raw evidence is mandatory - a claim asserting a hardware
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

    # Step 3: DCAP quote verification (offline, fail-closed) when a full quote and a
    # pinned Intel SGX root are supplied. The PCK chain travels inside the quote, so
    # no network is needed at verify time. Otherwise fall back to a reachability note
    # and leave the quote signature unverified.
    if raw_quote is not None and trusted_intel_root_pem is not None:
        q = verify_tdx_quote(raw_quote, trusted_intel_root_pem, report_data_hex)
        result.verified_fields.extend(q.verified_fields)
        result.unverified_fields.extend(q.unverified_fields)
        result.details.update(q.details)
        if not q.verified:
            result.verified = False
            result.failure_reason = result.failure_reason or q.failure_reason
        return result

    if _check_dcap_reachable():
        result.details["dcap_qe_identity"] = "reachable"
        # Full Quote verification requires a quote + pinned root -- mark unverified
        result.unverified_fields.append("dcap_quote_signature")
        result.details["dcap_chain"] = "dcap_service_reachable_full_verification_not_implemented"
    else:
        result.unverified_fields.extend(["dcap_quote_signature", "tcb_status"])
        result.details["dcap_chain"] = "dcap_service_unreachable"
        result.details["dcap_endpoint"] = _DCAP_QE_IDENTITY_URL

    return result


# --- DCAP TD quote v4 verification (issue #370, TDX portion) ------------------
#
# Offline verification of an Intel TDX ECDSA (att_key_type=2) quote. No network at
# verify time: the PCK cert chain travels inside the quote's certification data and
# the Intel SGX Provisioning Certification Root is pinned by the caller.
#
# TD Quote v4 layout (Intel DCAP): 48-byte header, 584-byte TD report body, a
# uint32 signature-data length, then the signature data (quote signature 64B,
# ECDSA attestation key 64B, QE report 384B, QE report signature 64B, QE auth data,
# and certification data carrying the PCK chain). The offsets below are per the Intel
# TDX DCAP spec and MUST be confirmed against a real Azure TDX quote fixture
# (capture-tdx-azure.sh); the skipped hardware test asserts them, which also settles
# the report_data offset in issue #371.
_QUOTE_HEADER_LEN = 48
_TD_REPORT_BODY_LEN = 584
_SIGNED_REGION_LEN = _QUOTE_HEADER_LEN + _TD_REPORT_BODY_LEN  # 632
_TD_BODY_REPORT_DATA_OFF = 520   # report_data sits after the RTMRs in the TD body
_QE_REPORT_LEN = 384
_QE_REPORT_DATA_OFF = 320        # report_data offset within the SGX QE report
_ATT_KEY_TYPE_ECDSA_P256 = 2


def _raw_p256_sig_to_der(sig64: bytes) -> bytes:
    if len(sig64) != 64:
        raise ValueError(f"expected 64-byte raw ECDSA sig, got {len(sig64)}")
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    return encode_dss_signature(r, s)


def _p256_pubkey_from_raw(xy: bytes) -> ec.EllipticCurvePublicKey:
    if len(xy) != 64:
        raise ValueError(f"expected 64-byte raw P-256 pubkey, got {len(xy)}")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + xy)


def _verify_p256(pub: ec.EllipticCurvePublicKey, sig64: bytes, data: bytes) -> bool:
    try:
        pub.verify(_raw_p256_sig_to_der(sig64), data, ec.ECDSA(SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass
class _ParsedQuote:
    signed_region: bytes
    report_data: bytes
    quote_sig: bytes
    att_pubkey_raw: bytes
    qe_report: bytes
    qe_report_sig: bytes
    qe_auth_data: bytes
    pck_chain_pem: bytes


def parse_td_quote(quote: bytes) -> _ParsedQuote:
    """Parse an Intel TDX ECDSA v4 quote. Raises ValueError on malformed input.

    Offsets are per the Intel TDX DCAP spec; confirm against a real fixture.
    """
    if len(quote) < _SIGNED_REGION_LEN + 4:
        raise ValueError("quote too short for header + TD report body + sig length")
    att_key_type = int.from_bytes(quote[2:4], "little")
    if att_key_type != _ATT_KEY_TYPE_ECDSA_P256:
        raise ValueError(f"unsupported att_key_type {att_key_type} (expected ECDSA-P256)")
    signed_region = quote[:_SIGNED_REGION_LEN]
    body = quote[_QUOTE_HEADER_LEN:_SIGNED_REGION_LEN]
    report_data = body[_TD_BODY_REPORT_DATA_OFF:_TD_BODY_REPORT_DATA_OFF + 64]
    off = _SIGNED_REGION_LEN
    sig_len = int.from_bytes(quote[off:off + 4], "little")
    off += 4
    sig_data = quote[off:off + sig_len]
    if len(sig_data) < 64 + 64 + _QE_REPORT_LEN + 64 + 2:
        raise ValueError("signature data truncated")
    p = 0
    quote_sig = sig_data[p:p + 64]
    p += 64
    att_pubkey_raw = sig_data[p:p + 64]
    p += 64
    qe_report = sig_data[p:p + _QE_REPORT_LEN]
    p += _QE_REPORT_LEN
    qe_report_sig = sig_data[p:p + 64]
    p += 64
    qe_auth_len = int.from_bytes(sig_data[p:p + 2], "little")
    p += 2
    qe_auth_data = sig_data[p:p + qe_auth_len]
    p += qe_auth_len
    p += 2  # cert_data_type
    cert_size = int.from_bytes(sig_data[p:p + 4], "little")
    p += 4
    pck_chain_pem = sig_data[p:p + cert_size]
    return _ParsedQuote(signed_region, report_data, quote_sig, att_pubkey_raw,
                        qe_report, qe_report_sig, qe_auth_data, pck_chain_pem)


def verify_tdx_quote(
    quote: bytes,
    trusted_intel_root_pem: bytes,
    expected_report_data_hex: str | None = None,
) -> TDXVerificationResult:
    """Offline DCAP verification of a TDX ECDSA quote, fail-closed.

    Verifies: the quote signature over header+body by the attestation key; the
    attestation key is bound into the QE report_data; the QE report is signed by the
    PCK leaf; and the PCK chain verifies to the pinned Intel root. TCB status and QE
    identity need Intel PCS collateral by FMSPC and are NOT checked here; they stay
    in unverified_fields (do not treat this result as full TCB appraisal).
    """
    def fail(reason: str) -> TDXVerificationResult:
        return TDXVerificationResult(
            verified=False, failure_reason=reason,
            unverified_fields=["dcap_quote_signature", "tcb_status"])

    try:
        pq = parse_td_quote(quote)
    except ValueError as exc:
        return fail(f"quote_parse_error: {exc}")

    # 1) quote signature over header+body by the attestation key
    try:
        att_pub = _p256_pubkey_from_raw(pq.att_pubkey_raw)
    except ValueError as exc:
        return fail(f"attestation_key_invalid: {exc}")
    if not _verify_p256(att_pub, pq.quote_sig, pq.signed_region):
        return fail("quote_signature_invalid")

    # 2) attestation key bound into QE report_data[:32] = SHA256(att_key || qe_auth)
    qe_rd = pq.qe_report[_QE_REPORT_DATA_OFF:_QE_REPORT_DATA_OFF + 64]
    if qe_rd[:32] != hashlib.sha256(pq.att_pubkey_raw + pq.qe_auth_data).digest():
        return fail("attestation_key_not_bound_to_qe")

    # 3) QE report signed by the PCK leaf; 4) PCK chain to the pinned Intel root
    try:
        certs = x509.load_pem_x509_certificates(pq.pck_chain_pem)
    except ValueError as exc:
        return fail(f"pck_chain_parse_error: {exc}")
    if not certs:
        return fail("pck_chain_empty")
    pck_pub = certs[0].public_key()
    if not isinstance(pck_pub, ec.EllipticCurvePublicKey) or \
            not _verify_p256(pck_pub, pq.qe_report_sig, pq.qe_report):
        return fail("qe_report_signature_invalid")
    try:
        root = x509.load_pem_x509_certificate(trusted_intel_root_pem)
    except ValueError as exc:
        return fail(f"intel_root_parse_error: {exc}")
    # PCK chain (leaf..intermediates) up to the pinned Intel root, via the shared
    # generic cert-chain verifier (agent-manifest) instead of a local copy.
    from agent_manifest import verify_cert_chain

    try:
        verify_cert_chain([*certs, root], [root])
    except Exception:  # noqa: BLE001  (CertChainError etc. -> fail closed)
        return fail("pck_chain_invalid")

    result = TDXVerificationResult(verified=True)
    result.verified_fields.extend(["dcap_quote_signature", "pck_chain"])

    # optional: confirm report_data binds our expected value (nonce / cnf)
    if expected_report_data_hex is not None:
        exp = bytes.fromhex(expected_report_data_hex[:128]).ljust(64, b"\x00")
        if pq.report_data == exp:
            result.verified_fields.append("report_data")
        else:
            result.verified = False
            result.failure_reason = "report_data_mismatch"
            return result

    # TCB status / QE identity need Intel PCS collateral by FMSPC (not done offline).
    result.unverified_fields.append("tcb_status")
    result.details["tcb_status"] = "requires_intel_pcs_collateral_by_fmspc"
    return result
