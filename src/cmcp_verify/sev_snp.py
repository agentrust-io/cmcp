"""AMD SEV-SNP attestation verification -- implements issue #67, hardened per #384."""
from __future__ import annotations

import ctypes
import hashlib
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, SHA384

# AMD signs report bytes [0, 0x2A0); the 512-byte signature field follows.
_SIGNED_BODY_LEN = 0x2A0
# sig_algo value for ECDSA P-384 with SHA-384 (AMD SEV-SNP ABI).
_SIG_ALGO_ECDSA_P384_SHA384 = 1


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


class _SNPChainError(Exception):
    """Raised when the VCEK certificate chain or report signature fails to verify."""


@dataclass
class SNPVerificationResult:
    verified: bool
    verified_fields: list[str] = field(default_factory=list)
    unverified_fields: list[str] = field(default_factory=list)
    failure_reason: str | None = None
    details: dict[str, str] = field(default_factory=dict)


def verify_cert_chain(
    chain: list[x509.Certificate], trusted_roots: list[x509.Certificate]
) -> None:
    """Verify a leaf-to-root certificate chain against a set of trusted roots.

    ``chain`` is ordered leaf first (VCEK), root last (ARK). Each certificate
    must be directly issued by the next, and the final certificate must match a
    trusted root by SHA-256 fingerprint. Raises ``_SNPChainError`` on any failure.
    """
    if not chain:
        raise _SNPChainError("empty certificate chain")

    for i in range(len(chain) - 1):
        child, issuer = chain[i], chain[i + 1]
        try:
            child.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise _SNPChainError(
                f"certificate at position {i} is not validly issued by the next: {exc}"
            ) from exc

    root = chain[-1]
    trusted = {c.fingerprint(SHA256()) for c in trusted_roots}
    if root.fingerprint(SHA256()) not in trusted:
        raise _SNPChainError("chain root is not a trusted AMD root")


def load_vcek_chain_from_evidence(pems: object) -> list[x509.Certificate] | None:
    """Parse a list of PEM-encoded certificates (leaf VCEK first, root ARK last).

    Returns None if ``pems`` is falsy or any entry fails to parse. The chain is
    caller-supplied evidence; its trust is established only by chaining to a
    configured trusted root in ``verify_cert_chain``.
    """
    if not pems or not isinstance(pems, (list, tuple)):
        return None
    try:
        return [
            x509.load_pem_x509_certificate(
                p.encode() if isinstance(p, str) else p
            )
            for p in pems
        ]
    except Exception:  # noqa: BLE001
        return None


def _verify_report_signature(
    raw_evidence: bytes, report: _SnpAttestationReport, vcek_cert: x509.Certificate
) -> None:
    """Verify the ECDSA-P384/SHA-384 report signature against the VCEK public key.

    Raises ``_SNPChainError`` on any failure.
    """
    if report.sig_algo != _SIG_ALGO_ECDSA_P384_SHA384:
        raise _SNPChainError(
            f"unsupported report signature algorithm: {report.sig_algo}"
        )
    pub = vcek_cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise _SNPChainError("VCEK does not carry an elliptic-curve public key")

    # AMD stores r and s as 72-byte little-endian fields; P-384 uses the low 48.
    sig = bytes(report.signature)
    r = int.from_bytes(sig[0:48], "little")
    s = int.from_bytes(sig[72:120], "little")
    der = encode_dss_signature(r, s)
    try:
        pub.verify(der, raw_evidence[:_SIGNED_BODY_LEN], ec.ECDSA(SHA384()))
    except InvalidSignature as exc:
        raise _SNPChainError("SEV-SNP report signature failed to verify") from exc


def verify_sev_snp_measurement(
    measurement: str,
    raw_evidence: bytes | None,
    report_data_hex: str | None = None,
    vcek_chain: list[x509.Certificate] | None = None,
    trusted_roots: list[x509.Certificate] | None = None,
) -> SNPVerificationResult:
    """
    Verify an AMD SEV-SNP attestation measurement.

    Checks:
    - measurement string format (sha384:<96 hex chars>)
    - SNP report version (must be 2 or 3)
    - measurement field in report matches the claimed measurement
    - report_data binding: if report_data_hex is provided, a mismatch is FATAL
      (it carries the confirmation-key binding / freshness nonce)
    - VCEK -> ASK -> ARK certificate chain and report signature: verified when a
      vcek_chain and trusted_roots are supplied. Trusted roots MUST come from the
      verifier configuration, never from the (untrusted) claim. When not supplied,
      vcek_cert_chain is left unverified and the report must not be treated as
      fully rooted (the dispatcher keeps such a claim at PARTIALLY_VERIFIED).
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

    # Step 2: raw evidence is mandatory - a claim asserting a hardware platform
    # with no evidence to check must fail closed, not pass on format alone.
    if raw_evidence is None:
        result.verified = False
        result.failure_reason = "no_raw_evidence"
        result.unverified_fields.extend(["measurement", "vcek_cert_chain"])
        result.details["raw_evidence"] = "not provided; SNP report cannot be checked"
        return result

    if len(raw_evidence) < _SNP_REPORT_MIN_SIZE:
        # Truncated report -- treat as parse error.
        result.verified = False
        result.failure_reason = "raw_evidence_parse_error"
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = "requires_amd_kds_lookup"
        return result

    # Parse via ctypes struct for named field access (HW-006).
    try:
        report = _SnpAttestationReport.from_buffer_copy(raw_evidence[:_SNP_REPORT_MIN_SIZE])
    except Exception:  # noqa: BLE001
        result.verified = False
        result.failure_reason = "raw_evidence_parse_error"
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = "requires_amd_kds_lookup"
        return result

    if report.version not in (2, 3):
        result.verified = False
        result.failure_reason = "invalid_snp_report_version"
        result.details["snp_report_version"] = str(report.version)
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = "requires_amd_kds_lookup"
        return result

    result.details["snp_report_version"] = str(report.version)

    # Verify measurement field using named struct access.
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

    # report_data binding -- a mismatch is FATAL. report_data carries the
    # confirmation-key binding / freshness nonce; silently ignoring a mismatch
    # would accept an SNP report for a different enclave whose measurement happens
    # to match.
    if report_data_hex is not None:
        extracted_rd = bytes(report.report_data)
        expected_rd = bytes.fromhex(report_data_hex[:128])
        if len(expected_rd) < 64:
            expected_rd = expected_rd + b"\x00" * (64 - len(expected_rd))
        if extracted_rd == expected_rd:
            result.verified_fields.append("report_data")
        else:
            result.verified = False
            result.failure_reason = "report_data_mismatch"
            result.unverified_fields.append("vcek_cert_chain")
            return result

    # VCEK -> ASK -> ARK chain + report signature. Trusted roots come from the
    # verifier configuration, never from the claim.
    if vcek_chain and trusted_roots:
        try:
            verify_cert_chain(vcek_chain, trusted_roots)
            _verify_report_signature(raw_evidence, report, vcek_chain[0])
        except _SNPChainError as exc:
            result.verified = False
            result.failure_reason = "vcek_chain_verification_failed"
            result.details["vcek_chain"] = str(exc)
            result.unverified_fields.append("vcek_cert_chain")
            return result
        result.verified_fields.extend(["vcek_cert_chain", "report_signature"])
    else:
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = (
            "not provided; supply vcek_chain and configure trusted AMD roots to verify"
        )

    return result
