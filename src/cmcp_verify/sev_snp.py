"""AMD SEV-SNP attestation verification -- implements issue #67.

Report-signature and VCEK cert-chain verification (issue #370) is implemented
below. Verifying that report_data binds our key (issue #67 / CRYPTO-001) is only
meaningful if the report itself is genuinely silicon-signed; otherwise a rogue
operator can forge a report that binds any key. This module therefore verifies:

  1. the SNP report ECDSA-P384/SHA-384 signature against the VCEK public key, and
  2. the VCEK -> ASK -> ARK certificate chain up to a caller-pinned AMD ARK.

No network access is performed at verify time: the VCEK/ASK/ARK chain is supplied
by the caller (loaded from the claim or a local fixture) and the trusted ARK is
pinned by the operator (AMD publishes it on the KDS).
"""
from __future__ import annotations

import ctypes
import hashlib
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA384

# The SNP report is signed over its leading bytes; the 512-byte signature field
# occupies the tail. sizeof(report) == 0x4A0, signature == 0x200, so the signed
# region is report[:0x2A0]. See AMD SEV-SNP ABI, Table "ATTESTATION_REPORT".
_SNP_SIG_OFFSET = 0x2A0
_SNP_SIGNED_LEN = 0x2A0
# sig_algo values (AMD SEV-SNP ABI). 1 == ECDSA P-384 with SHA-384.
_SIG_ALGO_ECDSA_P384_SHA384 = 1
# Within the 512-byte signature field, R and S are each stored as 72 little-endian
# bytes (P-384 components are 48 bytes; the upper 24 are zero padding).
_SNP_SIG_COMPONENT_LEN = 72
_P384_COMPONENT_LEN = 48


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


def _snp_report_signature_der(raw_report: bytes) -> bytes:
    """Extract the ECDSA-P384 signature from an SNP report and DER-encode it.

    R and S are stored as little-endian 72-byte fields; P-384 uses 48 bytes each.
    """
    sig_field = raw_report[_SNP_SIG_OFFSET : _SNP_SIG_OFFSET + 2 * _SNP_SIG_COMPONENT_LEN]
    r_le = sig_field[:_SNP_SIG_COMPONENT_LEN]
    s_le = sig_field[_SNP_SIG_COMPONENT_LEN : 2 * _SNP_SIG_COMPONENT_LEN]
    r = int.from_bytes(r_le[:_P384_COMPONENT_LEN], "little")
    s = int.from_bytes(s_le[:_P384_COMPONENT_LEN], "little")
    return encode_dss_signature(r, s)


def verify_snp_report_signature(
    raw_report: bytes, vcek_cert: x509.Certificate
) -> tuple[bool, str | None]:
    """Verify the SNP report is signed by the VCEK (ECDSA P-384 / SHA-384).

    Returns (True, None) on a valid signature, (False, reason) otherwise. Fails
    closed on any parse or verification error.
    """
    if len(raw_report) < _SNP_SIG_OFFSET + 2 * _SNP_SIG_COMPONENT_LEN:
        return False, "report too short to contain a signature"
    try:
        report = _SnpAttestationReport.from_buffer_copy(raw_report[:_SNP_REPORT_MIN_SIZE])
    except Exception:  # noqa: BLE001
        return False, "cannot parse SNP report"
    if report.sig_algo != _SIG_ALGO_ECDSA_P384_SHA384:
        return False, f"unsupported sig_algo {report.sig_algo} (expected ECDSA-P384/SHA-384)"

    pub = vcek_cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp384r1":
        return False, "VCEK public key is not EC P-384"

    signed_region = raw_report[:_SNP_SIGNED_LEN]
    try:
        der_sig = _snp_report_signature_der(raw_report)
        pub.verify(der_sig, signed_region, ec.ECDSA(SHA384()))
    except Exception:  # noqa: BLE001  (InvalidSignature and malformed r/s both fail closed)
        return False, "SNP report signature does not verify against the VCEK"
    return True, None


def _cert_signed_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """True iff `child` carries a valid signature from `issuer`'s public key.

    Handles both AMD's RSA-PSS cert signatures (ARK/ASK) and EC signatures by
    reading the signature parameters off the certificate, so we do not hand-roll
    fragile PSS parameters.
    """
    issuer_pub = issuer.public_key()
    try:
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            issuer_pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                child.signature_algorithm_parameters,
                child.signature_hash_algorithm,
            )
        elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except Exception:  # noqa: BLE001
        return False


def load_snp_cert_chain(
    pem_bundle: bytes,
) -> tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
    """Parse a PEM bundle into (vcek, ask, ark).

    VCEK is the EC leaf; among the RSA certs, the self-signed one is the ARK and
    the other is the ASK. Raises ValueError if the bundle is not a well-formed
    SNP chain.
    """
    certs = x509.load_pem_x509_certificates(pem_bundle)
    vcek = next(
        (c for c in certs if isinstance(c.public_key(), ec.EllipticCurvePublicKey)), None
    )
    rsa_certs = [c for c in certs if isinstance(c.public_key(), rsa.RSAPublicKey)]
    ark = next((c for c in rsa_certs if c.subject == c.issuer), None)
    ask = next((c for c in rsa_certs if c is not ark), None)
    if vcek is None or ask is None or ark is None:
        raise ValueError("bundle must contain a VCEK (EC), an ASK and a self-signed ARK (RSA)")
    return vcek, ask, ark


def verify_vcek_chain(
    vcek: x509.Certificate,
    ask: x509.Certificate,
    ark: x509.Certificate,
    trusted_ark: x509.Certificate,
) -> tuple[bool, str | None]:
    """Verify VCEK -> ASK -> ARK, with ARK pinned to a caller-trusted AMD root.

    Returns (True, None) or (False, reason). Fails closed.
    """
    if ark.fingerprint(SHA384()) != trusted_ark.fingerprint(SHA384()):
        return False, "chain ARK does not match the pinned trusted AMD ARK"
    if not _cert_signed_by(ark, ark):
        return False, "ARK is not validly self-signed"
    if not _cert_signed_by(ask, ark):
        return False, "ASK is not signed by the ARK"
    if not _cert_signed_by(vcek, ask):
        return False, "VCEK is not signed by the ASK"
    return True, None


def verify_sev_snp_measurement(
    measurement: str,
    raw_evidence: bytes | None,
    report_data_hex: str | None = None,
    cert_chain_pem: bytes | None = None,
    trusted_ark_pem: bytes | None = None,
) -> SNPVerificationResult:
    """
    Verify an AMD SEV-SNP attestation measurement.

    Checks:
    - measurement string format (sha384:<96 hex chars>)
    - SNP report version (must be 2 or 3)
    - measurement field in report matches the claimed measurement
    - report_data binding: if provided, a mismatch is FATAL (issue #371)

    When cert_chain_pem (a VCEK/ASK/ARK PEM bundle) and trusted_ark_pem (the
    operator-pinned AMD ARK) are both provided, the SNP report signature and the
    VCEK -> ASK -> ARK chain are verified and a failure is FATAL (fail closed).
    When the chain is not supplied, signature verification is reported as an
    unverified field rather than silently passing.
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

    # Step 2: raw evidence is mandatory - a claim asserting a hardware
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

            # Accept report version >= 2. The fields we read (report_data 0x50,
            # measurement 0x90, reported_tcb 0x180, chip_id 0x1a0, signature 0x2a0)
            # are layout-stable across v2..v5; later firmware only appends. Real
            # Milan hardware (GCP N2D) emits v5, which the old (2, 3) allowlist
            # wrongly rejected. The VCEK signature check below is the real gate.
            if report.version < 2:
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

            # Check report_data binding -- a mismatch is FATAL (issue #371).
            # report_data carries the confirmation-key binding / freshness nonce;
            # silently ignoring a mismatch would accept an SNP report for a
            # different enclave whose measurement happens to match.
            if report_data_hex is not None:
                extracted_rd = bytes(report.report_data)
                expected_rd = bytes.fromhex(report_data_hex[:128])
                # Pad expected to 64 bytes if shorter
                if len(expected_rd) < 64:
                    expected_rd = expected_rd + b"\x00" * (64 - len(expected_rd))
                if extracted_rd == expected_rd:
                    result.verified_fields.append("report_data")
                else:
                    result.verified = False
                    result.failure_reason = "report_data_mismatch"
                    result.unverified_fields.append("vcek_cert_chain")
                    return result

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

    # Step 3: VCEK/VLEK cert chain + report signature (issue #370).
    # Only meaningful when the caller supplies the cert chain and a pinned ARK;
    # otherwise report it as unverified rather than passing on measurement alone.
    if cert_chain_pem is None or trusted_ark_pem is None:
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = "cert chain and/or pinned ARK not supplied"
        return result

    try:
        vcek, ask, ark = load_snp_cert_chain(cert_chain_pem)
        trusted_arks = x509.load_pem_x509_certificates(trusted_ark_pem)
        trusted_ark = trusted_arks[0] if trusted_arks else None
        if trusted_ark is None:
            raise ValueError("trusted_ark_pem contained no certificate")
    except Exception as exc:  # noqa: BLE001
        result.verified = False
        result.failure_reason = "cert_chain_malformed"
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = f"could not parse cert chain / trusted ARK: {exc}"
        return result

    chain_ok, chain_reason = verify_vcek_chain(vcek, ask, ark, trusted_ark)
    if not chain_ok:
        result.verified = False
        result.failure_reason = "vcek_chain_invalid"
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = chain_reason or "VCEK chain verification failed"
        return result

    sig_ok, sig_reason = verify_snp_report_signature(raw_evidence, vcek)
    if not sig_ok:
        result.verified = False
        result.failure_reason = "report_signature_invalid"
        result.unverified_fields.append("report_signature")
        result.details["report_signature"] = sig_reason or "SNP report signature invalid"
        return result

    result.verified_fields.append("vcek_cert_chain")
    result.verified_fields.append("report_signature")
    return result
