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

import hashlib
from dataclasses import dataclass, field

from agent_manifest import (
    SIG_ALGO_ECDSA_P384_SHA384,
    SNP_REPORT_LEN,
    load_snp_cert_chain,
    parse_snp_report,
    verify_snp_signature,
)
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

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


@dataclass
class SNPVerificationResult:
    verified: bool
    verified_fields: list[str] = field(default_factory=list)
    unverified_fields: list[str] = field(default_factory=list)
    failure_reason: str | None = None
    details: dict[str, str] = field(default_factory=dict)


def verify_snp_report_signature(
    raw_report: bytes, vcek_cert: x509.Certificate
) -> tuple[bool, str | None]:
    """Verify the SNP report is signed by the VCEK (ECDSA P-384 / SHA-384).

    The cryptographic check is delegated to agent-manifest's shared verifier
    (`agent_manifest.verify_snp_signature`) so the org shares one implementation;
    the format pre-checks below keep cmcp's specific failure reasons. Returns
    (True, None) on a valid signature, (False, reason) otherwise. Fails closed.
    """
    if len(raw_report) < _SNP_SIG_OFFSET + 2 * _SNP_SIG_COMPONENT_LEN:
        return False, "report too short to contain a signature"
    try:
        report = parse_snp_report(raw_report)
    except Exception:  # noqa: BLE001
        return False, "cannot parse SNP report"
    if report.signature_algo != SIG_ALGO_ECDSA_P384_SHA384:
        return False, (
            f"unsupported sig_algo {report.signature_algo} (expected ECDSA-P384/SHA-384)"
        )

    pub = vcek_cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp384r1":
        return False, "VCEK public key is not EC P-384"

    try:
        ok = verify_snp_signature(report, vcek_cert.public_bytes(Encoding.DER))
    except Exception:  # noqa: BLE001  (fail closed on any parse/verify error)
        return False, "SNP report signature does not verify against the VCEK"
    if not ok:
        return False, "SNP report signature does not verify against the VCEK"
    return True, None


def verify_vcek_chain(
    vcek: x509.Certificate,
    ask: x509.Certificate,
    ark: x509.Certificate,
    trusted_ark: x509.Certificate,
) -> tuple[bool, str | None]:
    """Verify VCEK -> ASK -> ARK, with ARK pinned to a caller-trusted AMD root.

    Returns (True, None) or (False, reason). Fails closed. Delegates to
    agent-manifest's generic, algorithm-agnostic chain verifier (shared across
    the org) which honors each certificate's own signature algorithm and pins
    the root by fingerprint.
    """
    from agent_manifest import verify_cert_chain

    try:
        verify_cert_chain([vcek, ask, ark], [trusted_ark])
        return True, None
    except Exception as exc:  # noqa: BLE001  (CertChainError + any parse error → fail closed)
        return False, str(exc)


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

    if len(raw_evidence) >= SNP_REPORT_LEN:
        try:
            report = parse_snp_report(raw_evidence)

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
            m_bytes = report.measurement
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
                extracted_rd = report.report_data
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
