"""Report-signature + VCEK-chain verification for SEV-SNP (issue #370).

These tests exercise the verification LOGIC against a locally generated,
synthetic ARK -> ASK -> VCEK chain and a report signed by the synthetic VCEK
key. They are not real attestations; they prove the verifier accepts a
well-formed chain+signature and fails closed on tampering or a wrong root.

A test against a genuine Azure SEV-SNP report and the real AMD KDS VCEK chain is
marked skipped below and unblocks when that hardware fixture lands.
"""
from __future__ import annotations

import ctypes
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from cmcp_verify.sev_snp import (
    _SNP_SIG_OFFSET,
    _SnpAttestationReport,
    verify_sev_snp_measurement,
    verify_snp_report_signature,
)

_SIG_ALGO_OFFSET = _SnpAttestationReport.sig_algo.offset
_MEAS_OFFSET = _SnpAttestationReport.measurement.offset
_RD_OFFSET = _SnpAttestationReport.report_data.offset
_REPORT_SIZE = ctypes.sizeof(_SnpAttestationReport)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer_name, subject_pub, issuer_key):
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(subject_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(issuer_key, hashes.SHA384())
    )


def _synthetic_chain():
    """Return (chain_pem, ark_pem, vcek_key) mirroring AMD's RSA ARK/ASK + EC VCEK."""
    ark_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ask_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    ark = _cert(_name("ARK"), _name("ARK"), ark_key.public_key(), ark_key)  # self-signed
    ask = _cert(_name("ASK"), _name("ARK"), ask_key.public_key(), ark_key)
    vcek = _cert(_name("VCEK"), _name("ASK"), vcek_key.public_key(), ask_key)
    chain_pem = (
        vcek.public_bytes(Encoding.PEM)
        + ask.public_bytes(Encoding.PEM)
        + ark.public_bytes(Encoding.PEM)
    )
    return chain_pem, ark.public_bytes(Encoding.PEM), vcek_key


def _signed_report(vcek_key, *, measurement_bytes: bytes, report_data: bytes) -> tuple[bytes, str]:
    buf = bytearray(_REPORT_SIZE)
    buf[0x00:0x04] = (2).to_bytes(4, "little")  # version = 2
    buf[_SIG_ALGO_OFFSET : _SIG_ALGO_OFFSET + 4] = (1).to_bytes(4, "little")  # ECDSA-P384/SHA384
    buf[_MEAS_OFFSET : _MEAS_OFFSET + 48] = measurement_bytes[:48]
    buf[_RD_OFFSET : _RD_OFFSET + 64] = report_data[:64]
    signed_region = bytes(buf[:_SNP_SIG_OFFSET])
    der = vcek_key.sign(signed_region, ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(der)
    buf[_SNP_SIG_OFFSET : _SNP_SIG_OFFSET + 48] = r.to_bytes(48, "little")
    buf[_SNP_SIG_OFFSET + 72 : _SNP_SIG_OFFSET + 72 + 48] = s.to_bytes(48, "little")
    measurement = "sha384:" + hashlib.sha384(measurement_bytes[:48]).hexdigest()
    return bytes(buf), measurement


def test_valid_chain_and_signature_verifies() -> None:
    chain_pem, ark_pem, vcek_key = _synthetic_chain()
    report, measurement = _signed_report(vcek_key, measurement_bytes=b"\x11" * 48, report_data=b"\x00" * 64)
    res = verify_sev_snp_measurement(
        measurement=measurement,
        raw_evidence=report,
        cert_chain_pem=chain_pem,
        trusted_ark_pem=ark_pem,
    )
    assert res.verified is True, res.failure_reason
    assert "vcek_cert_chain" in res.verified_fields
    assert "report_signature" in res.verified_fields


def test_tampered_report_fails_closed() -> None:
    chain_pem, ark_pem, vcek_key = _synthetic_chain()
    report, measurement = _signed_report(vcek_key, measurement_bytes=b"\x22" * 48, report_data=b"\x00" * 64)
    tampered = bytearray(report)
    tampered[0x10] ^= 0xFF  # flip a byte inside the signed region
    res = verify_sev_snp_measurement(
        measurement=measurement,
        raw_evidence=bytes(tampered),
        cert_chain_pem=chain_pem,
        trusted_ark_pem=ark_pem,
    )
    assert res.verified is False
    # measurement field was not touched, so it reaches signature check and fails there
    assert res.failure_reason in {"report_signature_invalid", "measurement_mismatch"}


def test_wrong_pinned_ark_fails_closed() -> None:
    chain_pem, _good_ark, vcek_key = _synthetic_chain()
    _other_chain, other_ark_pem, _ = _synthetic_chain()  # a different, untrusted ARK
    report, measurement = _signed_report(vcek_key, measurement_bytes=b"\x33" * 48, report_data=b"\x00" * 64)
    res = verify_sev_snp_measurement(
        measurement=measurement,
        raw_evidence=report,
        cert_chain_pem=chain_pem,
        trusted_ark_pem=other_ark_pem,
    )
    assert res.verified is False
    assert res.failure_reason == "vcek_chain_invalid"


def test_missing_chain_stays_unverified_not_passed() -> None:
    # Backward compatible: with no chain supplied, the cert chain is reported as
    # unverified rather than silently trusted.
    _chain, _ark, vcek_key = _synthetic_chain()
    report, measurement = _signed_report(vcek_key, measurement_bytes=b"\x44" * 48, report_data=b"\x00" * 64)
    res = verify_sev_snp_measurement(measurement=measurement, raw_evidence=report)
    assert "vcek_cert_chain" in res.unverified_fields


def test_signature_helper_valid_and_tampered() -> None:
    chain_pem, _ark, vcek_key = _synthetic_chain()
    vcek = x509.load_pem_x509_certificates(chain_pem)[0]
    report, _ = _signed_report(vcek_key, measurement_bytes=b"\x55" * 48, report_data=b"\x01" * 64)
    ok, reason = verify_snp_report_signature(report, vcek)
    assert ok is True, reason
    bad = bytearray(report)
    bad[0x20] ^= 0x01
    ok2, _ = verify_snp_report_signature(bytes(bad), vcek)
    assert ok2 is False


@pytest.mark.skip(
    reason="unblocks when a genuine Azure SEV-SNP report + real AMD KDS VCEK/ASK/ARK "
    "fixture lands (Imran provisioning); validates real report layout, real PSS cert "
    "signatures, and the exact report_data offset shared with issue #371"
)
def test_real_azure_snp_fixture() -> None:  # pragma: no cover
    raise NotImplementedError("add tests/fixtures/snp/azure_report.bin + vcek_chain.pem")
