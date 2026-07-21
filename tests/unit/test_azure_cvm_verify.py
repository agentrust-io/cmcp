"""Azure CVM (vTPM-rooted SEV-SNP) attestation: verifier + collector round-trip.

Synthetic, self-consistent evidence proves the verification LOGIC: a
paravisor-style SNP report (REPORT_DATA binds the vTPM AK), an AK-signed TPM
quote whose extraData carries the cMCP nonce, and a VCEK/ASK/ARK chain. Not a
real attestation; it proves the verifier accepts a well-formed chain and fails
closed on tampering. A real-hardware fixture test is env-gated at the bottom.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import struct
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from cmcp_verify.azure_cvm import verify_azure_cvm_measurement
from cmcp_verify.sev_snp import _SNP_SIG_OFFSET, _SnpAttestationReport

_MEAS_OFFSET = _SnpAttestationReport.measurement.offset
_RD_OFFSET = _SnpAttestationReport.report_data.offset
_SIG_ALGO_OFFSET = _SnpAttestationReport.sig_algo.offset
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
    ark_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ask_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    ark = _cert(_name("ARK"), _name("ARK"), ark_key.public_key(), ark_key)
    ask = _cert(_name("ASK"), _name("ARK"), ask_key.public_key(), ark_key)
    vcek = _cert(_name("VCEK"), _name("ASK"), vcek_key.public_key(), ask_key)
    chain_pem = (
        vcek.public_bytes(Encoding.PEM)
        + ask.public_bytes(Encoding.PEM)
        + ark.public_bytes(Encoding.PEM)
    )
    return chain_pem, ark.public_bytes(Encoding.PEM), vcek_key


def _b64u_int(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")).rstrip(b"=").decode()


def _runtime_data(ak_pub: rsa.RSAPublicKey) -> bytes:
    pn = ak_pub.public_numbers()
    return json.dumps({
        "keys": [{"kid": "HCLAkPub", "kty": "RSA", "e": _b64u_int(pn.e), "n": _b64u_int(pn.n)}]
    }).encode()


def _signed_snp(vcek_key, runtime: bytes, measurement_bytes: bytes = b"\x11" * 48) -> tuple[bytes, str]:
    buf = bytearray(_REPORT_SIZE)
    buf[0x00:0x04] = (2).to_bytes(4, "little")
    buf[_SIG_ALGO_OFFSET : _SIG_ALGO_OFFSET + 4] = (1).to_bytes(4, "little")
    buf[_MEAS_OFFSET : _MEAS_OFFSET + 48] = measurement_bytes[:48]
    # paravisor binding: REPORT_DATA[:32] == sha256(runtime_data)
    buf[_RD_OFFSET : _RD_OFFSET + 32] = hashlib.sha256(runtime).digest()
    signed_region = bytes(buf[:_SNP_SIG_OFFSET])
    der = vcek_key.sign(signed_region, ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(der)
    buf[_SNP_SIG_OFFSET : _SNP_SIG_OFFSET + 48] = r.to_bytes(48, "little")
    buf[_SNP_SIG_OFFSET + 72 : _SNP_SIG_OFFSET + 72 + 48] = s.to_bytes(48, "little")
    measurement = "sha384:" + hashlib.sha384(measurement_bytes[:48]).hexdigest()
    return bytes(buf), measurement


def _tpm2b_attest(extra_data: bytes) -> bytes:
    body = (
        struct.pack(">I", 0xFF544347)  # magic
        + struct.pack(">H", 0x8018)  # type: TPM_ST_ATTEST_QUOTE
        + struct.pack(">H", 0)  # qualifiedSigner (empty TPM2B)
        + struct.pack(">H", len(extra_data)) + extra_data  # extraData
        + b"\x00" * 40  # clockInfo + firmwareVersion + attested (unparsed tail)
    )
    return struct.pack(">H", len(body)) + body


def _tpmt_signature(ak_key: rsa.RSAPrivateKey, quote_msg: bytes) -> bytes:
    sig = ak_key.sign(quote_msg, padding.PKCS1v15(), hashes.SHA256())
    return struct.pack(">H", 0x0014) + struct.pack(">H", 0x000B) + struct.pack(">H", len(sig)) + sig


def _build_evidence(nonce: bytes, *, include_chain: bool = True, ak_key=None, quote_extra=None):
    chain_pem, ark_pem, vcek_key = _synthetic_chain()
    ak_key = ak_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    runtime = _runtime_data(ak_key.public_key())
    snp, measurement = _signed_snp(vcek_key, runtime)
    quote_msg = _tpm2b_attest(quote_extra if quote_extra is not None else hashlib.sha256(nonce).digest())
    quote_sig = _tpmt_signature(ak_key, quote_msg)
    envelope = json.dumps({
        "v": 1,
        "snp_report": base64.b64encode(snp).decode(),
        "runtime_data": base64.b64encode(runtime).decode(),
        "quote_msg": base64.b64encode(quote_msg).decode(),
        "quote_sig": base64.b64encode(quote_sig).decode(),
        "ak_pub_pem": ak_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode(),
        "vcek_chain_pem": base64.b64encode(chain_pem if include_chain else b"").decode(),
    }).encode()
    return envelope, measurement, ark_pem


def test_happy_path_verifies() -> None:
    nonce = os.urandom(64)
    envelope, measurement, ark_pem = _build_evidence(nonce)
    res = verify_azure_cvm_measurement(measurement, envelope, nonce.hex(), ark_pem)
    assert res.verified is True, res.failure_reason
    for f in ("measurement", "runtime_data_binding", "ak_binding", "quote_nonce_binding",
              "vcek_cert_chain", "report_signature"):
        assert f in res.verified_fields, f


def test_tampered_quote_nonce_rejected() -> None:
    nonce = os.urandom(64)
    # quote commits a different nonce than the claim's report_data
    envelope, measurement, ark_pem = _build_evidence(nonce, quote_extra=os.urandom(64))
    res = verify_azure_cvm_measurement(measurement, envelope, nonce.hex(), ark_pem)
    assert res.verified is False
    assert res.failure_reason == "quote_nonce_mismatch"


def test_wrong_ak_rejected() -> None:
    # AK in runtime_data / ak_pub_pem signs the quote, but we swap ak_pub_pem for another
    nonce = os.urandom(64)
    envelope, measurement, ark_pem = _build_evidence(nonce)
    env = json.loads(envelope)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    env["ak_pub_pem"] = other.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    res = verify_azure_cvm_measurement(measurement, json.dumps(env).encode(), nonce.hex(), ark_pem)
    assert res.verified is False
    assert res.failure_reason == "ak_mismatch"


def test_runtime_data_binding_mismatch_rejected() -> None:
    nonce = os.urandom(64)
    envelope, measurement, ark_pem = _build_evidence(nonce)
    env = json.loads(envelope)
    # break the paravisor binding by substituting a different runtime_data
    ak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    env["runtime_data"] = base64.b64encode(_runtime_data(ak.public_key()) + b" ").decode()
    res = verify_azure_cvm_measurement(measurement, json.dumps(env).encode(), nonce.hex(), ark_pem)
    assert res.verified is False
    assert res.failure_reason == "runtime_data_binding_mismatch"


def test_missing_chain_stays_partial() -> None:
    nonce = os.urandom(64)
    envelope, measurement, ark_pem = _build_evidence(nonce, include_chain=False)
    res = verify_azure_cvm_measurement(measurement, envelope, nonce.hex(), ark_pem)
    assert "vcek_cert_chain" in res.unverified_fields
    # the vTPM-side checks still pass; only the silicon chain is unverified
    assert "quote_nonce_binding" in res.verified_fields


def test_no_evidence_fails_closed() -> None:
    res = verify_azure_cvm_measurement("sha384:" + "0" * 96, None, "00" * 64, b"")
    assert res.verified is False
    assert res.failure_reason == "no_raw_evidence"


# ── Collector round-trip (tpm2 calls monkeypatched) ─────────────────────────────


def test_collector_roundtrip(monkeypatch) -> None:
    """AzureCVMProvider.get_attestation_report -> verify_azure_cvm_measurement."""
    from cmcp_runtime.tee import azure_cvm as col

    nonce = os.urandom(64)
    chain_pem, ark_pem, vcek_key = _synthetic_chain()
    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    runtime = _runtime_data(ak_key.public_key())
    snp, measurement = _signed_snp(vcek_key, runtime)
    hcl = b"HCLA" + b"\x00" * 28 + snp + struct.pack("<I", len(runtime)) + runtime

    provider = col.AzureCVMProvider()
    monkeypatch.setattr(provider, "_read_hcl_report", lambda: hcl)
    monkeypatch.setattr(provider, "_find_ak_handle", lambda mod: "0x81000003")
    monkeypatch.setattr(provider, "_fetch_vcek_chain", lambda s: chain_pem)

    def fake_tpm(args):
        # Emulate tpm2_quote / tpm2_readpublic writing their output files.
        if args[0] == "tpm2_quote":
            out = dict(zip(args, args[1:], strict=False))
            quote_msg = _tpm2b_attest(bytes.fromhex(out["-q"]))
            __import__("pathlib").Path(out["-m"]).write_bytes(quote_msg)
            __import__("pathlib").Path(out["-s"]).write_bytes(_tpmt_signature(ak_key, quote_msg))
            __import__("pathlib").Path(out["-o"]).write_bytes(b"\x00")
        elif args[0] == "tpm2_readpublic":
            out = dict(zip(args, args[1:], strict=False))
            from cryptography.hazmat.primitives.serialization import PublicFormat
            __import__("pathlib").Path(out["-o"]).write_bytes(
                ak_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            )
        return b""

    monkeypatch.setattr(provider, "_tpm", fake_tpm)

    report = provider.get_attestation_report(nonce)
    assert report.provider == "azure-cvm-sev-snp"
    assert report.report_data == nonce.hex()
    assert report.measurement == measurement

    res = verify_azure_cvm_measurement(report.measurement, report.raw_evidence, nonce.hex(), ark_pem)
    assert res.verified is True, res.failure_reason


# ── Real hardware fixture (env-gated; not committed) ────────────────────────────


@pytest.mark.skipif(
    not os.environ.get("CMCP_AZURE_FIXTURE_DIR"),
    reason="set CMCP_AZURE_FIXTURE_DIR to a dir with hcl.bin + vcek.der + cert_chain.pem "
    "(real Azure SEV-SNP capture) to run the full-chain hardware test",
)
def test_real_azure_fixture() -> None:
    import pathlib

    from cmcp_verify.sev_snp import (
        load_snp_cert_chain,
        verify_snp_report_signature,
        verify_vcek_chain,
    )

    d = pathlib.Path(os.environ["CMCP_AZURE_FIXTURE_DIR"])
    hcl = (d / "hcl.bin").read_bytes()
    snp = hcl[0x20 : 0x20 + _REPORT_SIZE]
    runtime = hcl[0x20 + _REPORT_SIZE :]
    s, e = runtime.find(b"{"), runtime.rfind(b"}")
    runtime = runtime[s : e + 1]
    # paravisor binding holds on the real report
    assert snp[_RD_OFFSET : _RD_OFFSET + 32] == hashlib.sha256(runtime).digest()
    # cert_chain.pem holds ASK+ARK; prepend the DER VCEK as PEM
    vcek = x509.load_der_x509_certificate((d / "vcek.der").read_bytes())
    bundle = vcek.public_bytes(Encoding.PEM) + (d / "cert_chain.pem").read_bytes()
    vcek_c, ask, ark = load_snp_cert_chain(bundle)
    ok, reason = verify_vcek_chain(vcek_c, ask, ark, ark)
    assert ok, reason
    sig_ok, sig_reason = verify_snp_report_signature(snp, vcek_c)
    assert sig_ok, sig_reason
