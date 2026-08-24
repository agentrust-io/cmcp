"""TPMT_SIGNATURE metadata must reach the shared chained TPM verifier."""

from __future__ import annotations

import datetime
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from cmcp_verify.tpm import verify_tpm_quote_chained

_ALG_RSASSA = 0x0014
_ALG_RSAPSS = 0x0016
_ALG_SHA256 = 0x000B
_ALG_SHA384 = 0x000C
_TPM_GENERATED_VALUE = 0xFF544347
_TPM_ST_ATTEST_QUOTE = 0x8018

_NONCE = bytes(range(32))
_PCR_DIGEST = bytes(range(32, 64))
_NOW = datetime.datetime.now(datetime.UTC)
_NOT_BEFORE = _NOW - datetime.timedelta(days=1)
_NOT_AFTER = _NOW + datetime.timedelta(days=3650)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate(
    *,
    subject: str,
    subject_key: rsa.RSAPublicKey,
    issuer: str,
    issuer_key: rsa.RSAPrivateKey,
    is_ca: bool,
) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(subject_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


@pytest.fixture(scope="module")
def rsa_quote_material() -> tuple[rsa.RSAPrivateKey, bytes, bytes, bytes]:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _certificate(
        subject="test-tpm-root",
        subject_key=root_key.public_key(),
        issuer="test-tpm-root",
        issuer_key=root_key,
        is_ca=True,
    )
    ak = _certificate(
        subject="test-ak",
        subject_key=ak_key.public_key(),
        issuer="test-tpm-root",
        issuer_key=root_key,
        is_ca=False,
    )
    chain = ak.public_bytes(serialization.Encoding.PEM) + root.public_bytes(
        serialization.Encoding.PEM
    )
    return ak_key, _quote(), chain, root.public_bytes(serialization.Encoding.PEM)


def _quote() -> bytes:
    return (
        struct.pack(">IH", _TPM_GENERATED_VALUE, _TPM_ST_ATTEST_QUOTE)
        + struct.pack(">H", 0)  # qualifiedSigner
        + struct.pack(">H", len(_NONCE))
        + _NONCE
        + b"\x00" * 17  # clockInfo
        + b"\x00" * 8  # firmwareVersion
        + struct.pack(">IHB", 1, _ALG_SHA256, 3)  # one PCR selection
        + b"\x00\x00\x01"
        + struct.pack(">H", len(_PCR_DIGEST))
        + _PCR_DIGEST
    )


def _rsa_tpmt_signature(
    key: rsa.RSAPrivateKey,
    attest: bytes,
    *,
    actual_padding: padding.AsymmetricPadding,
    actual_digest: hashes.HashAlgorithm,
    declared_scheme: int,
    declared_hash: int,
) -> bytes:
    signature = key.sign(attest, actual_padding, actual_digest)
    return struct.pack(">HHH", declared_scheme, declared_hash, len(signature)) + signature


def _verify(
    signature: bytes, material: tuple[rsa.RSAPrivateKey, bytes, bytes, bytes]
) -> tuple[bool, dict[str, str]]:
    _key, attest, chain, root = material
    return verify_tpm_quote_chained(
        attest,
        signature,
        chain,
        trusted_roots_pem=root,
        expected_qualifying_data=_NONCE,
        expected_pcr_digest=_PCR_DIGEST,
    )


def test_chained_verifier_accepts_rsapss_sha384(
    rsa_quote_material: tuple[rsa.RSAPrivateKey, bytes, bytes, bytes],
) -> None:
    key, attest, _chain, _root = rsa_quote_material
    digest = hashes.SHA384()
    signature = _rsa_tpmt_signature(
        key,
        attest,
        actual_padding=padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size),
        actual_digest=digest,
        declared_scheme=_ALG_RSAPSS,
        declared_hash=_ALG_SHA384,
    )

    verified, details = _verify(signature, rsa_quote_material)

    assert verified is True
    assert details["signature_algorithm"] == "rsapss"
    assert details["signature_digest"] == "0x000c"


def test_chained_verifier_rejects_false_hash_metadata(
    rsa_quote_material: tuple[rsa.RSAPrivateKey, bytes, bytes, bytes],
) -> None:
    key, attest, _chain, _root = rsa_quote_material
    signature = _rsa_tpmt_signature(
        key,
        attest,
        actual_padding=padding.PKCS1v15(),
        actual_digest=hashes.SHA256(),
        declared_scheme=_ALG_RSASSA,
        declared_hash=_ALG_SHA384,
    )

    verified, details = _verify(signature, rsa_quote_material)

    assert verified is False
    assert details == {"verification": "signature or binding mismatch"}


def test_chained_verifier_rejects_false_scheme_metadata(
    rsa_quote_material: tuple[rsa.RSAPrivateKey, bytes, bytes, bytes],
) -> None:
    key, attest, _chain, _root = rsa_quote_material
    signature = _rsa_tpmt_signature(
        key,
        attest,
        actual_padding=padding.PKCS1v15(),
        actual_digest=hashes.SHA256(),
        declared_scheme=_ALG_RSAPSS,
        declared_hash=_ALG_SHA256,
    )

    verified, details = _verify(signature, rsa_quote_material)

    assert verified is False
    assert details == {"verification": "signature or binding mismatch"}
