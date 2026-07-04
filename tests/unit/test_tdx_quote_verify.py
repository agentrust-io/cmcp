"""TDX DCAP quote-verification tests (issue #370, TDX portion).

These exercise the verification LOGIC against a locally generated, synthetic TDX
ECDSA v4 quote and a synthetic PCK chain (leaf -> intermediate -> root), so parsing
and all four checks (quote signature, attestation-key binding, QE report signature,
PCK chain to a pinned root) run end to end. The real-hardware test is marked skipped
below and unblocks when an Azure TDX quote fixture lands (also settles the real
report_data offset for #371).
"""
from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from cmcp_verify.tdx import (
    _QE_REPORT_DATA_OFF,
    _QUOTE_HEADER_LEN,
    _TD_BODY_REPORT_DATA_OFF,
    _TD_REPORT_BODY_LEN,
    verify_tdx_quote,
)

_RD = b"cmcp-tdx-fixture-v1".ljust(64, b"\0")  # known report_data (matches capture script)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject: str, issuer: str, sub_pub, iss_priv) -> x509.Certificate:
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(sub_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(iss_priv, hashes.SHA256())
    )


def _raw_sig(priv, data: bytes) -> bytes:
    r, s = decode_dss_signature(priv.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _raw_pub(pub) -> bytes:
    n = pub.public_numbers()
    return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")


def _pck_chain():
    root_k = ec.generate_private_key(ec.SECP256R1())
    inter_k = ec.generate_private_key(ec.SECP256R1())
    leaf_k = ec.generate_private_key(ec.SECP256R1())
    root = _cert("Intel Root", "Intel Root", root_k.public_key(), root_k)  # self-signed
    inter = _cert("Intel PCK Intermediate", "Intel Root", inter_k.public_key(), root_k)
    leaf = _cert("Intel PCK Leaf", "Intel PCK Intermediate", leaf_k.public_key(), inter_k)
    chain_pem = leaf.public_bytes(Encoding.PEM) + inter.public_bytes(Encoding.PEM)
    return chain_pem, root.public_bytes(Encoding.PEM), leaf_k, root_k


def _build_quote(*, report_data: bytes = _RD, qe_auth: bytes = b"") -> tuple[bytes, bytes]:
    """Return (quote_bytes, trusted_intel_root_pem) for a well-formed synthetic quote."""
    att_k = ec.generate_private_key(ec.SECP256R1())
    att_pub_raw = _raw_pub(att_k.public_key())

    header = bytearray(_QUOTE_HEADER_LEN)
    header[2:4] = (2).to_bytes(2, "little")  # att_key_type = ECDSA-P256
    body = bytearray(_TD_REPORT_BODY_LEN)
    body[_TD_BODY_REPORT_DATA_OFF:_TD_BODY_REPORT_DATA_OFF + 64] = report_data
    signed_region = bytes(header) + bytes(body)
    quote_sig = _raw_sig(att_k, signed_region)

    chain_pem, root_pem, leaf_k, _root_k = _pck_chain()
    qe_report = bytearray(384)
    bind = hashlib.sha256(att_pub_raw + qe_auth).digest()
    qe_report[_QE_REPORT_DATA_OFF:_QE_REPORT_DATA_OFF + 32] = bind
    qe_report_sig = _raw_sig(leaf_k, bytes(qe_report))

    sig = bytearray()
    sig += quote_sig
    sig += att_pub_raw
    sig += bytes(qe_report)
    sig += qe_report_sig
    sig += len(qe_auth).to_bytes(2, "little") + qe_auth
    sig += (5).to_bytes(2, "little")              # cert_data_type (PCK chain)
    sig += len(chain_pem).to_bytes(4, "little") + chain_pem

    quote = signed_region + len(sig).to_bytes(4, "little") + bytes(sig)
    return quote, root_pem


def test_valid_quote_verifies() -> None:
    quote, root = _build_quote()
    r = verify_tdx_quote(quote, root, _RD.hex())
    assert r.verified, r.failure_reason
    assert "dcap_quote_signature" in r.verified_fields
    assert "pck_chain" in r.verified_fields
    assert "report_data" in r.verified_fields
    assert "tcb_status" in r.unverified_fields  # honest: not appraised offline


def test_tampered_quote_signature_fails_closed() -> None:
    quote, root = _build_quote()
    corrupted = bytearray(quote)
    corrupted[0] ^= 0xFF  # flip a byte inside the signed region
    r = verify_tdx_quote(bytes(corrupted), root)
    assert not r.verified
    assert r.failure_reason == "quote_signature_invalid"


def test_wrong_pinned_root_fails_closed() -> None:
    quote, _good_root = _build_quote()
    _q2, other_root = _build_quote()  # a different, untrusted root
    r = verify_tdx_quote(quote, other_root)
    assert not r.verified
    assert r.failure_reason == "pck_chain_invalid"


def test_report_data_mismatch_fails() -> None:
    quote, root = _build_quote(report_data=b"something-else".ljust(64, b"\0"))
    r = verify_tdx_quote(quote, root, _RD.hex())
    assert not r.verified
    assert r.failure_reason == "report_data_mismatch"


@pytest.mark.skipif(
    not os.environ.get("CMCP_TDX_FIXTURE_DIR"),
    reason="needs a real Azure TDX quote fixture (capture-tdx-azure.sh); set CMCP_TDX_FIXTURE_DIR",
)
def test_real_azure_tdx_quote() -> None:
    d = os.environ["CMCP_TDX_FIXTURE_DIR"]
    quote = open(os.path.join(d, "tdx_quote.bin"), "rb").read()
    root = open(os.path.join(d, "collateral", "intel_root_ca.pem"), "rb").read()
    expected_rd = open(os.path.join(d, "report_data.hex")).read().strip()
    r = verify_tdx_quote(quote, root, expected_rd)
    assert r.verified, r.failure_reason
    # confirms the report_data offset used by parse_td_quote is correct (issue #371)
    assert "report_data" in r.verified_fields
