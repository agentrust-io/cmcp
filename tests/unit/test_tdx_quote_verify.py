"""TDX DCAP quote-verification tests (issue #370, TDX portion).

These exercise the verification LOGIC against a locally generated, synthetic TDX
ECDSA v4 quote and a synthetic PCK chain (leaf -> intermediate -> root), so parsing
and all four checks (quote signature, attestation-key binding, QE report signature,
PCK chain to a pinned root) run end to end.

The synthetic quote emits the real nested layout: the signature section carries a
type-6 QE_REPORT_CERTIFICATION_DATA header wrapping the QE report and the type-5
PCK chain. It used to emit the flat shape, which matched the parser's own mistake
and let both pass CI while every genuine quote was rejected.

Set ``CMCP_TDX_FIXTURE_DIR`` to a directory holding a real ``tdx_quote.bin`` to run
the full-chain hardware tests at the bottom against the pinned Intel SGX Root CA.
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
    parse_td_quote,
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

    # Intel DCAP v4 nests the QE material: the bytes after the attestation key are
    # a type-6 QE_REPORT_CERTIFICATION_DATA header wrapping the QE report, its PCK
    # signature, the auth data and the type-5 PCK chain. Emitting the flat layout
    # here is what let the six-byte-early parse pass CI while rejecting real quotes.
    cert_data = bytearray()
    cert_data += bytes(qe_report)
    cert_data += qe_report_sig
    cert_data += len(qe_auth).to_bytes(2, "little") + qe_auth
    cert_data += (5).to_bytes(2, "little")        # cert_data_type (PCK chain)
    cert_data += len(chain_pem).to_bytes(4, "little") + chain_pem

    sig = bytearray()
    sig += quote_sig
    sig += att_pub_raw
    sig += (6).to_bytes(2, "little")              # cert_data_type (QE report)
    sig += len(cert_data).to_bytes(4, "little") + bytes(cert_data)

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


def test_parse_rejects_flat_signature_layout() -> None:
    """A quote without the type-6 QE wrapper must be rejected, not misread.

    The flat layout is what the parser used to assume. Genuine DCAP v4 quotes
    nest the QE material, so anything claiming the flat shape is malformed.
    """
    quote, _ = _build_quote()
    off = _QUOTE_HEADER_LEN + _TD_REPORT_BODY_LEN + 4 + 128
    flat = bytearray(quote)
    flat[off:off + 2] = (5).to_bytes(2, "little")  # PCK chain where the QE report belongs
    with pytest.raises(ValueError, match="certification data type"):
        parse_td_quote(bytes(flat))


# Offsets into a well-formed quote, used to mutate the declared lengths below.
# Every one of these lengths is attacker-controlled: Python slicing clamps an
# overstated length instead of raising, so the parser must reject the mismatch
# rather than verify a silently shorter buffer than the producer declared.
_SIG_LEN_OFF = _QUOTE_HEADER_LEN + _TD_REPORT_BODY_LEN      # uint32 signature-data size
_SIG_OFF = _SIG_LEN_OFF + 4
_QE_CERT_SIZE_OFF = _SIG_OFF + 130                          # uint32, after type-6 header
_CERT_DATA_OFF = _SIG_OFF + 134
_QE_AUTH_LEN_OFF = _CERT_DATA_OFF + 384 + 64                # uint16 QE auth data size


def test_parse_matches_shared_agent_manifest_parser() -> None:
    """The adapter must map the canonical parser's output field for field."""
    from agent_manifest import parse_tdx_quote_signature

    quote, _root = _build_quote(qe_auth=b"qe-auth-bytes")
    pq = parse_td_quote(quote)
    shared = parse_tdx_quote_signature(quote)

    assert pq.signed_region == shared.signed_body
    assert pq.signed_region == quote[:_QUOTE_HEADER_LEN + _TD_REPORT_BODY_LEN]
    assert pq.quote_sig == shared.quote_signature
    assert pq.att_pubkey_raw == shared.attestation_key
    assert pq.qe_report == shared.qe_report
    assert pq.qe_report_sig == shared.qe_report_signature
    assert pq.qe_auth_data == shared.qe_auth_data == b"qe-auth-bytes"
    assert pq.pck_chain_pem == shared.pck_chain_pem
    # report_data is not part of the signature section; cMCP still reads it from
    # the signed TD body, so the adapter has to supply it itself.
    assert pq.report_data == _RD


def test_parse_rejects_oversized_declared_signature_size() -> None:
    """An overstated signature-data length must fail closed, not be clamped."""
    quote, _root = _build_quote()
    tampered = bytearray(quote)
    declared = int.from_bytes(tampered[_SIG_LEN_OFF:_SIG_LEN_OFF + 4], "little")
    tampered[_SIG_LEN_OFF:_SIG_LEN_OFF + 4] = (declared + 64).to_bytes(4, "little")
    with pytest.raises(ValueError, match="signature data"):
        parse_td_quote(bytes(tampered))


def test_parse_rejects_oversized_qe_certification_size() -> None:
    """An overstated type-6 QE certification-data length must fail closed."""
    quote, _root = _build_quote()
    tampered = bytearray(quote)
    declared = int.from_bytes(tampered[_QE_CERT_SIZE_OFF:_QE_CERT_SIZE_OFF + 4], "little")
    tampered[_QE_CERT_SIZE_OFF:_QE_CERT_SIZE_OFF + 4] = (declared + 64).to_bytes(4, "little")
    with pytest.raises(ValueError, match="QE certification data"):
        parse_td_quote(bytes(tampered))


def test_parse_rejects_oversized_qe_auth_size() -> None:
    """A QE auth length running past the certification data must fail closed."""
    quote, _root = _build_quote()
    tampered = bytearray(quote)
    tampered[_QE_AUTH_LEN_OFF:_QE_AUTH_LEN_OFF + 2] = (0xFFFF).to_bytes(2, "little")
    with pytest.raises(ValueError, match="QE auth data"):
        parse_td_quote(bytes(tampered))


@pytest.mark.skipif(
    not os.environ.get("CMCP_TDX_FIXTURE_DIR"),
    reason="set CMCP_TDX_FIXTURE_DIR to a dir with a real tdx_quote.bin (see "
    "docs/testing/hardware-validation.md) to run the full-chain hardware test",
)
def test_real_tdx_quote() -> None:
    """Full-chain verification of a genuine TDX quote, against the pinned Intel root.

    Optional files in the fixture dir: ``collateral/intel_root_ca.pem`` overrides
    the pinned root, ``report_data.hex`` adds the report_data binding assertion
    (settles the offset in issue #371).
    """
    from agent_manifest._tdx_verify import INTEL_SGX_ROOT_CA_PEM

    d = os.environ["CMCP_TDX_FIXTURE_DIR"]
    with open(os.path.join(d, "tdx_quote.bin"), "rb") as f:
        quote = f.read()
    root_path = os.path.join(d, "collateral", "intel_root_ca.pem")
    root = INTEL_SGX_ROOT_CA_PEM
    if os.path.exists(root_path):
        with open(root_path, "rb") as f:
            root = f.read()
    rd_path = os.path.join(d, "report_data.hex")
    expected_rd = None
    if os.path.exists(rd_path):
        with open(rd_path) as f:
            expected_rd = f.read().strip()

    r = verify_tdx_quote(quote, root, expected_rd)
    assert r.verified, r.failure_reason
    assert "dcap_quote_signature" in r.verified_fields
    assert "pck_chain" in r.verified_fields
    if expected_rd is not None:
        assert "report_data" in r.verified_fields


@pytest.mark.skipif(
    not os.environ.get("CMCP_TDX_FIXTURE_DIR"),
    reason="set CMCP_TDX_FIXTURE_DIR to a dir with a real tdx_quote.bin",
)
def test_real_tdx_quote_agrees_with_agent_manifest() -> None:
    """cMCP and Agent Manifest must agree on verification of a real TDX quote.

    cMCP delegates the DCAP v4 signature-section parse to Agent Manifest; this
    hardware-gated test keeps the complete verification paths aligned against
    genuine evidence.
    """
    from agent_manifest import verify_tdx_quote as am_verify

    d = os.environ["CMCP_TDX_FIXTURE_DIR"]
    with open(os.path.join(d, "tdx_quote.bin"), "rb") as f:
        quote = f.read()
    assert am_verify(quote) is True
