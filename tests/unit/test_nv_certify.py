"""Tests for appraising a TPM2_NV_Certify pair (#432, second half).

Synthetic vectors: a real pair needs a TPM, and the collector half is exercised on
hardware separately (docs/testing/hardware-validation.md). What is asserted here is
the appraisal logic, and specifically that every way the pair can be forged or
degraded is rejected. A verifier that accepts a broken pair is worse than none,
since it converts an unsigned value into an apparently attested one.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, SHA384
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from cmcp_verify.nv_certify import (
    PHASE_POST,
    PHASE_PRE,
    TPM_ST_ATTEST_NV,
    build_envelope,
    certify_qualifying_data,
    parse_nv_certify,
    verify_gateway_measurement,
)

_ALG_RSASSA = 0x0014
_ALG_ECDSA = 0x0018
_ALG_SHA256 = 0x000B

NONCE = b"\xa5" * 32
GATEWAY_DIGEST = hashlib.sha256(b"gateway").digest()
INDEX_NAME = b"\x00\x0b" + b"\x77" * 32
PRE_CONTENTS = bytes(32)
POST_CONTENTS = hashlib.sha256(PRE_CONTENTS + GATEWAY_DIGEST).digest()


# ── builders ──────────────────────────────────────────────────────────────────


def build_nv_attest(
    *,
    qualifying_data: bytes,
    nv_contents: bytes,
    index_name: bytes = INDEX_NAME,
    magic: int = 0xFF544347,
    attest_type: int = TPM_ST_ATTEST_NV,
    offset: int = 0,
) -> bytes:
    out = bytearray()
    out += struct.pack(">I", magic)
    out += struct.pack(">H", attest_type)
    out += struct.pack(">H", 0)  # qualifiedSigner, empty
    out += struct.pack(">H", len(qualifying_data)) + qualifying_data
    out += b"\x00" * 17  # clockInfo
    out += b"\x00" * 8  # firmwareVersion
    out += struct.pack(">H", len(index_name)) + index_name
    out += struct.pack(">H", offset)
    out += struct.pack(">H", len(nv_contents)) + nv_contents
    return bytes(out)


def _tpmt_rsassa(sig: bytes) -> bytes:
    return struct.pack(">HH", _ALG_RSASSA, _ALG_SHA256) + struct.pack(">H", len(sig)) + sig


def _tpmt_ecdsa(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    rb, sb = r.to_bytes(32, "big"), s.to_bytes(32, "big")
    return (
        struct.pack(">HH", _ALG_ECDSA, _ALG_SHA256)
        + struct.pack(">H", len(rb))
        + rb
        + struct.pack(">H", len(sb))
        + sb
    )


def _cert(subject: str, issuer: str, subject_pub, issuer_key, issuer_hash=SHA384()):
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(subject_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key, issuer_hash)
    )


class Fixture:
    """An AK, its chain, a trusted root, and a signing helper."""

    def __init__(self, *, use_rsa: bool = True) -> None:
        root_key = ec.generate_private_key(ec.SECP256R1())
        root = _cert("root", "root", root_key.public_key(), root_key)
        if use_rsa:
            self.ak_key: object = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            ak_pub = self.ak_key.public_key()  # type: ignore[attr-defined]
        else:
            self.ak_key = ec.generate_private_key(ec.SECP256R1())
            ak_pub = self.ak_key.public_key()  # type: ignore[attr-defined]
        ak = _cert("ak", "root", ak_pub, root_key)
        self.chain_pem = ak.public_bytes(Encoding.PEM) + root.public_bytes(Encoding.PEM)
        self.root_pem = root.public_bytes(Encoding.PEM)
        self.use_rsa = use_rsa

    def sign(self, blob: bytes) -> bytes:
        if self.use_rsa:
            return _tpmt_rsassa(self.ak_key.sign(blob, padding.PKCS1v15(), SHA256()))  # type: ignore[attr-defined]
        return _tpmt_ecdsa(self.ak_key.sign(blob, ec.ECDSA(SHA256())))  # type: ignore[attr-defined]


def make_envelope(
    fx: Fixture,
    *,
    nonce: bytes = NONCE,
    pre_contents: bytes = PRE_CONTENTS,
    post_contents: bytes | None = None,
    gateway_digest: bytes = GATEWAY_DIGEST,
    pre_phase: bytes = PHASE_PRE,
    post_phase: bytes = PHASE_POST,
    pre_index: bytes = INDEX_NAME,
    post_index: bytes = INDEX_NAME,
) -> bytes:
    if post_contents is None:
        post_contents = hashlib.sha256(pre_contents + gateway_digest).digest()
    pre = build_nv_attest(
        qualifying_data=certify_qualifying_data(nonce, pre_phase),
        nv_contents=pre_contents,
        index_name=pre_index,
    )
    post = build_nv_attest(
        qualifying_data=certify_qualifying_data(nonce, post_phase),
        nv_contents=post_contents,
        index_name=post_index,
    )
    return build_envelope(
        pre_attest=pre,
        pre_signature=fx.sign(pre),
        post_attest=post,
        post_signature=fx.sign(post),
        gateway_digest=gateway_digest,
        components={"code": "x", "policy": "y", "config": "z"},
    )


def verify(fx: Fixture, envelope: bytes, **kw):
    kw.setdefault("expected_nonce", NONCE)
    kw.setdefault("expected_gateway_digest", GATEWAY_DIGEST)
    return verify_gateway_measurement(
        envelope, ak_chain_pem=fx.chain_pem, trusted_roots_pem=fx.root_pem, **kw
    )


# ── parsing ───────────────────────────────────────────────────────────────────


def test_parse_reads_the_certify_fields() -> None:
    qd = certify_qualifying_data(NONCE, PHASE_PRE)
    info = parse_nv_certify(build_nv_attest(qualifying_data=qd, nv_contents=POST_CONTENTS))
    assert info.qualifying_data == qd
    assert info.nv_contents == POST_CONTENTS
    assert info.index_name == INDEX_NAME
    assert info.offset == 0


def test_parse_rejects_a_quote() -> None:
    """A quote must not be readable as an NV certify.

    Both are TPMS_ATTEST, and the attested union differs. Without the type check a
    quote's PCR selection bytes would be misread as an index name and contents.
    """
    with pytest.raises(ValueError, match="not an NV certify"):
        parse_nv_certify(
            build_nv_attest(qualifying_data=b"x", nv_contents=b"y", attest_type=0x8018)
        )


def test_parse_rejects_bad_magic() -> None:
    with pytest.raises(ValueError, match="TPM_GENERATED"):
        parse_nv_certify(build_nv_attest(qualifying_data=b"x", nv_contents=b"y", magic=0))


def test_parse_rejects_truncated() -> None:
    blob = build_nv_attest(qualifying_data=b"x", nv_contents=POST_CONTENTS)
    with pytest.raises(ValueError):
        parse_nv_certify(blob[:-8])


# ── qualifying data ───────────────────────────────────────────────────────────


def test_phases_commit_different_values() -> None:
    assert certify_qualifying_data(NONCE, PHASE_PRE) != certify_qualifying_data(NONCE, PHASE_POST)


def test_qualifying_data_binds_the_nonce() -> None:
    assert certify_qualifying_data(NONCE, PHASE_PRE) != certify_qualifying_data(
        b"\x01" * 32, PHASE_PRE
    )


def test_qualifying_data_is_unambiguous() -> None:
    """Length-prefixed, so a nonce ending in the phase bytes cannot shift the split."""
    assert certify_qualifying_data(b"ab", b"c") != certify_qualifying_data(b"a", b"bc")


# ── the happy paths ───────────────────────────────────────────────────────────


def test_valid_pair_verifies_rsa() -> None:
    fx = Fixture(use_rsa=True)
    result = verify(fx, make_envelope(fx))
    assert result.verified, result.failure_reason
    assert "extend_relation" in result.verified_fields
    assert "ak_chain" in result.verified_fields
    assert "signatures" in result.verified_fields


def test_valid_pair_verifies_ecdsa() -> None:
    fx = Fixture(use_rsa=False)
    result = verify(fx, make_envelope(fx))
    assert result.verified, result.failure_reason


def test_without_an_expected_digest_it_notes_the_weaker_claim() -> None:
    """Internal consistency is not the same as matching a known-good value."""
    fx = Fixture()
    result = verify(fx, make_envelope(fx), expected_gateway_digest=None)
    assert result.verified
    assert "gateway_digest_note" in result.details


# ── forgeries and degradations, all must fail ─────────────────────────────────


def test_broken_extend_relation_is_rejected() -> None:
    """The core check: post must be pre extended by the expected digest."""
    fx = Fixture()
    env = make_envelope(fx, post_contents=hashlib.sha256(b"something else").digest())
    result = verify(fx, env)
    assert not result.verified
    assert result.failure_reason == "extend_relation_broken"


def test_a_different_gateway_digest_is_rejected() -> None:
    """A gateway that extended some other code must not verify as this one."""
    fx = Fixture()
    other = hashlib.sha256(b"tampered gateway").digest()
    env = make_envelope(fx, gateway_digest=other)
    result = verify(fx, env, expected_gateway_digest=GATEWAY_DIGEST)
    assert not result.verified
    assert result.failure_reason == "gateway_digest_mismatch"


def test_replayed_pair_from_another_session_is_rejected() -> None:
    """A pair certified under a different nonce is stale, however valid internally."""
    fx = Fixture()
    env = make_envelope(fx, nonce=b"\x09" * 32)
    result = verify(fx, env, expected_nonce=NONCE)
    assert not result.verified
    assert result.failure_reason == "pre_binding_mismatch"


def test_swapped_pre_and_post_is_rejected() -> None:
    """Roles are signed, so presenting them the other way round fails."""
    fx = Fixture()
    env = json.loads(make_envelope(fx))
    env["pre_attest"], env["post_attest"] = env["post_attest"], env["pre_attest"]
    env["pre_signature"], env["post_signature"] = env["post_signature"], env["pre_signature"]
    result = verify(fx, json.dumps(env).encode())
    assert not result.verified
    assert result.failure_reason in {"pre_binding_mismatch", "post_binding_mismatch"}


def test_two_certifies_of_different_indices_are_rejected() -> None:
    """Otherwise a clean index could be paired with the real one's successor."""
    fx = Fixture()
    env = make_envelope(fx, post_index=b"\x00\x0b" + b"\x11" * 32)
    result = verify(fx, env)
    assert not result.verified
    assert result.failure_reason == "index_mismatch"


def test_tampered_attest_breaks_the_signature() -> None:
    fx = Fixture()
    env = json.loads(make_envelope(fx))
    blob = bytearray(base64.b64decode(env["post_attest"]))
    blob[-1] ^= 0xFF
    env["post_attest"] = base64.b64encode(bytes(blob)).decode()
    result = verify(fx, json.dumps(env).encode())
    assert not result.verified
    assert result.failure_reason in {"signature_invalid", "malformed_nv_certify"}


def test_signature_from_an_unrelated_key_is_rejected() -> None:
    """Signed by a key that is not the certified AK."""
    fx = Fixture()
    stranger = Fixture()
    env = json.loads(make_envelope(fx))
    post = base64.b64decode(env["post_attest"])
    env["post_signature"] = base64.b64encode(stranger.sign(post)).decode()
    result = verify(fx, json.dumps(env).encode())
    assert not result.verified
    assert result.failure_reason == "signature_invalid"


def test_untrusted_root_is_rejected() -> None:
    fx = Fixture()
    stranger = Fixture()
    result = verify_gateway_measurement(
        make_envelope(fx),
        ak_chain_pem=fx.chain_pem,
        trusted_roots_pem=stranger.root_pem,
        expected_nonce=NONCE,
        expected_gateway_digest=GATEWAY_DIGEST,
    )
    assert not result.verified
    assert result.failure_reason == "ak_chain_invalid"


def test_no_trusted_roots_is_refused() -> None:
    """Verifying against no anchor would accept any self-consistent chain."""
    fx = Fixture()
    result = verify_gateway_measurement(
        make_envelope(fx),
        ak_chain_pem=fx.chain_pem,
        trusted_roots_pem=b"",
        expected_nonce=NONCE,
        expected_gateway_digest=GATEWAY_DIGEST,
    )
    assert not result.verified
    assert result.failure_reason in {"no_trusted_roots", "ak_chain_invalid"}


def test_a_quote_in_place_of_a_certify_is_rejected() -> None:
    """Substituting a PCR quote must not be appraised as a measurement proof."""
    fx = Fixture()
    quote = build_nv_attest(
        qualifying_data=certify_qualifying_data(NONCE, PHASE_POST),
        nv_contents=POST_CONTENTS,
        attest_type=0x8018,
    )
    env = json.loads(make_envelope(fx))
    env["post_attest"] = base64.b64encode(quote).decode()
    env["post_signature"] = base64.b64encode(fx.sign(quote)).decode()
    result = verify(fx, json.dumps(env).encode())
    assert not result.verified
    assert result.failure_reason == "malformed_nv_certify"


def test_malformed_envelope_is_rejected() -> None:
    fx = Fixture()
    assert verify(fx, b"not json").failure_reason == "malformed_envelope"


def test_unsupported_envelope_version_is_rejected() -> None:
    fx = Fixture()
    env = json.loads(make_envelope(fx))
    env["v"] = 99
    result = verify(fx, json.dumps(env).encode())
    assert not result.verified
    assert result.failure_reason == "unsupported_envelope_version"


def test_accumulated_index_still_verifies() -> None:
    """The pair works on a long-lived index, not just a freshly defined one.

    This is the case the two-certify design exists for: after many gateway starts
    the index is a hash chain with no predictable value, and the relation still
    checks out.
    """
    fx = Fixture()
    accumulated = PRE_CONTENTS
    for i in range(5):
        accumulated = hashlib.sha256(accumulated + bytes([i]) * 32).digest()
    result = verify(fx, make_envelope(fx, pre_contents=accumulated))
    assert result.verified, result.failure_reason
