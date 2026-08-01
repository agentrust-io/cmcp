"""Quote signature verification, covering what cMCP still owns after the union.

The `TPMT_SIGNATURE` unwrap and both `TPMS_ATTEST` framings moved to
agent-manifest (>=0.8), and the real Azure vTPM capture moved with them so the
code and the evidence validating it stay in one place. agent-manifest runs that
vector on every one of its PRs; `docs/testing/hardware-validation.md` here keeps
the capture provenance and now points at where the vector lives.

What is left to test here is cMCP's own layer: that `verify_quote_signature`
shapes a `(verified, details)` pair correctly, that it fails closed on inputs
agent-manifest rejects, and that the re-export keeps existing importers working.
The key below is generated per-run rather than captured, because none of these
assertions are about the wire format any more.
"""

from __future__ import annotations

import struct

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from cmcp_verify.tpm import parse_tpmt_signature, verify_quote_signature

_ALG_RSASSA = 0x0014
_ALG_SHA256 = 0x000B
_TPM_GENERATED_VALUE = 0xFF544347


def _attest(nonce: bytes = b"\x01" * 32) -> bytes:
    """A minimal well-formed bare TPMS_ATTEST carrying `nonce` as extraData."""
    return (
        struct.pack(">I", _TPM_GENERATED_VALUE)
        + struct.pack(">H", 0x8018)  # TPM_ST_ATTEST_QUOTE
        + struct.pack(">H", 4) + b"name"  # qualifiedSigner
        + struct.pack(">H", len(nonce)) + nonce  # extraData
        + b"\x00" * 17  # clockInfo
        + b"\x00" * 8  # firmwareVersion
        + struct.pack(">I", 0)  # TPML_PCR_SELECTION count
        + struct.pack(">H", 32) + b"\x02" * 32  # pcrDigest
    )


def _signed(attest: bytes) -> tuple[bytes, bytes]:
    """Return (TPMT_SIGNATURE blob, AK public PEM) over `attest`."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raw = key.sign(attest, padding.PKCS1v15(), hashes.SHA256())
    blob = struct.pack(">HH", _ALG_RSASSA, _ALG_SHA256) + struct.pack(">H", len(raw)) + raw
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return blob, pem


def test_the_re_export_still_resolves() -> None:
    """Importers of cmcp_verify.tpm must keep working after the implementation
    moved to agent-manifest."""
    import agent_manifest

    assert parse_tpmt_signature is agent_manifest.parse_tpmt_signature


def test_a_valid_signature_verifies_and_reports_its_algorithm() -> None:
    attest = _attest()
    blob, pem = _signed(attest)

    verified, details = verify_quote_signature(attest, blob, pem)

    assert verified is True
    assert details["signature_algorithm"] == "rsassa"


def test_a_tampered_attest_is_rejected() -> None:
    attest = _attest()
    blob, pem = _signed(attest)
    tampered = bytearray(attest)
    tampered[-1] ^= 0x01

    verified, details = verify_quote_signature(bytes(tampered), blob, pem)

    assert verified is False
    assert "does not verify" in details["signature_error"]


def test_a_different_key_does_not_verify() -> None:
    attest = _attest()
    blob, _ = _signed(attest)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    other_pem = other.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    verified, _details = verify_quote_signature(attest, blob, other_pem)

    assert verified is False


def test_an_unloadable_key_fails_closed() -> None:
    attest = _attest()
    blob, _ = _signed(attest)

    verified, details = verify_quote_signature(attest, blob, b"not a pem")

    assert verified is False
    assert "not loadable" in details["signature_error"]


@pytest.mark.parametrize(
    "blob",
    [
        b"\x00\x99\x00\x0b\x00\x04abcd",  # unsupported sigAlg
        struct.pack(">HH", _ALG_RSASSA, _ALG_SHA256) + struct.pack(">H", 400) + b"short",
    ],
    ids=["unsupported_algorithm", "truncated"],
)
def test_a_malformed_signature_blob_fails_closed(blob: bytes) -> None:
    """agent-manifest raises TpmVerificationError; cMCP must turn that into a
    reported failure rather than letting it escape to the caller."""
    verified, details = verify_quote_signature(_attest(), blob, b"")

    assert verified is False
    assert "signature_error" in details
