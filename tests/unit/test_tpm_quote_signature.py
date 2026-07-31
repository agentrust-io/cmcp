"""Quote signature verification, exercised against a real Azure vTPM capture.

The vector below was produced on 2026-07-31 on a Standard_D2s_v5 Azure VM with
Trusted Launch, vTPM and secure boot enabled, Ubuntu 24.04, TPM manufacturer MSFT.
The AK was created with tpm2_createek followed by tpm2_createak (RSA, RSASSA,
SHA-256) and the quote taken over PCRs 0-7 under a fresh 32-byte nonce.

Unlike the SEV-SNP captures, this vector is committed. It carries no per-CPU
hardware identifier: the AK public key belongs to a virtual TPM in a VM that no
longer exists, and the PCR values describe a stock Ubuntu image. Committing it
means signature verification is exercised on every PR rather than only when
someone sets a fixture directory.
"""

from __future__ import annotations

import base64

import pytest

from cmcp_verify.tpm import parse_tpmt_signature, verify_quote_signature

# Bare TPMS_ATTEST as written by `tpm2_quote -m`.
QUOTE_ATTEST = base64.b64decode(
    "/1RDR4AYACIAC1Gr2BpHLuEP6q3wUzFvxZPNyfm9bw98RBelxxduCCr7ACBJgPpvWQ1l+6Fc3u8LC7Au"
    "jPFVBEcFsa8HAb+gsuMjlgAAAAAAAeu7AAAAAwAAAAABICADEgASAAQAAAABAAsD/wAAACDUvEYCCXOU"
    "AOzy8r898/XnrH99z1VrFNtVJDUg6kRSag=="
)

# TPMT_SIGNATURE as written by `tpm2_quote -s`.
QUOTE_SIGNATURE = base64.b64decode(
    "ABQACwEASCi0Ht6m6zPVnt4HXAahI4V4DV9nHbjWCJT0kYZVtUUS7BLmv7pt/dY2tNjWTJXAZKXJCX5i"
    "43eo53eVzKjHN3AzFdvkLEK/ahjEQ2/D+Frb+sLe0FlfhvzgfgUyoQCDs9krmCnMy18fDjxOSO+Nm2uy"
    "Wyg38ZTUpR1fUmjb68n9WHbPR3QZV9nNI4G0IW3AgRhcHZ7gmb9WJdLLSRdzfFJ7wDWEsAFcrtGiycc0"
    "iRXbCOBh0xTeDTlIWn9ljEYTvDlr8duW3c2fT08ZcV4vxJA6Wa8cr1QQjpd6s1/UO0XaYXneCHxoGI1u"
    "fbEoR4QA3qTPYNCSKNgyHH9GdV1stg=="
)

AK_PUBLIC_PEM = base64.b64decode(
    "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFN"
    "SUlCQ2dLQ0FRRUF5K3pCVWdBQTcvZW5CMEdyWmQrdgo4OFgvd3F0U2VKZ2dCczBZU0lkcW5HLzF4SjNy"
    "MEpTc1hyZnJkSkpnU1BwL2t4bzY5eWVtMlhjUlBiVGIzbHQwCjJsakVyaTZlUjhjbEt5RmNFUFFMbUZC"
    "Qmg3RU5Lai9KV3FnWnJINHhLdW93Y1BlR0ltajJ2S1hlV21LclVmb1gKVU1wdmI3eTUyeTJpNU4vTERQ"
    "UUcrYnI5NFhyZlNQNFNKTmVJKzlWUUM1Q1ZzRDM1QmZEZncwOHNYNGd6dG5FSwp4SUpyZGFVRUgxRjFs"
    "MkxPUjJoT0FQcjI5MmxrYUlvdTVoNHF6Y3hwbm5NTTN1djF6Q2Y1ZU5rZ2QwZ1FLdUllCjZ2T2JMcStT"
    "ZURPWndmYzBTSzRIUjBRVEtNcnhEbSs5eEdnU3ZYeUlFVnVTOExwZzBsZGRYU1Uzd0xpUU5Td1EKOHdJ"
    "REFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
)

NONCE = bytes.fromhex("4980fa6f590d65fba15cdeef0b0bb02e8cf155044705b1af0701bfa0b2e32396")


def test_parses_a_real_tpmt_signature() -> None:
    parsed = parse_tpmt_signature(QUOTE_SIGNATURE)

    assert parsed.sig_alg == 0x0014  # TPM_ALG_RSASSA
    assert parsed.hash_alg == 0x000B  # TPM_ALG_SHA256
    assert len(parsed.signature) == 256


def test_real_hardware_quote_signature_verifies() -> None:
    verified, details = verify_quote_signature(QUOTE_ATTEST, QUOTE_SIGNATURE, AK_PUBLIC_PEM)

    assert verified is True
    assert details["signature_algorithm"] == "rsassa"


def test_the_quote_carries_the_nonce_it_was_taken_under() -> None:
    """extraData sits after the qualifiedSigner name; the signature is what makes it
    meaningful, since both fields are otherwise attacker-controllable."""
    assert NONCE in QUOTE_ATTEST


@pytest.mark.parametrize("flip", [0, 40, -1])
def test_a_tampered_attest_is_rejected(flip: int) -> None:
    tampered = bytearray(QUOTE_ATTEST)
    tampered[flip] ^= 0x01

    verified, details = verify_quote_signature(bytes(tampered), QUOTE_SIGNATURE, AK_PUBLIC_PEM)

    assert verified is False
    assert "does not verify" in details["signature_error"]


def test_a_tampered_signature_is_rejected() -> None:
    tampered = bytearray(QUOTE_SIGNATURE)
    tampered[-1] ^= 0x01

    verified, _ = verify_quote_signature(QUOTE_ATTEST, bytes(tampered), AK_PUBLIC_PEM)

    assert verified is False


def test_a_different_key_does_not_verify() -> None:
    """A quote is only evidence if it verifies under the key the relying party expects."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    other_pem = other.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    verified, _ = verify_quote_signature(QUOTE_ATTEST, QUOTE_SIGNATURE, other_pem)

    assert verified is False


def test_an_unloadable_key_fails_closed() -> None:
    verified, details = verify_quote_signature(QUOTE_ATTEST, QUOTE_SIGNATURE, b"not a pem")

    assert verified is False
    assert "not loadable" in details["signature_error"]


def test_unsupported_signature_algorithm_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported signature algorithm"):
        parse_tpmt_signature(b"\x00\x99\x00\x0b\x00\x04abcd")


def test_truncated_signature_is_rejected() -> None:
    with pytest.raises(ValueError, match="truncated"):
        parse_tpmt_signature(QUOTE_SIGNATURE[:20])
