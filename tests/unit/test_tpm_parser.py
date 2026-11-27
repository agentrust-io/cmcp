"""Unit tests for tpm2_pcrread output parsing."""

from __future__ import annotations

import re

import pytest

from cmcp_runtime.tee.tpm import _parse_tpm2_pcrread_output

# A realistic tpm2_pcrread block. PCR0 is all zeros (the common case for an unused
# PCR) and PCR1 and PCR3 begin with a zero digit.
PCRREAD_SAMPLE = """sha256:
  0 : 0x0000000000000000000000000000000000000000000000000000000000000000
  1 : 0x0AF7C1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E
  2 : 0xB1F2E3D4C5A697887766554433221100FFEEDDCCBBAA99887766554433221100
  3 : 0x00A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F
  4 : 0xC3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2
  5 : 0xD4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3
  6 : 0xE5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4
  7 : 0xF60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5
"""

EXPECTED_PCRS = [bytes.fromhex(m) for m in re.findall(r"0x([0-9A-Fa-f]{64})", PCRREAD_SAMPLE)]


def test_parser_returns_every_pcr_in_order() -> None:
    """Regression: stripping the 0x prefix with lstrip also removed leading zero
    digits, which dropped PCRs and shifted every later value into the wrong index."""
    parsed = _parse_tpm2_pcrread_output(PCRREAD_SAMPLE)

    assert len(parsed) == 8
    assert parsed == EXPECTED_PCRS


def test_parser_preserves_all_zero_and_leading_zero_values() -> None:
    parsed = _parse_tpm2_pcrread_output(PCRREAD_SAMPLE)

    # An all-zero PCR is a full-width digest, not a single 0x00 byte.
    assert parsed[0] == bytes(32)
    assert all(len(value) == 32 for value in parsed)
    assert parsed[1].hex().startswith("0af7")
    assert parsed[3].hex().startswith("00a1")


def test_parser_rejects_an_unparseable_value_instead_of_dropping_it() -> None:
    with pytest.raises(RuntimeError, match="unparseable"):
        _parse_tpm2_pcrread_output("sha256:\n  0 : 0xZZZZ\n")


def test_parser_rejects_an_empty_value() -> None:
    with pytest.raises(RuntimeError, match="empty"):
        _parse_tpm2_pcrread_output("sha256:\n  0 : 0x\n")


def _rows(bank: str, size: int, indices=range(8)) -> str:
    return f"{bank}:\n" + "".join(f"  {i} : 0x{'ab' * size}\n" for i in indices)


@pytest.mark.parametrize(
    "output, message",
    [
        (_rows("sha256", 32, [0, 1, 2, 3, 4, 5, 6, 6]), "PCR 6"),
        (_rows("sha256", 32, [0, 1, 2, 3, 4, 5, 6, 8]), "PCR 8"),
        (_rows("sha256", 32, range(7)), "expected PCRs 0-7"),
        (_rows("sha256", 1), "1 bytes"),
        (_rows("sha256", 32, range(7)) + "  7 : 0xab\n", "1 bytes"),
        (_rows("sha256", 20), "20 bytes"),
        (_rows("sha1", 20), "expected PCRs 0-7"),
        ("  0 : 0x" + "ab" * 32 + "\n", "expected PCRs 0-7"),
        (_rows("sha256", 32) + "garbage line\n", "unexpected line"),
    ],
    ids=[
        "duplicate", "out-of-range", "missing", "one-byte-digests", "one-short-digest",
        "sha1-size-in-sha256", "only-another-bank", "no-header", "stray-line",
    ],
)
def test_parser_refuses_anything_but_pcrs_0_to_7_of_the_bank(output: str, message: str) -> None:
    with pytest.raises(RuntimeError, match=message):
        _parse_tpm2_pcrread_output(output)


def test_parser_reads_only_the_requested_bank_in_index_order() -> None:
    reordered = "sha256:\n" + "".join(f"  {i} : 0x{i:02x}{'00' * 31}\n" for i in reversed(range(8)))
    output = _rows("sha1", 20) + reordered
    values = _parse_tpm2_pcrread_output(output)
    assert [v[0] for v in values] == list(range(8))
    assert _parse_tpm2_pcrread_output(output, "sha1") == [bytes.fromhex("ab" * 20)] * 8


def test_blank_lines_between_pcrs_are_skipped():
    output = "\n".join(["", "sha256:", "", *[f"  {i} : 0x" + "0a" * 32 + "\n" for i in range(8)], ""])
    assert _parse_tpm2_pcrread_output(output) == [b"\x0a" * 32] * 8
