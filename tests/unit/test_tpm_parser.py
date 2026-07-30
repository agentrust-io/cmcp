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
