"""Known-answer and fail-closed tests for verifier-owned NV policy."""

from __future__ import annotations

import hashlib

import pytest

from cmcp_verify.nv_policy import (
    DEFAULT_MEASUREMENT_NV_INDEX,
    MEASUREMENT_NV_BASE_ATTRIBUTES,
    MEASUREMENT_NV_SIZE,
    MEASUREMENT_NV_WRITTEN_ATTRIBUTES,
    GatewayNvAppraisalPolicy,
    measurement_nv_name,
    measurement_nv_public_bytes,
)

GATEWAY_DIGEST = hashlib.sha256(b"gateway").digest()


def test_production_public_templates_are_exact_known_answers() -> None:
    assert MEASUREMENT_NV_BASE_ATTRIBUTES == 0x02060042
    assert MEASUREMENT_NV_WRITTEN_ATTRIBUTES == 0x22060042
    assert MEASUREMENT_NV_SIZE == 32
    assert measurement_nv_public_bytes(written=False).hex() == ("01500432000b0206004200000020")
    assert measurement_nv_public_bytes(written=True).hex() == ("01500432000b2206004200000020")


def test_production_names_are_exact_known_answers() -> None:
    assert measurement_nv_name(written=False).hex() == (
        "000be0f2cbc7347cd042a540459b3bab3734601e3cf0ea72e140c46983c40a84fb14"
    )
    assert measurement_nv_name(written=True).hex() == (
        "000bd884eed008e17b8e06485bcf29a5f0e88ca44a4355d711fa2cafb368c3ff3763"
    )


def test_name_algorithm_and_hash_cover_complete_public_area() -> None:
    public = measurement_nv_public_bytes()
    assert measurement_nv_name() == b"\x00\x0b" + hashlib.sha256(public).digest()

    # Independent swtpm fixture public area.  This is deliberately not cMCP's
    # production policy because its handle and attributes differ.
    fixture_public = bytes.fromhex("01500018000b2002004200000020")
    fixture_name = b"\x00\x0b" + hashlib.sha256(fixture_public).digest()
    assert fixture_name.hex() == (
        "000bcf69802ad7625fffd515aecef934a1632ca6c7df36bf5a4e241d33701465a854"
    )


def test_policy_factory_binds_written_production_name_and_digest() -> None:
    policy = GatewayNvAppraisalPolicy.for_measurement_index(expected_gateway_digest=GATEWAY_DIGEST)
    assert policy.expected_index_name == measurement_nv_name(
        DEFAULT_MEASUREMENT_NV_INDEX, written=True
    )
    assert policy.expected_offset == 0
    assert policy.expected_size == 32
    assert policy.expected_gateway_digest == GATEWAY_DIGEST


@pytest.mark.parametrize("index", [0, 0x00FFFFFF, 0x02000000, 0xFFFFFFFF])
def test_non_nv_handles_are_rejected(index: int) -> None:
    with pytest.raises(ValueError, match="not a TPM NV handle"):
        measurement_nv_public_bytes(index)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("expected_index_name", b"\x00\x0b" + bytes(31), "SHA-256 TPM Name"),
        ("expected_index_name", b"\x00\x0c" + bytes(32), "SHA-256 TPM Name"),
        ("expected_index_name", bytearray(34), "must be bytes"),
        ("expected_offset", 1, "offset zero"),
        ("expected_offset", True, "must be an integer"),
        ("expected_size", 31, "32-byte extent"),
        ("expected_size", True, "must be an integer"),
        ("expected_gateway_digest", bytes(31), "must be 32 bytes"),
        ("expected_gateway_digest", bytearray(32), "must be bytes"),
    ],
)
def test_policy_rejects_malformed_or_unsupported_values(
    field: str, value: object, error: str
) -> None:
    values: dict[str, object] = {
        "expected_index_name": measurement_nv_name(),
        "expected_offset": 0,
        "expected_size": 32,
        "expected_gateway_digest": GATEWAY_DIGEST,
    }
    values[field] = value
    with pytest.raises((TypeError, ValueError), match=error):
        GatewayNvAppraisalPolicy(**values)  # type: ignore[arg-type]
