"""Verifier-owned policy for cMCP's gateway-measurement NV index.

An NV certification signs the index ``Name``, not the handle or attributes as
separate fields.  The Name is ``nameAlg || H(TPMS_NV_PUBLIC)``.  A verifier that
only compares the two signed Names with each other therefore learns that both
certifications refer to *some* index, not that they refer to cMCP's configured
``TPM_NT_EXTEND`` index.

This module keeps the expected public template independent of TPM evidence and
of ``tpm2-pytss``.  The collector uses the same constants to validate an
existing index before use; the remote verifier computes the expected written
Name from them and requires both signed attestations to match it.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

# TPM handle and algorithm values from the TPM 2.0 structures specification.
DEFAULT_MEASUREMENT_NV_INDEX = 0x01500432
MEASUREMENT_NV_NAME_ALG = 0x000B  # TPM2_ALG_SHA256
MEASUREMENT_NV_SIZE = 32

# TPMA_NV bits in the public template created by measurement._define_extend_index.
_TPMA_NV_OWNERWRITE = 0x00000002
_TPMA_NV_TPM_NT_EXTEND = 0x00000040
_TPMA_NV_OWNERREAD = 0x00020000
_TPMA_NV_AUTHREAD = 0x00040000
_TPMA_NV_NO_DA = 0x02000000
_TPMA_NV_WRITTEN = 0x20000000

MEASUREMENT_NV_BASE_ATTRIBUTES = (
    _TPMA_NV_OWNERWRITE
    | _TPMA_NV_TPM_NT_EXTEND
    | _TPMA_NV_OWNERREAD
    | _TPMA_NV_AUTHREAD
    | _TPMA_NV_NO_DA
)
MEASUREMENT_NV_WRITTEN_ATTRIBUTES = MEASUREMENT_NV_BASE_ATTRIBUTES | _TPMA_NV_WRITTEN


@dataclass(frozen=True, slots=True)
class GatewayNvAppraisalPolicy:
    """Verifier-owned authorization policy for one NV-certify appraisal.

    Every field is trusted configuration, never evidence copied from the
    transport envelope.  cMCP's construction certifies the complete 32-byte
    ``TPM_NT_EXTEND`` value at offset zero, so accepting any other range would
    authorize a different statement.

    ``expected_index_name`` is the TPM Name of the *written* public template.
    Binding the signed Name is what commits the attestations to the configured
    handle, name algorithm, attributes, authorization policy, and data size.
    """

    expected_index_name: bytes
    expected_offset: int
    expected_size: int
    expected_gateway_digest: bytes

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Reject malformed or unsupported policy values.

        The verifier calls this again at its trust boundary.  The repeat check
        is intentional: frozen dataclasses prevent ordinary mutation, but a
        security boundary should not rely on callers having constructed the
        object normally.
        """
        if type(self.expected_index_name) is not bytes:
            raise TypeError("expected_index_name must be bytes")
        if len(self.expected_index_name) != 34 or self.expected_index_name[:2] != struct.pack(
            ">H", MEASUREMENT_NV_NAME_ALG
        ):
            raise ValueError("expected_index_name must be a SHA-256 TPM Name")
        if type(self.expected_offset) is not int:
            raise TypeError("expected_offset must be an integer")
        if self.expected_offset != 0:
            raise ValueError("cMCP gateway appraisal requires offset zero")
        if type(self.expected_size) is not int:
            raise TypeError("expected_size must be an integer")
        if self.expected_size != MEASUREMENT_NV_SIZE:
            raise ValueError("cMCP gateway appraisal requires a 32-byte extent")
        if type(self.expected_gateway_digest) is not bytes:
            raise TypeError("expected_gateway_digest must be bytes")
        if len(self.expected_gateway_digest) != 32:
            raise ValueError("expected_gateway_digest must be 32 bytes")

    @classmethod
    def for_measurement_index(
        cls,
        *,
        expected_gateway_digest: bytes,
        index: int = DEFAULT_MEASUREMENT_NV_INDEX,
    ) -> GatewayNvAppraisalPolicy:
        """Build the exact policy for cMCP's written measurement index."""
        return cls(
            expected_index_name=measurement_nv_name(index, written=True),
            expected_offset=0,
            expected_size=MEASUREMENT_NV_SIZE,
            expected_gateway_digest=expected_gateway_digest,
        )


def measurement_nv_public_bytes(
    index: int = DEFAULT_MEASUREMENT_NV_INDEX, *, written: bool = True
) -> bytes:
    """Marshal the exact policy-authorized ``TPMS_NV_PUBLIC`` template.

    The authorization policy is deliberately empty because the collector
    defines an owner-authorized index.  ``written=True`` is the appraisal form:
    cMCP seeds a new extend index before its first certification, so every signed
    Name must include the TPM-managed ``TPMA_NV_WRITTEN`` state bit.
    """
    if not 0x01000000 <= index <= 0x01FFFFFF:
        raise ValueError(f"index is not a TPM NV handle: {index:#x}")
    attributes = MEASUREMENT_NV_WRITTEN_ATTRIBUTES if written else MEASUREMENT_NV_BASE_ATTRIBUTES
    # TPMS_NV_PUBLIC = nvIndex (UINT32), nameAlg (UINT16), attributes
    # (UINT32), authPolicy (TPM2B_DIGEST), dataSize (UINT16).
    return struct.pack(">IHIH", index, MEASUREMENT_NV_NAME_ALG, attributes, 0) + struct.pack(
        ">H", MEASUREMENT_NV_SIZE
    )


def measurement_nv_name(
    index: int = DEFAULT_MEASUREMENT_NV_INDEX, *, written: bool = True
) -> bytes:
    """Return the TPM Name for the policy-authorized NV public template."""
    public = measurement_nv_public_bytes(index, written=written)
    return struct.pack(">H", MEASUREMENT_NV_NAME_ALG) + hashlib.sha256(public).digest()
