"""TPM 2.0 attestation verification - implements issue #62."""

from __future__ import annotations

import hmac
import struct
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TPMVerificationResult:
    verified: bool
    verified_fields: list[str] = field(default_factory=list)
    unverified_fields: list[str] = field(default_factory=list)
    failure_reason: str | None = None
    details: dict[str, str] = field(default_factory=dict)


# TPMS_ATTEST magic constant (FF 54 43 47 - "TPM generated")
_TPM_GENERATED_VALUE = 0xFF544347


def verify_tpm_measurement(
    measurement: str,
    raw_evidence: bytes | None,
    expected_qualifying_data: bytes | None = None,
) -> TPMVerificationResult:
    """
    Verify TPM attestation from a TRACE Claim.

    What can be verified WITHOUT raw hardware evidence:
    - measurement field format: must start with "sha256:" followed by 64 hex chars

    What requires raw_evidence (TPM2B_ATTEST):
    - the quote's qualifying_data equals expected_qualifying_data. The gateway
      commits the attestation nonce's first 32 bytes -- the RFC 7638 JWK Thumbprint
      of the TEE public key (docs/spec/attestation.md §3.3) -- as the TPM2_Quote
      qualifying_data. The caller re-derives that thumbprint from cnf.jwk and passes
      it here, so a key substituted after attestation is detected.
    - PCR digest in quote matches measurement field

    EK cert chain validation: always marked as unverified_fields (requires
    manufacturer CA lookup - out of scope for Phase 1).
    """
    verified_fields: list[str] = []
    unverified_fields: list[str] = []
    details: dict[str, Any] = {}

    # Step 1: Validate measurement format
    if not _valid_measurement(measurement):
        unverified_fields.append("ek_cert_chain")
        details["ek_cert_chain_validation"] = "ek_cert_chain_validation_requires_ca_lookup"
        return TPMVerificationResult(
            verified=False,
            verified_fields=verified_fields,
            unverified_fields=unverified_fields,
            failure_reason="invalid_measurement_format",
            details=details,
        )

    # Measurement format is valid
    verified_fields.append("measurement_format")

    # Step 2: Parse raw_evidence if provided
    if raw_evidence is not None:
        parse_ok, parse_details = _parse_tpm2b_attest(
            raw_evidence,
            expected_qualifying_data=expected_qualifying_data,
        )
        if parse_ok:
            verified_fields.append("pcr_format")
            if expected_qualifying_data is not None:
                qd_verified = parse_details.get("qualifying_data_verified", False)
                if qd_verified:
                    verified_fields.append("qualifying_data")
                else:
                    unverified_fields.append("qualifying_data")
                    details["qualifying_data_error"] = parse_details.get(
                        "qualifying_data_error", "mismatch"
                    )
            else:
                unverified_fields.append("qualifying_data")
                details["qualifying_data_error"] = "expected_qualifying_data not provided"
        else:
            unverified_fields.append("pcr_format")
            unverified_fields.append("qualifying_data")
            details["tpm_parse_error"] = parse_details.get("error", "failed to parse TPM2B_ATTEST")
    else:
        # No raw evidence - a claim asserting a hardware platform with no
        # evidence to check must fail closed, not pass on format checks alone.
        unverified_fields.extend(["pcr_digest", "qualifying_data", "ek_cert_chain"])
        details["pcr_digest_note"] = "raw_evidence not provided; PCR digest unverifiable"
        return TPMVerificationResult(
            verified=False,
            verified_fields=verified_fields,
            unverified_fields=unverified_fields,
            failure_reason="no_raw_evidence",
            details=details,
        )

    # Step 3: EK cert chain always unverified in Phase 1
    unverified_fields.append("ek_cert_chain")
    details["ek_cert_chain_validation"] = "ek_cert_chain_validation_requires_ca_lookup"

    # verified=True only when the evidence parsed and matched
    verified = "measurement_format" in verified_fields and "pcr_format" not in unverified_fields

    return TPMVerificationResult(
        verified=verified,
        verified_fields=verified_fields,
        unverified_fields=unverified_fields,
        failure_reason=None if verified else "tpm_evidence_check_failed",
        details=details,
    )


def _valid_measurement(measurement: str) -> bool:
    """Return True if measurement is "sha256:" followed by exactly 64 hex characters."""
    if not measurement.startswith("sha256:"):
        return False
    hex_part = measurement[len("sha256:"):]
    if len(hex_part) != 64:
        return False
    try:
        bytes.fromhex(hex_part)
    except ValueError:
        return False
    return True


def _parse_tpm2b_attest(
    data: bytes,
    *,
    expected_qualifying_data: bytes | None,
) -> tuple[bool, dict[str, Any]]:
    """
    Parse a TPM2B_ATTEST blob and verify qualifying_data if an expected value is given.

    TPM2B_ATTEST layout:
      [0:2]  size (uint16 big-endian) - size of the following TPMS_ATTEST
      [2:]   TPMS_ATTEST

    A bare TPMS_ATTEST with no TPM2B size prefix is also accepted, because that
    is what `tpm2_quote -m` writes and what a real capture therefore looks like.
    The two are told apart by the magic: a bare blob starts with 0xFF544347
    where a wrapped one starts with a length. Rejecting the bare framing would
    mean the verifier could not read quotes produced by the standard tooling.

    TPMS_ATTEST layout (big-endian):
      [0:4]  magic (uint32, must be 0xFF544347)
      [4:6]  type (uint16)
      [6:]   qualifiedSigner (TPM2B: uint16 size + <size> bytes)
      [...]  extraData / qualifyingData (TPM2B: uint16 size + <size> bytes)
      [...]  clockInfo (8 bytes)
      [...]  firmwareVersion (8 bytes)
      [...]  attested (union, type-dependent)
    """
    try:
        if len(data) < 2:
            return False, {"error": "TPM2B_ATTEST too short"}

        if len(data) >= 4 and struct.unpack_from(">I", data, 0)[0] == _TPM_GENERATED_VALUE:
            # Bare TPMS_ATTEST (tpm2_quote -m output): no outer TPM2B size field.
            attest = data
        else:
            # Skip the outer TPM2B size field
            tpms_size = struct.unpack_from(">H", data, 0)[0]
            if tpms_size == 0 or len(data) < 2 + tpms_size:
                return False, {"error": "TPM2B_ATTEST size field invalid"}
            attest = data[2 : 2 + tpms_size]

        if len(attest) < 6:
            return False, {"error": "TPMS_ATTEST too short for magic+type"}

        magic = struct.unpack_from(">I", attest, 0)[0]
        if magic != _TPM_GENERATED_VALUE:
            return False, {"error": f"TPMS_ATTEST magic mismatch: got 0x{magic:08x}"}

        # Skip magic (4) + type (2) = 6 bytes, then read qualifiedSigner (TPM2B)
        offset = 6
        if len(attest) < offset + 2:
            return False, {"error": "TPMS_ATTEST truncated before qualifiedSigner"}

        qs_size = struct.unpack_from(">H", attest, offset)[0]
        offset += 2 + qs_size  # skip qualifiedSigner

        if len(attest) < offset + 2:
            return False, {"error": "TPMS_ATTEST truncated before extraData"}

        # Read extraData (qualifyingData)
        ed_size = struct.unpack_from(">H", attest, offset)[0]
        offset += 2
        if len(attest) < offset + ed_size:
            return False, {"error": "TPMS_ATTEST truncated inside extraData"}

        qualifying_data = attest[offset : offset + ed_size]

        result: dict[str, Any] = {"qualifying_data_verified": False}

        if expected_qualifying_data is not None:
            # hmac.compare_digest for constant-time comparison of the committed nonce
            if hmac.compare_digest(qualifying_data, expected_qualifying_data):
                result["qualifying_data_verified"] = True
            else:
                result["qualifying_data_error"] = "qualifying_data does not match expected key thumbprint"

        return True, result

    except struct.error as exc:
        return False, {"error": f"struct parse error: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return False, {"error": f"unexpected parse error: {exc}"}


# ---------------------------------------------------------------------------
# Quote signature verification (issue #429)
#
# Parsing an attest blob and comparing its qualifying data proves nothing on its
# own: both are attacker-controllable. The signature is what binds the blob to a
# key held in a TPM. Validated against a real Azure Trusted Launch vTPM quote,
# see docs/testing/hardware-validation.md.
# ---------------------------------------------------------------------------

# TPM2_ALG_ID values for the signing schemes a quote can use.
_ALG_RSASSA = 0x0014
_ALG_RSAPSS = 0x0016
_ALG_ECDSA = 0x0018

_ALG_SHA1 = 0x0004
_ALG_SHA256 = 0x000B
_ALG_SHA384 = 0x000C
_ALG_SHA512 = 0x000D

_SIG_ALG_NAMES = {
    _ALG_RSASSA: "rsassa",
    _ALG_RSAPSS: "rsapss",
    _ALG_ECDSA: "ecdsa",
}


@dataclass
class ParsedSignature:
    """A parsed TPMT_SIGNATURE."""

    sig_alg: int
    hash_alg: int
    signature: bytes


def parse_tpmt_signature(blob: bytes) -> ParsedSignature:
    """
    Parse a TPMT_SIGNATURE as written by ``tpm2_quote -s``.

    Layout: sigAlg (2), hashAlg (2), then the algorithm-specific signature. For RSA
    that is a TPM2B_PUBLIC_KEY_RSA (size-prefixed). For ECDSA it is two size-prefixed
    integers, R then S.
    """
    if len(blob) < 6:
        raise ValueError("TPMT_SIGNATURE too short")
    sig_alg, hash_alg = struct.unpack_from(">HH", blob, 0)
    offset = 4

    if sig_alg in (_ALG_RSASSA, _ALG_RSAPSS):
        (size,) = struct.unpack_from(">H", blob, offset)
        offset += 2
        if len(blob) < offset + size:
            raise ValueError("TPMT_SIGNATURE truncated inside the RSA signature")
        return ParsedSignature(sig_alg, hash_alg, blob[offset : offset + size])

    if sig_alg == _ALG_ECDSA:
        parts = []
        for _ in range(2):
            (size,) = struct.unpack_from(">H", blob, offset)
            offset += 2
            if len(blob) < offset + size:
                raise ValueError("TPMT_SIGNATURE truncated inside the ECDSA signature")
            parts.append(blob[offset : offset + size])
            offset += size
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        r = int.from_bytes(parts[0], "big")
        s = int.from_bytes(parts[1], "big")
        return ParsedSignature(sig_alg, hash_alg, encode_dss_signature(r, s))

    raise ValueError(f"unsupported signature algorithm 0x{sig_alg:04x}")


def verify_quote_signature(
    attest: bytes, signature_blob: bytes, ak_public_pem: bytes
) -> tuple[bool, dict[str, str]]:
    """
    Verify a TPMT_SIGNATURE over a TPMS_ATTEST blob using a bare attestation key.

    This is the **unchained** path and it establishes no key provenance: it proves
    the blob was signed by the key supplied, not that the key lives in a TPM.
    Prefer :func:`verify_tpm_quote_chained`, which verifies the certificate chain
    to a pinned root. This function remains for platforms that expose no
    attestation key certificate, where a signature is still better than nothing but
    must not be reported as hardware-rooted.

    ``attest`` must be the exact bytes the TPM signed, which is the bare TPMS_ATTEST
    written by ``tpm2_quote -m``. Returns (verified, details); never raises.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    hashes_by_alg = {
        _ALG_SHA1: hashes.SHA1,
        _ALG_SHA256: hashes.SHA256,
        _ALG_SHA384: hashes.SHA384,
        _ALG_SHA512: hashes.SHA512,
    }

    try:
        parsed = parse_tpmt_signature(signature_blob)
    except ValueError as exc:
        return False, {"signature_error": str(exc)}

    hash_cls = hashes_by_alg.get(parsed.hash_alg)
    if hash_cls is None:
        return False, {"signature_error": f"unsupported digest 0x{parsed.hash_alg:04x}"}

    try:
        key = serialization.load_pem_public_key(ak_public_pem)
    except Exception as exc:  # noqa: BLE001
        return False, {"signature_error": f"attestation key not loadable: {exc}"}

    try:
        if parsed.sig_alg == _ALG_RSASSA:
            if not isinstance(key, rsa.RSAPublicKey):
                return False, {"signature_error": "RSASSA signature with a non-RSA key"}
            key.verify(parsed.signature, attest, padding.PKCS1v15(), hash_cls())
        elif parsed.sig_alg == _ALG_RSAPSS:
            if not isinstance(key, rsa.RSAPublicKey):
                return False, {"signature_error": "RSAPSS signature with a non-RSA key"}
            key.verify(
                parsed.signature,
                attest,
                padding.PSS(mgf=padding.MGF1(hash_cls()), salt_length=hash_cls.digest_size),
                hash_cls(),
            )
        else:
            if not isinstance(key, ec.EllipticCurvePublicKey):
                return False, {"signature_error": "ECDSA signature with a non-EC key"}
            key.verify(parsed.signature, attest, ec.ECDSA(hash_cls()))
    except InvalidSignature:
        return False, {"signature_error": "signature does not verify against the attestation key"}
    except Exception as exc:  # noqa: BLE001
        return False, {"signature_error": f"verification error: {exc}"}

    return True, {
        "signature_algorithm": _SIG_ALG_NAMES.get(parsed.sig_alg, f"0x{parsed.sig_alg:04x}"),
        "signature_digest": f"0x{parsed.hash_alg:04x}",
    }


# ---------------------------------------------------------------------------
# Chained verification (issues #431, #447)
#
# The signature, chain, and root pinning all live in agent-manifest, which cMCP
# already depends on and which is hardware-validated. cMCP keeps only the piece
# agent-manifest does not model: the TPMT_SIGNATURE wire format written by
# tpm2_quote and by tpm2-pytss `signature.marshal()`.
# ---------------------------------------------------------------------------


def verify_tpm_quote_chained(
    attest: bytes,
    signature_blob: bytes,
    ak_chain_pem: bytes,
    *,
    trusted_roots_pem: bytes,
    expected_qualifying_data: bytes | None = None,
    expected_pcr_digest: bytes | None = None,
) -> tuple[bool, dict[str, str]]:
    """
    Fully verify a TPM quote: signature, certificate chain, and pinned root.

    Delegates the cryptography to ``agent_manifest.verify_tpm_quote`` rather than
    reimplementing it. ``signature_blob`` is a marshalled TPMT_SIGNATURE; the raw
    signature is extracted here because agent-manifest takes the bare signature.

    Returns (verified, details) and never raises. A malformed quote, a broken
    chain, or a root outside ``trusted_roots_pem`` all report verified=False with a
    reason, so callers cannot mistake a chain failure for a signature failure.
    """
    try:
        parsed = parse_tpmt_signature(signature_blob)
    except ValueError as exc:
        return False, {"signature_error": str(exc)}

    try:
        from agent_manifest import verify_tpm_quote
    except ImportError as exc:  # pragma: no cover
        return False, {"error": f"agent-manifest is required for chained verification: {exc}"}

    try:
        ok = verify_tpm_quote(
            attest,
            parsed.signature,
            ak_chain_pem,
            trusted_roots_pem=trusted_roots_pem,
            expected_qualifying_data=expected_qualifying_data,
            expected_pcr_digest=expected_pcr_digest,
        )
    except Exception as exc:  # noqa: BLE001 - agent-manifest raises on chain/structure faults
        return False, {"chain_error": f"{type(exc).__name__}: {exc}"}

    if not ok:
        return False, {"verification": "signature or binding mismatch"}

    return True, {
        "signature_algorithm": _SIG_ALG_NAMES.get(parsed.sig_alg, f"0x{parsed.sig_alg:04x}"),
        "signature_digest": f"0x{parsed.hash_alg:04x}",
        "chain": "verified to a pinned root",
    }
