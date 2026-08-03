"""TPM 2.0 attestation verification - implements issue #62.

The wire formats live in agent-manifest and are imported, not reimplemented:
``parse_tpm_quote`` handles both attest framings and ``parse_tpmt_signature``
unwraps the signature that ``tpm2_quote -s`` writes. cMCP keeps only what is
genuinely its own, which is the ``TPMVerificationResult`` shaping and the
verified/unverified field accounting. ``ParsedSignature`` and
``parse_tpmt_signature`` are re-exported so existing importers of
``cmcp_verify.tpm`` keep working.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agent_manifest import (
    ParsedSignature,
    TpmVerificationError,
    parse_tpm_quote,
    parse_tpmt_signature,
)

__all__ = [
    "ParsedSignature",
    "TPMVerificationResult",
    "parse_tpmt_signature",
    "verify_ak_ek_chain",
    "verify_quote_signature",
    "verify_tpm_measurement",
    "verify_tpm_quote_chained",
]


@dataclass
class TPMVerificationResult:
    verified: bool
    verified_fields: list[str] = field(default_factory=list)
    unverified_fields: list[str] = field(default_factory=list)
    failure_reason: str | None = None
    details: dict[str, str] = field(default_factory=dict)


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

    EK cert chain validation: always marked as unverified_fields here, because
    this function sees no certificates. :func:`verify_ak_ek_chain` is what
    establishes it, and ``verify_trace_claim`` clears this field's unverified
    note when that succeeds.
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
    Parse an attest blob and verify qualifying_data if an expected value is given.

    Both framings are handled by ``agent_manifest.parse_tpm_quote``: the bare
    ``TPMS_ATTEST`` that ``tpm2_quote -m`` writes, and the size-prefixed
    ``TPM2B_ATTEST`` other producers write. What stays here is the ``(ok, details)``
    shaping that :class:`TPMVerificationResult` needs; the layout itself is shared
    so a fix found on hardware lands once rather than three times.
    """
    try:
        quote = parse_tpm_quote(data)
    except TpmVerificationError as exc:
        return False, {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return False, {"error": f"unexpected parse error: {exc}"}

    result: dict[str, Any] = {"qualifying_data_verified": False}

    if expected_qualifying_data is not None:
        # hmac.compare_digest for constant-time comparison of the committed nonce
        if hmac.compare_digest(quote.qualifying_data, expected_qualifying_data):
            result["qualifying_data_verified"] = True
        else:
            result["qualifying_data_error"] = (
                "qualifying_data does not match expected key thumbprint"
            )

    return True, result


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

    # Typed as a factory rather than type[HashAlgorithm]: the latter makes mypy read
    # hash_cls() below as instantiating the abstract base class.
    hashes_by_alg: dict[int, Callable[[], hashes.HashAlgorithm]] = {
        _ALG_SHA1: hashes.SHA1,
        _ALG_SHA256: hashes.SHA256,
        _ALG_SHA384: hashes.SHA384,
        _ALG_SHA512: hashes.SHA512,
    }

    try:
        parsed = parse_tpmt_signature(signature_blob)
    except TpmVerificationError as exc:
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
                # DIGEST_LENGTH is the salt length this previously computed as
                # hash_cls.digest_size; same value, and it types correctly.
                padding.PSS(mgf=padding.MGF1(hash_cls()), salt_length=padding.PSS.DIGEST_LENGTH),
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


# TCG OIDs that say what a certificate is for. An Endorsement Key certificate is
# the manufacturer's statement that a specific key is resident in a specific TPM,
# so it is the hop that turns "signed by a certified key" into "signed by a TPM".
#
# The EKU alone does NOT identify an EK. Azure's real vTPM chain carries
# 2.23.133.8.1 on its *intermediate CAs* -- there it means "this CA may issue EK
# certificates", not "this is an EK". Keying on the OID by itself reports
# ek_cert_chain verified on a chain with no EK in it, which is a false claim of
# hardware-backed verification. A genuine EK certificate is an end-entity
# certificate, so ``ca=False`` in basicConstraints is required as well.
_TCG_EK_CERTIFICATE = "2.23.133.8.1"
_TCG_AIK_CERTIFICATE = "2.23.133.8.3"


def verify_ak_ek_chain(
    ak_chain_pem: bytes,
    *,
    trusted_ca_pem: bytes,
    ek_chain_pem: bytes | None = None,
) -> tuple[bool, list[str], str | None]:
    """Verify AK -> EK -> manufacturer CA with the CA pinned by the caller.

    Mirrors :func:`cmcp_verify.sev_snp.verify_vcek_chain`: a thin cMCP wrapper
    that delegates the actual path building to agent-manifest's shared,
    algorithm-agnostic ``verify_cert_chain`` and pins the root by fingerprint.
    (Issue #370 named ``_cert_signed_by`` in ``sev_snp.py``; that helper was
    replaced by the shared verifier in the agent-manifest 0.5 refactor, so this
    reuses its successor rather than reviving a deleted private function.)

    Issue #370 asks for "AK->EK and EK->manufacturer-CA". Only the second half
    is a certificate path, and the split matters:

    * ``ak_chain_pem`` -- AK -> ... -> pinned CA. Establishes
      ``ak_cert_chain``: the attestation key is certified by a path the
      operator's root anchors.
    * ``ek_chain_pem`` -- the Endorsement Key certificate and its own path to
      the pinned CA, supplied separately. Establishes ``ek_cert_chain``: this
      EK is a genuine one the manufacturer vouched for.

    **AK->EK is deliberately not attempted here, because it is not a
    certificate link.** An EK is a restricted *decryption* key: it cannot sign,
    so it cannot issue an AK certificate, and an end-entity EK can never appear
    in the AK's issuance path. TPM 2.0 binds an AK to an EK by credential
    activation (``TPM2_MakeCredential`` / ``TPM2_ActivateCredential``), a
    challenge-response the verifier runs. That is blocker (3) on the issue and
    remains an open design decision. Verifying both chains here proves each key
    is individually certified; it does not prove they live in the same TPM.

    A supplied EK chain must present a real end-entity EK certificate: the TCG
    EK EKU **and** ``ca=False``. The EKU alone is not enough -- Azure's vTPM
    intermediate CAs carry ``2.23.133.8.1`` to mean "may issue EK
    certificates", and accepting that would report ``ek_cert_chain`` verified
    for a chain holding no EK at all.

    Returns ``(ok, established_links, reason)`` and never raises. A supplied
    but invalid EK chain fails the whole call rather than downgrading, so bad
    material is never silently ignored.
    """
    from agent_manifest import verify_cert_chain
    from cryptography import x509

    try:
        chain = x509.load_pem_x509_certificates(ak_chain_pem)
    except Exception as exc:  # noqa: BLE001
        return False, [], f"AK cert chain is not parseable: {exc}"
    if not chain:
        return False, [], "AK cert chain contained no certificate"

    try:
        roots = x509.load_pem_x509_certificates(trusted_ca_pem)
    except Exception as exc:  # noqa: BLE001
        return False, [], f"trusted_tpm_ca_pem is not parseable: {exc}"
    if not roots:
        return False, [], "trusted_tpm_ca_pem contained no certificate"

    try:
        verify_cert_chain(chain, roots)
    except Exception as exc:  # noqa: BLE001 - CertChainError or parse fault -> fail closed
        return False, [], str(exc)

    established = ["ak_cert_chain"]

    if ek_chain_pem is not None:
        try:
            ek_chain = x509.load_pem_x509_certificates(ek_chain_pem)
        except Exception as exc:  # noqa: BLE001
            return False, [], f"EK cert chain is not parseable: {exc}"
        if not ek_chain:
            return False, [], "EK cert chain contained no certificate"
        if not _is_endorsement_key_cert(ek_chain[0]):
            return False, [], (
                "EK chain leaf is not an end-entity Endorsement Key certificate "
                "(needs TCG EK EKU 2.23.133.8.1 and ca=False)"
            )
        try:
            verify_cert_chain(ek_chain, roots)
        except Exception as exc:  # noqa: BLE001
            return False, [], f"EK chain does not reach the pinned CA: {exc}"
        established.append("ek_cert_chain")

    return True, established, None


def _is_endorsement_key_cert(cert: Any) -> bool:
    """True only for an end-entity certificate bearing the TCG EK EKU.

    Both conditions are load-bearing. The EKU alone matches Azure's issuing CAs,
    which advertise it as a permission to issue EK certificates; requiring
    ``ca=False`` keeps a CA from being counted as an endorsement of a TPM.
    """
    return _has_eku(cert, _TCG_EK_CERTIFICATE) and not _is_ca(cert)


def _is_ca(cert: Any) -> bool:
    """True when basicConstraints marks *cert* as a CA. Absent extension: not a CA."""
    from cryptography import x509

    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False
    except Exception:  # noqa: BLE001
        # Unreadable constraints: treat as a CA so it cannot pass as an EK.
        return True


def _has_eku(cert: Any, oid_dotted: str) -> bool:
    """True when *cert* carries *oid_dotted* in its extended key usage."""
    from cryptography import x509

    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    except Exception:  # noqa: BLE001 - a malformed extension is not an endorsement
        return False
    return any(usage.dotted_string == oid_dotted for usage in eku)


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
    except TpmVerificationError as exc:
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
