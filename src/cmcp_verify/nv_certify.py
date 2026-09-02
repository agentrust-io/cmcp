"""Verify a TPM2_NV_Certify pair proving the gateway measurement (#432).

The gateway is measured into a ``TPM_NT_EXTEND`` NV index at startup
(:mod:`cmcp_runtime.tee.measurement`). That index value travels as an ordinary NV
read, which no signature covers, so on its own it is a local integrity control: a
compromised gateway could report any value. ``TPM2_NV_Certify`` fixes that by
having the TPM itself sign a ``TPMS_ATTEST`` structure over the index contents.

## Why two certifies

Extends accumulate and NV is persistent, so after N gateway starts the index is a
hash chain over all N digests rather than ``H(0 || digest)``. There is no absolute
value a verifier could expect. ``TPM2_NV_Certify`` signs only the *current* value
and cannot attest to a previous one, so a single certify is uncheckable.

The collector therefore certifies, extends, and certifies again. Both values are
TPM-signed, and the verifier checks::

    post_contents == H(pre_contents || expected_gateway_digest)

Nothing is collector-asserted and the verifier holds no state. This proves that
this gateway extended exactly this digest. It deliberately does not prove the
history behind ``pre_contents``, which would require the verifier to remember
prior attestations.

The two blobs are domain-separated in their qualifying data (``pre`` / ``post``)
rather than distinguished by position, so each blob's role is signed. Swapping them
would already fail the chain check, but making the role explicit means a verifier
never has to infer it from ordering.

## Boundary with agent-manifest

Agent Manifest owns the TPM wire formats: ``parse_tpm_nv_certify`` parses the
signed common header and the ``TPMS_NV_CERTIFY_INFO`` union, accepts bare
``TPMS_ATTEST`` and size-prefixed ``TPM2B_ATTEST`` transport framing, and requires
the union payload to consume the complete inner structure. Its returned
``attest.raw`` is the exact inner byte range signed by the attestation key.

cMCP keeps the gateway-specific policy: the two-certify phase bindings, same-index
check, expected gateway digest, and extend relation. It also preserves the public
``parse_nv_certify`` compatibility adapter and performs signature verification
against the certified AK. Certificate-chain and TPM signature-envelope parsing are
delegated to Agent Manifest as well.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agent_manifest import TPM_ST_ATTEST_NV as _TPM_ST_ATTEST_NV
from agent_manifest import (
    TpmNvCertify,
    TpmVerificationError,
    parse_tpm_nv_certify,
    parse_tpmt_signature,
)

# Preserve the module-level constant imported by existing cMCP callers/tests while
# taking its value from the canonical wire-format library.
TPM_ST_ATTEST_NV = _TPM_ST_ATTEST_NV

# TPM2_ALG_ID digests a signature may use.
_ALG_SHA1 = 0x0004
_ALG_SHA256 = 0x000B
_ALG_SHA384 = 0x000C
_ALG_SHA512 = 0x000D

_ALG_RSASSA = 0x0014
_ALG_RSAPSS = 0x0016
_ALG_ECDSA = 0x0018

# Domain separators for the two certify calls, mirrored in the collector.
PHASE_PRE = b"pre"
PHASE_POST = b"post"
_QUALIFYING_PREFIX = b"cmcp-nv-certify-v1"

ENVELOPE_VERSION = 1


@dataclass
class NvCertifyResult:
    """Outcome of appraising a gateway-measurement certify pair."""

    verified: bool
    failure_reason: str | None = None
    verified_fields: list[str] = field(default_factory=list)
    details: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class NvCertifyInfo:
    """The parsed subset of a ``TPM_ST_ATTEST_NV`` structure."""

    qualifying_data: bytes
    index_name: bytes
    offset: int
    nv_contents: bytes


def certify_qualifying_data(nonce: bytes, phase: bytes) -> bytes:
    """Return the 32 bytes a certify call commits, bound to its phase.

    Length-prefixed rather than delimiter-joined, for the same reason the quote
    binding is: a delimiter lets a value containing it shift the split without
    changing the digest.
    """
    parts = [_QUALIFYING_PREFIX]
    for f in (nonce, phase):
        parts.append(len(f).to_bytes(4, "big"))
        parts.append(f)
    return hashlib.sha256(b"".join(parts)).digest()


def _parse_nv_certify(attest: bytes) -> TpmNvCertify:
    """Use Agent Manifest's parser while preserving cMCP's ``ValueError`` API."""
    try:
        return parse_tpm_nv_certify(attest)
    except TpmVerificationError as exc:
        raise ValueError(str(exc)) from exc


def _as_nv_certify_info(parsed: TpmNvCertify) -> NvCertifyInfo:
    return NvCertifyInfo(
        qualifying_data=parsed.attest.qualifying_data,
        index_name=parsed.info.index_name,
        offset=parsed.info.offset,
        nv_contents=parsed.info.nv_contents,
    )


def parse_nv_certify(attest: bytes) -> NvCertifyInfo:
    """Parse a bare or size-prefixed TPM NV certification.

    Wire parsing is delegated to :func:`agent_manifest.parse_tpm_nv_certify`.
    ``ValueError`` and the cMCP ``NvCertifyInfo`` return shape are retained for
    compatibility. A quote, truncated structure, or structure with undeclared
    trailing data is rejected rather than partially appraised.
    """
    return _as_nv_certify_info(_parse_nv_certify(attest))


def build_envelope(
    *,
    pre_attest: bytes,
    pre_signature: bytes,
    post_attest: bytes,
    post_signature: bytes,
    gateway_digest: bytes,
    components: dict[str, str],
) -> bytes:
    """Serialise a certify pair for transport in an attestation report."""
    return json.dumps(
        {
            "v": ENVELOPE_VERSION,
            "pre_attest": base64.b64encode(pre_attest).decode(),
            "pre_signature": base64.b64encode(pre_signature).decode(),
            "post_attest": base64.b64encode(post_attest).decode(),
            "post_signature": base64.b64encode(post_signature).decode(),
            "gateway_digest": gateway_digest.hex(),
            "components": components,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _verify_signature(ak_public: Any, parsed: Any, message: bytes) -> None:
    """Verify one TPM signature, raising on failure."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    # Typed as a factory rather than type[HashAlgorithm]: the latter makes mypy
    # read hash_cls() as instantiating the abstract base.
    digests: dict[int, Callable[[], hashes.HashAlgorithm]] = {
        _ALG_SHA1: hashes.SHA1,
        _ALG_SHA256: hashes.SHA256,
        _ALG_SHA384: hashes.SHA384,
        _ALG_SHA512: hashes.SHA512,
    }
    hash_cls = digests.get(parsed.hash_alg)
    if hash_cls is None:
        raise ValueError(f"unsupported digest {parsed.hash_alg:#06x}")

    if parsed.sig_alg == _ALG_RSASSA:
        if not isinstance(ak_public, rsa.RSAPublicKey):
            raise ValueError("RSASSA signature with a non-RSA attestation key")
        ak_public.verify(parsed.signature, message, padding.PKCS1v15(), hash_cls())
    elif parsed.sig_alg == _ALG_RSAPSS:
        if not isinstance(ak_public, rsa.RSAPublicKey):
            raise ValueError("RSAPSS signature with a non-RSA attestation key")
        ak_public.verify(
            parsed.signature,
            message,
            padding.PSS(mgf=padding.MGF1(hash_cls()), salt_length=padding.PSS.DIGEST_LENGTH),
            hash_cls(),
        )
    elif parsed.sig_alg == _ALG_ECDSA:
        if not isinstance(ak_public, ec.EllipticCurvePublicKey):
            raise ValueError("ECDSA signature with a non-EC attestation key")
        ak_public.verify(parsed.signature, message, ec.ECDSA(hash_cls()))
    else:
        raise ValueError(f"unsupported signature algorithm {parsed.sig_alg:#06x}")


def verify_gateway_measurement(
    envelope: bytes,
    *,
    ak_chain_pem: bytes,
    trusted_roots_pem: bytes,
    expected_nonce: bytes,
    expected_gateway_digest: bytes | None = None,
) -> NvCertifyResult:
    """Appraise a gateway-measurement certify pair. Never raises.

    Fail-closed order: parse, structure and type, AK chain to a pinned root, both
    signatures, the phase bindings, the index identity, and finally the extend
    relation. Every step must pass; ``verified=True`` means the TPM signed both
    values and the second is the first extended by the expected gateway digest.
    """
    verified: list[str] = []
    details: dict[str, str] = {}

    def fail(reason: str, **extra: str) -> NvCertifyResult:
        details.update(extra)
        return NvCertifyResult(
            verified=False, failure_reason=reason, verified_fields=verified, details=details
        )

    # 1. Envelope.
    try:
        payload = json.loads(envelope)
        if int(payload.get("v", 0)) != ENVELOPE_VERSION:
            return fail("unsupported_envelope_version", version=str(payload.get("v")))
        pre_attest = base64.b64decode(payload["pre_attest"])
        pre_sig = base64.b64decode(payload["pre_signature"])
        post_attest = base64.b64decode(payload["post_attest"])
        post_sig = base64.b64decode(payload["post_signature"])
        claimed_digest = bytes.fromhex(payload["gateway_digest"])
    except Exception as exc:  # noqa: BLE001
        return fail("malformed_envelope", error=f"{type(exc).__name__}: {exc}")
    verified.append("envelope")

    # 2. Structure and attest type.
    try:
        pre_parsed = _parse_nv_certify(pre_attest)
        post_parsed = _parse_nv_certify(post_attest)
    except ValueError as exc:
        return fail("malformed_nv_certify", error=str(exc))
    pre = _as_nv_certify_info(pre_parsed)
    post = _as_nv_certify_info(post_parsed)
    verified.append("structure")

    # 3. AK certificate chain to a pinned root, delegated to agent-manifest.
    try:
        from agent_manifest import verify_cert_chain
        from cryptography import x509

        chain = x509.load_pem_x509_certificates(ak_chain_pem)
        roots = x509.load_pem_x509_certificates(trusted_roots_pem)
        if not chain:
            return fail("no_ak_chain")
        if not roots:
            return fail("no_trusted_roots")
        verify_cert_chain(chain, roots)
        ak_public = chain[0].public_key()
    except Exception as exc:  # noqa: BLE001
        return fail("ak_chain_invalid", error=f"{type(exc).__name__}: {exc}")
    verified.append("ak_chain")

    # 4. Both signatures, against the certified AK.
    try:
        for label, attestation, sig in (
            ("pre", pre_parsed, pre_sig),
            ("post", post_parsed, post_sig),
        ):
            parsed_signature = parse_tpmt_signature(sig)
            try:
                _verify_signature(ak_public, parsed_signature, attestation.attest.raw)
            except Exception as exc:  # noqa: BLE001
                return fail("signature_invalid", which=label, error=str(exc))
    except Exception as exc:  # noqa: BLE001
        return fail("malformed_signature", error=f"{type(exc).__name__}: {exc}")
    verified.append("signatures")

    # 5. Phase bindings: each blob's role is signed, not inferred from position.
    if not hmac.compare_digest(
        pre.qualifying_data, certify_qualifying_data(expected_nonce, PHASE_PRE)
    ):
        return fail("pre_binding_mismatch")
    if not hmac.compare_digest(
        post.qualifying_data, certify_qualifying_data(expected_nonce, PHASE_POST)
    ):
        return fail("post_binding_mismatch")
    verified.append("freshness")

    # 6. Same index in both, otherwise the pair proves nothing about one index.
    if not hmac.compare_digest(pre.index_name, post.index_name):
        return fail(
            "index_mismatch",
            pre_index=pre.index_name.hex()[:32],
            post_index=post.index_name.hex()[:32],
        )
    verified.append("index_identity")

    # 7. The extend relation. This is the step that makes the pair meaningful.
    digest = expected_gateway_digest if expected_gateway_digest is not None else claimed_digest
    if expected_gateway_digest is not None and not hmac.compare_digest(
        claimed_digest, expected_gateway_digest
    ):
        return fail(
            "gateway_digest_mismatch",
            claimed=claimed_digest.hex(),
            expected=expected_gateway_digest.hex(),
        )
    if not hmac.compare_digest(
        post.nv_contents, hashlib.sha256(pre.nv_contents + digest).digest()
    ):
        return fail(
            "extend_relation_broken",
            pre=pre.nv_contents.hex(),
            post=post.nv_contents.hex(),
            digest=digest.hex(),
        )
    verified.append("extend_relation")

    if expected_gateway_digest is None:
        details["gateway_digest_note"] = (
            "no expected digest supplied; the pair is internally consistent but the "
            "measurement was not compared against a known-good value"
        )

    details["index_name"] = post.index_name.hex()
    details["nv_contents"] = post.nv_contents.hex()
    return NvCertifyResult(verified=True, verified_fields=verified, details=details)
