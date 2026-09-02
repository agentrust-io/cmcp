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
TPM-signed, and the verifier applies a locally configured NV policy before it
checks::

    post_contents == H(pre_contents || expected_gateway_digest)

The policy supplies the expected signed Name, offset, extent size, and gateway
digest; none of those authorization inputs comes from the evidence envelope.
The Name commits the configured handle and complete ``TPMS_NV_PUBLIC`` template.
This proves that the accepted AK signed two states of the configured index whose
values have the expected extend relation. The signed phase bindings identify the
states' roles; they do not prove wall-clock adjacency, exclude intervening TPM
operations, or establish the history behind ``pre_contents``. Those properties
would require a stronger protocol or verifier-side state.

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

cMCP keeps the gateway-specific policy: the two-certify phase bindings, exact
signed index Name and byte range, expected gateway digest, and extend relation. It
also preserves the public
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

from cmcp_verify.nv_policy import GatewayNvAppraisalPolicy

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
    policy: GatewayNvAppraisalPolicy | None = None,
    expected_gateway_digest: bytes | None = None,
) -> NvCertifyResult:
    """Appraise a gateway-measurement certify pair. Never raises.

    ``policy`` is mandatory trusted verifier configuration.  In particular, a
    digest carried by the evidence cannot stand in for a full policy because two
    valid signatures over the same attacker-selected NV Name only prove internal
    consistency.  ``expected_gateway_digest`` remains as a compatibility
    consistency check for callers migrating to ``policy``; it can never authorize
    evidence without the full policy.

    Fail-closed order: validate policy, parse the envelope and signed structures,
    verify the AK chain and both signatures, check phase bindings, bind both signed
    Names and byte ranges to policy, and finally check the extend relation. Every
    step must pass; ``verified=True`` means the accepted AK signed both 32-byte
    values for the configured written NV public area at offset zero and the second
    is the first extended by the configured gateway digest.
    """
    verified: list[str] = []
    details: dict[str, str] = {}

    def fail(reason: str, **extra: str) -> NvCertifyResult:
        details.update(extra)
        return NvCertifyResult(
            verified=False, failure_reason=reason, verified_fields=verified, details=details
        )

    # 0. Authorization inputs.  These are verifier-owned and must be complete
    # before evidence is inspected.  Revalidate even a frozen instance at the
    # trust boundary so abnormal construction cannot bypass the invariants.
    if policy is None:
        return fail("missing_nv_policy")
    if type(policy) is not GatewayNvAppraisalPolicy:
        return fail("invalid_nv_policy", error="policy has an unsupported type")
    try:
        policy.validate()
    except (TypeError, ValueError) as exc:
        return fail("invalid_nv_policy", error=str(exc))
    if type(expected_nonce) is not bytes or len(expected_nonce) not in {32, 64}:
        return fail(
            "invalid_expected_nonce",
            error="expected_nonce must be a 32- or 64-byte verifier challenge",
        )
    if expected_gateway_digest is not None:
        if type(expected_gateway_digest) is not bytes or len(expected_gateway_digest) != 32:
            return fail(
                "invalid_legacy_gateway_digest",
                error="expected_gateway_digest must be 32 bytes",
            )
        if not hmac.compare_digest(expected_gateway_digest, policy.expected_gateway_digest):
            return fail("gateway_digest_parameter_mismatch")
    verified.append("policy")

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
    # This proves binding to the caller-supplied transcript nonce. Freshness also
    # requires the surrounding protocol to issue that nonce freshly and reject its
    # reuse, which this stateless primitive cannot establish on its own.
    verified.append("transcript_binding")

    # 6. Bind both signed Names and exact certified ranges to verifier policy.
    # Comparing the Names only with each other would authorize any index chosen
    # by a caller able to use the accepted AK.
    for label, certification in (("pre", pre), ("post", post)):
        if not hmac.compare_digest(certification.index_name, policy.expected_index_name):
            return fail(
                "nv_index_name_mismatch",
                which=label,
                actual_index=certification.index_name.hex()[:32],
                expected_index=policy.expected_index_name.hex()[:32],
            )
        if certification.offset != policy.expected_offset:
            return fail(
                "nv_offset_mismatch",
                which=label,
                actual=str(certification.offset),
                expected=str(policy.expected_offset),
            )
        if len(certification.nv_contents) != policy.expected_size:
            return fail(
                "nv_extent_size_mismatch",
                which=label,
                actual=str(len(certification.nv_contents)),
                expected=str(policy.expected_size),
            )
    verified.append("nv_policy")

    # 7. The claimed digest must match policy.  The envelope copy is transport
    # metadata only and cannot select what code measurement is authorized.
    if not hmac.compare_digest(claimed_digest, policy.expected_gateway_digest):
        return fail(
            "gateway_digest_mismatch",
            claimed=claimed_digest.hex(),
            expected=policy.expected_gateway_digest.hex(),
        )

    # 8. The extend relation. This is the step that makes the pair meaningful.
    digest = policy.expected_gateway_digest
    if not hmac.compare_digest(post.nv_contents, hashlib.sha256(pre.nv_contents + digest).digest()):
        return fail(
            "extend_relation_broken",
            pre=pre.nv_contents.hex(),
            post=post.nv_contents.hex(),
            digest=digest.hex(),
        )
    verified.append("extend_relation")

    details["index_name"] = post.index_name.hex()
    details["nv_contents"] = post.nv_contents.hex()
    return NvCertifyResult(verified=True, verified_fields=verified, details=details)
