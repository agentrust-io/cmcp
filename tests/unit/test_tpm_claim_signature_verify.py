"""TPM quote signature + AK chain wired into the claim path (issue #370).

The unit-level pieces already existed: ``verify_quote_signature`` and
``verify_tpm_quote_chained`` are covered by ``test_tpm_quote_signature.py`` and
``test_tpm_chained_verify.py``. What was missing is the wiring -- until this
change ``verify_trace_claim``'s tpm2 branch called only
``verify_tpm_measurement``, which takes no signature, so a forged TPMS_ATTEST
with the right magic and a matching ``qualifying_data`` reported
``hardware_attestation`` as verified. ``test_forged_attest_no_longer_reports_
hardware_attestation`` is that regression.

Mirrors ``test_snp_signature_verify.py``: synthetic chains plus a signed attest,
exercised valid / tampered / wrong-root / missing-chain.

The EK cases pin down where issue #370's "verify AK->EK" cannot be met as
written. An EK cannot sign, so it cannot issue an AK certificate and cannot
appear in the AK's issuance path; only ``EK->manufacturer-CA`` is a certificate
path, supplied as its own chain. Binding an AK to an EK needs credential
activation, which is the issue's open blocker (3).
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import struct
from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    _to_dict,
    canonical_json,
    generate_trace_claim,
)
from cmcp_runtime.tee.base import jwk_thumbprint
from cmcp_verify.tpm import verify_ak_ek_chain
from cmcp_verify.verify import ApprovedHashes, verify_trace_claim

POLICY_HASH = "sha256:" + "a" * 64
CATALOG_HASH = "sha256:" + "b" * 64
VALID_MEASUREMENT = "sha256:" + "c" * 64

_ALG_RSASSA = 0x0014
_ALG_SHA256 = 0x000B
_TPM_GENERATED_VALUE = 0xFF544347


# ── Synthetic CA -> AK chain ─────────────────────────────────────────────────


def _rsa() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn: str = "Synthetic TPM Manufacturer CA") -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _rsa()
    now = datetime.now(tz=UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


_TCG_EK_CERTIFICATE = x509.ObjectIdentifier("2.23.133.8.1")


def _issued(
    cn: str,
    issuer: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
    *,
    ca: bool = False,
    ekus: list[x509.ObjectIdentifier] | None = None,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _rsa()
    now = datetime.now(tz=UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=180))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ekus:
        builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
    return builder.sign(issuer_key, hashes.SHA256()), key


def _ek_ak_chain() -> tuple[bytes, bytes, rsa.RSAPrivateKey]:
    """Synthetic CA -> EK -> AK, the literal shape issue #370 describes.

    The "EK" has to be marked ``ca=True`` for it to issue the AK certificate at
    all, which is precisely why this shape is not evidence of endorsement: a
    real EK is an end-entity decryption key that signs nothing. Kept as a test
    case so the verifier is pinned to *not* credit it.

    Returns (chain_pem_leaf_first, root_ca_pem, ak_private_key).
    """
    ca_cert, ca_key = _ca()
    ek_cert, ek_key = _issued(
        "synthetic-ek", ca_cert, ca_key, ca=True, ekus=[_TCG_EK_CERTIFICATE]
    )
    ak_cert, ak_key = _issued("synthetic-ak", ek_cert, ek_key)
    chain = _pem(ak_cert) + _pem(ek_cert) + _pem(ca_cert)
    return chain, _pem(ca_cert), ak_key


def _ak_only_chain() -> tuple[bytes, bytes, rsa.RSAPrivateKey]:
    """CA -> AK with no EK in the path (the Azure vTPM model)."""
    ca_cert, ca_key = _ca()
    ak_cert, ak_key = _issued("synthetic-ak", ca_cert, ca_key)
    return _pem(ak_cert) + _pem(ca_cert), _pem(ca_cert), ak_key


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


# ── Evidence ─────────────────────────────────────────────────────────────────


def _attest(qualifying_data: bytes) -> bytes:
    """A bare TPMS_ATTEST -- the exact bytes a TPM signs."""
    return (
        struct.pack(">I", _TPM_GENERATED_VALUE)
        + struct.pack(">H", 0x8018)  # TPM_ST_ATTEST_QUOTE
        + struct.pack(">H", 4) + b"name"  # qualifiedSigner
        + struct.pack(">H", len(qualifying_data)) + qualifying_data  # extraData
        + b"\x00" * 17  # clockInfo
        + b"\x00" * 8  # firmwareVersion
        + struct.pack(">I", 0)  # TPML_PCR_SELECTION count
        + struct.pack(">H", 32) + b"\x02" * 32  # pcrDigest
    )


def _tpmt_signature(attest: bytes, ak_key: rsa.RSAPrivateKey) -> bytes:
    raw = ak_key.sign(attest, padding.PKCS1v15(), hashes.SHA256())
    return struct.pack(">HH", _ALG_RSASSA, _ALG_SHA256) + struct.pack(">H", len(raw)) + raw


def _b64(data: bytes) -> str:
    """Encode the way the gateway does: base64url, unpadded.

    Deliberately not standard base64. `session.manager` writes this alphabet, so
    encoding any other way here would exercise a decoder branch production never
    takes and leave the real one uncovered.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ── Claim ────────────────────────────────────────────────────────────────────


def _make_tpm2_claim(
    key: SigningKey,
    *,
    raw_evidence: bytes | None = None,
    quote_signature: bytes | None = None,
    cert_chain: bytes | None = None,
) -> dict:
    """A fully valid tpm2 claim: key-bound, chain-root-bound, correctly signed.

    Evidence goes through the real producer path -- ``AttestationReportInfo`` ->
    ``gateway.attestation_evidence`` -- so the claim is schema-valid. Injecting
    it into ``trace.runtime`` instead makes the claim CLAIM_MALFORMED, because
    ``RuntimeInfo`` is ``extra="forbid"``; that is what kept the chain verifiers
    unreachable before #370.

    ``report_data`` satisfies both bindings the verifier checks:
    ``jwk_thumbprint(key) || SHA-256(chain_root)`` (CRYPTO-001 / AUDIT-006).
    """
    chain = AuditChain("tpm-session")
    root_hex = chain.chain_root.removeprefix("sha256:").removeprefix("sha384:")
    report_data = (
        jwk_thumbprint(key.public_key_bytes)
        + hashlib.sha256(bytes.fromhex(root_hex)).digest()
    ).hex()
    claim = generate_trace_claim(
        session_id="tpm-session",
        signing_key=key,
        attestation_report=AttestationReportInfo(
            provider="tpm",
            measurement=VALID_MEASUREMENT,
            report_data=report_data,
            attestation_generated_at=datetime.now(tz=UTC).isoformat(),
            attestation_validity_seconds=86400,
            raw_evidence=_b64(raw_evidence) if raw_evidence is not None else None,
            quote_signature=_b64(quote_signature) if quote_signature is not None else None,
            cert_chain=_b64(cert_chain) if cert_chain is not None else None,
        ),
        policy_bundle=PolicyBundleInfo(
            hash=POLICY_HASH, enforcement_mode="enforcing", policy_version="1.0.0"
        ),
        tool_catalog=ToolCatalogInfo(hash=CATALOG_HASH),
        call_summary=CallSummary(
            tool_calls_total=1,
            tool_calls_allowed=1,
            tool_calls_denied=0,
            tool_calls_faulted=0,
            tools_invoked=["test.tool"],
            session_max_sensitivity="public",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=[], cross_boundary_events=[]
            ),
        ),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        do_sign=False,
    )
    claim_dict = _to_dict(claim)
    claim_dict["trace"]["runtime"]["firmware_version"] = "2.0-production"
    # Sign last, so the signature covers the evidence too.
    claim_dict["signature"] = (
        base64.urlsafe_b64encode(key.sign(canonical_json(claim_dict)))
        .rstrip(b"=")
        .decode()
    )
    return claim_dict


def _approved() -> ApprovedHashes:
    return ApprovedHashes(policy_bundle_hash=POLICY_HASH, tool_catalog_hash=CATALOG_HASH)


def _claim_for(
    chain_pem: bytes,
    ak_key: rsa.RSAPrivateKey,
    *,
    tamper_attest: bool = False,
    omit: str | None = None,
) -> dict:
    """Build a signed claim carrying evidence through the producer path.

    ``tamper_attest`` flips a byte in the attest *after* signing it, so the
    quote signature no longer matches the evidence shipped. ``omit`` drops one
    evidence field, standing in for a producer that predates it. Both are done
    at build time rather than by mutating the finished claim, which would break
    the claim signature and mask the behaviour under test.
    """
    key = SigningKey()
    attest = _attest(jwk_thumbprint(key.public_key_bytes))
    signature = _tpmt_signature(attest, ak_key)
    if tamper_attest:
        mutated = bytearray(attest)
        mutated[-1] ^= 0x01
        attest = bytes(mutated)
    return _make_tpm2_claim(
        key,
        raw_evidence=attest,
        quote_signature=None if omit == "quote_signature" else signature,
        cert_chain=None if omit == "cert_chain" else chain_pem,
    )


@pytest.fixture
def signed_quote():
    """(claim_dict, root_pem) for a signed quote on a CA -> EK -> AK chain."""
    chain_pem, root_pem, ak_key = _ek_ak_chain()
    return _claim_for(chain_pem, ak_key), root_pem


# ── The regression this issue is about ───────────────────────────────────────


def test_forged_attest_no_longer_reports_hardware_attestation() -> None:
    """Issue #370: a forged TPMS_ATTEST used to pass.

    Correct magic, and a ``qualifying_data`` matching the claim's own key -- both
    attacker-writable. With no signature there is nothing binding the blob to a
    TPM, so ``hardware_attestation`` must not be reported as verified.
    """
    key = SigningKey()
    forged = _attest(jwk_thumbprint(key.public_key_bytes))
    claim = _make_tpm2_claim(key, raw_evidence=forged)

    result = verify_trace_claim(claim, _approved(), trusted_tpm_ca_pem=None)

    # The parse-level checks still pass -- that is exactly why the hole existed.
    assert "qualifying_data" in result.verified_fields
    assert "hardware_attestation" not in result.verified_fields
    assert "hardware_attestation" in result.unverified_fields
    assert "ak_cert_chain" in result.unverified_fields


# ── Happy path ───────────────────────────────────────────────────────────────


def test_signed_and_chained_quote_verifies(signed_quote) -> None:
    claim, root_pem = signed_quote
    result = verify_trace_claim(claim, _approved(), trusted_tpm_ca_pem=root_pem)

    assert "tpm_quote_signature" in result.verified_fields
    assert "ak_cert_chain" in result.verified_fields
    assert "hardware_attestation" in result.verified_fields
    assert "hardware_attestation" not in result.unverified_fields


def test_an_issuing_ek_is_not_counted_as_an_endorsement(signed_quote) -> None:
    """A CA->EK->AK chain does not establish ek_cert_chain, and should not.

    To issue the AK certificate the "EK" must be a CA, and a real Endorsement
    Key is an end-entity decryption key that cannot sign anything. So this
    shape -- the one issue #370 describes -- is not evidence that an EK
    endorsed this AK. The AK chain is still verified; the EK claim is withheld.
    """
    claim, root_pem = signed_quote
    result = verify_trace_claim(claim, _approved(), trusted_tpm_ca_pem=root_pem)

    assert "ak_cert_chain" in result.verified_fields
    assert "ek_cert_chain" not in result.verified_fields
    assert "ek_cert_chain" in result.unverified_fields


def test_a_ca_bearing_the_ek_eku_is_not_counted_as_an_ek() -> None:
    """Regression: Azure's real vTPM intermediates carry the TCG EK EKU.

    On the committed hardware fixture, `Azure Cloud Virtual TPM CA - 11` has
    EKU 2.23.133.8.1 -- there it means "may issue EK certificates", not "is an
    EK". Matching on the EKU alone reported ek_cert_chain verified on a chain
    containing no EK whatsoever.
    """
    ca_cert, ca_key = _ca()
    azure_shaped, mid_key = _issued(
        "Issuing CA that may issue EKs",
        ca_cert,
        ca_key,
        ca=True,
        ekus=[_TCG_EK_CERTIFICATE],
    )
    ak_cert, ak_key = _issued("synthetic-ak", azure_shaped, mid_key)
    chain = _pem(ak_cert) + _pem(azure_shaped) + _pem(ca_cert)

    result = verify_trace_claim(
        _claim_for(chain, ak_key), _approved(), trusted_tpm_ca_pem=_pem(ca_cert)
    )

    assert "ak_cert_chain" in result.verified_fields
    assert "ek_cert_chain" not in result.verified_fields
    assert "ek_cert_chain" in result.unverified_fields


def test_ak_certified_directly_by_the_ca_leaves_ek_unverified() -> None:
    """The Azure vTPM model: a platform CA certifies the AK, no EK in the path."""
    chain_pem, root_pem, ak_key = _ak_only_chain()
    result = verify_trace_claim(
        _claim_for(chain_pem, ak_key), _approved(), trusted_tpm_ca_pem=root_pem
    )

    assert "ak_cert_chain" in result.verified_fields
    assert "hardware_attestation" in result.verified_fields
    assert "ek_cert_chain" in result.unverified_fields
    assert "ek_cert_chain" not in result.verified_fields


def test_a_plain_intermediate_ca_is_not_counted_as_an_ek() -> None:
    """Chain depth is not endorsement."""
    ca_cert, ca_key = _ca()
    mid_cert, mid_key = _issued("plain-intermediate", ca_cert, ca_key, ca=True)
    ak_cert, ak_key = _issued("synthetic-ak", mid_cert, mid_key)
    chain = _pem(ak_cert) + _pem(mid_cert) + _pem(ca_cert)

    result = verify_trace_claim(
        _claim_for(chain, ak_key), _approved(), trusted_tpm_ca_pem=_pem(ca_cert)
    )

    assert "ak_cert_chain" in result.verified_fields
    assert "ek_cert_chain" not in result.verified_fields
    assert "ek_cert_chain" in result.unverified_fields


def test_a_separately_supplied_ek_chain_is_verified() -> None:
    """EK->manufacturer-CA is a real path, supplied as its own chain.

    No platform in this repo bundles one today; the path exists so a producer
    that does gets credit for it. Note what this does and does not prove: the
    EK is genuine and the AK is certified, but nothing here binds them to the
    same TPM -- that needs credential activation.
    """
    ca_cert, ca_key = _ca()
    ek_cert, _ek_key = _issued(
        "genuine-ek", ca_cert, ca_key, ca=False, ekus=[_TCG_EK_CERTIFICATE]
    )
    ak_cert, ak_key = _issued("synthetic-ak", ca_cert, ca_key)

    ok, established, reason = verify_ak_ek_chain(
        _pem(ak_cert) + _pem(ca_cert),
        trusted_ca_pem=_pem(ca_cert),
        ek_chain_pem=_pem(ek_cert) + _pem(ca_cert),
    )

    assert ok is True, reason
    assert established == ["ak_cert_chain", "ek_cert_chain"]

    # And end to end through the claim path.
    claim = _claim_for(_pem(ak_cert) + _pem(ca_cert), ak_key)
    claim["trace"]["runtime"]["ek_cert_chain"] = base64.b64encode(
        _pem(ek_cert) + _pem(ca_cert)
    ).decode()
    result = verify_trace_claim(claim, _approved(), trusted_tpm_ca_pem=_pem(ca_cert))
    assert "ek_cert_chain" in result.verified_fields
    assert "ek_cert_chain" not in result.unverified_fields


def test_a_ca_passed_as_an_ek_chain_is_rejected() -> None:
    """Supplied-but-bogus EK material fails the call, it does not downgrade."""
    ca_cert, ca_key = _ca()
    not_an_ek, _ = _issued(
        "CA wearing the EK EKU", ca_cert, ca_key, ca=True, ekus=[_TCG_EK_CERTIFICATE]
    )
    ak_cert, _ak_key = _issued("synthetic-ak", ca_cert, ca_key)

    ok, established, reason = verify_ak_ek_chain(
        _pem(ak_cert) + _pem(ca_cert),
        trusted_ca_pem=_pem(ca_cert),
        ek_chain_pem=_pem(not_an_ek) + _pem(ca_cert),
    )

    assert ok is False
    assert established == []
    assert "not an end-entity Endorsement Key" in reason


def test_an_ek_chain_to_the_wrong_root_is_rejected() -> None:
    ca_cert, ca_key = _ca()
    other_ca, other_key = _ca("Unrelated CA")
    ek_cert, _ = _issued(
        "genuine-ek", other_ca, other_key, ca=False, ekus=[_TCG_EK_CERTIFICATE]
    )
    ak_cert, _ak_key = _issued("synthetic-ak", ca_cert, ca_key)

    ok, _established, reason = verify_ak_ek_chain(
        _pem(ak_cert) + _pem(ca_cert),
        trusted_ca_pem=_pem(ca_cert),
        ek_chain_pem=_pem(ek_cert) + _pem(other_ca),
    )

    assert ok is False
    assert "does not reach the pinned CA" in reason


# ── Supplied-but-bad chain material is fatal ─────────────────────────────────


def test_tampered_attest_is_fatal() -> None:
    chain_pem, root_pem, ak_key = _ek_ak_chain()
    claim = _claim_for(chain_pem, ak_key, tamper_attest=True)

    result = verify_trace_claim(claim, _approved(), trusted_tpm_ca_pem=root_pem)

    assert "tpm_quote_signature" in result.unverified_fields
    assert "hardware_attestation" not in result.verified_fields
    # Fatal, per the issue: supplied material that fails is an error, not a
    # downgrade. Observable now that evidence rides in a schema-valid envelope.
    assert result.failure_reason is not None
    assert result.failure_reason.value == "HARDWARE_ATTESTATION_FAILED"


def test_wrong_pinned_root_is_fatal(signed_quote) -> None:
    """A chain that does not reach the operator's pinned CA must not verify."""
    claim, _root_pem = signed_quote
    other_ca, _ = _ca("Some Other CA")

    result = verify_trace_claim(claim, _approved(), trusted_tpm_ca_pem=_pem(other_ca))

    assert "ak_cert_chain" in result.unverified_fields
    assert "hardware_attestation" not in result.verified_fields
    assert result.failure_reason is not None
    assert result.failure_reason.value == "HARDWARE_ATTESTATION_FAILED"


def test_quote_signed_by_a_key_outside_the_chain_is_fatal() -> None:
    """The AK cert chains to the pinned root, but a different key signed."""
    chain_pem, root_pem, _ak_key = _ek_ak_chain()
    claim = _claim_for(chain_pem, _rsa())  # signed by an attacker key

    result = verify_trace_claim(claim, _approved(), trusted_tpm_ca_pem=root_pem)

    assert "tpm_quote_signature" in result.unverified_fields
    assert "hardware_attestation" not in result.verified_fields
    assert result.failure_reason is not None


# ── Absent chain material degrades, it does not error ────────────────────────


@pytest.mark.parametrize(
    "drop", ["quote_signature", "cert_chain"], ids=["no_signature", "no_chain"]
)
def test_missing_chain_material_degrades_to_unverified(drop) -> None:
    """Back-compat: evidence predating the signature fields stays unverified.

    Distinct from the fatal cases above -- nothing here is *wrong*, there is
    simply nothing to check, which is the same shape as the SNP no-chain path.
    """
    chain_pem, root_pem, ak_key = _ek_ak_chain()
    claim = _claim_for(chain_pem, ak_key, omit=drop)

    result = verify_trace_claim(claim, _approved(), trusted_tpm_ca_pem=root_pem)

    assert "ak_cert_chain" in result.unverified_fields
    assert "hardware_attestation" in result.unverified_fields
    assert "not verified" in result.details["ak_cert_chain"]
    # Parse-level results survive: this is a downgrade, not a rejection.
    assert "qualifying_data" in result.verified_fields
    # And crucially not fatal -- absent material must not raise an error.
    assert result.failure_reason is None


def test_unpinned_ca_degrades_to_unverified(signed_quote) -> None:
    """Perfectly good evidence, but the operator pinned no root to check it against."""
    claim, _root_pem = signed_quote

    result = verify_trace_claim(claim, _approved(), trusted_tpm_ca_pem=None)

    assert "ak_cert_chain" in result.unverified_fields
    assert "no trusted_tpm_ca_pem pinned" in result.details["ak_cert_chain"]


def test_no_raw_evidence_still_fails_closed() -> None:
    key = SigningKey()
    claim = _make_tpm2_claim(key)

    result = verify_trace_claim(claim, _approved(), trusted_tpm_ca_pem=None)

    assert "hardware_attestation" in result.unverified_fields
    assert result.details["tpm_failure"] == "no_raw_evidence"
    assert "unverifiable" in result.details["ak_cert_chain"]


# ── The blocker that stops any of this working end to end ────────────────────


def test_evidence_fields_are_rejected_by_the_claim_schema() -> None:
    """The verifier reads fields its own schema forbids, so a real claim cannot
    carry them.

    ``RuntimeInfo`` in agentrust-trace is ``extra="forbid"`` with only
    platform / measurement / rim_uri / nonce / firmware_version. Step 1 of
    ``verify_trace_claim`` validates against that model, so any claim carrying
    the evidence the tpm2 branch reads is rejected as CLAIM_MALFORMED before
    the branch runs.

    This is not TPM-specific and not introduced by this change: the merged SNP
    path reads ``cert_chain`` under the identical constraint. Closing it needs
    the schema change upstream in agentrust-trace. Recorded as a test so the
    gap is visible in CI rather than only in a comment.
    """
    from agentrust_trace.models import RuntimeInfo
    from pydantic import ValidationError

    base = {"platform": "tpm2", "measurement": VALID_MEASUREMENT, "nonce": "AA"}
    for evidence_field in (
        "raw_evidence",
        "quote_signature",
        "cert_chain",
        "ek_cert_chain",
    ):
        with pytest.raises(ValidationError):
            RuntimeInfo(**base, **{evidence_field: "x"})

    # Which is why evidence rides in the cmcp-owned envelope instead -- see
    # test_evidence_travels_in_the_gateway_envelope_end_to_end. The verifier
    # still reads trace.runtime as a fallback for older fixtures, but a claim
    # built that way cannot pass schema validation.


def test_evidence_travels_in_the_gateway_envelope_end_to_end() -> None:
    """The whole point of #370: a real claim carries evidence and verifies.

    Built through the producer path, so this is the shape a gateway actually
    emits -- schema-valid, signed over the evidence, and reaching VERIFIED only
    because the quote signature and AK chain both check out.
    """
    chain_pem, root_pem, ak_key = _ek_ak_chain()
    claim = _claim_for(chain_pem, ak_key)

    # Evidence is in the cmcp envelope, not the agentrust-trace runtime block.
    assert "attestation_evidence" in claim["gateway"]
    assert "cert_chain" not in claim["trace"]["runtime"]

    result = verify_trace_claim(claim, _approved(), trusted_tpm_ca_pem=root_pem)

    assert result.failure_reason is None
    assert result.status.value == "verified"
    assert "hardware_attestation" in result.verified_fields
    assert "tpm_quote_signature" in result.verified_fields
    assert "ak_cert_chain" in result.verified_fields


# ── The producer half: session.manager -> claim ──────────────────────────────


def test_session_manager_encoding_round_trips_into_the_verifier() -> None:
    """The gateway's encoder and the verifier's decoder must agree.

    `session.manager` writes base64url without padding; the verifier historically
    used standard `b64decode`, which cannot read that alphabet. Nothing caught it
    because no test carried evidence through both halves.
    """
    from cmcp_runtime.session.manager import _b64 as producer_b64
    from cmcp_verify.verify import _decode_evidence

    for blob in (b"\xfb\xff\xfe" * 11, b"", b"\x00", bytes(range(256))):
        encoded = producer_b64(blob)
        assert encoded is not None
        assert _decode_evidence(encoded) == blob or blob == b""

    # Non-bytes (an older provider, or a mock) is absent, not an error.
    assert producer_b64(None) is None
    assert producer_b64(object()) is None


def test_session_manager_carries_evidence_onto_the_report_info() -> None:
    """The producer must actually copy the captured evidence into the claim.

    Guards the line that matters: an AttestationReport holding a signature and a
    chain has to surface them, or the verifier has nothing to check and every
    claim silently degrades to unverified.
    """
    from cmcp_runtime.audit.trace_claim import _build_evidence
    from cmcp_runtime.session.manager import _b64 as producer_b64

    chain_pem, _root_pem, ak_key = _ek_ak_chain()
    attest = _attest(b"\x01" * 32)
    signature = _tpmt_signature(attest, ak_key)

    info = AttestationReportInfo(
        provider="tpm",
        measurement=VALID_MEASUREMENT,
        report_data="00" * 32,
        attestation_generated_at=datetime.now(tz=UTC).isoformat(),
        attestation_validity_seconds=86400,
        raw_evidence=producer_b64(attest),
        quote_signature=producer_b64(signature),
        cert_chain=producer_b64(chain_pem),
    )
    evidence = _build_evidence(info)

    assert evidence is not None
    assert evidence.quote_signature is not None
    assert evidence.cert_chain is not None

    from cmcp_verify.verify import _decode_evidence

    assert _decode_evidence(evidence.raw_evidence) == attest
    assert _decode_evidence(evidence.quote_signature) == signature
    assert _decode_evidence(evidence.cert_chain) == chain_pem


def test_evidence_is_omitted_entirely_when_there_is_none() -> None:
    """Software-only and evidence-less claims keep their previous shape."""
    from cmcp_runtime.audit.trace_claim import _build_evidence

    info = AttestationReportInfo(
        provider="software-only",
        measurement=VALID_MEASUREMENT,
        report_data="00" * 32,
        attestation_generated_at=datetime.now(tz=UTC).isoformat(),
        attestation_validity_seconds=86400,
    )
    assert _build_evidence(info) is None
