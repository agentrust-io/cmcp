"""Genuine swtpm evidence for the verifier-owned NV public/range policy.

The checked-in blobs were signed by a fresh software TPM through tpm2-tools.
The synthetic certificate binds the TPM-created AK public key to a test root; it
does not establish hardware provenance or production enrollment.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from agent_manifest import parse_tpm_nv_certify
from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from cmcp_verify.nv_certify import NvCertifyResult, build_envelope, verify_gateway_measurement
from cmcp_verify.nv_policy import (
    GatewayNvAppraisalPolicy,
    measurement_nv_name,
    measurement_nv_public_bytes,
)

_FIXTURE = Path(__file__).parents[1] / "fixtures" / "reference" / "swtpm-nv-policy-0.7.3"
_NONCE = b"\xa5" * 32
_PRE_QUALIFYING_DATA = bytes.fromhex(
    "ac2bc955b7d97a5589f9a6c48db86f87aea9d9af22e43cc97330f7b560145fa3"
)
_POST_QUALIFYING_DATA = bytes.fromhex(
    "230587d8162f6a14fb8573d2b3fddec4b98413ffad0f83e804aff3740d8bfa8c"
)
_WRONG_PUBLIC_NAME = bytes.fromhex(
    "000b7ee6de688f90e26e0bbf3b8fc4d3ad1888999a5c85129f9f1a0bf56aefd58d18"
)


def _read(name: str) -> bytes:
    return (_FIXTURE / name).read_bytes()


def _profile_read(profile: str, name: str) -> bytes:
    return _read(f"{profile}/{name}")


def _envelope(profile: str) -> bytes:
    return build_envelope(
        pre_attest=_profile_read(profile, "pre-attest.bin"),
        pre_signature=_profile_read(profile, "pre-tpmt-signature.bin"),
        post_attest=_profile_read(profile, "post-attest.bin"),
        post_signature=_profile_read(profile, "post-tpmt-signature.bin"),
        gateway_digest=_profile_read("production", "gateway-digest.bin"),
        components={"producer": "swtpm 0.7.3", "profile": profile},
    )


def _verify(profile: str) -> NvCertifyResult:
    digest = _profile_read("production", "gateway-digest.bin")
    root = _read("synthetic-root.pem")
    return verify_gateway_measurement(
        _envelope(profile),
        ak_chain_pem=_read("ak-cert.pem") + root,
        trusted_roots_pem=root,
        expected_nonce=_NONCE,
        policy=GatewayNvAppraisalPolicy.for_measurement_index(expected_gateway_digest=digest),
    )


def _public_entry(profile: str) -> dict[str, object]:
    document = yaml.safe_load(_profile_read(profile, "nv-public.yaml"))
    return next(iter(document.values()))


def test_swtpm_production_profile_matches_verifier_owned_public_area() -> None:
    """The signed Name is derived from the exact cMCP production template."""
    pre = parse_tpm_nv_certify(_profile_read("production", "pre-attest.bin"))
    post = parse_tpm_nv_certify(_profile_read("production", "post-attest.bin"))
    public = _public_entry("production")
    digest = _profile_read("production", "gateway-digest.bin")
    seed = _profile_read("production", "seed-event.bin")

    assert measurement_nv_public_bytes().hex() == "01500432000b2206004200000020"
    assert public["name"] == measurement_nv_name().hex()
    assert public["hash algorithm"] == {"friendly": "sha256", "value": 0x000B}
    assert public["attributes"] == {
        "friendly": "ownerwrite|nt=0x1|ownerread|authread|no_da|written",
        "value": 0x22060042,
    }
    assert public["size"] == 32

    assert pre.attest.qualifying_data == _PRE_QUALIFYING_DATA
    assert post.attest.qualifying_data == _POST_QUALIFYING_DATA
    assert pre.info.index_name == post.info.index_name == measurement_nv_name()
    assert pre.info.offset == post.info.offset == 0
    assert len(pre.info.nv_contents) == len(post.info.nv_contents) == 32
    assert pre.info.nv_contents == hashlib.sha256(bytes(32) + seed).digest()
    assert post.info.nv_contents == hashlib.sha256(pre.info.nv_contents + digest).digest()

    certified_public = x509.load_pem_x509_certificate(_read("ak-cert.pem")).public_key()
    swtpm_public = load_pem_public_key(_read("ak-public.pem"))
    assert certified_public.public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    ) == swtpm_public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    result = _verify("production")
    assert result.verified, result.failure_reason
    assert result.failure_reason is None
    assert "ak_chain" in result.verified_fields
    assert "signatures" in result.verified_fields
    assert "nv_policy" in result.verified_fields
    assert "extend_relation" in result.verified_fields


def test_swtpm_same_handle_ordinary_index_is_denied_after_signature_verification() -> None:
    """A genuine AK signature and arranged byte relation cannot replace Name policy."""
    pre = parse_tpm_nv_certify(_profile_read("wrong-public", "pre-attest.bin"))
    post = parse_tpm_nv_certify(_profile_read("wrong-public", "post-attest.bin"))
    public = _public_entry("wrong-public")
    digest = _profile_read("production", "gateway-digest.bin")

    assert public["attributes"] == {
        "friendly": "ownerwrite|ownerread|authread|no_da|written",
        "value": 0x22060002,
    }
    assert str(public["name"]) == _WRONG_PUBLIC_NAME.hex()
    assert pre.info.index_name == post.info.index_name == _WRONG_PUBLIC_NAME
    assert pre.info.index_name != measurement_nv_name()
    assert pre.info.offset == post.info.offset == 0
    assert len(pre.info.nv_contents) == len(post.info.nv_contents) == 32
    assert post.info.nv_contents == hashlib.sha256(pre.info.nv_contents + digest).digest()

    result = _verify("wrong-public")
    assert not result.verified
    assert result.failure_reason == "nv_index_name_mismatch"
    assert "signatures" in result.verified_fields
    assert "transcript_binding" in result.verified_fields
    assert "nv_policy" not in result.verified_fields


def test_swtpm_production_name_partial_range_is_denied_after_signature_verification() -> None:
    """The exact signed Name does not authorize a partial offset/extent."""
    pre = parse_tpm_nv_certify(_profile_read("wrong-range", "pre-attest.bin"))
    post = parse_tpm_nv_certify(_profile_read("wrong-range", "post-attest.bin"))

    assert pre.info.index_name == post.info.index_name == measurement_nv_name()
    assert pre.info.offset == post.info.offset == 16
    assert len(pre.info.nv_contents) == len(post.info.nv_contents) == 16

    result = _verify("wrong-range")
    assert not result.verified
    assert result.failure_reason == "nv_offset_mismatch"
    assert "signatures" in result.verified_fields
    assert "transcript_binding" in result.verified_fields
    assert "nv_policy" not in result.verified_fields


def test_swtpm_nv_policy_artifact_checksums() -> None:
    entries: dict[str, str] = {}
    for line in _read("SHA256SUMS").decode().splitlines():
        digest, name = line.split("  ", 1)
        entries[name] = digest

    fixture_files = {
        path.relative_to(_FIXTURE).as_posix()
        for path in _FIXTURE.rglob("*")
        if path.is_file() and path.name not in {"README.md", "SHA256SUMS"}
    }
    assert entries
    assert set(entries) == fixture_files
    assert not any(
        path.name.endswith((".key", ".ctx", ".priv", ".state")) for path in _FIXTURE.rglob("*")
    )
    for name, digest in entries.items():
        assert hashlib.sha256(_read(name)).hexdigest() == digest
