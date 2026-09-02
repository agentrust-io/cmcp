"""Independent-producer coverage for the gateway NV-certify appraisal path.

The fixture was emitted by swtpm/tpm2-tools, not by either parser under test. Its
certificate is deliberately synthetic and establishes no hardware provenance; see
the fixture README for the exact evidence and assurance boundary.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml
from agent_manifest import parse_tpm_nv_certify, parse_tpmt_signature
from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from cmcp_verify.nv_certify import NvCertifyResult, build_envelope, verify_gateway_measurement

_FIXTURE = Path(__file__).parents[1] / "fixtures" / "reference" / "swtpm-nv-certify-0.7.3"
_NONCE = b"\xa5" * 32
_PRE_QUALIFYING_DATA = bytes.fromhex(
    "ac2bc955b7d97a5589f9a6c48db86f87aea9d9af22e43cc97330f7b560145fa3"
)
_POST_QUALIFYING_DATA = bytes.fromhex(
    "230587d8162f6a14fb8573d2b3fddec4b98413ffad0f83e804aff3740d8bfa8c"
)


def _read(name: str) -> bytes:
    return (_FIXTURE / name).read_bytes()


def _tpm2b(attest: bytes) -> bytes:
    return len(attest).to_bytes(2, "big") + attest


def _envelope(*, size_prefixed: bool = False, post_signature: bytes | None = None) -> bytes:
    pre = _read("pre-attest.bin")
    post = _read("post-attest.bin")
    return build_envelope(
        pre_attest=_tpm2b(pre) if size_prefixed else pre,
        pre_signature=_read("pre-tpmt-signature.bin"),
        post_attest=_tpm2b(post) if size_prefixed else post,
        post_signature=(
            post_signature if post_signature is not None else _read("post-tpmt-signature.bin")
        ),
        gateway_digest=_read("gateway-digest.bin"),
        components={"producer": "swtpm 0.7.3", "purpose": "reference test"},
    )


def _verify(envelope: bytes, *, expected_nonce: bytes = _NONCE) -> NvCertifyResult:
    root = _read("synthetic-root.pem")
    return verify_gateway_measurement(
        envelope,
        ak_chain_pem=_read("ak-cert.pem") + root,
        trusted_roots_pem=root,
        expected_nonce=expected_nonce,
        expected_gateway_digest=_read("gateway-digest.bin"),
    )


def test_swtpm_reference_artifacts_are_self_consistent() -> None:
    pre = parse_tpm_nv_certify(_read("pre-attest.bin"))
    post = parse_tpm_nv_certify(_read("post-attest.bin"))
    nv_public = yaml.safe_load(_read("nv-public.yaml"))
    public_entry = next(iter(nv_public.values()))
    expected_index_name = bytes.fromhex(public_entry["name"])

    assert pre.attest.qualifying_data == _PRE_QUALIFYING_DATA
    assert post.attest.qualifying_data == _POST_QUALIFYING_DATA
    assert pre.info.index_name == post.info.index_name == expected_index_name
    assert pre.info.offset == post.info.offset == 0
    assert pre.info.nv_contents == _read("pre-contents.bin")
    assert post.info.nv_contents == _read("post-contents.bin")
    assert pre.info.nv_contents == hashlib.sha256(bytes(32) + _read("seed-event.bin")).digest()
    assert (
        post.info.nv_contents
        == hashlib.sha256(pre.info.nv_contents + _read("gateway-digest.bin")).digest()
    )

    signature = parse_tpmt_signature(_read("pre-tpmt-signature.bin"))
    assert signature.sig_alg == 0x0014  # TPM2_ALG_RSASSA
    assert signature.hash_alg == 0x000B  # TPM2_ALG_SHA256
    assert len(signature.signature) == 256

    certified_public = x509.load_pem_x509_certificate(_read("ak-cert.pem")).public_key()
    swtpm_public = load_pem_public_key(_read("ak-public.pem"))
    assert certified_public.public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    ) == swtpm_public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def test_swtpm_reference_artifact_checksums() -> None:
    entries = {}
    for line in (_FIXTURE / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        entries[name] = digest

    assert entries
    assert set(entries) == {
        path.name for path in _FIXTURE.iterdir() if path.name not in {"README.md", "SHA256SUMS"}
    }
    for name, digest in entries.items():
        assert hashlib.sha256(_read(name)).hexdigest() == digest


@pytest.mark.parametrize("size_prefixed", [False, True], ids=["TPMS_ATTEST", "TPM2B_ATTEST"])
def test_swtpm_reference_pair_verifies(size_prefixed: bool) -> None:
    result = _verify(_envelope(size_prefixed=size_prefixed))
    assert result.verified, result.failure_reason
    assert result.verified_fields == [
        "envelope",
        "structure",
        "ak_chain",
        "signatures",
        "freshness",
        "index_identity",
        "extend_relation",
    ]


def test_swtpm_reference_pair_rejects_replay_under_a_new_nonce() -> None:
    result = _verify(_envelope(), expected_nonce=b"\xa6" * 32)
    assert not result.verified
    assert result.failure_reason == "pre_binding_mismatch"


def test_swtpm_reference_pair_rejects_signature_tampering() -> None:
    signature = bytearray(_read("post-tpmt-signature.bin"))
    signature[-1] ^= 0x01
    result = _verify(_envelope(post_signature=bytes(signature)))
    assert not result.verified
    assert result.failure_reason == "signature_invalid"
