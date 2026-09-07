"""#595: real platform appraisal must bind evidence to the signed claim nonce.

Synthetic SNP/Azure signatures exercise the full cryptographic chain. TDX's
TDREPORT-only path must detect mismatches while remaining partially verified.
"""
from __future__ import annotations

import base64
import hashlib

import pytest

from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import canonical_json
from cmcp_verify.verify import VerificationError, VerificationStatus, verify_trace_claim
from tests.unit.test_azure_cvm_verify import _build_evidence
from tests.unit.test_evidence_envelope_all_platforms import _approved, _claim
from tests.unit.test_snp_signature_verify import _signed_report, _synthetic_chain
from tests.unit.test_tdx_opaque_verify import _make_tdreport


def _resign(claim: dict, key: SigningKey) -> None:
    claim.pop("signature", None)
    claim["signature"] = base64.urlsafe_b64encode(key.sign(canonical_json(claim))).rstrip(b"=").decode()


def _with_evidence(provider: str, *, mismatch: int | None = None) -> tuple[dict, SigningKey, dict]:
    key = SigningKey()
    claim = _claim(provider, key=key)
    runtime = claim["trace"]["runtime"]
    nonce = bytearray(base64.urlsafe_b64decode(runtime["nonce"] + "=="))
    if mismatch is not None:
        nonce[mismatch] ^= 1
    evidence = claim["gateway"]["attestation_evidence"]
    kwargs = {}
    if provider == "sev-snp":
        chain, root, vcek = _synthetic_chain()
        raw, measurement = _signed_report(vcek, measurement_bytes=b"\x11" * 48, report_data=bytes(nonce))
        evidence["cert_chain"] = base64.b64encode(chain).decode()
        kwargs["trusted_ark_pem"] = root
    elif provider == "azure-cvm-sev-snp":
        raw, measurement, root = _build_evidence(bytes(nonce))
        kwargs["trusted_ark_pem"] = root
    else:
        mrtd = b"\x11" * 48
        raw = _make_tdreport(mrtd, bytes(nonce))
        measurement = "sha384:" + hashlib.sha384(mrtd).hexdigest()
    runtime["measurement"] = measurement
    evidence["raw_evidence"] = base64.b64encode(raw).decode()
    _resign(claim, key)
    return claim, key, kwargs


@pytest.mark.parametrize("provider", ["sev-snp", "azure-cvm-sev-snp", "tdx"])
@pytest.mark.parametrize("mismatch", [None, 0, 32, 63])
def test_platform_evidence_binds_both_nonce_halves(monkeypatch, provider, mismatch):
    monkeypatch.setattr("cmcp_verify.tdx._check_dcap_reachable", lambda: False)
    claim, _, kwargs = _with_evidence(provider, mismatch=mismatch)
    result = verify_trace_claim(claim, _approved(), **kwargs)
    assert "schema" in result.verified_fields
    assert "signature" in result.verified_fields
    # These generic checks only compare the claim with itself. The platform
    # verifier must independently compare it with the hardware evidence.
    assert "public_key_binding" in result.verified_fields
    if mismatch is not None:
        assert result.failure_reason == VerificationError.HARDWARE_ATTESTATION_FAILED
        assert "hardware_attestation" not in result.verified_fields
        assert result.status != VerificationStatus.VERIFIED
    elif provider == "tdx":
        assert result.failure_reason is None
        assert result.status == VerificationStatus.PARTIALLY_VERIFIED
        assert "report_data" in result.verified_fields
        assert "dcap_quote_signature" in result.unverified_fields
    else:
        assert result.failure_reason is None
        assert "hardware_attestation" in result.verified_fields
        binding = "quote_nonce_binding" if provider == "azure-cvm-sev-snp" else "report_data"
        assert binding in result.verified_fields


@pytest.mark.parametrize("provider", ["sev-snp", "azure-cvm-sev-snp", "tdx"])
@pytest.mark.parametrize("nonce", [None, "", "!" * 86, "oversized", "short", "noncanonical"])
def test_invalid_nonce_never_reaches_optional_binding_verifier(monkeypatch, provider, nonce):
    key = SigningKey()
    claim = _claim(provider, key=key)
    original = claim["trace"]["runtime"]["nonce"]
    if nonce == "oversized":
        raw = base64.urlsafe_b64decode(original + "==") + b"x"
        nonce = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    elif nonce == "short":
        raw = base64.urlsafe_b64decode(original + "==")[:32]
        nonce = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    elif nonce == "noncanonical":
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        nonce = original[:-1] + alphabet[alphabet.index(original[-1]) + 1]
    if nonce is None:
        claim["trace"]["runtime"].pop("nonce")
    else:
        claim["trace"]["runtime"]["nonce"] = nonce
    _resign(claim, key)
    module, func = {
        "sev-snp": ("sev_snp", "verify_sev_snp_measurement"),
        "azure-cvm-sev-snp": ("azure_cvm", "verify_azure_cvm_measurement"),
        "tdx": ("tdx", "verify_tdx_measurement"),
    }[provider]
    def unexpected(**kwargs):
        pytest.fail("invalid nonce must not disable the platform's optional binding check")
    monkeypatch.setattr(f"cmcp_verify.{module}.{func}", unexpected)
    result = verify_trace_claim(claim, _approved())
    assert "hardware_attestation" in result.unverified_fields
    assert "hardware_attestation" not in result.verified_fields
