"""Authenticated platform policy through both SNP paths and the public API.

Synthetic PKI exercises real signatures; this is not hardware validation.
Bit positions here are literal AMD ABI positions, independent of the parser map.
"""
from __future__ import annotations

import base64
import json

import pytest

from cmcp_runtime.audit.keys import SigningKey
from cmcp_verify import SnpPlatformPolicy
from cmcp_verify.azure_cvm import verify_azure_cvm_measurement
from cmcp_verify.sev_snp import verify_sev_snp_measurement
from cmcp_verify.verify import VerificationError, VerificationStatus, verify_trace_claim
from tests.unit.test_azure_cvm_verify import _build_evidence
from tests.unit.test_evidence_envelope_all_platforms import _approved, _claim
from tests.unit.test_platform_nonce_binding import _resign
from tests.unit.test_snp_signature_verify import _signed_report, _synthetic_chain

STRICT = SnpPlatformPolicy(
    require=frozenset({"ciphertext_hiding_dram_enabled", "alias_check_complete"}),
    forbid=frozenset({"smt_enabled"}),
    reject_unrecognized_bits=True,
)
GOOD_STATE = (1 << 4) | (1 << 5)


def _evidence(provider, state, nonce):
    if provider == "azure-cvm-sev-snp":
        raw, measurement, root = _build_evidence(nonce, platform_info=state)
        return raw, measurement, {"trusted_ark_pem": root}
    chain, root, vcek = _synthetic_chain()
    raw, measurement = _signed_report(
        vcek, measurement_bytes=b"\x11" * 48, report_data=nonce, platform_info=state,
    )
    return raw, measurement, {"trusted_ark_pem": root, "cert_chain_pem": chain}


@pytest.mark.parametrize("provider", ["sev-snp", "azure-cvm-sev-snp"])
@pytest.mark.parametrize("state,allowed", [
    (GOOD_STATE, True), (0, False), (1 << 4, False), (1 << 5, False),
    (GOOD_STATE | 1, False), (GOOD_STATE | (1 << 6), False),
])
def test_signed_platform_state_gates_public_claim(provider, state, allowed):
    key = SigningKey()
    claim = _claim(provider, key=key)
    runtime = claim["trace"]["runtime"]
    nonce = base64.urlsafe_b64decode(runtime["nonce"] + "==")
    raw, measurement, kwargs = _evidence(provider, state, nonce)
    runtime["measurement"] = measurement
    envelope = claim["gateway"]["attestation_evidence"]
    envelope["raw_evidence"] = base64.b64encode(raw).decode()
    chain = kwargs.pop("cert_chain_pem", None)
    if chain:
        envelope["cert_chain"] = base64.b64encode(chain).decode()
    _resign(claim, key)
    # Positive control: authentic reports from unsuitable machines used to pass
    # because the platform policy did not exist. No-policy compatibility remains.
    baseline = verify_trace_claim(claim, _approved(), **kwargs)
    assert baseline.status == VerificationStatus.VERIFIED
    assert "platform_state" not in baseline.verified_fields
    result = verify_trace_claim(claim, _approved(), snp_platform_policy=STRICT, **kwargs)
    if allowed:
        assert result.status == VerificationStatus.VERIFIED
        assert "platform_state" in result.verified_fields
        assert result.details["platform_info"] == "0x30"
    else:
        assert result.failure_reason == VerificationError.HARDWARE_ATTESTATION_FAILED
        assert result.status != VerificationStatus.VERIFIED
        assert "platform_state" in result.unverified_fields
        assert "hardware_attestation" not in result.verified_fields


@pytest.mark.parametrize("provider", ["sev-snp", "azure-cvm-sev-snp"])
@pytest.mark.parametrize("attack", ["missing-root", "missing-report", "tamper-state"])
def test_acceptable_bits_without_authentic_evidence_never_satisfy_policy(provider, attack):
    nonce = b"n" * 64
    raw, measurement, kwargs = _evidence(provider, GOOD_STATE, nonce)
    if attack == "missing-root":
        kwargs.pop("trusted_ark_pem")
    elif attack == "missing-report":
        raw = None
    elif provider == "sev-snp":
        modified = bytearray(raw)
        modified[0x40] ^= 4  # ECC is unconstrained: policy would still pass.
        raw = bytes(modified)
    else:
        envelope = json.loads(raw)
        report = bytearray(base64.b64decode(envelope["snp_report"]))
        report[0x40] ^= 4
        envelope["snp_report"] = base64.b64encode(report).decode()
        raw = json.dumps(envelope).encode()
    verify = verify_sev_snp_measurement if provider == "sev-snp" else verify_azure_cvm_measurement
    result = verify(measurement, raw, nonce.hex(), platform_policy=STRICT, **kwargs)
    assert not result.verified
    assert "platform_state" not in result.verified_fields
    if attack == "missing-root":
        assert result.failure_reason == "platform_policy_requires_authenticated_evidence"
    elif attack == "tamper-state":
        assert result.failure_reason == "report_signature_invalid"


@pytest.mark.parametrize("provider", ["software-only", "tdx", "tpm"])
def test_snp_requirement_cannot_be_bypassed_by_selecting_another_provider(provider):
    result = verify_trace_claim(_claim(provider), _approved(), snp_platform_policy=STRICT)
    assert result.failure_reason is not None
    assert result.status != VerificationStatus.VERIFIED
    assert "platform_state" in result.unverified_fields


@pytest.mark.parametrize("kwargs", [
    {"require": {"typo"}}, {"forbid": {"smt"}},
    {"require": {"smt_enabled"}, "forbid": {"smt_enabled"}},
    {"require": "smt_enabled"}, {"require": {123}},
    {"reject_unrecognized_bits": "false"},
])
def test_invalid_policy_is_a_configuration_error(kwargs):
    with pytest.raises(ValueError):
        SnpPlatformPolicy(**kwargs)


def test_policy_snapshots_mutable_inputs():
    required = {"alias_check_complete"}
    policy = SnpPlatformPolicy(require=required)
    required.clear()
    assert policy.require == frozenset({"alias_check_complete"})
