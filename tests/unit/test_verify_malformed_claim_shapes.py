"""Regression matrix for malformed TRACE Claim structure (#592).

These vectors pin the maintainer-ruling structural boundary: malformed external
claim structure is classified as CLAIM_MALFORMED before signature or key-binding
interpretation, and the result identifies which intermediate failed to parse.
"""

from __future__ import annotations

import pytest

import cmcp_verify.verify as verify_module
from cmcp_verify.verify import (
    ApprovedHashes,
    VerificationError,
    VerificationResult,
    VerificationStatus,
    verify_trace_claim,
)

_APPROVED = ApprovedHashes(
    policy_bundle_hash="sha256:" + "a" * 64,
    tool_catalog_hash="sha256:" + "b" * 64,
)

_CASES = [
    ("trace-string", {"trace": "bad"}, "trace"),
    ("trace-list", {"trace": []}, "trace"),
    ("trace-null", {"trace": None}, "trace"),
    ("cnf-string", {"trace": {"cnf": "bad"}}, "trace.cnf"),
    ("cnf-list", {"trace": {"cnf": []}}, "trace.cnf"),
    ("cnf-bool", {"trace": {"cnf": True}}, "trace.cnf"),
    ("jwk-string", {"trace": {"cnf": {"jwk": "bad"}}}, "trace.cnf.jwk"),
    ("jwk-list", {"trace": {"cnf": {"jwk": []}}}, "trace.cnf.jwk"),
    ("jwk-x-integer", {"trace": {"cnf": {"jwk": {"x": 1}}}}, "trace.cnf.jwk.x"),
    ("jwk-x-list", {"trace": {"cnf": {"jwk": {"x": []}}}}, "trace.cnf.jwk.x"),
    ("gateway-string", {"trace": {}, "gateway": "bad"}, "gateway"),
    ("gateway-list", {"trace": {}, "gateway": []}, "gateway"),
    (
        "audit-chain-string",
        {"trace": {}, "gateway": {"audit_chain": "bad"}},
        "gateway.audit_chain",
    ),
    (
        "attestation-evidence-string",
        {
            "trace": {"runtime": {"platform": "tpm2"}},
            "gateway": {"attestation_evidence": "bad"},
        },
        "gateway.attestation_evidence",
    ),
]


@pytest.mark.parametrize(
    ("label", "claim", "malformed_field"),
    _CASES,
    ids=[case[0] for case in _CASES],
)
def test_malformed_claim_shape_is_structural_failure(
    label: str,
    claim: dict[str, object],
    malformed_field: str,
) -> None:
    result = verify_trace_claim(claim, _APPROVED)

    assert isinstance(result, VerificationResult), label
    assert result.status is VerificationStatus.UNVERIFIED, label
    assert result.failure_reason is VerificationError.CLAIM_MALFORMED, label
    assert result.verified_fields == [], label
    assert result.unverified_fields == ["schema"], label
    assert result.attestation_age_seconds == -1, label
    assert result.is_attestation_fresh is False, label
    assert result.details.get("malformed_field") == malformed_field, label
    assert "schema_error" in result.details, label


def test_malformed_claim_stops_before_crypto(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_crypto(*args: object, **kwargs: object) -> tuple[bool, str | None]:
        pytest.fail("malformed claim reached cryptographic interpretation")

    monkeypatch.setattr(verify_module, "_verify_signature", unexpected_crypto)
    monkeypatch.setattr(verify_module, "_verify_key_binding", unexpected_crypto)

    result = verify_module.verify_trace_claim({"trace": "bad"}, _APPROVED)

    assert result.failure_reason is VerificationError.CLAIM_MALFORMED
