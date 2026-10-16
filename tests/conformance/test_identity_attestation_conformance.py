"""IA-003/IA-004 conformance vectors for optional and required attestation.

These acceptance fixtures do not add claim fields or define token-exchange wire
format. Runtime attestation remains independent of authentication standing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "identity-attestation"
DIMENSIONS = {
    "workload_identity",
    "represented_user",
    "token_audience",
    "proof_of_possession_binding",
    "delegation_reference",
    "runtime_attestation",
}


def _load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("fixture", "evidence_condition", "not_established_reason"),
    [
        ("ia-003.json", "absent", "runtime_attestation_absent"),
        ("ia-004.json", "unverifiable", "runtime_attestation_unverifiable"),
    ],
)
def test_optional_and_required_attestation_policies_keep_authentication_independent(
    fixture: str,
    evidence_condition: str,
    not_established_reason: str,
) -> None:
    vector = _load(fixture)
    assert set(vector["independent_dimensions"]) == DIMENSIONS
    assert len(vector["independent_dimensions"]) == len(DIMENSIONS)
    assert vector["authentication_standing"] == "authenticated"
    assert vector["evidence_condition"] == evidence_condition
    variants = {case["attestation_policy"]: case for case in vector["policy_variants"]}
    assert set(variants) == {"optional", "required"}

    optional = variants["optional"]
    assert optional["verifier_disposition"] == "continue_to_policy"
    assert optional["positive_attestation_claim"] is False
    assert optional["evidence_status"] == "not_established"
    assert optional["reason"] == not_established_reason
    assert optional["refusal"] is False
    assert optional["upstream_calls"] == "policy_dependent"

    required = variants["required"]
    assert required["verifier_disposition"] == "refuse_before_upstream"
    assert required["positive_attestation_claim"] is False
    assert required["evidence_status"] == "not_established"
    assert required["reason"] == not_established_reason
    assert required["refusal"] is True
    assert required["upstream_calls"] == 0
    assert required["boundary_bypass_control"].startswith("must_fail_if_")
    assert required["boundary_bypass_control"].endswith("_is_bypassed")


def test_absence_and_unverifiable_evidence_are_not_verified_contradictions() -> None:
    absent = _load("ia-003.json")
    unverifiable = _load("ia-004.json")
    contradiction = unverifiable["verified_contradiction_control"]

    assert absent["evidence_condition"] == "absent"
    assert absent["policy_variants"][1]["evidence_status"] == "not_established"
    assert unverifiable["evidence_condition"] == "unverifiable"
    assert unverifiable["policy_variants"][1]["evidence_status"] == "not_established"

    assert contradiction["evidence_condition"] == "verified_contradiction"
    assert contradiction["authentication_standing"] == "authenticated"
    assert contradiction["positive_attestation_claim"] is False
    assert contradiction["evidence_status"] == "contradictory"
    assert contradiction["reason"] == "runtime_attestation_binding_mismatch"
    assert contradiction["verifier_disposition"] == "refuse_on_attestation_boundary"
    assert contradiction["refusal"] is True
    assert contradiction["upstream_calls"] == 0
    assert contradiction["boundary_bypass_control"] == (
        "must_fail_if_attestation_binding_check_is_bypassed"
    )
