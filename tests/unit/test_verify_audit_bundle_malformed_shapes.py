"""Malformed audit-bundle boundary vectors for issue #593."""

from __future__ import annotations

import hashlib
import json

import pytest

from cmcp_verify.verify import AuditBundleResult, verify_audit_bundle


def _one_entry_bundle() -> dict:
    body = {
        "entry_type": "session",
        "call_id": "call-1",
        "prev_entry_hash": "genesis",
    }
    entry_hash = hashlib.sha256(
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()
    return {"entries": [{**body, "entry_hash": entry_hash}]}


@pytest.mark.parametrize(
    "entries",
    [
        "bad",
        1,
        True,
        {"unexpected": "object"},
        ["bad"],
        [1],
        [True],
        [[]],
        [None],
    ],
)
def test_malformed_entries_return_failed_result(entries) -> None:
    try:
        result = verify_audit_bundle({"entries": entries})
    except (AttributeError, TypeError) as exc:
        pytest.xfail(f"known #593 malformed-bundle escape: {type(exc).__name__}: {exc}")

    assert isinstance(result, AuditBundleResult)
    assert not result.verified
    assert result.failures


@pytest.mark.parametrize(
    "claim",
    [
        {"gateway": "bad"},
        {"gateway": {"audit_chain": "bad"}},
        {"trace": "bad"},
        {"trace": {"tool_transcript": "bad"}},
        {"trace": {"cnf": "bad"}},
        {"trace": {"cnf": {"jwk": "bad"}}},
    ],
)
def test_malformed_claim_binding_shapes_return_failed_result(claim: dict) -> None:
    try:
        result = verify_audit_bundle(_one_entry_bundle(), claim)
    except (AttributeError, TypeError) as exc:
        pytest.xfail(f"known #593 malformed-claim escape: {type(exc).__name__}: {exc}")

    assert isinstance(result, AuditBundleResult)
    assert not result.verified
    assert result.failures


def test_missing_entries_preserves_existing_failure() -> None:
    result = verify_audit_bundle({})

    assert result == AuditBundleResult(
        verified=False,
        entry_count=0,
        failures=["bundle has no entries"],
    )
