"""Malformed audit-bundle boundary vectors for issue #593."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from cmcp_verify.verify import AuditBundleResult, verify_audit_bundle


def _one_entry_bundle() -> dict[str, Any]:
    body = {
        "entry_type": "session",
        "session_id": "session-1",
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
    ("entries", "failure_path"),
    [
        ("bad", "bundle.entries"),
        (1, "bundle.entries"),
        (True, "bundle.entries"),
        ({"unexpected": "object"}, "bundle.entries"),
        (["bad"], "bundle.entries[0]"),
        ([1], "bundle.entries[0]"),
        ([True], "bundle.entries[0]"),
        ([[]], "bundle.entries[0]"),
        ([None], "bundle.entries[0]"),
    ],
)
def test_malformed_entries_return_failed_result(entries: Any, failure_path: str) -> None:
    result = verify_audit_bundle({"entries": entries})

    assert result == AuditBundleResult(
        verified=False,
        entry_count=len(entries) if isinstance(entries, list) else 0,
        failures=[f"{failure_path} has invalid object or array shape"],
    )


@pytest.mark.parametrize(
    ("claim", "failure_path"),
    [
        ({"gateway": "bad"}, "claim.gateway"),
        ({"gateway": {"audit_chain": "bad"}}, "claim.gateway.audit_chain"),
        ({"gateway": {"call_summary": "bad"}}, "claim.gateway.call_summary"),
        ({"trace": "bad"}, "claim.trace"),
        ({"trace": {"tool_transcript": "bad"}}, "claim.trace.tool_transcript"),
        ({"trace": {"cnf": "bad"}}, "claim.trace.cnf"),
        ({"trace": {"cnf": {"jwk": "bad"}}}, "claim.trace.cnf.jwk"),
    ],
)
def test_malformed_claim_binding_shapes_return_failed_result(
    claim: dict[str, Any], failure_path: str
) -> None:
    result = verify_audit_bundle(_one_entry_bundle(), claim)

    assert result == AuditBundleResult(
        verified=False,
        entry_count=1,
        failures=[f"{failure_path} has invalid object or array shape"],
    )


def test_malformed_bundle_root_returns_failed_result() -> None:
    result = verify_audit_bundle(None)  # type: ignore[arg-type]

    assert result == AuditBundleResult(
        verified=False,
        entry_count=0,
        failures=["bundle has invalid object or array shape"],
    )


def test_malformed_claim_root_returns_failed_result() -> None:
    result = verify_audit_bundle(_one_entry_bundle(), "bad")  # type: ignore[arg-type]

    assert result == AuditBundleResult(
        verified=False,
        entry_count=1,
        failures=["claim has invalid object or array shape"],
    )


def test_missing_entries_preserves_existing_failure() -> None:
    result = verify_audit_bundle({})

    assert result == AuditBundleResult(
        verified=False,
        entry_count=0,
        failures=["bundle has no entries"],
    )


def test_valid_entry_preserves_success() -> None:
    assert verify_audit_bundle(_one_entry_bundle()) == AuditBundleResult(
        verified=True,
        entry_count=1,
        failures=[],
    )


def _hash_entries(entries: list[dict[str, Any]]) -> dict[str, Any]:
    previous = "genesis"
    for entry in entries:
        entry["prev_entry_hash"] = previous
        body = {key: value for key, value in entry.items() if key != "entry_hash"}
        previous = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
        entry["entry_hash"] = previous
    return {"entries": entries}


@pytest.mark.parametrize("bad_name", [["x"], {"name": "x"}, 1, True])
@pytest.mark.parametrize("position", [0, 1])
def test_invalid_tool_name_returns_failure(bad_name: Any, position: int) -> None:
    entries = [{"entry_type": "tool_call", "tool_name": "valid"} for _ in range(2)]
    entries[position]["tool_name"] = bad_name
    result = verify_audit_bundle(_hash_entries(entries), {})
    assert not result.verified
    assert f"entry {position}: tool_name must be a string" in result.failures
    assert not any("hash mismatch" in failure for failure in result.failures)


@pytest.mark.parametrize("bad_type", [["receipt"], {"type": "receipt"}, 1, True, None])
def test_invalid_evidence_type_returns_failure(bad_type: Any) -> None:
    entry = {
        "entry_type": "tool_call",
        "call_id": "call-1",
        "tool_name": "valid",
        "external_execution_evidence": {
            "linked_call_id": "call-1",
            "issuer_key_id": "a" * 64,
            "evidence_hash": "sha256:" + "b" * 64,
            "evidence_type": bad_type,
        },
    }
    result = verify_audit_bundle(_hash_entries([entry]), external_evidence_keys={})
    assert not result.verified
    assert any("unsupported evidence_type" in failure for failure in result.failures)
    assert not any("hash mismatch" in failure for failure in result.failures)
