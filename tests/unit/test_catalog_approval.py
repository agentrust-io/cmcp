from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cmcp_runtime.catalog.approval import (
    PROFILE,
    CatalogApprovalError,
    CatalogApprovalMismatch,
    TrustedReviewer,
    compute_policy_hash,
    digest_json,
    sign_approval,
    verify_catalog_change,
)

CATALOG_ID = "gateway-prod"


def _record(threshold: int = 2, distinct: bool = True) -> tuple[dict, Ed25519PrivateKey, Ed25519PrivateKey]:
    first, second = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    policy = {"policy_id": "catalog-policy-v1", "threshold": threshold, "distinct_principals": distinct, "distinct_roles": distinct}
    record = {
        "profile": PROFILE, "catalog_id": CATALOG_ID, "sequence": 2,
        "previous_record_hash": "sha256:" + "1" * 64,
        "previous_catalog_hash": "sha256:" + "2" * 64,
        "new_catalog_hash": "sha256:" + "3" * 64,
        "change_set_digest": digest_json({"added": ["ehr.read"], "removed": []}),
        "approval_policy": {**policy, "policy_hash": compute_policy_hash(policy)},
        "automated_checks_digest": digest_json({"ci": "passed", "security": "passed"}),
        "approvals": [],
    }
    record["approvals"] = [
        sign_approval(record, {"principal_id": "alice", "issuer": "idp", "key_id": "k1", "role": "security", "approved_at": 100, "expires_at": 200}, first),
        sign_approval(record, {"principal_id": "bob", "issuer": "idp", "key_id": "k2", "role": "owner", "approved_at": 100, "expires_at": 200}, second),
    ]
    return record, first, second


def _trusted(first: Ed25519PrivateKey, second: Ed25519PrivateKey) -> dict[str, TrustedReviewer]:
    return {
        "k1": TrustedReviewer("alice", "idp", first.public_key(), "security"),
        "k2": TrustedReviewer("bob", "idp", second.public_key(), "owner"),
    }


def _verify(record: dict, trusted: dict[str, TrustedReviewer], **overrides: object) -> dict:
    kwargs: dict = {
        "runtime_catalog_hash": record["new_catalog_hash"],
        "expected_policy_hash": record["approval_policy"]["policy_hash"],
        "expected_catalog_id": CATALOG_ID,
        "now": 150,
    }
    kwargs.update(overrides)
    return verify_catalog_change(record, trusted, **kwargs)  # type: ignore[arg-type]


def test_two_distinct_valid_approvals_bind_runtime_catalog() -> None:
    record, first, second = _record()
    result = _verify(record, _trusted(first, second))
    assert result == {"verified": True, "valid_approvals": 2, "new_catalog_hash": record["new_catalog_hash"]}


def test_runtime_hash_and_chain_are_bound() -> None:
    record, first, second = _record()
    trusted = _trusted(first, second)
    with pytest.raises(CatalogApprovalMismatch, match="runtime"):
        _verify(record, trusted, runtime_catalog_hash="sha256:" + "4" * 64)
    with pytest.raises(CatalogApprovalMismatch, match="next chain"):
        _verify(record, trusted, expected_previous_record_hash="sha256:" + "9" * 64)


def test_catalog_identity_and_chain_fields_are_bound() -> None:
    """previous_catalog_hash, sequence, and catalog_id must be pinnable, not decorative."""
    record, first, second = _record()
    trusted = _trusted(first, second)
    with pytest.raises(CatalogApprovalMismatch, match="expected catalog"):
        _verify(record, trusted, expected_catalog_id="gateway-dev")
    with pytest.raises(CatalogApprovalMismatch, match="sequence number"):
        _verify(record, trusted, expected_sequence=7)
    with pytest.raises(CatalogApprovalMismatch, match="previous_catalog_hash"):
        _verify(record, trusted, expected_previous_catalog_hash="sha256:" + "a" * 64)
    assert _verify(
        record, trusted,
        expected_sequence=2,
        expected_previous_record_hash=record["previous_record_hash"],
        expected_previous_catalog_hash=record["previous_catalog_hash"],
    )["verified"]


def test_record_cannot_declare_its_own_policy() -> None:
    """A single trusted key must not be able to downgrade the threshold to one."""
    record, first, _ = _record(threshold=1, distinct=False)
    record["approvals"] = [record["approvals"][0]]
    trusted = {"k1": TrustedReviewer("alice", "idp", first.public_key(), "security")}
    two_of_two = {"policy_id": "catalog-policy-v1", "threshold": 2, "distinct_principals": True, "distinct_roles": True}
    with pytest.raises(CatalogApprovalMismatch, match="does not trust"):
        _verify(record, trusted, expected_policy_hash=compute_policy_hash(two_of_two))


def test_policy_hash_must_cover_the_policy_body() -> None:
    record, first, second = _record()
    trusted = _trusted(first, second)
    forged = copy.deepcopy(record)
    forged["approval_policy"]["threshold"] = 1
    with pytest.raises(CatalogApprovalError, match="does not cover"):
        _verify(forged, trusted, expected_policy_hash=forged["approval_policy"]["policy_hash"])


def test_tampering_expiry_revocation_and_duplicate_principal_fail() -> None:
    record, first, second = _record()
    trusted = _trusted(first, second)
    tampered = copy.deepcopy(record)
    tampered["new_catalog_hash"] = "sha256:" + "4" * 64
    with pytest.raises(CatalogApprovalMismatch, match="signature"):
        _verify(tampered, trusted, runtime_catalog_hash=tampered["new_catalog_hash"])
    with pytest.raises(CatalogApprovalMismatch, match="revoked"):
        _verify(record, trusted, revoked_key_ids=frozenset({"k1"}))
    with pytest.raises(CatalogApprovalMismatch, match="not currently valid"):
        _verify(record, trusted, now=10_000)
    with pytest.raises(CatalogApprovalMismatch, match="not trusted"):
        _verify(record, {"k1": trusted["k1"]})


def test_duplicate_principal_rejected_even_with_surplus_approvals() -> None:
    """Distinctness must reject repeats, not merely count distinct values."""
    record, first, second = _record(threshold=2, distinct=True)
    trusted = _trusted(first, second)
    surplus = copy.deepcopy(record)
    trusted["k3"] = TrustedReviewer("alice", "idp", first.public_key(), "security")
    surplus["approvals"].append(
        sign_approval(surplus, {"principal_id": "alice", "issuer": "idp", "key_id": "k3", "role": "security", "approved_at": 100, "expires_at": 200}, first)
    )
    with pytest.raises(CatalogApprovalMismatch, match="repeats a principal"):
        _verify(surplus, trusted)


def test_malformed_record_fails_closed() -> None:
    record, _, _ = _record()
    record["unexpected"] = True
    with pytest.raises(CatalogApprovalError, match="unknown"):
        _verify(record, {})


def test_malformed_field_types_fail_closed() -> None:
    """Bad field types must surface as CatalogApprovalError, never TypeError."""
    record, first, _ = _record(threshold=1, distinct=False)
    trusted = {"k1": TrustedReviewer("alice", "idp", first.public_key())}
    unhashable = copy.deepcopy(record)
    unhashable["approvals"] = [
        sign_approval(unhashable, {"principal_id": "alice", "issuer": "idp", "key_id": "k1", "role": {"nested": "obj"}, "approved_at": 100, "expires_at": 200}, first)
    ]
    with pytest.raises(CatalogApprovalError, match="approval.role"):
        _verify(unhashable, trusted)
    boolean_times = copy.deepcopy(record)
    boolean_times["approvals"] = [
        sign_approval(boolean_times, {"principal_id": "alice", "issuer": "idp", "key_id": "k1", "role": "security", "approved_at": False, "expires_at": True}, first)
    ]
    with pytest.raises(CatalogApprovalError, match="must be an integer"):
        _verify(boolean_times, trusted, now=0)


def test_signature_encoding_is_validated() -> None:
    record, first, second = _record()
    trusted = _trusted(first, second)
    for bad in ("not base64!!", "c2hvcnQ"):
        broken = copy.deepcopy(record)
        broken["approvals"][0]["signature"] = bad
        with pytest.raises(CatalogApprovalError, match="base64url|64 bytes"):
            _verify(broken, trusted)
