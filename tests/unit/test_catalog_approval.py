from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cmcp_runtime.catalog.approval import (
    PROFILE,
    CatalogApprovalError,
    CatalogApprovalMismatch,
    TrustedReviewer,
    digest_json,
    sign_approval,
    verify_catalog_change,
)


def _record() -> tuple[dict, Ed25519PrivateKey, Ed25519PrivateKey]:
    first, second = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    policy = {"policy_id": "catalog-policy-v1", "threshold": 2, "distinct_principals": True, "distinct_roles": True}
    record = {
        "profile": PROFILE, "catalog_id": "gateway-prod", "sequence": 2,
        "previous_record_hash": "sha256:" + "1" * 64,
        "previous_catalog_hash": "sha256:" + "2" * 64,
        "new_catalog_hash": "sha256:" + "3" * 64,
        "change_set_digest": digest_json({"added": ["ehr.read"], "removed": []}),
        "approval_policy": {**policy, "policy_hash": digest_json(policy)},
        "automated_checks_digest": digest_json({"ci": "passed", "security": "passed"}),
        "approvals": [],
    }
    record["approvals"] = [
        sign_approval(record, {"principal_id": "alice", "issuer": "idp", "key_id": "k1", "role": "security", "approved_at": 100, "expires_at": 200}, first),
        sign_approval(record, {"principal_id": "bob", "issuer": "idp", "key_id": "k2", "role": "owner", "approved_at": 100, "expires_at": 200}, second),
    ]
    return record, first, second


def test_two_distinct_valid_approvals_bind_runtime_catalog() -> None:
    record, first, second = _record()
    result = verify_catalog_change(
        record,
        {"k1": TrustedReviewer("alice", "idp", first.public_key(), "security"), "k2": TrustedReviewer("bob", "idp", second.public_key(), "owner")},
        runtime_catalog_hash=record["new_catalog_hash"], now=150,
    )
    assert result == {"verified": True, "valid_approvals": 2, "new_catalog_hash": record["new_catalog_hash"]}


def test_runtime_hash_and_chain_are_bound() -> None:
    record, first, second = _record()
    trusted = {"k1": TrustedReviewer("alice", "idp", first.public_key()), "k2": TrustedReviewer("alice", "idp", second.public_key())}
    with pytest.raises(CatalogApprovalMismatch, match="runtime"):
        verify_catalog_change(record, trusted, runtime_catalog_hash="sha256:" + "4" * 64, now=150)
    with pytest.raises(CatalogApprovalMismatch, match="next chain"):
        verify_catalog_change(record, trusted, runtime_catalog_hash=record["new_catalog_hash"], expected_previous_record_hash="sha256:" + "9" * 64, now=150)


def test_tampering_expiry_revocation_and_duplicate_principal_fail() -> None:
    record, first, second = _record()
    trusted = {"k1": TrustedReviewer("alice", "idp", first.public_key()), "k2": TrustedReviewer("alice", "idp", second.public_key())}
    tampered = copy.deepcopy(record)
    tampered["new_catalog_hash"] = "sha256:" + "4" * 64
    with pytest.raises(CatalogApprovalMismatch, match="signature"):
        verify_catalog_change(tampered, trusted, runtime_catalog_hash=tampered["new_catalog_hash"], now=150)
    with pytest.raises(CatalogApprovalMismatch, match="revoked"):
        verify_catalog_change(record, trusted, runtime_catalog_hash=record["new_catalog_hash"], revoked_key_ids=frozenset({"k1"}), now=150)
    duplicate = copy.deepcopy(record)
    duplicate["approvals"][1]["principal_id"] = "alice"
    duplicate["approvals"][1] = sign_approval(record, {k: v for k, v in duplicate["approvals"][1].items() if k != "signature"}, second)
    with pytest.raises(CatalogApprovalMismatch, match="distinct principals"):
        verify_catalog_change(duplicate, trusted, runtime_catalog_hash=record["new_catalog_hash"], now=150)


def test_malformed_record_fails_closed() -> None:
    record, _, _ = _record()
    record["unexpected"] = True
    with pytest.raises(CatalogApprovalError, match="unknown"):
        verify_catalog_change(record, {}, runtime_catalog_hash=record["new_catalog_hash"], now=150)
