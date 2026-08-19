"""RFC 8785 conformance for the catalog-approval signing input (#517)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cmcp_runtime.catalog.approval import (
    PROFILE,
    CatalogApprovalError,
    TrustedReviewer,
    canonical_json,
    digest_json,
    sign_approval,
    verify_catalog_change,
)


def test_non_ascii_is_emitted_as_utf8() -> None:
    """JCS escapes only what JSON.stringify escapes, so no ASCII escapes appear."""
    assert canonical_json({"principal_id": "josé"}) == '{"principal_id":"josé"}'.encode()


def test_ascii_records_keep_their_existing_bytes() -> None:
    """The signing input for an ASCII record must not move, or nothing already signed still verifies."""
    assert canonical_json({"b": 1, "a": "x", "n": None, "t": True}) == b'{"a":"x","b":1,"n":null,"t":true}'
    assert digest_json({"added": ["ehr.read"], "removed": []}) == (
        "sha256:5abec4d8f1edbfc37f5fb61594363c2ac9ebb1ecaf2007203462eb41016e5678"
    )


def test_members_are_ordered_by_utf16_code_units() -> None:
    """Section 3.2.3 orders by UTF-16 code units, so a non-BMP key sorts below U+FFFF."""
    assert canonical_json({"\uffff": 1, "\U00010000": 2}) == '{"\U00010000":2,"\uffff":1}'.encode()
    assert canonical_json({"b": 1, "A": 2, "a": 3}) == b'{"A":2,"a":3,"b":1}'


def test_nested_containers_are_canonicalized_throughout() -> None:
    assert canonical_json({"outer": [{"b": 1, "a": "é"}]}) == '{"outer":[{"a":"é","b":1}]}'.encode()


@pytest.mark.parametrize(
    "value, message",
    [
        ({"x": 1.5}, "floating point"),
        ({"x": float("nan")}, "floating point"),
        ({"x": 2**53}, "outside the range"),
        ({"x": -(2**53)}, "outside the range"),
        ({1: "a"}, "keys must be strings"),
        ({"x": "\ud800"}, "unpaired surrogate"),
        ({"\ud800": "x"}, "unpaired surrogate"),
    ],
)
def test_values_jcs_cannot_pin_down_are_refused(value: object, message: str) -> None:
    """Refusing beats emitting bytes an interoperating implementation would disagree with."""
    with pytest.raises(CatalogApprovalError, match=message):
        canonical_json(value)


def test_the_largest_exact_integer_is_accepted() -> None:
    assert canonical_json({"x": 2**53 - 1}) == b'{"x":9007199254740991}'


def test_a_non_ascii_reviewer_identity_signs_and_verifies() -> None:
    key = Ed25519PrivateKey.generate()
    policy = {"policy_id": "politique-des-catalogues", "threshold": 1, "distinct_principals": True, "distinct_roles": False}
    record = {
        "profile": PROFILE, "catalog_id": "passerelle-prod", "sequence": 2,
        "previous_record_hash": "sha256:" + "1" * 64,
        "previous_catalog_hash": "sha256:" + "2" * 64,
        "new_catalog_hash": "sha256:" + "3" * 64,
        "change_set_digest": digest_json({"added": ["dossier.lecture"], "removed": []}),
        "approval_policy": {**policy, "policy_hash": digest_json(policy)},
        "automated_checks_digest": digest_json({"ci": "réussi"}),
        "approvals": [],
    }
    record["approvals"] = [
        sign_approval(record, {"principal_id": "josé", "issuer": "idp", "key_id": "k1", "role": "sécurité", "approved_at": 100, "expires_at": 200}, key)
    ]
    assert b"\\u" not in canonical_json(record)
    result = verify_catalog_change(
        record,
        {"k1": TrustedReviewer("josé", "idp", key.public_key(), "sécurité")},
        runtime_catalog_hash=record["new_catalog_hash"], now=150,
    )
    assert result["verified"]
