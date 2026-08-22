from __future__ import annotations

import copy
import json
import pathlib
import tomllib

import jsonschema
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cmcp_runtime.catalog import approval as approval_module
from cmcp_runtime.catalog.approval import (
    CATALOG_APPROVAL_SCHEMA_PATH,
    GENESIS_PREVIOUS_RECORD_HASH,
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
SCHEMA = json.loads(CATALOG_APPROVAL_SCHEMA_PATH.read_text())


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
        "validity_instant": 150,
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
    with pytest.raises(CatalogApprovalMismatch, match="not valid at the instant"):
        _verify(record, trusted, validity_instant=10_000)
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
    with pytest.raises(CatalogApprovalError, match="Additional properties"):
        _verify(record, {})


def test_malformed_field_types_fail_closed() -> None:
    """Bad field types must surface as CatalogApprovalError, never TypeError."""
    record, first, _ = _record(threshold=1, distinct=False)
    trusted = {"k1": TrustedReviewer("alice", "idp", first.public_key())}
    unhashable = copy.deepcopy(record)
    unhashable["approvals"] = [
        sign_approval(unhashable, {"principal_id": "alice", "issuer": "idp", "key_id": "k1", "role": {"nested": "obj"}, "approved_at": 100, "expires_at": 200}, first)
    ]
    with pytest.raises(CatalogApprovalError, match="approvals/0/role"):
        _verify(unhashable, trusted)
    boolean_times = copy.deepcopy(record)
    boolean_times["approvals"] = [
        sign_approval(boolean_times, {"principal_id": "alice", "issuer": "idp", "key_id": "k1", "role": "security", "approved_at": False, "expires_at": True}, first)
    ]
    with pytest.raises(CatalogApprovalError, match="approvals/0/(approved_at|expires_at)"):
        _verify(boolean_times, trusted, validity_instant=0)


def test_signature_encoding_is_validated() -> None:
    record, first, second = _record()
    trusted = _trusted(first, second)
    for bad in ("not base64!!", "c2hvcnQ", "A"):
        broken = copy.deepcopy(record)
        broken["approvals"][0]["signature"] = bad
        with pytest.raises(CatalogApprovalError, match="base64url|64 bytes|approvals/0/signature"):
            _verify(broken, trusted)


def _resign(record: dict, keys: dict[str, Ed25519PrivateKey]) -> dict:
    """Re-sign every approval after the record body changed."""
    record["approvals"] = [
        sign_approval(record, {k: v for k, v in approval.items() if k != "signature"}, keys[approval["key_id"]])
        for approval in record["approvals"]
    ]
    return record


def test_threshold_shortfall_is_rejected() -> None:
    """One approval must not satisfy a 2-of-N policy."""
    record, first, second = _record(threshold=2)
    short = copy.deepcopy(record)
    short["approvals"] = [short["approvals"][0]]
    with pytest.raises(CatalogApprovalMismatch, match="threshold is not satisfied"):
        _verify(short, _trusted(first, second))


def test_repeated_role_rejected_under_distinct_role_policy() -> None:
    """Distinct principals sharing one role must not satisfy a distinct-role policy."""
    record, first, second = _record(threshold=2, distinct=True)
    trusted = _trusted(first, second)
    trusted["k2"] = TrustedReviewer("bob", "idp", second.public_key(), "security")
    shared = copy.deepcopy(record)
    shared["approvals"][1]["role"] = "security"
    _resign(shared, {"k1": first, "k2": second})
    with pytest.raises(CatalogApprovalMismatch, match="repeats a role"):
        _verify(shared, trusted)


def test_approval_identity_must_match_the_trusted_key() -> None:
    """principal_id, issuer, and role are claims about the key, not free text."""
    record, first, second = _record()
    wrong_principal = _trusted(first, second) | {"k1": TrustedReviewer("carol", "idp", first.public_key(), "security")}
    with pytest.raises(CatalogApprovalMismatch, match="principal or issuer"):
        _verify(record, wrong_principal)
    wrong_issuer = _trusted(first, second) | {"k1": TrustedReviewer("alice", "other-idp", first.public_key(), "security")}
    with pytest.raises(CatalogApprovalMismatch, match="principal or issuer"):
        _verify(record, wrong_issuer)
    wrong_role = _trusted(first, second) | {"k1": TrustedReviewer("alice", "idp", first.public_key(), "owner")}
    with pytest.raises(CatalogApprovalMismatch, match="role does not match"):
        _verify(record, wrong_role)


def test_validity_interval_boundaries() -> None:
    """Against a supplied instant: approved_at inclusive, expires_at exclusive, interval ordered."""
    record, first, second = _record()
    trusted = _trusted(first, second)
    assert _verify(record, trusted, validity_instant=100)["verified"]
    with pytest.raises(CatalogApprovalMismatch, match="not valid at the instant"):
        _verify(record, trusted, validity_instant=99)
    with pytest.raises(CatalogApprovalMismatch, match="not valid at the instant"):
        _verify(record, trusted, validity_instant=200)
    inverted = copy.deepcopy(record)
    for approval in inverted["approvals"]:
        approval["approved_at"], approval["expires_at"] = 200, 100
    _resign(inverted, {"k1": first, "k2": second})
    with pytest.raises(CatalogApprovalError, match="validity interval is invalid"):
        _verify(inverted, trusted, validity_instant=150)


def test_genesis_record_is_representable() -> None:
    """The first record in a chain has no predecessor, so previous_record_hash is all zeroes.

    The convention is asserted here rather than in the schema, which still demands a
    previous_record_hash without defining what a sequence 1 record puts there.
    """
    record, first, second = _record()
    genesis = copy.deepcopy(record)
    genesis["sequence"] = 1
    genesis["previous_record_hash"] = GENESIS_PREVIOUS_RECORD_HASH
    _resign(genesis, {"k1": first, "k2": second})
    jsonschema.validate(genesis, SCHEMA)
    assert _verify(
        genesis,
        _trusted(first, second),
        expected_sequence=1,
        expected_previous_record_hash=GENESIS_PREVIOUS_RECORD_HASH,
    )["verified"]


def _unknown_field(record: dict) -> None:
    record["unexpected"] = True


def _zero_sequence(record: dict) -> None:
    record["sequence"] = 0


def _bool_sequence(record: dict) -> None:
    record["sequence"] = True


def _zero_threshold(record: dict) -> None:
    record["approval_policy"]["threshold"] = 0


def _empty_catalog_id(record: dict) -> None:
    record["catalog_id"] = ""


def _missing_chain_field(record: dict) -> None:
    del record["previous_record_hash"]


def _missing_policy_field(record: dict) -> None:
    del record["approval_policy"]["distinct_roles"]


def _no_approvals(record: dict) -> None:
    record["approvals"] = []


def _bool_timestamps(record: dict) -> None:
    record["approvals"][0]["approved_at"] = False
    record["approvals"][0]["expires_at"] = True


def _bad_signature_alphabet(record: dict) -> None:
    record["approvals"][0]["signature"] = "not base64!!"


def _malformed_digest(record: dict) -> None:
    record["new_catalog_hash"] = "sha256:" + "z" * 64


@pytest.mark.parametrize(
    "mutate",
    [
        _unknown_field,
        _zero_sequence,
        _bool_sequence,
        _zero_threshold,
        _empty_catalog_id,
        _missing_chain_field,
        _missing_policy_field,
        _no_approvals,
        _bool_timestamps,
        _bad_signature_alphabet,
        _malformed_digest,
    ],
)
def test_schema_and_verifier_reject_the_same_records(mutate) -> None:
    """Anything the shipped schema rejects the verifier must reject too.

    The verifier reimplements structural validation by hand and does not load the
    schema, so the two can only be kept in step by asserting it.
    """
    record, first, second = _record()
    jsonschema.validate(record, SCHEMA)
    assert _verify(record, _trusted(first, second))["verified"]

    mutated = copy.deepcopy(record)
    mutate(mutated)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(mutated, SCHEMA)
    with pytest.raises(CatalogApprovalError):
        _verify(mutated, _trusted(first, second))


def test_negative_approved_at_is_rejected_like_the_schema() -> None:
    """The divergence #531 could only document: the schema sets a minimum, and now the verifier applies it."""
    record, first, second = _record()
    negative = copy.deepcopy(record)
    negative["approvals"][0]["approved_at"] = -1
    _resign(negative, {"k1": first, "k2": second})
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(negative, SCHEMA)
    with pytest.raises(CatalogApprovalError):
        _verify(negative, _trusted(first, second))


def test_policy_distinctness_flags_must_be_booleans() -> None:
    """A truthy string must not stand in for a policy flag the verifier branches on."""
    record, first, second = _record()
    mangled = copy.deepcopy(record)
    mangled["approval_policy"]["distinct_roles"] = "yes"
    with pytest.raises(CatalogApprovalError, match="approval_policy/distinct_roles"):
        _verify(mangled, _trusted(first, second))


def test_unknown_profile_and_malformed_members_fail_closed() -> None:
    record, first, second = _record()
    trusted = _trusted(first, second)
    wrong_profile = copy.deepcopy(record)
    wrong_profile["profile"] = "tag:example.com,2026:something-else"
    with pytest.raises(CatalogApprovalError, match="schema violation at profile"):
        _verify(wrong_profile, trusted)
    wrong_shape = copy.deepcopy(record)
    wrong_shape["change_set_digest"] = "not-a-digest"
    with pytest.raises(CatalogApprovalError, match="schema violation at change_set_digest"):
        _verify(wrong_shape, trusted)
    bad_digest = copy.deepcopy(record)
    bad_digest["change_set_digest"] = "sha256:" + "z" * 64
    with pytest.raises(CatalogApprovalError, match="schema violation at change_set_digest"):
        _verify(bad_digest, trusted)
    stray_field = copy.deepcopy(record)
    stray_field["approvals"][0]["note"] = "looks harmless"
    with pytest.raises(CatalogApprovalError, match="Additional properties"):
        _verify(stray_field, trusted)


def test_one_key_cannot_satisfy_a_threshold_by_signing_twice() -> None:
    """A repeated signature is one approval pasted N times, not N approvals.

    Both cases verified before this guard existed: a policy that does not demand
    distinct principals counted the same approval three times, and a policy that
    demands distinct roles counted one key twice when its trusted entry pins no role.
    """
    record, first, _ = _record(threshold=3, distinct=False)
    repeated = copy.deepcopy(record)
    repeated["approvals"] = [copy.deepcopy(repeated["approvals"][0]) for _ in range(3)]
    trusted = {"k1": TrustedReviewer("alice", "idp", first.public_key(), "security")}
    with pytest.raises(CatalogApprovalMismatch, match="reuses a reviewer key"):
        _verify(repeated, trusted)


def test_a_roleless_trusted_key_cannot_claim_two_roles() -> None:
    """distinct_roles must not be satisfiable by one key asserting two role strings."""
    policy = {"policy_id": "catalog-policy-v1", "threshold": 2, "distinct_principals": False, "distinct_roles": True}
    first = Ed25519PrivateKey.generate()
    record = {
        "profile": PROFILE, "catalog_id": CATALOG_ID, "sequence": 2,
        "previous_record_hash": "sha256:" + "1" * 64,
        "previous_catalog_hash": "sha256:" + "2" * 64,
        "new_catalog_hash": "sha256:" + "3" * 64,
        "change_set_digest": digest_json({"added": ["ehr.read"], "removed": []}),
        "approval_policy": {**policy, "policy_hash": compute_policy_hash(policy)},
        "automated_checks_digest": digest_json({"ci": "passed"}),
        "approvals": [],
    }
    record["approvals"] = [
        sign_approval(record, {"principal_id": "alice", "issuer": "idp", "key_id": "k1", "role": role, "approved_at": 100, "expires_at": 200}, first)
        for role in ("security", "owner")
    ]
    with pytest.raises(CatalogApprovalMismatch, match="reuses a reviewer key"):
        _verify(record, {"k1": TrustedReviewer("alice", "idp", first.public_key())})


def test_verification_refuses_when_the_schema_is_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Follows loader.py: no structural validation available means no verification."""
    record, first, second = _record()
    monkeypatch.setattr(approval_module, "CATALOG_APPROVAL_SCHEMA_PATH", pathlib.Path("no-such-schema.json"))
    monkeypatch.setattr(approval_module, "_schema_cache", None)
    with pytest.raises(CatalogApprovalError, match="missing from the CMCP installation"):
        _verify(record, _trusted(first, second))


def test_every_schema_the_runtime_loads_ships_in_the_wheel() -> None:
    """force-include is the only thing putting these next to the code; nothing else notices if it goes."""
    pyproject = tomllib.loads((pathlib.Path(__file__).parents[2] / "pyproject.toml").read_text())
    force_include = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    for schema in ("catalog-entry.schema.json", "catalog-approval.schema.json"):
        assert force_include.get(f"schemas/{schema}") == f"cmcp_runtime/schemas/{schema}"


def test_a_malformed_expected_policy_hash_is_rejected() -> None:
    """The caller's pin is not schema-validated, so the verifier still checks its shape."""
    record, first, second = _record()
    with pytest.raises(CatalogApprovalError, match="must be a sha256 digest"):
        _verify(record, _trusted(first, second), expected_policy_hash="not-a-digest")
    with pytest.raises(CatalogApprovalError, match="lowercase hexadecimal"):
        _verify(record, _trusted(first, second), expected_policy_hash="sha256:" + "Z" * 64)


def test_an_unreadable_schema_fails_closed(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    record, first, second = _record()
    broken = tmp_path / "catalog-approval.schema.json"
    broken.write_text("{ not json")
    monkeypatch.setattr(approval_module, "CATALOG_APPROVAL_SCHEMA_PATH", broken)
    monkeypatch.setattr(approval_module, "_schema_cache", None)
    with pytest.raises(CatalogApprovalError, match="cannot load catalog approval schema"):
        _verify(record, _trusted(first, second))


def test_a_record_stays_verifiable_after_its_approvals_expire() -> None:
    """The point of #533: a provenance record an auditor cannot replay is not provenance.

    The approvals below are valid for [100, 200). Under the verification clock this
    record stopped verifying the moment that window closed.
    """
    record, first, second = _record()
    trusted = _trusted(first, second)
    kwargs: dict = {
        "runtime_catalog_hash": record["new_catalog_hash"],
        "expected_policy_hash": record["approval_policy"]["policy_hash"],
        "expected_catalog_id": CATALOG_ID,
    }
    assert verify_catalog_change(record, trusted, **kwargs)["verified"]
    assert verify_catalog_change(record, trusted, validity_instant=150, **kwargs)["verified"]
    with pytest.raises(CatalogApprovalMismatch, match="not valid at the instant"):
        verify_catalog_change(record, trusted, validity_instant=10**9, **kwargs)


def test_revocation_is_judged_now_not_at_the_approval_instant() -> None:
    """A key revoked today must not validate a record presented today, however old the record."""
    record, first, second = _record()
    trusted = _trusted(first, second)
    assert _verify(record, trusted, validity_instant=None)["verified"]
    with pytest.raises(CatalogApprovalMismatch, match="revoked"):
        _verify(record, trusted, validity_instant=None, revoked_key_ids=frozenset({"k2"}))
