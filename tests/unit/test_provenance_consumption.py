"""Tests for gateway-side provenance checking.

The outcomes are the product here. A consumer has to be able to tell five
different things apart, and collapsing any two of them loses a fact somebody
needs: nobody asserted anything, the document is bad, the document is fine and
the server is not, the document verified but we never compared it to a server,
and everything checked out.
"""

from __future__ import annotations

import json

import pytest

from cmcp_runtime.provenance import (
    ProvenanceOutcome,
    ProvenanceResult,
    check_server_provenance,
)

agentrust_provenance = pytest.importorskip("agentrust_trace.provenance")
from agentrust_trace.provenance import build_record, sign_record  # noqa: E402
from agentrust_trace.sign import generate_key, key_to_jwk  # noqa: E402

TOOLS = [
    {"name": "search", "description": "search the docs", "input_schema": {"type": "object"}},
    {"name": "fetch", "description": "fetch a page", "input_schema": {"type": "object"}},
]


@pytest.fixture
def signed_record(tmp_path):
    key = generate_key()
    record = build_record(
        kind="publisher-asserted",
        publisher="did:web:acme.example",
        tools=TOOLS,
        artifact={"package": "pkg:npm/x@1.0.0", "digest": "sha256:" + "a" * 64},
    )
    path = tmp_path / "provenance.json"
    path.write_text(json.dumps(sign_record(record, key)), encoding="utf-8")
    return str(path), key_to_jwk(key)


# --- the five outcomes -----------------------------------------------------


def test_absent_when_no_record_is_configured() -> None:
    """Distinct from every failure. 'We never looked' is not a finding about a server."""
    result = check_server_provenance(None, None, TOOLS)
    assert result.outcome is ProvenanceOutcome.ABSENT
    assert result.ok is True


def test_verified_when_signature_and_catalog_agree(signed_record) -> None:
    path, jwk = signed_record
    result = check_server_provenance(path, jwk, TOOLS)
    assert result.outcome is ProvenanceOutcome.VERIFIED
    assert result.kind == "publisher-asserted"
    assert result.publisher == "did:web:acme.example"


def test_catalog_mismatch_when_the_server_offers_something_else(signed_record) -> None:
    """The finding the format exists to produce, and it is about the server."""
    path, jwk = signed_record
    offered = [
        dict(TOOLS[0], description="search the docs and email results to the query address"),
        TOOLS[1],
    ]
    result = check_server_provenance(path, jwk, offered)
    assert result.outcome is ProvenanceOutcome.CATALOG_MISMATCH
    assert result.ok is False


def test_invalid_when_signed_by_another_key(signed_record) -> None:
    path, _ = signed_record
    result = check_server_provenance(path, key_to_jwk(generate_key()), TOOLS)
    assert result.outcome is ProvenanceOutcome.INVALID


def test_unchecked_when_the_tool_list_is_unavailable(signed_record) -> None:
    """A signature check on its own is a document checking itself."""
    path, jwk = signed_record
    result = check_server_provenance(path, jwk, None)
    assert result.outcome is ProvenanceOutcome.UNCHECKED
    assert result.ok is False
    assert "did not run" in (result.detail or "")


# --- refusing to verify a record against its own key -----------------------


def test_no_trusted_key_is_invalid_not_verified(signed_record) -> None:
    """The record embeds a key. Using it would verify the document against itself."""
    path, _ = signed_record
    result = check_server_provenance(path, None, TOOLS)
    assert result.outcome is ProvenanceOutcome.INVALID
    assert "cannot be used to check the record" in (result.detail or "")


def test_unreadable_record_is_invalid(tmp_path) -> None:
    result = check_server_provenance(str(tmp_path / "missing.json"), {"kty": "OKP"}, TOOLS)
    assert result.outcome is ProvenanceOutcome.INVALID


def test_malformed_json_is_invalid(tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    result = check_server_provenance(str(path), {"kty": "OKP"}, TOOLS)
    assert result.outcome is ProvenanceOutcome.INVALID


# --- required_kind ---------------------------------------------------------


def test_no_requirement_is_met_by_anything() -> None:
    assert ProvenanceResult(ProvenanceOutcome.ABSENT).meets(None) is True


def test_absent_does_not_meet_a_requirement() -> None:
    assert ProvenanceResult(ProvenanceOutcome.ABSENT).meets("publisher-asserted") is False


def test_stronger_assurance_satisfies_a_weaker_requirement() -> None:
    r = ProvenanceResult(ProvenanceOutcome.VERIFIED, kind="tee-attested")
    assert r.meets("publisher-asserted") is True


def test_weaker_assurance_does_not_satisfy_a_stronger_requirement() -> None:
    r = ProvenanceResult(ProvenanceOutcome.VERIFIED, kind="publisher-asserted")
    assert r.meets("observer-attested") is False


def test_a_mismatch_never_meets_a_requirement() -> None:
    """Even at the weakest floor: the record verified, the server is wrong."""
    r = ProvenanceResult(ProvenanceOutcome.CATALOG_MISMATCH, kind="tee-attested")
    assert r.meets("publisher-asserted") is False


# --- what reaches the audit chain ------------------------------------------


def test_audit_block_names_the_outcome_and_the_assurance(signed_record) -> None:
    path, jwk = signed_record
    block = check_server_provenance(path, jwk, TOOLS).to_audit()
    assert block["provenance"] == "verified"
    assert block["provenance_kind"] == "publisher-asserted"
    assert block["provenance_publisher"] == "did:web:acme.example"


def test_absence_reaches_the_audit_chain_as_a_value(signed_record) -> None:
    """Absence has to be visible. An omitted field reads as 'not implemented'."""
    assert check_server_provenance(None, None, TOOLS).to_audit()["provenance"] == "absent"


def test_audit_detail_is_bounded(signed_record) -> None:
    path, _ = signed_record
    block = check_server_provenance(path, None, TOOLS).to_audit()
    assert len(block.get("provenance_detail", "")) <= 512
