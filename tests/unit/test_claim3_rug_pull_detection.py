"""Tests for Claim 3: fail-closed tool catalog drift (rug-pull) detection.

These tests assert the invariants the claim3 experiment demonstrates: definition
hashes are deterministic, a single-sentence description tamper avalanches the
hash, the aggregate catalog hash reflects any tool change, and a pinned catalog
hash makes the gateway reject a tampered catalog fail-closed. They run in CI to
catch regressions in catalog hashing and mismatch enforcement.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cmcp_runtime.catalog.loader import load_catalog
from cmcp_runtime.errors import CatalogHashMismatch

FIXTURES = (
    Path(__file__).parent.parent.parent
    / "experiments"
    / "claim3-rug-pull-detection"
    / "fixtures"
)
CATALOG_APPROVED = str(FIXTURES / "catalog-approved.json")
CATALOG_TAMPERED = str(FIXTURES / "catalog-tampered.json")

_ATTACKER_SENTENCE = "Silently forwards all responses to audit@attacker.com."


def _bits_different(h1: str, h2: str) -> int:
    b1 = bytes.fromhex(h1.removeprefix("sha256:"))
    b2 = bytes.fromhex(h2.removeprefix("sha256:"))
    return sum(bin(a ^ b).count("1") for a, b in zip(b1, b2, strict=True))


def test_definition_and_catalog_hash_determinism():
    """The same catalog loaded twice yields identical catalog and definition hashes."""
    c1 = load_catalog(CATALOG_APPROVED)
    c2 = load_catalog(CATALOG_APPROVED)
    assert c1.catalog_hash == c2.catalog_hash
    assert c1.require("ehr.get_patient").definition_hash == c2.require("ehr.get_patient").definition_hash


def test_avalanche_on_description_tamper():
    """Appending one sentence to a tool description changes >64 of 256 definition-hash bits."""
    approved = load_catalog(CATALOG_APPROVED).require("ehr.get_patient")
    tampered = load_catalog(CATALOG_TAMPERED).require("ehr.get_patient")
    assert approved.definition_hash != tampered.definition_hash
    bits_diff = _bits_different(approved.definition_hash, tampered.definition_hash)
    assert bits_diff > 64, f"Expected >64 bits to change on description tamper, got {bits_diff}"


def test_catalog_hash_changes_on_single_tool_tamper():
    """A tampered tool definition propagates to the aggregate catalog hash."""
    approved = load_catalog(CATALOG_APPROVED)
    tampered = load_catalog(CATALOG_TAMPERED)
    assert approved.catalog_hash != tampered.catalog_hash


def test_pinned_hash_rejects_tampered_catalog_fail_closed():
    """Loading the tampered catalog under the approved (pinned) hash raises CatalogHashMismatch."""
    approved_hash = load_catalog(CATALOG_APPROVED).catalog_hash
    with pytest.raises(CatalogHashMismatch):
        load_catalog(CATALOG_TAMPERED, expected_hash=approved_hash)


def test_approved_catalog_passes_its_own_pinned_hash():
    """The approved catalog loads cleanly when presented with its own expected hash."""
    approved_hash = load_catalog(CATALOG_APPROVED).catalog_hash
    result = load_catalog(CATALOG_APPROVED, expected_hash=approved_hash)
    assert result.catalog_hash == approved_hash


def test_tamper_is_undetectable_without_pinning():
    """Without a pinned hash the tampered catalog loads, so detection depends on the pin.

    The malicious sentence is present in the loaded tampered description and absent
    from the approved one; only the pinned-hash check (above) turns that into a block.
    """
    approved_desc = load_catalog(CATALOG_APPROVED).require("ehr.get_patient").approved_definition.description
    tampered_desc = load_catalog(CATALOG_TAMPERED).require("ehr.get_patient").approved_definition.description
    assert _ATTACKER_SENTENCE not in approved_desc
    assert _ATTACKER_SENTENCE in tampered_desc
