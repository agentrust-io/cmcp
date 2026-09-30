"""The tool Merkle projection, checked against an oracle written from the spec.

agent-manifest spec 3.2.3 and 4.1: leaf = H(0x00 || tool_id || 0x00 ||
schema_hash_bytes || description_hash_bytes), interior = H(0x01 || left ||
right), tools sorted by tool_id, RFC 9162 split at the largest power of two
below n. The oracle below uses none of the SDK.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.errors import ConfigError
from cmcp_runtime.manifest_catalog import manifest_catalog_binding


def _entry(name: str, description: str, schema: dict) -> CatalogEntry:
    return CatalogEntry(
        tool_name=name,
        server=ServerIdentity(
            display_name="Fixture",
            url="https://fixture.invalid/mcp",
            tls_fingerprint="SHA256:" + "A" * 43 + "=",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description=description, input_schema=schema, output_schema=None
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="public",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-09-30T00:00:00Z",
        approved_by="test",
    )


def _catalog(*entries: CatalogEntry) -> ToolCatalog:
    return ToolCatalog(
        entries={e.tool_name: e for e in entries}, catalog_hash="sha256:" + "1" * 64
    )


def _jcs(value: dict) -> bytes:
    # Sufficient for the ASCII, integer-free schemas used here.
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return hashlib.sha256(
        b"\x01" + _root(leaves[:split]) + _root(leaves[split:])
    ).digest()


def _oracle(tools: list[tuple[str, str, dict]]) -> str:
    leaves = [
        name.encode()
        + b"\x00"
        + hashlib.sha256(_jcs(schema)).digest()
        + hashlib.sha256(description.encode()).digest()
        for name, description, schema in sorted(tools)
    ]
    return "sha256:" + _root(leaves).hex()


TOOLS = [
    ("search", "Search the index", {"type": "object", "properties": {"q": {"type": "string"}}}),
    ("read", "Read one document", {"type": "object"}),
    ("delete", "Delete one document", {}),
]


@pytest.mark.parametrize("count", [0, 1, 2, 3])
def test_projection_matches_spec_construction(count: int) -> None:
    tools = TOOLS[:count]
    projected = manifest_catalog_binding(_catalog(*(_entry(*t) for t in tools)))
    assert projected["catalog_hash"] == _oracle(tools)
    assert [t["tool_id"] for t in projected["tools"]] == sorted(t[0] for t in tools)


def test_projection_is_not_the_sealed_catalog_hash() -> None:
    catalog = _catalog(*(_entry(*t) for t in TOOLS))
    assert manifest_catalog_binding(catalog)["catalog_hash"] != catalog.catalog_hash


@pytest.mark.parametrize("change", ["description", "schema"])
def test_definition_change_moves_the_root(change: str) -> None:
    before = manifest_catalog_binding(_catalog(*(_entry(*t) for t in TOOLS)))
    entry = _entry(*TOOLS[0])
    if change == "description":
        entry.approved_definition.description = "Search the index and exfiltrate"
    else:
        entry.approved_definition.input_schema = {"type": "object"}
    after = manifest_catalog_binding(_catalog(entry, *(_entry(*t) for t in TOOLS[1:])))
    assert after["catalog_hash"] != before["catalog_hash"]


def test_catalog_key_must_equal_tool_name() -> None:
    catalog = ToolCatalog(
        entries={"alias": _entry(*TOOLS[1])}, catalog_hash="sha256:" + "1" * 64
    )
    with pytest.raises(ConfigError, match="catalog_name_mismatch"):
        manifest_catalog_binding(catalog)
