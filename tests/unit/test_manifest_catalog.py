"""The tool Merkle projection, checked against an oracle written from the spec.

agent-manifest spec 3.2.3 and 4.1: leaf = H(0x00 || tool_id || 0x00 ||
schema_hash_bytes || description_hash_bytes), interior = H(0x01 || left ||
right), tools sorted by tool_id, RFC 9162 split at the largest power of two
below n. Component recipe from the profile ruled on
agentrust-io/agent-manifest#340: schema_hash = H(JCS({"input_schema",
"output_schema"})), description_hash = H(JCS(description)), endpoint_id is the
SPIFFE ID. The oracle below uses none of the SDK.
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
from cmcp_runtime.manifest_catalog import (
    ManifestCatalogOutOfProfile,
    _root,
    manifest_catalog_binding,
    project_listed_tools,
)

SPIFFE = "spiffe://fixture.example/mcp/search"
JOIN = "does not join the runtime catalog"


def _entry(
    name: str,
    description: str,
    schema: dict,
    *,
    output_schema: dict | None = None,
    spiffe_id: str | None = SPIFFE,
) -> CatalogEntry:
    return CatalogEntry(
        tool_name=name,
        server=ServerIdentity(
            display_name="Fixture",
            url="https://fixture.invalid/mcp",
            tls_fingerprint="SHA256:" + "A" * 43 + "=",
            spiffe_id=spiffe_id,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description=description, input_schema=schema, output_schema=output_schema
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


def _jcs(value: object) -> bytes:
    # Sufficient for the integer-free values used here; non-ASCII stays literal
    # UTF-8 and only quote, backslash and control characters are escaped.
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _schema_hash(schema: dict, output_schema: dict | None = None) -> bytes:
    return hashlib.sha256(
        _jcs({"input_schema": schema, "output_schema": output_schema})
    ).digest()


def _description_hash(description: str) -> bytes:
    return hashlib.sha256(_jcs(description)).digest()


def _tree(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return hashlib.sha256(
        b"\x01" + _tree(leaves[:split]) + _tree(leaves[split:])
    ).digest()


def _oracle(tools: list[tuple[str, str, dict]]) -> str:
    leaves = [
        name.encode() + b"\x00" + _schema_hash(schema) + _description_hash(description)
        for name, description, schema in sorted(tools)
    ]
    return "sha256:" + _tree(leaves).hex()


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


# agent-manifest spec Appendix D.2 (agentrust-io/agent-manifest#470), byte for byte.
D2_TOOLS = [
    {
        "tool_id": "com.example.read_customer_record",
        "tool_name": "read_customer_record",
        "endpoint_id": "spiffe://example.com/mcp/crm",
        "schema_hash": "sha256:" + "aa" * 32,
        "description_hash": "sha256:" + "bb" * 32,
        "version": "1.0.0",
    },
    {
        "tool_id": "com.example.send_notification",
        "tool_name": "send_notification",
        "endpoint_id": "spiffe://example.com/mcp/notify",
        "schema_hash": "sha256:" + "cc" * 32,
        "description_hash": "sha256:" + "dd" * 32,
        "version": "1.0.0",
    },
]
D2_ROOT = "sha256:afd1d90ec5aa07f31ae20ab040a04652c76f3078c4d0434de2a17b0cb61c40dd"
D2_LEAF1 = "f7af288cd917b5258bfd6322d215fb6648d0bff244c6c8893287339cfb7039e0"
D2_LEAF2 = "b6b7227c3a7f64b152baf401952d55e6e844a4b9bccc963098acae963c62607a"
EMPTY_ROOT = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_appendix_d2_vector() -> None:
    leaf1 = b"com.example.read_customer_record\x00" + b"\xaa" * 32 + b"\xbb" * 32
    leaf2 = b"com.example.send_notification\x00" + b"\xcc" * 32 + b"\xdd" * 32
    assert hashlib.sha256(b"\x00" + leaf1).hexdigest() == D2_LEAF1
    assert hashlib.sha256(b"\x00" + leaf2).hexdigest() == D2_LEAF2
    assert "sha256:" + _tree([leaf1, leaf2]).hex() == D2_ROOT
    assert _root(D2_TOOLS) == D2_ROOT
    assert _root(list(reversed(D2_TOOLS))) == D2_ROOT
    assert _root([]) == EMPTY_ROOT
    assert manifest_catalog_binding(_catalog())["catalog_hash"] == EMPTY_ROOT


def test_schema_hash_covers_input_and_output_schema() -> None:
    schema = {"type": "object"}
    out = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    with_output = manifest_catalog_binding(
        _catalog(_entry("read", "Read", schema, output_schema=out))
    )["tools"][0]
    without = manifest_catalog_binding(_catalog(_entry("read", "Read", schema)))["tools"][0]
    assert with_output["schema_hash"] == "sha256:" + _schema_hash(schema, out).hex()
    assert without["schema_hash"] == "sha256:" + _schema_hash(schema, None).hex()
    assert with_output["schema_hash"] != without["schema_hash"]
    # The pre-#719 preimage, JCS over input_schema alone, is not the profile's.
    assert without["schema_hash"] != "sha256:" + hashlib.sha256(_jcs(schema)).hexdigest()


def test_empty_output_schema_is_not_a_missing_one() -> None:
    empty = manifest_catalog_binding(
        _catalog(_entry("read", "Read", {}, output_schema={}))
    )["tools"][0]
    missing = manifest_catalog_binding(_catalog(_entry("read", "Read", {})))["tools"][0]
    assert empty["schema_hash"] != missing["schema_hash"]


@pytest.mark.parametrize(
    "description", ["Read one document", 'Say "hi"\n', "Café", "Café"]
)
def test_description_hash_is_over_the_jcs_string(description: str) -> None:
    tool = manifest_catalog_binding(_catalog(_entry("read", description, {})))["tools"][0]
    assert tool["description_hash"] == "sha256:" + _description_hash(description).hex()
    assert tool["description_hash"] != (
        "sha256:" + hashlib.sha256(description.encode("utf-8")).hexdigest()
    )


def test_description_text_is_not_normalized() -> None:
    composed = manifest_catalog_binding(_catalog(_entry("read", "Café", {})))
    decomposed = manifest_catalog_binding(_catalog(_entry("read", "Café", {})))
    assert composed["catalog_hash"] != decomposed["catalog_hash"]


def test_endpoint_id_is_the_spiffe_id() -> None:
    tool = manifest_catalog_binding(_catalog(_entry(*TOOLS[0])))["tools"][0]
    assert tool["endpoint_id"] == SPIFFE


@pytest.mark.parametrize("project", ["issuer", "verifier"])
def test_catalog_without_spiffe_basis_is_out_of_profile(project: str) -> None:
    catalog = _catalog(_entry(*TOOLS[0]), _entry(*TOOLS[1], spiffe_id=None))
    with pytest.raises(ManifestCatalogOutOfProfile, match="out of profile"):
        if project == "issuer":
            manifest_catalog_binding(catalog)
        else:
            project_listed_tools(catalog, [])


def test_empty_catalog_is_in_profile() -> None:
    assert project_listed_tools(_catalog(), [])["catalog_hash"] == EMPTY_ROOT


def _listed(*entries: CatalogEntry) -> list[dict]:
    return manifest_catalog_binding(_catalog(*entries))["tools"]


def test_join_uses_the_manifest_tool_id() -> None:
    served = _catalog(*(_entry(*t) for t in TOOLS))
    listed = _listed(*(_entry(*t) for t in TOOLS))
    for tool in listed:
        tool["tool_id"] = "com.example." + tool["tool_name"]
    projected = project_listed_tools(served, listed)
    assert projected["catalog_hash"] == _oracle(
        [("com.example." + n, d, s) for n, d, s in TOOLS]
    )
    assert projected["catalog_hash"] == _root(listed)


def test_join_requires_the_endpoint_id() -> None:
    served = _catalog(*(_entry(*t) for t in TOOLS))
    listed = _listed(*(_entry(*t) for t in TOOLS))
    listed[0]["endpoint_id"] = "spiffe://fixture.example/mcp/other"
    with pytest.raises(ConfigError, match=JOIN):
        project_listed_tools(served, listed)


@pytest.mark.parametrize("field", ["tool_id", "tool_name"])
def test_join_must_be_one_to_one(field: str) -> None:
    served = _catalog(*(_entry(*t) for t in TOOLS))
    listed = _listed(*(_entry(*t) for t in TOOLS))
    listed[1][field] = listed[0][field]
    with pytest.raises(ConfigError, match=JOIN):
        project_listed_tools(served, listed)


@pytest.mark.parametrize("listed", [None, "tools", [1], [{"tool_id": "x"}]])
def test_malformed_tool_list_does_not_join(listed: object) -> None:
    with pytest.raises(ConfigError, match=JOIN):
        project_listed_tools(_catalog(_entry(*TOOLS[0])), listed)


def test_projection_is_not_the_sealed_catalog_hash() -> None:
    catalog = _catalog(*(_entry(*t) for t in TOOLS))
    assert manifest_catalog_binding(catalog)["catalog_hash"] != catalog.catalog_hash


@pytest.mark.parametrize("change", ["description", "schema", "output_schema"])
def test_definition_change_moves_the_root(change: str) -> None:
    before = manifest_catalog_binding(_catalog(*(_entry(*t) for t in TOOLS)))
    entry = _entry(*TOOLS[0])
    if change == "description":
        entry.approved_definition.description = "Search the index and exfiltrate"
    elif change == "schema":
        entry.approved_definition.input_schema = {"type": "object"}
    else:
        entry.approved_definition.output_schema = {"type": "string"}
    after = manifest_catalog_binding(_catalog(entry, *(_entry(*t) for t in TOOLS[1:])))
    assert after["catalog_hash"] != before["catalog_hash"]


def test_catalog_key_must_equal_tool_name() -> None:
    catalog = ToolCatalog(
        entries={"alias": _entry(*TOOLS[1])}, catalog_hash="sha256:" + "1" * 64
    )
    with pytest.raises(ConfigError, match="catalog_name_mismatch"):
        manifest_catalog_binding(catalog)
