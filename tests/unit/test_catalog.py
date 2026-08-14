"""Tests for tool catalog loading and identity binding (issues #86, #88)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import cmcp_runtime.catalog.loader as catalog_loader
from cmcp_runtime.catalog.loader import ToolCatalog, load_catalog
from cmcp_runtime.errors import (
    CatalogHashMismatch,
    CatalogToolNameCollision,
    ConfigError,
    ToolNotInCatalog,
)

ENTRY_1 = {
    "tool_name": "crm.query",
    "server": {
        "display_name": "CRM MCP Server",
        "url": "https://crm.example.com/mcp",
        "tls_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "transport": "http-sse",
    },
    "approved_definition": {
        "description": "Query CRM records",
        "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}},
    },
    "definition_hash": "sha256:8a32c564635ceea9faab7116e81057efb9d89d3b3946dff734612120b0a34fab",
    "compliance_domain": "pii",
    "requires_baa": False,
    "sensitivity_level": "pii",
    "added_at": "2026-06-01T00:00:00Z",
    "approved_by": "security@example.com",
}

ENTRY_2 = {
    "tool_name": "hr.lookup",
    "server": {
        "display_name": "HR MCP Server",
        "url": "https://hr.example.com/mcp",
        "tls_fingerprint": "SHA256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "transport": "http-sse",
    },
    "approved_definition": {
        "description": "Look up HR records",
        "input_schema": {"type": "object"},
    },
    "definition_hash": "sha256:d2db6ce8fc66b6db6e182b1d94d242249174aae362841927c47d9dc4d604ab35",
    "compliance_domain": "internal",
    "requires_baa": False,
    "sensitivity_level": "confidential",
    "added_at": "2026-06-01T00:00:00Z",
    "approved_by": "security@example.com",
}


@pytest.fixture
def catalog_file(tmp_path: Path):
    def _write(entries: list) -> str:
        p = tmp_path / "catalog.json"
        p.write_text(json.dumps(entries))
        return str(p)
    return _write


def test_missing_catalog_schema_fails_closed(catalog_file, tmp_path, monkeypatch):
    missing_schema = tmp_path / "missing-catalog-entry.schema.json"
    monkeypatch.setattr(catalog_loader, "_CATALOG_ENTRY_SCHEMA_PATH", missing_schema)

    with pytest.raises(ConfigError, match="schema is missing"):
        load_catalog(catalog_file([ENTRY_1]))


def test_load_valid_catalog(catalog_file):
    path = catalog_file([ENTRY_1, ENTRY_2])
    cat = load_catalog(path)
    assert isinstance(cat, ToolCatalog)
    assert "crm.query" in cat.entries
    assert "hr.lookup" in cat.entries
    assert cat.catalog_hash.startswith("sha256:")


def test_lookup_existing_tool(catalog_file):
    cat = load_catalog(catalog_file([ENTRY_1]))
    entry = cat.lookup("crm.query")
    assert entry is not None
    assert entry.tool_name == "crm.query"
    assert entry.server.url == "https://crm.example.com/mcp"


def test_lookup_missing_tool_returns_none(catalog_file):
    cat = load_catalog(catalog_file([ENTRY_1]))
    assert cat.lookup("nonexistent.tool") is None


def test_require_missing_tool_raises(catalog_file):
    cat = load_catalog(catalog_file([ENTRY_1]))
    with pytest.raises(ToolNotInCatalog):
        cat.require("nonexistent.tool")


def test_catalog_hash_deterministic(catalog_file):
    path = catalog_file([ENTRY_1, ENTRY_2])
    c1 = load_catalog(path)
    c2 = load_catalog(path)
    assert c1.catalog_hash == c2.catalog_hash


def test_catalog_hash_verification_passes(catalog_file):
    path = catalog_file([ENTRY_1])
    c1 = load_catalog(path)
    c2 = load_catalog(path, expected_hash=c1.catalog_hash)
    assert c2.catalog_hash == c1.catalog_hash


def test_catalog_hash_mismatch_raises(catalog_file):
    path = catalog_file([ENTRY_1])
    with pytest.raises(CatalogHashMismatch):
        load_catalog(path, expected_hash="sha256:" + "0" * 64)


def test_catalog_tool_name_collision_raises(catalog_file):
    duplicate = dict(ENTRY_1, server=ENTRY_2["server"])
    with pytest.raises(CatalogToolNameCollision):
        load_catalog(catalog_file([ENTRY_1, duplicate]))


def test_catalog_defaults_compliance_domain(catalog_file):
    entry = dict(ENTRY_1)
    del entry["compliance_domain"]
    cat = load_catalog(catalog_file([entry]))
    assert cat.entries["crm.query"].compliance_domain == "external"


def test_catalog_defaults_sensitivity_level(catalog_file):
    entry = dict(ENTRY_1)
    del entry["sensitivity_level"]
    cat = load_catalog(catalog_file([entry]))
    assert cat.entries["crm.query"].sensitivity_level == "public"


def test_streamable_http_transport_loads(catalog_file):
    entry = dict(ENTRY_1)
    entry["server"] = dict(entry["server"], transport="streamable-http")
    cat = load_catalog(catalog_file([entry]))
    assert cat.entries["crm.query"].server.transport == "streamable-http"


def test_unimplemented_websocket_transport_fails_closed(catalog_file):
    entry = dict(ENTRY_1)
    entry["server"] = dict(entry["server"], transport="websocket")
    with pytest.raises(ConfigError, match="schema violation"):
        load_catalog(catalog_file([entry]))


def test_catalog_empty_is_valid(catalog_file):
    cat = load_catalog(catalog_file([]))
    assert len(cat.entries) == 0


def test_catalog_not_a_list(catalog_file):
    path = catalog_file({})  # type: ignore
    with pytest.raises(ConfigError, match="array"):
        load_catalog(path)


def test_catalog_hash_changes_when_entry_changes(catalog_file):
    c1 = load_catalog(catalog_file([ENTRY_1]))
    modified = dict(ENTRY_1)
    modified["approved_by"] = "changed@example.com"
    c2 = load_catalog(catalog_file([modified]))
    assert c1.catalog_hash != c2.catalog_hash


# ── POLICY-002: tool name must be lowercase ───────────────────────────────────

def test_uppercase_tool_name_is_rejected(catalog_file):
    """POLICY-002: mixed-case tool names must be rejected at load time."""
    entry = dict(ENTRY_1)
    entry["tool_name"] = "CRM.Query"
    with pytest.raises(ConfigError, match="lowercase"):
        load_catalog(catalog_file([entry]))


def test_unknown_sensitivity_level_is_rejected(catalog_file):
    """An out-of-vocabulary sensitivity level must not load.

    This guards a would-be fail-open path. SENSITIVITY_ORDER.get(level, 0) ranks
    anything it does not recognise at 0, the same rank as "public", so a catalog
    that slipped through with "secret" or "restricted" would silently be treated
    as the least sensitive class the gateway has: policies keyed on
    sensitivity_level would under-enforce and the session maximum would never
    rise. Schema validation at load is what stops that, and this test pins it.
    """
    entry = dict(ENTRY_1, sensitivity_level="secret")
    with pytest.raises(ConfigError, match="is not one of"):
        load_catalog(catalog_file([entry]))


def test_miscased_sensitivity_level_is_rejected(catalog_file):
    """The vocabulary is case-sensitive, so "Confidential" is not "confidential"."""
    entry = dict(ENTRY_1, sensitivity_level="Confidential")
    with pytest.raises(ConfigError, match="is not one of"):
        load_catalog(catalog_file([entry]))


def test_every_known_sensitivity_level_loads(catalog_file):
    """The accepted set is exactly the one the ordering table knows about."""
    from cmcp_runtime.session.state import SENSITIVITY_ORDER

    for level in SENSITIVITY_ORDER:
        entry = dict(ENTRY_1, sensitivity_level=level)
        cat = load_catalog(catalog_file([entry]))
        assert cat.entries["crm.query"].sensitivity_level == level


# ── #479: configurable sensitivity vocabulary ──────────────────────────────────


def test_custom_sensitivity_level_rejected_without_extension(catalog_file):
    """A deployment configured label is not legal until load_catalog is told
    about it, same fail closed default as an unknown level."""
    entry = dict(ENTRY_1, sensitivity_level="top_secret")
    with pytest.raises(ConfigError, match="is not one of"):
        load_catalog(catalog_file([entry]))


def test_custom_sensitivity_level_accepted_with_extension(catalog_file):
    entry = dict(ENTRY_1, sensitivity_level="top_secret")
    cat = load_catalog(
        catalog_file([entry]), extra_sensitivity_levels=frozenset({"top_secret"})
    )
    assert cat.entries["crm.query"].sensitivity_level == "top_secret"


def test_extra_sensitivity_levels_does_not_loosen_built_in_check(catalog_file):
    """extra_sensitivity_levels only adds labels, an unrelated typo is still
    rejected even when some extension set is configured."""
    entry = dict(ENTRY_1, sensitivity_level="secret")
    with pytest.raises(ConfigError, match="is not one of"):
        load_catalog(catalog_file([entry]), extra_sensitivity_levels=frozenset({"top_secret"}))
