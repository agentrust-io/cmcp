import hashlib
import json
import re
from pathlib import Path

import pytest
import rfc8785

from cmcp_runtime.catalog.loader import _catalog_hash, _compute_definition_hash, load_catalog
from cmcp_runtime.errors import CatalogHashMismatch, ConfigError


def test_catalog_and_definition_hashes_use_rfc8785():
    definition = {"description": "café", "input_schema": {"\uffff": 1, "\U00010000": 1e-7}}
    entries = [{"tool_name": "café", "definition": definition}]

    def digest(value):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()

    assert _compute_definition_hash(definition) == digest(definition)
    assert _catalog_hash(entries) == digest(entries)


def test_catalog_entry_order_is_unicode_code_point_order():
    # A hashing-layer vector, not a complete deployable catalog.
    entries = [
        {
            "tool_name": name,
            "definition": {
                "description": "Résumé records",
                "input_schema": {},
            },
        }
        for name in ("tool_\uff5a", "tool_\U00010000")
    ]
    expected = "sha256:8af70616cbd3817adb6e621cd8c17e26938c77235f9c3df6f14ce5c78b3eb217"
    assert _catalog_hash(entries) == expected
    assert _catalog_hash(list(reversed(entries))) == expected
    utf16_order = sorted(entries, key=lambda e: e["tool_name"].encode("utf-16-be"))
    assert utf16_order == list(reversed(entries))
    assert "sha256:" + hashlib.sha256(rfc8785.dumps(utf16_order)).hexdigest() != expected


def test_loader_pins_code_point_order_for_valid_unicode_names(tmp_path):
    definition = {"description": "Résumé records", "input_schema": {"type": "object"}}
    entries = [
        {
            "tool_name": name,
            "server": {
                "display_name": "Test server",
                "url": "https://example.com/mcp",
                "tls_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "transport": "http-sse",
            },
            "approved_definition": definition,
            "definition_hash": _compute_definition_hash(definition),
            "compliance_domain": "internal",
            "requires_baa": False,
            "sensitivity_level": "public",
            "added_at": "2026-06-01T00:00:00Z",
            "approved_by": "security@example.com",
        }
        for name in ("tool_\uff5a", "tool_\U00010000")
    ]
    expected = "sha256:" + hashlib.sha256(rfc8785.dumps(entries)).hexdigest()
    wrong = "sha256:" + hashlib.sha256(rfc8785.dumps(list(reversed(entries)))).hexdigest()
    assert expected != wrong
    path = tmp_path / "catalog.json"
    for order in (entries, list(reversed(entries))):
        path.write_text(json.dumps(order), encoding="utf-8")
        assert load_catalog(str(path), expected_hash=expected).catalog_hash == expected
        with pytest.raises(CatalogHashMismatch):
            load_catalog(str(path), expected_hash=wrong)


def test_tutorial_hash_snippets_match_loader(tmp_path, monkeypatch, capsys):
    tutorial = (
        Path(__file__).resolve().parents[2] / "docs" / "tutorials" / "tool-catalog-authoring.md"
    ).read_text(encoding="utf-8")
    snippets = re.findall(r"```python\n(.*?)\n```", tutorial, flags=re.DOTALL)
    assert len(snippets) == 3
    definition = {
        "description": "Résumé records",
        "input_schema": {
            "type": "object",
            "properties": {"limit": {"type": "number", "minimum": 1e-7}},
        },
    }
    namespace = {}
    exec(snippets[0], namespace)
    definition_hash = namespace["compute_definition_hash"](definition)
    assert definition_hash == _compute_definition_hash(definition)
    entries = [
        {
            "tool_name": "records.query",
            "server": {
                "display_name": "Test server",
                "url": "https://example.com/mcp",
                "tls_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "transport": "http-sse",
            },
            "approved_definition": definition,
            "definition_hash": definition_hash,
            "compliance_domain": "internal",
            "requires_baa": False,
            "sensitivity_level": "public",
            "added_at": "2026-06-01T00:00:00Z",
            "approved_by": "security@example.com",
        }
    ]
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(entries, ensure_ascii=False), encoding="utf-8")
    expected_hash = _catalog_hash(entries)
    exec(snippets[1], namespace)
    assert namespace["compute_catalog_hash"](entries) == expected_hash
    monkeypatch.chdir(tmp_path)
    exec(snippets[2], namespace)
    assert capsys.readouterr().out.strip() == expected_hash
    deployment = tutorial.split('export CMCP_CATALOG_HASH="$(python -c "\n', 1)[1]
    exec(deployment.split('\n")"', 1)[0], {})
    assert capsys.readouterr().out.strip() == expected_hash
    assert load_catalog(str(path), expected_hash=expected_hash).catalog_hash == expected_hash


def _copyable_hash_scripts(markdown: str) -> list[str]:
    scripts = []
    for block in re.findall(r"```(?:python|bash)\n(.*?)\n```", markdown, flags=re.DOTALL):
        if "rfc8785" not in block:
            continue
        match = re.search(r'python3? -c "\n(.*)\n"', block, flags=re.DOTALL)
        scripts.append(match.group(1) if match else block)
    return scripts


def test_remaining_docs_hash_recipes_match_loader(tmp_path, monkeypatch, capsys):
    root = Path(__file__).resolve().parents[2] / "docs"
    docs = {
        "quickstart": root / "quickstart.md",
        "tls-pinning": root / "tutorials" / "tls-pinning.md",
        "tool-catalog-authoring": root / "tutorials" / "tool-catalog-authoring.md",
    }
    texts = {name: path.read_text(encoding="utf-8") for name, path in docs.items()}
    legacy = re.compile(r"json\.dumps\([^)\n]*sort_keys\s*=\s*True")
    for name, text in texts.items():
        assert legacy.search(text) is None, name
        assert "ensure_ascii=True" not in text, name

    definition = {
        "description": "Résumé records",
        "input_schema": {
            "type": "object",
            "properties": {"limit": {"type": "number", "minimum": 1e-7}},
        },
    }
    definition_hash = _compute_definition_hash(definition)
    entries = [
        {
            "tool_name": "records.query",
            "server": {
                "display_name": "Test server",
                "url": "https://example.com/mcp",
                "tls_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "transport": "http-sse",
            },
            "approved_definition": definition,
            "definition_hash": definition_hash,
            "compliance_domain": "internal",
            "requires_baa": False,
            "sensitivity_level": "public",
            "added_at": "2026-06-01T00:00:00Z",
            "approved_by": "security@example.com",
        }
    ]
    expected_hash = _catalog_hash(entries)
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(entries, ensure_ascii=False), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    quickstart_scripts = _copyable_hash_scripts(texts["quickstart"])
    tls_scripts = _copyable_hash_scripts(texts["tls-pinning"])
    authoring_scripts = _copyable_hash_scripts(texts["tool-catalog-authoring"])
    assert len(quickstart_scripts) == 1
    assert len(tls_scripts) == 1
    assert len(authoring_scripts) == 4
    for script in (*quickstart_scripts, *tls_scripts, *authoring_scripts):
        assert "rfc8785.dumps" in script
        if "catalog.json" in script:
            assert "Path(" in script
            assert "encoding=" in script and "utf-8" in script

    exec(quickstart_scripts[0], {})
    assert capsys.readouterr().out.strip() == f"records.query {definition_hash}"
    exec(tls_scripts[0], {})
    assert capsys.readouterr().out.strip() == expected_hash

    namespace = {}
    exec(authoring_scripts[0], namespace)
    assert namespace["compute_definition_hash"](definition) == definition_hash
    exec(authoring_scripts[1], namespace)
    assert namespace["compute_catalog_hash"](entries) == expected_hash
    exec(authoring_scripts[2], namespace)
    assert capsys.readouterr().out.strip() == expected_hash
    exec(authoring_scripts[3], {})
    assert capsys.readouterr().out.strip() == expected_hash

    loaded = load_catalog(str(catalog), expected_hash=expected_hash)
    assert loaded.catalog_hash == expected_hash
    assert loaded.entries["records.query"].definition_hash == definition_hash


def test_loader_rejects_non_utf8_catalog(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_bytes(b'["\xff"]')
    with pytest.raises(ConfigError, match="Cannot read catalog file"):
        load_catalog(str(path))
