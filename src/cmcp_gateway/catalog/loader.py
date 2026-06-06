"""Tool catalog loading, hash verification, and identity binding — implements #86, #88."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import jsonschema

from cmcp_gateway.errors import (
    CatalogHashMismatch,
    CatalogToolNameCollision,
    ConfigError,
    ToolNotInCatalog,
)

_CATALOG_ENTRY_SCHEMA_PATH = Path(__file__).parent.parent.parent.parent / "schemas" / "catalog-entry.schema.json"


@dataclass
class ServerIdentity:
    display_name: str
    url: str
    tls_fingerprint: str
    spiffe_id: str | None
    transport: str  # "http-sse" or "websocket"
    rotation_mode: str  # "key-pinned" (default) or "cert-pinned"


@dataclass
class ApprovedDefinition:
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None


@dataclass
class CatalogEntry:
    tool_name: str
    server: ServerIdentity
    approved_definition: ApprovedDefinition
    definition_hash: str  # sha256:<hex> of canonical approved_definition
    compliance_domain: str
    requires_baa: bool
    sensitivity_level: str
    added_at: str
    approved_by: str
    catalog_exception: bool = False
    schema_validation_mode: Literal["redact", "strict", "log"] = field(default="redact")


@dataclass
class ToolCatalog:
    entries: dict[str, CatalogEntry]  # tool_name -> entry
    catalog_hash: str  # sha256:<hex> measured into the TEE report

    def lookup(self, tool_name: str) -> CatalogEntry | None:
        return self.entries.get(tool_name)

    def require(self, tool_name: str) -> CatalogEntry:
        entry = self.lookup(tool_name)
        if entry is None:
            raise ToolNotInCatalog(f"Tool '{tool_name}' not in attested catalog")
        return entry


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compute_definition_hash(definition: dict[str, Any]) -> str:
    canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"sha256:{_sha256_hex(canonical.encode())}"


def _catalog_hash(raw_entries: list[dict[str, Any]]) -> str:
    """SHA-256 of canonical JSON of entries sorted by tool_name."""
    sorted_entries = sorted(raw_entries, key=lambda e: e["tool_name"])
    canonical = json.dumps(sorted_entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"sha256:{_sha256_hex(canonical.encode())}"


def _load_entry_schema() -> dict[str, Any] | None:
    if _CATALOG_ENTRY_SCHEMA_PATH.exists():
        return dict(json.loads(_CATALOG_ENTRY_SCHEMA_PATH.read_text()))
    return None


def _validate_entry(raw: dict[str, Any], schema: dict[str, Any] | None) -> None:
    if schema is None:
        return
    try:
        jsonschema.validate(raw, schema)
    except jsonschema.ValidationError as exc:
        raise ConfigError(f"Catalog entry '{raw.get('tool_name', '?')}' schema violation: {exc.message}") from exc


def load_catalog(catalog_path: str, expected_hash: str | None = None) -> ToolCatalog:
    """
    Load and validate the tool catalog from a JSON file.

    Raises CatalogHashMismatch if expected_hash is provided and doesn't match.
    Raises CatalogToolNameCollision if two entries share a tool_name.
    Raises ConfigError on schema violation or file errors.
    """
    path = Path(catalog_path)
    try:
        raw_list: list[dict[str, Any]] = json.loads(path.read_text())
    except OSError as exc:
        raise ConfigError(f"Cannot read catalog file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Catalog JSON parse error: {exc}") from exc

    if not isinstance(raw_list, list):
        raise ConfigError("Catalog must be a JSON array of entries")

    entry_schema = _load_entry_schema()
    entries: dict[str, CatalogEntry] = {}

    for raw in raw_list:
        if not isinstance(raw, dict):
            raise ConfigError("Each catalog entry must be a JSON object")

        _validate_entry(raw, entry_schema)

        tool_name: str = raw["tool_name"]
        if tool_name in entries:
            raise CatalogToolNameCollision(
                f"Duplicate tool_name '{tool_name}' — gateway will not start",
                detail="Each tool_name must map to exactly one upstream server",
            )

        raw_server = raw["server"]
        server = ServerIdentity(
            display_name=raw_server["display_name"],
            url=raw_server["url"],
            tls_fingerprint=raw_server["tls_fingerprint"],
            spiffe_id=raw_server.get("spiffe_id"),
            transport=raw_server.get("transport", "http-sse"),
            rotation_mode=raw_server.get("rotation_mode", "key-pinned"),
        )

        raw_def = raw["approved_definition"]
        approved_def = ApprovedDefinition(
            description=raw_def["description"],
            input_schema=raw_def.get("input_schema", {}),
            output_schema=raw_def.get("output_schema"),
        )

        # Verify definition_hash if present in the entry
        computed_def_hash = _compute_definition_hash(raw_def)
        if "definition_hash" in raw and raw["definition_hash"] != computed_def_hash:
            raise ConfigError(
                f"Catalog entry '{tool_name}': definition_hash mismatch. "
                f"Stored: {raw['definition_hash']}, computed: {computed_def_hash}"
            )

        raw_mode = raw.get("schema_validation_mode", "redact")
        if raw_mode not in ("redact", "strict", "log"):
            raise ConfigError(
                f"Catalog entry '{tool_name}': invalid schema_validation_mode '{raw_mode}'; "
                "must be 'redact', 'strict', or 'log'"
            )
        schema_validation_mode: Literal["redact", "strict", "log"] = raw_mode

        entries[tool_name] = CatalogEntry(
            tool_name=tool_name,
            server=server,
            approved_definition=approved_def,
            definition_hash=computed_def_hash,
            compliance_domain=raw.get("compliance_domain", "external"),
            requires_baa=raw.get("requires_baa", False),
            sensitivity_level=raw.get("sensitivity_level", "public"),
            added_at=raw.get("added_at", ""),
            approved_by=raw.get("approved_by", ""),
            catalog_exception=raw.get("catalog_exception", False),
            schema_validation_mode=schema_validation_mode,
        )

    computed_hash = _catalog_hash(raw_list)
    if expected_hash is not None:
        expected_hex = expected_hash.removeprefix("sha256:")
        actual_hex = computed_hash.removeprefix("sha256:")
        if expected_hex != actual_hex:
            raise CatalogHashMismatch(
                "Tool catalog hash mismatch — gateway will not start",
                detail=f"expected=sha256:{expected_hex} actual={computed_hash}",
            )

    return ToolCatalog(entries=entries, catalog_hash=computed_hash)
