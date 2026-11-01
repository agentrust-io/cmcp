"""Agent Manifest's tool Merkle root, computed from the catalog cMCP is serving.

cMCP seals its catalog as one digest over the full canonical entries
(``catalog/loader.py``), covering server identity, TLS pins and output schemas.
Agent Manifest's ``tool_manifest.catalog_hash`` is a different construction
when the manifest lists its tools: a Merkle root over
``(tool_id, schema_hash, description_hash)`` per tool (agent-manifest spec
3.2.3). The two are never equal and must never be compared to each other.
This module produces the second one from the runtime catalog.

The projection follows the restricted profile ruled on
agentrust-io/agent-manifest#340 (2026-09-29):

- ``schema_hash`` is SHA-256 over the RFC 8785 (JCS) form of
  ``{"input_schema": ..., "output_schema": ...}`` from the approved
  definition. A missing output schema and an explicit null are the same
  preimage; ``{}`` is not.
- ``description_hash`` is SHA-256 over the approved description as a JCS
  string. No text normalization is applied.
- ``endpoint_id`` is the server's SPIFFE ID. A non-empty catalog with any
  server lacking one is out of profile (:class:`ManifestCatalogOutOfProfile`),
  which is its own outcome, neither a match nor a mismatch. An empty catalog
  is in profile.
- A manifest's tools join the runtime entries on exact ``tool_name`` plus
  ``endpoint_id``, one to one. The leaves are then rebuilt from the manifest's
  ``tool_id`` and the runtime's component hashes, and only that rebuilt root is
  compared with the manifest's ``catalog_hash``.

These hashes belong to the projection only. cMCP's ``definition_hash`` and
sealed catalog digest are separate constructions and are unchanged.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

import rfc8785
from agent_manifest._merkle import build_catalog_tree
from agent_manifest.models import ToolEntry

from cmcp_runtime.errors import ConfigError

if TYPE_CHECKING:
    from cmcp_runtime.catalog.loader import CatalogEntry, ToolCatalog

#: Labels the projection rules above. Still experimental until the profile is
#: written into the Agent Manifest and cMCP specs.
PROJECTION_VERSION = "experimental-v1"


class ManifestCatalogOutOfProfile(ConfigError):
    """The catalog cannot be projected under this profile.

    Not a mismatch: nothing was compared. A gateway still refuses to bind,
    because a binding it could not evaluate is not a binding it can enforce.
    """


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _components(entry: CatalogEntry) -> tuple[str, str]:
    definition = entry.approved_definition
    schema_hash = _digest(
        rfc8785.dumps(
            {"input_schema": definition.input_schema, "output_schema": definition.output_schema}
        )
    )
    return schema_hash, _digest(rfc8785.dumps(definition.description))


def _require_profile(catalog: ToolCatalog) -> None:
    for name, entry in catalog.entries.items():
        if name != entry.tool_name:
            raise ConfigError("catalog_name_mismatch")
        spiffe_id = entry.server.spiffe_id
        if not isinstance(spiffe_id, str) or not spiffe_id.startswith("spiffe://"):
            raise ManifestCatalogOutOfProfile(
                f"Agent Manifest tool binding is out of profile: tool {name!r} has no "
                "SPIFFE endpoint_id (agentrust-io/agent-manifest#340)"
            )


def _root(tools: list[dict[str, Any]]) -> str:
    return build_catalog_tree([ToolEntry.model_validate(t) for t in tools])


def manifest_catalog_binding(catalog: ToolCatalog) -> dict[str, Any]:
    """Return ``{"catalog_hash": <Merkle root>, "tools": [...]}`` for *catalog*.

    The result is shaped like an Agent Manifest ``tool_manifest`` binding, so
    an issuer can copy it into a manifest. ``tool_id`` defaults to the cMCP
    tool name; an issuer may replace it, since verification joins on
    ``tool_name`` and ``endpoint_id``. It describes locally approved
    definitions, not remote provenance.
    """
    _require_profile(catalog)
    tools = []
    for name, entry in sorted(catalog.entries.items()):
        schema_hash, description_hash = _components(entry)
        tools.append(
            {
                "tool_id": name,
                "tool_name": name,
                "endpoint_id": entry.server.spiffe_id,
                "schema_hash": schema_hash,
                "description_hash": description_hash,
                "version": PROJECTION_VERSION,
            }
        )
    return {"catalog_hash": _root(tools), "tools": tools}


def project_listed_tools(catalog: ToolCatalog, listed: Any) -> dict[str, Any]:
    """Project *catalog* onto a manifest's ``tool_manifest.tools`` list.

    Joins on exact ``tool_name`` plus ``endpoint_id``. Raises
    :class:`ManifestCatalogOutOfProfile` when the catalog has no SPIFFE basis,
    and ``ConfigError`` when the list is malformed or the join is not one to
    one. Otherwise returns the projected binding, whose ``catalog_hash`` is
    ``A_projected`` for comparison with the manifest's root.
    """
    _require_profile(catalog)
    join_failed = ConfigError(
        "Agent Manifest tool list does not join the runtime catalog on "
        "tool_name and endpoint_id"
    )
    if not isinstance(listed, list) or not all(
        isinstance(t, dict)
        and all(isinstance(t.get(k), str) for k in ("tool_id", "tool_name", "endpoint_id"))
        for t in listed
    ):
        raise join_failed
    tool_ids = [t.get("tool_id") for t in listed]
    keys = [(t.get("tool_name"), t.get("endpoint_id")) for t in listed]
    if len(set(tool_ids)) != len(tool_ids) or len(set(keys)) != len(keys):
        raise join_failed
    by_key = dict(zip(keys, listed, strict=True))
    runtime_keys = {(e.tool_name, e.server.spiffe_id): e for e in catalog.entries.values()}
    if set(by_key) != set(runtime_keys):
        raise join_failed
    tools = []
    for key, entry in sorted(runtime_keys.items()):
        schema_hash, description_hash = _components(entry)
        tools.append(
            {
                "tool_id": by_key[key]["tool_id"],
                "tool_name": entry.tool_name,
                "endpoint_id": entry.server.spiffe_id,
                "schema_hash": schema_hash,
                "description_hash": description_hash,
                "version": PROJECTION_VERSION,
            }
        )
    try:
        root = _root(tools)
    except ValueError as exc:  # pydantic ValidationError included
        raise join_failed from exc
    return {"catalog_hash": root, "tools": tools}
