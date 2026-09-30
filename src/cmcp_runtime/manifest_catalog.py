"""Agent Manifest's tool Merkle root, computed from the catalog cMCP is serving.

cMCP seals its catalog as one digest over the full canonical entries
(``catalog/loader.py``), covering server identity, TLS pins and output schemas.
Agent Manifest's ``tool_manifest.catalog_hash`` is a different construction
when the manifest lists its tools: a Merkle root over
``(tool_id, schema_hash, description_hash)`` per tool (agent-manifest spec
3.2.3). The two are never equal and must never be compared to each other.
This module produces the second one from the runtime catalog.

Projection rules, which are cMCP's since the spec does not fix them:

- ``tool_id`` and ``tool_name`` are the exact cMCP catalog keys.
- ``schema_hash`` is SHA-256 over the RFC 8785 (JCS) form of the approved
  input schema.
- ``description_hash`` is SHA-256 over the UTF-8 approved description.

Only those three fields enter the root. ``endpoint_id`` and ``version`` are
filled so the projected entries validate as ``ToolEntry``; they are not
committed. Output schemas and server identity are covered by the sealed
catalog digest, not by this root.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

import rfc8785
from agent_manifest._merkle import build_catalog_tree
from agent_manifest.models import ToolEntry

from cmcp_runtime.errors import ConfigError

if TYPE_CHECKING:
    from cmcp_runtime.catalog.loader import ToolCatalog

#: Labels the projection rules above, which are cMCP's and may change.
PROJECTION_VERSION = "experimental-v1"


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def manifest_catalog_binding(catalog: ToolCatalog) -> dict[str, Any]:
    """Return ``{"catalog_hash": <Merkle root>, "tools": [...]}`` for *catalog*.

    The result is shaped like an Agent Manifest ``tool_manifest`` binding, so
    an issuer can copy it into a manifest and a verifier can compare it with
    one. It describes locally approved definitions, not remote provenance.
    """
    tools = []
    for name, entry in sorted(catalog.entries.items()):
        if name != entry.tool_name:
            raise ConfigError("catalog_name_mismatch")
        tools.append(
            {
                "tool_id": name,
                "tool_name": name,
                "endpoint_id": entry.server.spiffe_id or entry.server.url,
                "schema_hash": _digest(rfc8785.dumps(entry.approved_definition.input_schema)),
                "description_hash": _digest(
                    entry.approved_definition.description.encode("utf-8")
                ),
                "version": PROJECTION_VERSION,
            }
        )
    entries = [ToolEntry.model_validate(t) for t in tools]
    return {"catalog_hash": build_catalog_tree(entries), "tools": tools}
