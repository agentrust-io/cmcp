"""Server provenance: check who says this MCP server is what it claims.

Consumes ``spec/server-provenance-v1.md`` records via ``agentrust_trace.provenance``.
This module is the gateway's side: load, verify, and decide what to do about the
answer.

**Absence is recorded, never silently passed, and by default not fatal.** Nearly
every MCP server in existence has no provenance record. A gateway that refuses to
route without one is a gateway that gets turned off on first contact and never
turned back on. So the default is to record ``absent`` and continue, with
``provenance.required_kind`` available for a deployment that wants a floor.

The rule that matters is not the default. It is that a verifier reading the audit
trail afterwards can tell "we checked and found nothing" from "we never looked".
Those are different facts and only one of them is about the server.
"""

from __future__ import annotations

import json
import logging
import pathlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["ProvenanceOutcome", "ProvenanceResult", "check_server_provenance"]


class ProvenanceOutcome(StrEnum):
    """What the gateway concluded. Every value is recorded in the audit chain."""

    VERIFIED = "verified"
    """Signature verified against the configured key and the server's advertised
    tools match the record. The assurance this is worth is the record's ``kind``,
    which is carried separately: verifying a ``publisher-asserted`` record proves
    the publisher said it, and nothing else."""

    CATALOG_MISMATCH = "catalog-mismatch"
    """The record verified and the server offered a different tool set. This is
    the finding the format exists to produce, and it is about the server rather
    than the document."""

    INVALID = "invalid"
    """The record is malformed, unsigned, or signed by a key that is not the one
    configured for this server."""

    UNCHECKED = "unchecked"
    """A record is configured but the server's tools could not be listed, so the
    comparison that matters never happened. Deliberately not ``verified``: a
    signature check alone is a document checking itself."""

    ABSENT = "absent"
    """No record is configured for this server. Recorded so the audit trail can
    distinguish this from having looked and found a problem."""


#: Ordered weakest to strongest, for `required_kind` comparisons.
_KIND_ORDER = ("publisher-asserted", "observer-attested", "tee-attested")


@dataclass(frozen=True)
class ProvenanceResult:
    outcome: ProvenanceOutcome
    kind: str | None = None
    publisher: str | None = None
    detail: str | None = None

    @property
    def ok(self) -> bool:
        """Whether the check produced no finding. Not the same as 'trustworthy'."""
        return self.outcome in (ProvenanceOutcome.VERIFIED, ProvenanceOutcome.ABSENT)

    def meets(self, required_kind: str | None) -> bool:
        """Whether this satisfies a configured minimum assurance."""
        if required_kind is None:
            return True
        if self.outcome is not ProvenanceOutcome.VERIFIED or self.kind is None:
            return False
        return _KIND_ORDER.index(self.kind) >= _KIND_ORDER.index(required_kind)

    def to_audit(self) -> dict[str, str]:
        block = {"provenance": self.outcome.value}
        if self.kind:
            block["provenance_kind"] = self.kind
        if self.publisher:
            block["provenance_publisher"] = self.publisher[:256]
        if self.detail:
            block["provenance_detail"] = self.detail[:512]
        return block


def check_server_provenance(
    record_path: str | None,
    trusted_jwk: dict[str, Any] | None,
    advertised_tools: list[dict[str, Any]] | None,
) -> ProvenanceResult:
    """Load, verify, and compare. Returns a result rather than raising.

    Raising would make an absent record indistinguishable from a failed one at
    the call site, and the whole point is that a consumer can tell those apart.

    *advertised_tools* is what the server offered **this gateway**. Passing the
    catalog's own approved definitions instead would compare the record against
    our approval rather than against the server, which is the substitution that
    turns this check into theatre.
    """
    if not record_path:
        return ProvenanceResult(ProvenanceOutcome.ABSENT)

    try:
        from agentrust_trace.provenance import (
            ProvenanceError,
            ToolCatalogMismatch,
            check_tool_catalog,
            verify_record,
        )
    except ImportError:  # pragma: no cover - dependency is declared
        return ProvenanceResult(
            ProvenanceOutcome.UNCHECKED,
            detail="agentrust-trace is not installed; provenance was not checked",
        )

    try:
        record = json.loads(pathlib.Path(record_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return ProvenanceResult(
            ProvenanceOutcome.INVALID, detail=f"could not read the record: {exc}"
        )

    if trusted_jwk is None:
        # The record embeds a key. Using it would verify the document against
        # itself, which is what a forgery does successfully.
        return ProvenanceResult(
            ProvenanceOutcome.INVALID,
            detail=(
                "no trusted publisher key is configured for this server, and the key in "
                "the record cannot be used to check the record"
            ),
        )

    kind = record.get("kind")
    publisher = record.get("publisher")

    try:
        verify_record(record, trusted_jwk)
    except ProvenanceError as exc:
        return ProvenanceResult(
            ProvenanceOutcome.INVALID, kind=kind, publisher=publisher, detail=str(exc)[:500]
        )

    if advertised_tools is None:
        return ProvenanceResult(
            ProvenanceOutcome.UNCHECKED,
            kind=kind,
            publisher=publisher,
            detail=(
                "the record verified but the server's tool list was unavailable, so the "
                "comparison that would catch a substituted server did not run"
            ),
        )

    try:
        check_tool_catalog(record, advertised_tools)
    except ToolCatalogMismatch as exc:
        logger.error("PROVENANCE_CATALOG_MISMATCH: publisher=%s: %s", publisher, exc)
        return ProvenanceResult(
            ProvenanceOutcome.CATALOG_MISMATCH,
            kind=kind,
            publisher=publisher,
            detail=str(exc)[:500],
        )

    return ProvenanceResult(ProvenanceOutcome.VERIFIED, kind=kind, publisher=publisher)
