"""Per-session call log and temporal adjacency tracking — implements issue #94."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class CallRecord:
    tool_name: str
    called_at: datetime
    duration_ms: float
    allowed: bool
    sensitivity_raised: bool  # True if this call raised session sensitivity level
    stage_results: dict[str, str]  # stage name -> decision string


@dataclass
class CallLog:
    session_id: str
    records: list[CallRecord] = field(default_factory=list)

    def record(self, call: CallRecord) -> None:
        self.records.append(call)

    def recent(self, n: int = 10) -> list[CallRecord]:
        """Return the last n records."""
        return self.records[-n:]

    def tools_called(self) -> list[str]:
        """Return unique tool names in call order (first-seen)."""
        seen: set[str] = set()
        result: list[str] = []
        for r in self.records:
            if r.tool_name not in seen:
                seen.add(r.tool_name)
                result.append(r.tool_name)
        return result

    def adjacent_pairs(self) -> list[tuple[str, str]]:
        """Return (tool_i, tool_i+1) pairs for consecutive calls."""
        names = [r.tool_name for r in self.records]
        return list(zip(names, names[1:], strict=False))

    def suspicious_sequence(self, threshold: int = 3) -> bool:
        """
        Return True if the same tool was called more than `threshold` times
        consecutively — a potential injection/replay pattern.
        """
        if not self.records:
            return False
        count = 1
        for i in range(1, len(self.records)):
            if self.records[i].tool_name == self.records[i - 1].tool_name:
                count += 1
                if count > threshold:
                    return True
            else:
                count = 1
        return False

    def consecutive_count(self, tool_name: str) -> int:
        """Return the current run length of `tool_name` at the tail of the log."""
        count = 0
        for r in reversed(self.records):
            if r.tool_name == tool_name:
                count += 1
            else:
                break
        return count


# ---------------------------------------------------------------------------
# SessionCallLog and CallLogEntry — richer per-call tracking for TRACE Claims
# ---------------------------------------------------------------------------

#: Sentinel for the compliance_domain of calls where no catalog entry exists.
_UNKNOWN_DOMAIN = "unknown"

#: High-sensitivity compliance domains that trigger cross-boundary event recording
#: when a call transitions away from them.
_HIGH_SENSITIVITY_DOMAINS: frozenset[str] = frozenset({"pii", "phi", "pci", "restricted"})


@dataclass
class CallLogEntry:
    """One entry in the per-session call log (issue #94 spec).

    Tracks temporal adjacency only — not data provenance.  Edges in the
    call graph represent "B was called immediately after A", not "B consumed
    A's output".
    """

    call_id: str
    sequence_number: int
    tool_name: str
    server_identity: str | None
    compliance_domain: str
    timestamp: datetime
    policy_decision: str
    response_sensitivity_tags: list[str]


class SessionCallLog:
    """
    Per-session call log with compliance-domain tracking and cross-boundary
    event detection for the TRACE Claim call_graph_summary (issue #94).

    Edges represent temporal adjacency (call order), NOT data provenance.
    This distinction is surfaced explicitly in get_call_graph_summary() via
    the 'edges_represent' metadata field so consumers do not misinterpret
    temporal edges as data-flow edges.
    """

    #: Metadata note embedded in every call_graph_summary dict.  Do not remove.
    _ADJACENCY_NOTE = (
        "Edges represent temporal adjacency (call order), not data provenance. "
        "A -> B means B was called immediately after A within this session."
    )

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id
        self._entries: list[CallLogEntry] = []

    @property
    def entries(self) -> list[CallLogEntry]:
        return list(self._entries)

    @property
    def session_id(self) -> str:
        return self._session_id

    def record_call(
        self,
        call_id: str,
        catalog_entry: Any | None,
        policy_decision: str,
        *,
        response_sensitivity_tags: list[str] | None = None,
    ) -> CallLogEntry:
        """
        Append a CallLogEntry derived from the catalog entry and policy decision.

        compliance_domain is taken from catalog_entry.compliance_domain when
        a catalog entry is available; falls back to "unknown" for catalog misses.
        server_identity is taken from catalog_entry.server.url.
        tool_name is taken from catalog_entry.tool_name.

        Returns the appended entry.
        """
        if catalog_entry is not None:
            tool_name: str = catalog_entry.tool_name
            server_identity: str | None = getattr(
                getattr(catalog_entry, "server", None), "url", None
            )
            compliance_domain: str = getattr(catalog_entry, "compliance_domain", _UNKNOWN_DOMAIN)
        else:
            tool_name = "unknown"
            server_identity = None
            compliance_domain = _UNKNOWN_DOMAIN

        entry = CallLogEntry(
            call_id=call_id,
            sequence_number=len(self._entries),
            tool_name=tool_name,
            server_identity=server_identity,
            compliance_domain=compliance_domain,
            timestamp=datetime.now(UTC),
            policy_decision=policy_decision,
            response_sensitivity_tags=list(response_sensitivity_tags or []),
        )
        self._entries.append(entry)
        return entry

    def get_call_graph_summary(self) -> dict[str, Any]:
        """
        Build the call_graph_summary dict for inclusion in the TRACE Claim.

        Returns:
            {
                "compliance_domains_touched": [sorted list of unique domains],
                "cross_boundary_events": [
                    {
                        "from_domain": str,
                        "to_domain": str,
                        "call_id": str,
                        "tool_name": str,
                        "sequence_number": int,
                    },
                    ...
                ],
                "edges_represent": "<adjacency note>",
            }

        Cross-boundary events are recorded when a call follows a call in a
        high-sensitivity compliance domain (pii, phi, pci, restricted) and
        the new call is in a different domain.  This captures data-sensitivity
        boundary crossings, not arbitrary domain transitions.
        """
        domains: set[str] = set()
        cross_boundary: list[dict[str, Any]] = []

        for entry in self._entries:
            domains.add(entry.compliance_domain)

        for i in range(1, len(self._entries)):
            prev = self._entries[i - 1]
            curr = self._entries[i]
            if (
                prev.compliance_domain in _HIGH_SENSITIVITY_DOMAINS
                and curr.compliance_domain != prev.compliance_domain
            ):
                cross_boundary.append(
                    {
                        "from_domain": prev.compliance_domain,
                        "to_domain": curr.compliance_domain,
                        "call_id": curr.call_id,
                        "tool_name": curr.tool_name,
                        "sequence_number": curr.sequence_number,
                    }
                )

        return {
            "compliance_domains_touched": sorted(domains),
            "cross_boundary_events": cross_boundary,
            "edges_represent": self._ADJACENCY_NOTE,
        }


__all__ = ["CallLog", "CallRecord", "SessionCallLog", "CallLogEntry"]
