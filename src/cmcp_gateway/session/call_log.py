"""Per-session call log and temporal adjacency tracking — implements issue #94."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


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


__all__ = ["CallLog", "CallRecord"]
