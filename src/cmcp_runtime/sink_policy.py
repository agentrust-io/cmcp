"""Operator-owned sensitivity ceilings; no content-based declassification."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from cmcp_runtime.errors import ConfigError, PolicyDeny


@dataclass(frozen=True)
class SinkPolicy:
    """An absent tool is denied. The response ceiling applies to the caller.

    Names refer to the deployment's sensitivity ordering, not compartment or
    purpose permissions. Transport identity remains the catalog's responsibility.
    """

    tool_max_sensitivity: Mapping[str, str]
    response_max_sensitivity: str

    def __post_init__(self) -> None:
        if not isinstance(self.tool_max_sensitivity, Mapping):
            raise ConfigError("sink_policy.tool_max_sensitivity must be a mapping")
        if any(not isinstance(k, str) or not k or not isinstance(v, str) or not v
               for k, v in self.tool_max_sensitivity.items()):
            raise ConfigError("sink_policy tool names and ceilings must be nonempty strings")
        if not isinstance(self.response_max_sensitivity, str) or not self.response_max_sensitivity:
            raise ConfigError("sink_policy.response_max_sensitivity must be a nonempty string")
        object.__setattr__(self, "tool_max_sensitivity", MappingProxyType(dict(self.tool_max_sensitivity)))

    def validate(self, order: Mapping[str, int]) -> None:
        if any(label not in order for label in (
            *self.tool_max_sensitivity.values(), self.response_max_sensitivity,
        )):
            raise ConfigError("sink_policy contains an unknown sensitivity ceiling")

    def require(self, *, tool: str | None, labels: tuple[str, ...], order: Mapping[str, int]) -> None:
        """No unknown-label fallback, advisory bypass, or lowering by callers."""
        ceiling = self.response_max_sensitivity if tool is None else self.tool_max_sensitivity.get(tool)
        sink = "response" if tool is None else "tool"
        if (ceiling is None or ceiling not in order or not labels or any(label not in order for label in labels)
                or any(order[label] > order[ceiling] for label in labels)):
            raise PolicyDeny(f"sink_policy:{sink}_denied")
