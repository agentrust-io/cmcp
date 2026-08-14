"""Small, fail-closed Cedar adapter owned by cMCP.

This module preserves the request mapping cMCP previously received from AGT
v4's ``CedarBackend`` while depending only on the real Cedar engine exposed by
``cedarpy``.  Keeping the mapping here avoids coupling the enforcement path to
AGT's removed v4 policy API or its unrelated v5 ACS lifecycle model.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from time import perf_counter
from typing import Any

import cedarpy

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CedarDecision:
    """The evaluation fields consumed by :class:`PolicyEvaluator`."""

    allowed: bool
    reason: str
    evaluation_ms: float
    policy_ids: tuple[str, ...] = ()
    error: str | None = None


class CedarBackend:
    """Evaluate cMCP's measured policy bytes with cedarpy.

    The class name intentionally remains ``CedarBackend`` so existing test and
    extension seams do not change.  There is no mock or permissive fallback: an
    invalid policy, malformed request, or unavailable engine produces a deny.
    """

    def __init__(self, *, policy_content: str) -> None:
        self._policy_content = policy_content

    @staticmethod
    def build_request(context: dict[str, Any]) -> dict[str, Any]:
        """Map cMCP call context to the same Cedar entities used by AGT v4."""
        agent_id = context.get("agent_id", 'Agent::"anonymous"')
        resource = context.get("resource", 'Resource::"default"')

        if "::" not in str(agent_id):
            agent_id = f'Agent::"{agent_id}"'
        if "::" not in str(resource):
            resource = f'Resource::"{resource}"'

        tool_name = str(context.get("tool_name", "unknown"))
        action_name = "".join(part.capitalize() for part in tool_name.split("_"))
        return {
            "principal": agent_id,
            "action": f'Action::"{action_name}"',
            "resource": resource,
            "context": {
                key: value
                for key, value in context.items()
                if key not in ("agent_id", "tool_name", "resource")
            },
        }

    def evaluate(self, context: dict[str, Any]) -> CedarDecision:
        """Authorize one call, failing closed on every engine error."""
        started = perf_counter()
        try:
            response = cedarpy.is_authorized(
                request=self.build_request(context),
                policies=self._policy_content,
                entities=[],
            )
            allowed = response.decision == cedarpy.Decision.Allow
            reasons = tuple(str(reason) for reason in response.diagnostics.reasons)
            errors = tuple(str(error) for error in response.diagnostics.errors)
            return CedarDecision(
                allowed=allowed,
                reason=(
                    f"Cedar evaluation error: {'; '.join(errors)}"
                    if errors
                    else f"Cedar (cedarpy): {'allowed' if allowed else 'denied'}"
                ),
                evaluation_ms=(perf_counter() - started) * 1000,
                policy_ids=reasons,
                error="; ".join(errors) or None,
            )
        except Exception as exc:
            logger.error("Cedar evaluation failed: %s", exc)
            return CedarDecision(
                allowed=False,
                reason=f"Cedar evaluation error: {exc}",
                evaluation_ms=(perf_counter() - started) * 1000,
                error=str(exc),
            )
