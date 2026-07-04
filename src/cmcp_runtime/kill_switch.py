"""AGT SRE kill switch evaluator: implements issue #341."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cmcp_runtime.config import KillSwitchConfig


class KillSwitchEvaluator:
    """Rolling-window deny-rate evaluator for per-agent-identity enforcement.

    When a registered agent identity exceeds `deny_rate_threshold` policy
    denies over the rolling `window_seconds` window (with at least `min_calls`
    events), the identity is flagged. The TRACE claim for the session that
    trips the threshold carries `kill_switch_triggered=true`: hardware-attested
    evidence of automated enforcement. Subsequent `create_session()` calls for
    the same agent identity raise `KillSwitchTripped`.

    Thread-safety: this evaluator is not thread-safe by itself. The caller
    (SessionManager) must serialise calls if sessions are closed concurrently.
    In practice the gateway processes sessions on an asyncio event loop and
    close_session() is called synchronously, so no lock is needed.
    """

    def __init__(self, config: KillSwitchConfig) -> None:
        self._config = config
        # agent_id -> deque of (monotonic_time, is_deny: bool)
        self._events: dict[str, deque[tuple[float, bool]]] = defaultdict(deque)
        self._blocked: set[str] = set()

    def record_calls(self, agent_id: str, *, allowed: int, denied: int) -> None:
        """Record call outcomes from a just-closed session into the rolling window."""
        now = time.monotonic()
        q = self._events[agent_id]
        for _ in range(allowed):
            q.append((now, False))
        for _ in range(denied):
            q.append((now, True))
        self._prune(agent_id)

    def evaluate(self, agent_id: str) -> bool:
        """Return True and flag the agent if the kill switch threshold is exceeded."""
        if not self._config.enabled:
            return False
        self._prune(agent_id)
        q = self._events[agent_id]
        total = len(q)
        if total < self._config.min_calls:
            return False
        deny_count = sum(1 for _, is_deny in q if is_deny)
        rate = deny_count / total
        if rate >= self._config.deny_rate_threshold:
            self._blocked.add(agent_id)
            return True
        return False

    def is_blocked(self, agent_id: str) -> bool:
        """Return True if this agent identity has previously tripped the kill switch."""
        return agent_id in self._blocked

    def unblock(self, agent_id: str) -> None:
        """Manually unblock an agent identity. Clears its event history too."""
        self._blocked.discard(agent_id)
        self._events.pop(agent_id, None)

    def _prune(self, agent_id: str) -> None:
        cutoff = time.monotonic() - self._config.window_seconds
        q = self._events[agent_id]
        while q and q[0][0] < cutoff:
            q.popleft()
