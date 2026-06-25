"""Session sensitivity state machine — implements issue #84."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

# Sensitivity level ordering — monotonically increasing only.
# hipaa_phi, mnpi, trade_secret are all at level 3 (equal highest).
SENSITIVITY_ORDER: dict[str, int] = {
    "public": 0,
    "pii": 1,
    "confidential": 2,
    "hipaa_phi": 3,
    "mnpi": 3,
    "trade_secret": 3,  # nosec B105
}


def _max_sensitivity(a: str, b: str) -> str:
    """Return whichever sensitivity level is higher. Ties return 'a'."""
    if SENSITIVITY_ORDER.get(b, 0) > SENSITIVITY_ORDER.get(a, 0):
        return b
    return a


@dataclass
class InjectionEvent:
    call_id: str
    timestamp: str


@dataclass
class SessionState:
    """
    Per-session sensitivity state machine.

    State transitions are monotonically increasing — sensitivity can only rise,
    never fall automatically. A session reset (operator-only, issue #92) is the
    only way to lower sensitivity.

    update_from_inspection() is the ONLY place where session sensitivity state
    is updated. It is called by InspectionPipeline after all inspection stages
    complete, including for denied responses (a denied high-sensitivity response
    still raises session sensitivity because the agent knows the call was attempted).
    """

    session_id: str
    max_sensitivity: str = "public"
    sensitivity_raised_at: str | None = None
    sensitivity_raised_by_call: str | None = None
    injection_events: list[InjectionEvent] = field(default_factory=list)
    reset_count: int = 0
    suspicious_sequences: int = 0
    attestation_stale: bool = False
    catalog_drift: bool = False
    kill_switch_triggered: bool = False
    # AUTH-002: guards concurrent mutations from tool-call coroutines and session-reset requests
    mutation_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False, compare=False)

    def update_from_inspection(
        self,
        call_id: str,
        sensitivity_tags: list[str],
        injection_detected: bool,
        response_allowed: bool,  # noqa: ARG002 — logged for future use
    ) -> None:
        """
        Update session state from an inspection result.

        Called by InspectionPipeline after all stages complete.
        """
        for tag in sensitivity_tags:
            new_max = _max_sensitivity(self.max_sensitivity, tag)
            if new_max != self.max_sensitivity:
                self.max_sensitivity = new_max
                self.sensitivity_raised_at = datetime.now(tz=UTC).isoformat()
                self.sensitivity_raised_by_call = call_id

        if injection_detected:
            self.injection_events.append(
                InjectionEvent(
                    call_id=call_id,
                    timestamp=datetime.now(tz=UTC).isoformat(),
                )
            )

    def reset(self, *, reason: str, authorized_by: str) -> tuple[str, str]:
        """
        Reset session sensitivity to 'public'. Returns (previous_session_id, new_session_id).

        This is an operator-only action. The caller is responsible for writing
        the session_reset audit entry.
        """
        previous_session_id = self.session_id
        self.session_id = str(uuid4())
        self.max_sensitivity = "public"
        self.sensitivity_raised_at = None
        self.sensitivity_raised_by_call = None
        self.suspicious_sequences = 0
        self.reset_count += 1
        self.attestation_stale = False
        self.catalog_drift = False
        # reason and authorized_by are logged by the caller in the audit chain
        return previous_session_id, self.session_id

    def upgrade_attestation(self) -> tuple[str, str]:
        """
        Rotate the session token when attestation upgrades (e.g. software-only → hardware TEE).

        Unlike reset(), session sensitivity state is preserved — the ongoing session
        continues at its current sensitivity level. Only the session_id is rotated so
        that any trust assertions cached against the old ID are invalidated.

        Returns (previous_session_id, new_session_id). The caller is responsible for
        writing an attestation_refresh audit entry.
        """
        previous_session_id = self.session_id
        self.session_id = str(uuid4())
        self.attestation_stale = False
        return previous_session_id, self.session_id
