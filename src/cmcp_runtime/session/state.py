"""Session sensitivity state machine: implements issue #84."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

from cmcp_runtime.session.store import SessionStateStore, StoredSensitivity

# Sensitivity level ordering: monotonically increasing only.
# hipaa_phi, mnpi, trade_secret are all at level 3 (equal highest).
SENSITIVITY_ORDER: dict[str, int] = {
    "public": 0,
    "pii": 1,
    "confidential": 2,
    "hipaa_phi": 3,
    "mnpi": 3,
    "trade_secret": 3,  # nosec B105
}


# Compliance domains a catalog entry may declare. Kept here, beside
# SENSITIVITY_ORDER, because the two vocabularies overlap by name and drifting
# them apart is exactly how the cross-boundary control below stopped firing.
#
# regulated=True means a call leaving this domain is a compliance boundary
# crossing worth recording. The three regulated names are the reason the field
# exists; internal/external/public are ordinary traffic.
COMPLIANCE_DOMAINS: dict[str, bool] = {
    "hipaa_phi": True,
    "pci_data": True,
    "mnpi": True,
    "pii": True,
    "internal": False,
    "external": False,
    "public": False,
}


def effective_compliance_domains(extra: dict[str, bool] | None = None) -> dict[str, bool]:
    """Built in domains plus any deployment configured additions.

    Same additive contract as effective_sensitivity_order: extra can add a
    domain, for example a regulator's own classification, but a built in name
    always keeps its built in regulated flag. A deployment that adds a domain
    says whether it is regulated, because nothing else can know.
    """
    return {**(extra or {}), **COMPLIANCE_DOMAINS}


def effective_sensitivity_order(extra: dict[str, int] | None = None) -> dict[str, int]:
    """Built in vocabulary plus any deployment configured additions (#479).

    Additive only: extra can add new labels, for example a regulator's own top
    tier, but can never remove or shadow a built in name. SENSITIVITY_ORDER is
    merged in last so a built in name always keeps its built in rank even if
    something upstream of this function failed to reject a colliding key, since
    config.py's parser is expected to reject that collision before this ever
    runs. This matters because response inspection emits hardcoded tags such as
    pii and hipaa_phi (inspection/pipeline.py); if one of those names silently
    dropped out of the effective vocabulary it would rank at 0 by
    SENSITIVITY_ORDER.get(tag, 0)'s fail open default, the same class of hole
    the schema validation at catalog load time closes for #478.
    """
    return {**(extra or {}), **SENSITIVITY_ORDER}


def _max_sensitivity(a: str, b: str, order: dict[str, int] = SENSITIVITY_ORDER) -> str:
    """Return whichever sensitivity level is higher. Ties return 'a'."""
    if order.get(b, 0) > order.get(a, 0):
        return b
    return a


@dataclass
class InjectionEvent:
    call_id: str
    timestamp: str


@dataclass(frozen=True)
class ClosedSessionRecord:
    """The final state of a session closed by a credentialed reset.

    Held apart from the successor's live state so that the accumulated value the
    closed session reached is preserved rather than overwritten. The successor
    starts at the minimum level, and this is the only place its predecessor's
    final value survives outside the audit chain.
    """

    session_id: str
    max_sensitivity: str
    sensitivity_raised_at: str | None
    sensitivity_raised_by_call: str | None
    reset_count: int
    closed_at: str
    reason: str
    authorized_by: str


@dataclass
class SessionState:
    """
    Per-session sensitivity state machine.

    State transitions are monotonically increasing: sensitivity can only rise,
    never fall automatically. A session reset (operator-only, issue #92) is the
    only way to lower sensitivity.

    update_from_inspection() is the ONLY place where session sensitivity state
    is updated. It is called by the proxy response path after all inspection stages
    complete, including for denied responses (a denied high-sensitivity response
    still raises session sensitivity because the agent knows the call was attempted).

    A response is only allowed to raise the session it was issued under. Callers
    pass the ``reset_count`` observed when the call started and a response that
    lands after a reset is dropped rather than applied to the successor. The
    discriminator is ``reset_count`` and not ``session_id`` because
    upgrade_attestation() rotates ``session_id`` while deliberately continuing
    the same session at its current sensitivity, so a call in flight across an
    attestation upgrade must still be applied.
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
    upstream_drift_tools: list[str] = field(default_factory=list)
    """Tools whose upstream server advertised a definition that does not match
    the approved one (P4.2). Tracked separately from ``catalog_drift`` for two
    reasons: it names *which* tools drifted, and under
    ``catalog.drift_policy: warn_only`` the calls still route, so ``catalog_drift``
    stays False while the session is demonstrably no longer what was approved.
    A TRACE claim must report drift in both cases.
    """
    kill_switch_triggered: bool = False
    # #479: the effective vocabulary this session ranks tags against. Defaults to
    # the built in table; SessionManager passes the deployment's configured one.
    sensitivity_order: dict[str, int] = field(
        default_factory=lambda: SENSITIVITY_ORDER, repr=False, compare=False
    )
    # AUTH-002: guards concurrent mutations from tool-call coroutines and session-reset requests
    mutation_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False, compare=False)
    #: Where the accumulated value is held. None keeps the value in this object
    #: alone, which is the single-instance default. A shared store makes the
    #: ratchet hold per session across gateway instances rather than per
    #: instance, and makes it survive a restart. See ``session/store.py``.
    state_store: SessionStateStore | None = field(
        default=None, repr=False, compare=False
    )

    def update_from_inspection(
        self,
        call_id: str,
        sensitivity_tags: list[str],
        injection_detected: bool,
        response_allowed: bool,  # noqa: ARG002 (logged for future use)
        *,
        for_reset_count: int | None = None,
    ) -> bool:
        """
        Update session state from an inspection result.

        Called by the proxy response path after all stages complete. Returns True
        if the state was updated, False if the response belonged to a session that
        has since been closed by a reset and was therefore dropped.

        ``for_reset_count`` is the reset counter observed when the call started.
        When it does not match the current counter the response is evidence about
        a closed session and must not raise the successor, whose whole purpose is
        to start at the minimum level.
        """
        if for_reset_count is not None and for_reset_count != self.reset_count:
            return False
        for tag in sensitivity_tags:
            new_max = _max_sensitivity(self.max_sensitivity, tag, self.sensitivity_order)
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
        return True

    def snapshot_for_close(self, *, reason: str, authorized_by: str) -> ClosedSessionRecord:
        """Capture this session's final state before a reset opens a successor.

        Call inside the mutation lock, immediately before reset(), so the value
        recorded is the one the session held at the ordered session boundary.
        """
        return ClosedSessionRecord(
            session_id=self.session_id,
            max_sensitivity=self.max_sensitivity,
            sensitivity_raised_at=self.sensitivity_raised_at,
            sensitivity_raised_by_call=self.sensitivity_raised_by_call,
            reset_count=self.reset_count,
            closed_at=datetime.now(tz=UTC).isoformat(),
            reason=reason,
            authorized_by=authorized_by,
        )

    async def apply_inspection(
        self,
        call_id: str,
        sensitivity_tags: list[str],
        injection_detected: bool,
        response_allowed: bool,
        *,
        for_reset_count: int | None = None,
    ) -> bool:
        """Serialise and apply one inspection result to the accumulated value.

        This is the only write path for tool-call processing. With no store
        configured it is the previous behaviour: take the in-process lock and
        mutate. With a store it holds the store's exclusive section, reads the
        current value back, folds this response into it and writes it, so the
        greater-of comparison is made against the value every instance shares
        rather than against this instance's copy.
        """
        if self.state_store is None:
            async with self.mutation_lock:
                return self.update_from_inspection(
                    call_id,
                    sensitivity_tags,
                    injection_detected,
                    response_allowed,
                    for_reset_count=for_reset_count,
                )
        async with self.state_store.exclusive(self.session_id):
            self._adopt(self.state_store.load(self.session_id))
            applied = self.update_from_inspection(
                call_id,
                sensitivity_tags,
                injection_detected,
                response_allowed,
                for_reset_count=for_reset_count,
            )
            if applied:
                self.state_store.save(self.session_id, self._stored())
            return applied

    async def apply_reset(
        self, *, reason: str, authorized_by: str
    ) -> tuple[str, str, ClosedSessionRecord]:
        """Serialise and apply a credentialed reset, closing the session.

        Returns the closed identifier, the successor identifier, and the record
        preserving what the closed session reached. The snapshot is taken inside
        the exclusive section so the preserved value is the one held at the
        ordered session boundary, and the successor is written to the store so
        that no instance keeps serving the closed session's value.
        """
        if self.state_store is None:
            async with self.mutation_lock:
                closed = self.snapshot_for_close(
                    reason=reason, authorized_by=authorized_by
                )
                old_id, new_id = self.reset(reason=reason, authorized_by=authorized_by)
                return old_id, new_id, closed
        async with self.state_store.exclusive(self.session_id):
            self._adopt(self.state_store.load(self.session_id))
            closed = self.snapshot_for_close(reason=reason, authorized_by=authorized_by)
            old_id, new_id = self.reset(reason=reason, authorized_by=authorized_by)
            self.state_store.record_closed(old_id, closed)
            # Advance the closed session's generation in the store, keeping the
            # value it reached. Another instance may still be holding the old
            # identifier with a response in flight; without this it would read a
            # generation matching the one it captured and raise a session that is
            # already closed. The successor is written under its own identifier,
            # so bumping the old row is the only way that instance finds out.
            self.state_store.save(
                old_id,
                StoredSensitivity(
                    max_sensitivity=closed.max_sensitivity,
                    sensitivity_raised_at=closed.sensitivity_raised_at,
                    sensitivity_raised_by_call=closed.sensitivity_raised_by_call,
                    reset_count=self.reset_count,
                ),
            )
            self.state_store.save(new_id, self._stored())
            return old_id, new_id, closed

    async def hydrate(self) -> bool:
        """Adopt this session's stored value, if the store holds one.

        Called at startup so a gateway that restarts, or an instance joining a
        session another instance opened, enforces against what the session
        already accumulated instead of starting the ratchet again at the minimum
        level. Returns True when a stored value was adopted.
        """
        if self.state_store is None:
            return False
        async with self.state_store.exclusive(self.session_id):
            stored = self.state_store.load(self.session_id)
            if stored is None:
                self.state_store.save(self.session_id, self._stored())
                return False
            self._adopt(stored)
            return True

    def _stored(self) -> StoredSensitivity:
        return StoredSensitivity(
            max_sensitivity=self.max_sensitivity,
            sensitivity_raised_at=self.sensitivity_raised_at,
            sensitivity_raised_by_call=self.sensitivity_raised_by_call,
            reset_count=self.reset_count,
        )

    def _adopt(self, stored: StoredSensitivity | None) -> None:
        """Take the store's value as this instance's own.

        Only ever raises: the stored value is the greater of what any instance
        has seen, and a local value above it would mean this instance observed
        something it has not yet written. The reset counter is taken whole,
        because a reset performed on another instance closed this session there
        and this instance must not keep applying responses to it.
        """
        if stored is None:
            return
        self.max_sensitivity = _max_sensitivity(
            self.max_sensitivity, stored.max_sensitivity, self.sensitivity_order
        )
        if self.max_sensitivity == stored.max_sensitivity:
            self.sensitivity_raised_at = stored.sensitivity_raised_at
            self.sensitivity_raised_by_call = stored.sensitivity_raised_by_call
        self.reset_count = max(self.reset_count, stored.reset_count)

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
        self.upstream_drift_tools = []
        self.reset_count += 1
        self.attestation_stale = False
        self.catalog_drift = False
        # reason and authorized_by are logged by the caller in the audit chain
        return previous_session_id, self.session_id

    def upgrade_attestation(self) -> tuple[str, str]:
        """
        Rotate the session token when attestation upgrades (e.g. software-only → hardware TEE).

        Unlike reset(), session sensitivity state is preserved: the ongoing session
        continues at its current sensitivity level. Only the session_id is rotated so
        that any trust assertions cached against the old ID are invalidated.

        Returns (previous_session_id, new_session_id). The caller is responsible for
        writing an attestation_refresh audit entry.
        """
        previous_session_id = self.session_id
        self.session_id = str(uuid4())
        self.attestation_stale = False
        return previous_session_id, self.session_id
