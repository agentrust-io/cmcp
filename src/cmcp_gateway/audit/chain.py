"""Audit chain — append-only hash-chained log inside the enclave. Implements issue #47."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

logger = logging.getLogger(__name__)

EntryType = Literal[
    "session_start",
    "session_end",
    "session_reset",
    "tool_call",
    "egress_denied",
    "attestation_refresh",
    "policy_load",
    "catalog_load",
    "fault",
    "suspicious_call_sequence",
    "attestation_stale",
    "catalog_drift",
    "break_glass_used",
]

PolicyDecision = Literal["allow", "deny", "redact", "advisory_deny", "fault", "n/a"]

InspectionResult = Literal[
    "pass", "injection_detected", "schema_violation", "surplus_stripped", "size_exceeded", "n/a"
]


@dataclass
class AuditEntry:
    """Single entry in the append-only audit chain."""

    entry_id: str
    sequence_number: int
    timestamp_utc: str
    session_id: str
    call_id: str | None
    entry_type: EntryType
    tool_name: str | None
    server_identity: str | None
    policy_decision: PolicyDecision | None
    policy_rule_matched: str | None
    latency_us: int | None
    request_payload_hash: str | None  # SHA-256 of canonical request; NOT the payload
    response_payload_hash: str | None
    response_inspection_result: InspectionResult | None
    session_sensitivity_before: str | None
    session_sensitivity_after: str | None
    detail: dict[str, str | int] | None  # optional structured detail (e.g. suspicious_call_sequence)
    workflow_id: str | None
    prev_entry_hash: str  # "genesis" for first entry
    entry_hash: str = field(default="")  # computed after construction

    def _canonical_body(self) -> bytes:
        """Deterministic JSON of all fields except entry_hash, for hashing."""
        d = asdict(self)
        d.pop("entry_hash")
        return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

    def compute_hash(self) -> str:
        """SHA-256 of the canonical body, hex-encoded."""
        return hashlib.sha256(self._canonical_body()).hexdigest()


class AuditChain:
    """
    Append-only hash-chained audit log maintained inside the enclave.

    Every call, denial, session event, and fault produces one entry.
    chain_root is the hash of the first entry; chain_tip is the hash
    of the most recent entry. Any tampering breaks the hash chain.

    AUDIT-002: to prevent chain substitution, the caller must call
    set_tee_anchor(chain_root) immediately after session start.  The anchor
    is the chain_root committed into the TEE attestation nonce so that an
    attacker who discards _entries and re-builds a fresh chain will get a
    different root that will not match the externally-witnessed value.

    When a TEE anchor is set, verify_chain() also checks that the current
    chain_root equals the anchored value.  In dev / Level-0 mode where no
    TEE is available, anchoring is skipped and a warning is emitted — the
    internal hash-chain check still runs.
    """

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id
        self._entries: list[AuditEntry] = []
        # AUDIT-002: TEE-anchored chain root.  None until set_tee_anchor() is called.
        self._tee_anchor: str | None = None
        self._append_session_start()

    def _append_session_start(self) -> None:
        self.append(
            entry_type="session_start",
            call_id=None,
            tool_name=None,
            server_identity=None,
            policy_decision="n/a",
            policy_rule_matched=None,
            latency_us=None,
            request_payload_hash=None,
            response_payload_hash=None,
            response_inspection_result="n/a",
            session_sensitivity_before=None,
            session_sensitivity_after="public",
            workflow_id=None,
        )

    def set_tee_anchor(self, anchor: str) -> None:
        """
        AUDIT-002: commit the chain root into an external anchor.

        anchor must equal chain_root at the time of the call (i.e. the value
        that was measured into the TEE attestation report nonce).  Raises
        ValueError if anchor does not match the current chain_root — this
        would indicate a programming error in the caller.

        Once set, verify_chain() will reject any chain whose root no longer
        matches this anchored value, preventing silent chain substitution.
        """
        if anchor != self.chain_root:
            raise ValueError(
                f"TEE anchor '{anchor[:16]}...' does not match current chain_root "
                f"'{self.chain_root[:16]}...'. Anchor must be set to the chain_root "
                "immediately after session start."
            )
        self._tee_anchor = anchor

    @property
    def tee_anchor(self) -> str | None:
        """The TEE-committed chain root, or None if not yet anchored (dev/Level-0 mode)."""
        return self._tee_anchor

    def append(
        self,
        entry_type: EntryType,
        *,
        call_id: str | None = None,
        tool_name: str | None = None,
        server_identity: str | None = None,
        policy_decision: PolicyDecision | None = None,
        policy_rule_matched: str | None = None,
        latency_us: int | None = None,
        request_payload_hash: str | None = None,
        response_payload_hash: str | None = None,
        response_inspection_result: InspectionResult | None = None,
        session_sensitivity_before: str | None = None,
        session_sensitivity_after: str | None = None,
        detail: dict[str, str | int] | None = None,
        workflow_id: str | None = None,
    ) -> AuditEntry:
        prev_hash = self._entries[-1].entry_hash if self._entries else "genesis"
        now = datetime.now(tz=UTC)
        if self._entries:
            prev_ts = datetime.fromisoformat(self._entries[-1].timestamp_utc)
            if now < prev_ts:
                now = prev_ts
        entry = AuditEntry(
            entry_id=str(uuid4()),
            sequence_number=len(self._entries),
            timestamp_utc=now.isoformat(),
            session_id=self._session_id,
            call_id=call_id,
            entry_type=entry_type,
            tool_name=tool_name,
            server_identity=server_identity,
            policy_decision=policy_decision,
            policy_rule_matched=policy_rule_matched,
            latency_us=latency_us,
            request_payload_hash=request_payload_hash,
            response_payload_hash=response_payload_hash,
            response_inspection_result=response_inspection_result,
            session_sensitivity_before=session_sensitivity_before,
            session_sensitivity_after=session_sensitivity_after,
            detail=detail,
            workflow_id=workflow_id,
            prev_entry_hash=prev_hash,
        )
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)
        return entry

    @property
    def chain_root(self) -> str:
        """SHA-256 hash of the first entry (session_start)."""
        return self._entries[0].entry_hash

    @property
    def chain_tip(self) -> str:
        """SHA-256 hash of the most recent entry."""
        return self._entries[-1].entry_hash

    @property
    def length(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def verify_chain(self) -> bool:
        """
        Re-compute all hashes and verify internal consistency.

        AUDIT-002: if a TEE anchor has been set, also verify that the current
        chain_root matches the externally-committed value.  A chain that was
        silently replaced by an attacker will have a different root and fail
        this check even if its internal hash links are self-consistent.

        If no anchor is set (dev / Level-0 mode), emit a warning but do not
        fail — the caller should ensure set_tee_anchor() is called in
        production.
        """
        if not self._entries:
            return True
        if self._entries[0].prev_entry_hash != "genesis":
            return False
        for i, entry in enumerate(self._entries):
            expected = entry.compute_hash()
            if entry.entry_hash != expected:
                return False
            if i > 0 and entry.prev_entry_hash != self._entries[i - 1].entry_hash:
                return False

        # AUDIT-002: external anchor check.
        if self._tee_anchor is None:
            logger.warning(
                "AUDIT-002: audit chain has no TEE anchor — chain substitution cannot be "
                "detected. Call set_tee_anchor() at session start in production. "
                "session_id=%s",
                self._session_id,
            )
        elif self.chain_root != self._tee_anchor:
            return False

        return True
