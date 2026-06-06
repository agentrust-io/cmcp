"""Audit chain — append-only hash-chained log inside the enclave. Implements issue #47."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

EntryType = Literal[
    "session_start",
    "session_end",
    "session_reset",
    "tool_call",
    "attestation_refresh",
    "policy_load",
    "catalog_load",
    "fault",
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
    """

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id
        self._entries: list[AuditEntry] = []
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
        workflow_id: str | None = None,
    ) -> AuditEntry:
        prev_hash = self._entries[-1].entry_hash if self._entries else "genesis"
        entry = AuditEntry(
            entry_id=str(uuid4()),
            sequence_number=len(self._entries),
            timestamp_utc=datetime.now(tz=UTC).isoformat(),
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
        """Re-compute all hashes and verify internal consistency."""
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
        return True
