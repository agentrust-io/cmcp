"""Opt-in exact-byte release adapter; not an exception to MCP sink policy."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Literal

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

Disposition = Literal["unchanged", "authorized_disclosure", "unavailable", "denied"]
Delivery = Literal["not_attempted", "unknown", "acknowledged"]
_DOMAIN = b"cmcp/exact-output-disclosure/v1\x00"


def _names(values: tuple[str, ...]) -> None:
    if any(not isinstance(v, str) or not v or len(v) > 256 for v in values):
        raise ValueError("nonempty bounded identifiers required")


@dataclass(frozen=True)
class ReleaseRequest:
    """Labels and identity come from the trusted controller, never the prompt."""

    payload: bytes = field(repr=False)
    workload: str
    source_scope: str
    labels: tuple[str, ...]
    recipient: str
    purpose: str
    policy_version: str
    request_id: str = field(default_factory=lambda: secrets.token_hex(32))

    def __post_init__(self) -> None:
        _names((self.workload, self.source_scope, self.recipient, self.purpose, self.policy_version))
        if not isinstance(self.payload, bytes):
            raise ValueError("immutable payload bytes required")
        if not isinstance(self.labels, tuple) or not self.labels:
            raise ValueError("nonempty inherited label tuple required")
        _names(self.labels)
        if (not isinstance(self.request_id, str) or len(self.request_id) != 64
                or any(c not in "0123456789abcdef" for c in self.request_id)):
            raise ValueError("canonical random request identifier required")


@dataclass(frozen=True)
class ReleaseAuthority:
    key: Ed25519PublicKey
    source_scopes: frozenset[str]
    recipients: frozenset[str]
    purposes: frozenset[str]

    def __post_init__(self) -> None:
        for name in ("source_scopes", "recipients", "purposes"):
            values = frozenset(getattr(self, name))
            _names(tuple(values))
            object.__setattr__(self, name, values)


@dataclass(frozen=True)
class ReleaseRecipient:
    """Operator-pinned transport; unknown boundary cannot silently mean external."""

    ceiling: str
    boundary: Literal["accepted", "external", "unknown"]
    deliver: Callable[[bytes], None] = field(repr=False)

    def __post_init__(self) -> None:
        _names((self.ceiling,))
        if self.boundary not in ("accepted", "external", "unknown") or not callable(self.deliver):
            raise ValueError("registered boundary and delivery adapter required")


@dataclass(frozen=True)
class DisclosureApproval:
    principal: str
    not_before: int
    expires_at: int
    signature: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _names((self.principal,))
        if (type(self.not_before) is not int or type(self.expires_at) is not int
                or not 0 <= self.not_before < self.expires_at <= 2**53 - 1):
            raise ValueError("integer validity interval required")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise ValueError("Ed25519 signature required")


def _approval_input(request: ReleaseRequest, principal: str, not_before: int, expires_at: int) -> bytes:
    return _DOMAIN + rfc8785.dumps({
        "principal": principal, "not_before": not_before, "expires_at": expires_at,
        "request_id": request.request_id, "workload": request.workload,
        "source_scope": request.source_scope, "labels": list(request.labels),
        "recipient": request.recipient, "purpose": request.purpose,
        "policy_version": request.policy_version,
        "output_sha256": hashlib.sha256(request.payload).hexdigest(),
    })


def approve_exact_output(
    request: ReleaseRequest, *, principal: str, key: Ed25519PrivateKey,
    not_before: int, expires_at: int,
) -> DisclosureApproval:
    """Owner-side signing after independent review; this is not model approval."""
    signature = key.sign(_approval_input(request, principal, not_before, expires_at))
    return DisclosureApproval(principal, not_before, expires_at, signature)


@dataclass(frozen=True)
class ReleaseObservation:
    """Minimized local observation, not a signed receipt or installation proof."""

    disposition: Disposition
    reason: str
    delivery: Delivery = "not_attempted"
    event_id: str = field(default_factory=lambda: secrets.token_hex(32))


class ReplayStore:
    """Trusted shared storage is required; deletion and rollback are not resisted."""

    def __init__(self, path: str | Path):
        if str(path) == ":memory:":
            raise ValueError("persistent replay database required")
        self._path = str(Path(path).resolve())
        connection = sqlite3.connect(self._path)
        try:
            connection.execute("CREATE TABLE IF NOT EXISTS disclosure_attempts "
                               "(request_id TEXT PRIMARY KEY)")
            connection.commit()
        finally:
            connection.close()

    def consume(self, request_id: str) -> bool:
        connection = sqlite3.connect(self._path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("INSERT INTO disclosure_attempts VALUES (?)", (request_id,))
            connection.commit()
        except sqlite3.IntegrityError:
            connection.rollback()
            return False
        finally:
            connection.close()
        return True


class DisclosureGate:
    """Validate and consume before invoking one operator-registered byte sink.

    Immutable policy snapshot. Stop old admission before replacing this gate;
    no remote revocation or distributed policy-ordering mechanism is supplied.
    """

    def __init__(
        self, *, policy_version: str, source_scopes: frozenset[str],
        sensitivity_order: Mapping[str, int], recipients: Mapping[str, ReleaseRecipient],
        authorities: Mapping[str, ReleaseAuthority], replay_store: ReplayStore,
        now: Callable[[], int] | None = None,
    ) -> None:
        _names((policy_version, *source_scopes, *sensitivity_order, *recipients, *authorities))
        if not sensitivity_order or any(type(v) is not int or v < 0 for v in sensitivity_order.values()):
            raise ValueError("nonnegative integer sensitivity ranks required")
        self._version = policy_version
        self._scopes = frozenset(source_scopes)
        self._order = MappingProxyType(dict(sensitivity_order))
        self._recipients = MappingProxyType(dict(recipients))
        self._authorities = MappingProxyType(dict(authorities))
        self._store = replay_store
        self._now = now or (lambda: int(time.time()))

    def release(
        self, request: ReleaseRequest, approval: DisclosureApproval | None = None,
    ) -> ReleaseObservation:
        """No callback for refusal. Any callback failure leaves delivery unknown."""
        if request.policy_version != self._version:
            return ReleaseObservation("denied", "policy_mismatch")
        recipient = self._recipients.get(request.recipient)
        if recipient is None or recipient.boundary == "unknown":
            return ReleaseObservation("unavailable", "recipient_boundary")
        if request.source_scope not in self._scopes:
            return ReleaseObservation("unavailable", "source_scope")
        if recipient.ceiling not in self._order or any(label not in self._order for label in request.labels):
            return ReleaseObservation("unavailable", "classification")
        within = recipient.boundary == "accepted" and all(
            self._order[label] <= self._order[recipient.ceiling] for label in request.labels)
        disposition: Disposition = "unchanged" if within else "authorized_disclosure"
        if not within:
            if approval is None:
                return ReleaseObservation("unavailable", "release_authority")
            authority = self._authorities.get(approval.principal)
            if authority is None:
                return ReleaseObservation("unavailable", "release_authority")
            if (request.source_scope not in authority.source_scopes
                    or request.recipient not in authority.recipients
                    or request.purpose not in authority.purposes):
                return ReleaseObservation("denied", "authority_scope")
            try:
                authority.key.verify(approval.signature, _approval_input(
                    request, approval.principal, approval.not_before, approval.expires_at))
            except InvalidSignature:
                return ReleaseObservation("denied", "approval_binding")
            validity = self._validity(approval)
            if validity is not None:
                return validity
        try:
            if not self._store.consume(request.request_id):
                return ReleaseObservation("denied", "replay")
        except sqlite3.Error:
            return ReleaseObservation("unavailable", "replay_storage")
        # SQLite may have waited for another process; expiry is rechecked after
        # reservation. Failed rechecks still consume the attempt, before delivery.
        if not within and approval is not None:
            validity = self._validity(approval)
            if validity is not None:
                return validity
        try:
            recipient.deliver(request.payload)
        except Exception:
            # Do not copy upstream exception text or a traceback into evidence.
            return ReleaseObservation(disposition, "delivery_unknown", "unknown")
        return ReleaseObservation(disposition, "adapter_acknowledged", "acknowledged")

    def _validity(self, approval: DisclosureApproval) -> ReleaseObservation | None:
        try:
            now = self._now()
            if type(now) is not int or now < 0:
                raise ValueError("clock value unavailable")
        except Exception:
            return ReleaseObservation("unavailable", "clock")
        if not approval.not_before <= now < approval.expires_at:
            return ReleaseObservation("denied", "approval_expired_or_early")
        return None
