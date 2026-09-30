"""Optional pre-transport admission hook for verifier-issued TRACE tokens.

cMCP does not verify TRACE tokens itself. An operator that wants every tool
call to carry a holder-bound, verifier-issued token supplies an object that
implements :class:`TraceGate` (the reference is ``prototype/cmcp_gate.py`` in
agentrust-io/trace-spec) and passes it to ``build_server``. With no gate
configured, no route, parameter or code path below is reachable.

Every method refuses by raising ``ValueError``. The proxy treats a refusal as a
deny and never reaches transport.
"""

from __future__ import annotations

import base64
from typing import Any, Protocol

#: Upper bound on one base64url credential on the wire, before decoding.
MAX_ENCODED_TOKEN_CHARS = 90_000


class TraceGate(Protocol):
    """What the proxy and the HTTP routes call. Refusals raise ``ValueError``."""

    def challenge(
        self, token_bytes: bytes, *, session_id: str, action: dict[str, Any]
    ) -> dict[str, Any]:
        """Mint a single-use nonce bound to the token, session and action."""
        ...

    def admit(self, token_bytes: bytes, credentials: object, *, session_id: str) -> dict[str, Any]:
        """Admit a token for the session after a holder proof."""
        ...

    def begin(
        self,
        credentials: object,
        *,
        action: dict[str, Any],
        session_id: str,
        call_id: str,
        policy_digest: str,
    ) -> tuple[Any, dict[str, Any]]:
        """Consume the holder proof for one call and return an opaque handle."""
        ...

    def recheck(self, handle: Any, *, action: dict[str, Any], policy_digest: str) -> None:
        """Refuse if the token, admission, action or gateway policy changed."""
        ...

    def receipt(self, handle: Any, *, allowed: bool, reason: str) -> None:
        """Durably record the gateway's decision for the call."""
        ...

    def refusal(self, *, action: dict[str, Any], session_id: str, call_id: str) -> None:
        """Record a deny for a call that never obtained a handle."""
        ...


def decode_trace_token(value: object) -> bytes:
    """Decode one unpadded base64url credential; only the canonical encoding is accepted."""
    if not isinstance(value, str) or len(value) > MAX_ENCODED_TOKEN_CHARS:
        raise ValueError("credential_shape")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise ValueError("credential_encoding") from exc
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        raise ValueError("credential_encoding")
    return raw
