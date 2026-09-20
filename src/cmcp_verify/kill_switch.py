"""Verify a kill switch refusal receipt against the claim of the session the trip closed.

When the kill switch refuses a call, the gateway returns a receipt signed with
the key that signs its TRACE claims. This module checks that a receipt and a
claim belong together: the claim is signed, it records that the kill switch
stopped the session, and the receipt was signed by the same gateway key and
names that exact claim by digest.

What it does not establish on its own: that the gateway key is the one bound
to attested hardware. That is ``verify_trace_claim``'s job on the claim. Run
both; a receipt that passes here against a claim that fails there proves only
that some key refused a call.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cmcp_runtime.audit.trace_claim import REFUSAL_RECEIPT_TYPE
from cmcp_verify.verify import _canonical_json, _verify_signature


@dataclass
class KillSwitchRefusalResult:
    """Outcome of checking one refusal receipt against one claim."""

    valid: bool
    agent_id: str | None = None
    session_id: str | None = None
    refused_at: str | None = None
    errors: list[str] = field(default_factory=list)


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_kill_switch_refusal(
    receipt: dict[str, Any], claim: dict[str, Any]
) -> KillSwitchRefusalResult:
    """Check that ``receipt`` is a refusal issued by the gateway that signed ``claim``.

    Every check runs and every failure is reported, so a caller sees all the
    ways a receipt and claim disagree rather than the first one.
    """
    errors: list[str] = []
    if not isinstance(receipt, dict) or not isinstance(claim, dict):
        return KillSwitchRefusalResult(valid=False, errors=["receipt and claim must be objects"])

    if receipt.get("type") != REFUSAL_RECEIPT_TYPE:
        errors.append(f"receipt type is not {REFUSAL_RECEIPT_TYPE!r}")

    claim_ok, claim_error = _verify_signature(claim)
    if not claim_ok:
        errors.append(f"claim signature: {claim_error}")

    raw_gateway = claim.get("gateway")
    gateway: dict[str, Any] = raw_gateway if isinstance(raw_gateway, dict) else {}
    try:
        claim_key = claim["trace"]["cnf"]["jwk"]["x"]
    except (KeyError, TypeError):
        claim_key = None
    receipt_key = receipt.get("gateway_key")
    if not isinstance(receipt_key, str) or receipt_key != claim_key:
        errors.append("receipt was not signed by the key that signed the claim")

    signature = receipt.get("signature")
    if isinstance(receipt_key, str) and isinstance(signature, str):
        try:
            public_key = Ed25519PublicKey.from_public_bytes(_b64url_decode(receipt_key))
            public_key.verify(_b64url_decode(signature), _canonical_json(receipt))
        except (ValueError, binascii.Error):
            errors.append("receipt key or signature cannot be decoded")
        except InvalidSignature:
            errors.append("receipt signature verification failed")
    else:
        errors.append("receipt carries no signature")

    if receipt.get("session_id") != gateway.get("session_id"):
        errors.append("receipt names a different session than the claim")
    if gateway.get("kill_switch_triggered") is not True:
        errors.append("claim does not record that the kill switch stopped this session")

    digest = receipt.get("claim_digest")
    if not isinstance(digest, str):
        errors.append(
            "receipt is not bound to a signed claim (issued before the session's claim existed)"
        )
    elif digest != "sha256:" + hashlib.sha256(_canonical_json(claim)).hexdigest():
        errors.append("receipt claim_digest does not match the claim")

    identity = gateway.get("agent_identity")
    if isinstance(identity, dict) and receipt.get("agent_id") != identity.get("agent_id"):
        errors.append("receipt names a different agent identity than the claim")

    return KillSwitchRefusalResult(
        valid=not errors,
        agent_id=receipt.get("agent_id"),
        session_id=receipt.get("session_id"),
        refused_at=receipt.get("refused_at"),
        errors=errors,
    )
