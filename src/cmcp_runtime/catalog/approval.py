"""Detached, signed provenance for approved tool-catalog changes (#517)."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROFILE = "tag:agentrust-io.com,2026:cmcp-catalog-approval-v1"


class CatalogApprovalError(ValueError):
    """The detached approval record is malformed or cannot be trusted."""


class CatalogApprovalMismatch(CatalogApprovalError):
    """The record does not apply to the catalog or policy being verified."""


@dataclass(frozen=True)
class TrustedReviewer:
    principal_id: str
    issuer: str
    key: Ed25519PublicKey
    role: str | None = None


def canonical_json(value: Any) -> bytes:
    """Return the RFC 8785-compatible JSON form used by cMCP records."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest_json(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise CatalogApprovalError("signature must be a base64url string")
    try:
        return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, TypeError) as exc:
        raise CatalogApprovalError("signature is not valid base64url") from exc


def _approval_input(record: dict[str, Any], approval: dict[str, Any]) -> bytes:
    body = {k: v for k, v in record.items() if k != "approvals"}
    unsigned = {k: v for k, v in approval.items() if k != "signature"}
    return canonical_json({"record": body, "approval": unsigned})


def sign_approval(
    record: dict[str, Any], approval: dict[str, Any], key: Ed25519PrivateKey
) -> dict[str, Any]:
    """Return an approval with a signature over the record and approval fields."""
    signed = dict(approval)
    signed["signature"] = _b64(key.sign(_approval_input(record, signed)))
    return signed


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        raise CatalogApprovalError(f"{field} must be a sha256 digest")
    if any(c not in "0123456789abcdef" for c in value[7:]):
        raise CatalogApprovalError(f"{field} must be lowercase hexadecimal")
    return value


def verify_catalog_change(
    record: dict[str, Any],
    trusted_reviewers: dict[str, TrustedReviewer],
    *,
    runtime_catalog_hash: str,
    now: int | None = None,
    revoked_key_ids: frozenset[str] = frozenset(),
    expected_previous_record_hash: str | None = None,
) -> dict[str, Any]:
    """Verify policy, chain, reviewer signatures, freshness, and runtime binding."""
    if not isinstance(record, dict) or record.get("profile") != PROFILE:
        raise CatalogApprovalError("unknown or missing catalog approval profile")
    required = {
        "catalog_id", "sequence", "previous_record_hash", "previous_catalog_hash",
        "new_catalog_hash", "change_set_digest", "approval_policy", "automated_checks_digest",
        "approvals",
    }
    if set(record) != {"profile", *required}:
        raise CatalogApprovalError("record contains missing or unknown fields")
    if not isinstance(record["sequence"], int) or isinstance(record["sequence"], bool) or record["sequence"] < 1:
        raise CatalogApprovalError("sequence must be a positive integer")
    for field in ("previous_record_hash", "previous_catalog_hash", "new_catalog_hash", "change_set_digest", "automated_checks_digest"):
        _require_digest(record[field], field)
    if expected_previous_record_hash is not None and record["previous_record_hash"] != expected_previous_record_hash:
        raise CatalogApprovalMismatch("record is not the expected next chain element")
    if record["new_catalog_hash"] != runtime_catalog_hash:
        raise CatalogApprovalMismatch("new_catalog_hash does not match runtime catalog hash")

    policy = record["approval_policy"]
    if not isinstance(policy, dict) or set(policy) != {"policy_id", "policy_hash", "threshold", "distinct_principals", "distinct_roles"}:
        raise CatalogApprovalError("approval_policy has missing or unknown fields")
    _require_digest(policy["policy_hash"], "approval_policy.policy_hash")
    threshold = policy["threshold"]
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise CatalogApprovalError("approval threshold must be a positive integer")
    instant = int(time.time()) if now is None else now
    approvals = record["approvals"]
    if not isinstance(approvals, list) or len(approvals) < threshold:
        raise CatalogApprovalMismatch("approval threshold is not satisfied")
    principals: set[str] = set()
    roles: set[str] = set()
    valid = 0
    for approval in approvals:
        if not isinstance(approval, dict) or set(approval) != {"principal_id", "issuer", "key_id", "role", "approved_at", "expires_at", "signature"}:
            raise CatalogApprovalError("approval has missing or unknown fields")
        key_id = approval["key_id"]
        reviewer = trusted_reviewers.get(key_id)
        if key_id in revoked_key_ids:
            raise CatalogApprovalMismatch(f"reviewer key {key_id!r} is revoked")
        if reviewer is None:
            raise CatalogApprovalMismatch(f"reviewer key {key_id!r} is not trusted")
        if approval["principal_id"] != reviewer.principal_id or approval["issuer"] != reviewer.issuer:
            raise CatalogApprovalMismatch("approval principal or issuer does not match trusted key")
        if reviewer.role is not None and approval["role"] != reviewer.role:
            raise CatalogApprovalMismatch("approval role does not match trusted key")
        if not isinstance(approval["approved_at"], int) or not isinstance(approval["expires_at"], int) or approval["expires_at"] <= approval["approved_at"]:
            raise CatalogApprovalError("approval validity interval is invalid")
        if instant < approval["approved_at"] or instant >= approval["expires_at"]:
            raise CatalogApprovalMismatch("approval is not currently valid")
        try:
            reviewer.key.verify(_decode(approval["signature"]), _approval_input(record, approval))
        except (InvalidSignature, ValueError) as exc:
            raise CatalogApprovalMismatch("approval signature is invalid") from exc
        valid += 1
        principals.add(approval["principal_id"])
        roles.add(approval["role"])
    if policy["distinct_principals"] and len(principals) < threshold:
        raise CatalogApprovalMismatch("approval threshold lacks distinct principals")
    if policy["distinct_roles"] and len(roles) < threshold:
        raise CatalogApprovalMismatch("approval threshold lacks distinct roles")
    if valid < threshold:
        raise CatalogApprovalMismatch("approval threshold is not satisfied")
    return {"verified": True, "valid_approvals": valid, "new_catalog_hash": record["new_catalog_hash"]}
