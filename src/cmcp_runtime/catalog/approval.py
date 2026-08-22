"""Detached, signed provenance for approved tool-catalog changes (#517)."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROFILE = "tag:agentrust-io.com,2026:cmcp-catalog-approval-v1"

_PACKAGED_SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "catalog-approval.schema.json"
_SOURCE_SCHEMA_PATH = (
    Path(__file__).parent.parent.parent.parent / "schemas" / "catalog-approval.schema.json"
)
CATALOG_APPROVAL_SCHEMA_PATH = (
    _PACKAGED_SCHEMA_PATH if _PACKAGED_SCHEMA_PATH.exists() else _SOURCE_SCHEMA_PATH
)

# The first record in a chain has no predecessor. The schema cannot express "absent"
# for a required digest, so the convention is the all-zero one.
GENESIS_PREVIOUS_RECORD_HASH = "sha256:" + "0" * 64

# RFC 8785 numbers are IEEE 754 doubles, so integers stay exact only to 2**53 - 1.
_MAX_EXACT_INT = 2**53 - 1


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


def _utf16_order(key: Any) -> bytes:
    """Sort key placing object members in RFC 8785 order.

    Section 3.2.3 orders members by their UTF-16 code units, which is not the
    code point order `sort_keys` applies. Comparing UTF-16BE bytes is the same
    comparison, since every code unit occupies two bytes.
    """
    if not isinstance(key, str):
        raise CatalogApprovalError("canonical JSON object keys must be strings")
    try:
        return key.encode("utf-16-be")
    except UnicodeEncodeError as exc:
        raise CatalogApprovalError("canonical JSON cannot encode an unpaired surrogate") from exc


def _canonical_members(value: Any) -> Any:
    """Rebuild containers in canonical order, refusing what JCS cannot pin down."""
    if isinstance(value, dict):
        return {k: _canonical_members(v) for k, v in sorted(value.items(), key=lambda kv: _utf16_order(kv[0]))}
    if isinstance(value, list):
        return [_canonical_members(item) for item in value]
    if isinstance(value, float):
        raise CatalogApprovalError("canonical JSON does not accept floating point numbers")
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > _MAX_EXACT_INT:
        raise CatalogApprovalError("integer is outside the range RFC 8785 serializes exactly")
    return value


def canonical_json(value: Any) -> bytes:
    """Return the RFC 8785 (JCS) form used by cMCP records.

    JCS emits UTF-8 and escapes only what ECMAScript `JSON.stringify` escapes, so
    `ensure_ascii` would put ASCII escapes where an interoperating producer puts
    UTF-8 bytes, giving two different signing inputs for one record.
    """
    text = json.dumps(_canonical_members(value), ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CatalogApprovalError("canonical JSON cannot encode an unpaired surrogate") from exc


def digest_json(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def compute_policy_hash(policy: dict[str, Any]) -> str:
    """Digest of the approval policy body, excluding the policy_hash field itself.

    Producers and verifiers must agree on this definition, otherwise the policy a
    record claims to follow cannot be pinned to the policy the verifier trusts.
    """
    return digest_json({k: v for k, v in policy.items() if k != "policy_hash"})


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    """Decode a signature the schema has already constrained to unpadded base64url."""
    try:
        raw = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, TypeError) as exc:
        raise CatalogApprovalError("signature is not valid base64url") from exc
    if len(raw) != 64:
        raise CatalogApprovalError("signature must decode to 64 bytes")
    return raw


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


_schema_cache: dict[str, Any] | None = None


def _approval_schema() -> dict[str, Any]:
    """Return the record schema, refusing to verify without it.

    `loader.py` refuses to load a catalog when its schema is missing from the
    installation rather than validating structure by hand, and an approval record
    carries more weight than a catalog entry, not less.
    """
    global _schema_cache
    if _schema_cache is None:
        if not CATALOG_APPROVAL_SCHEMA_PATH.is_file():
            raise CatalogApprovalError(
                "catalog approval schema is missing from the CMCP installation; "
                "refusing to verify a record without structural validation"
            )
        try:
            _schema_cache = dict(json.loads(CATALOG_APPROVAL_SCHEMA_PATH.read_text()))
        except (OSError, json.JSONDecodeError) as exc:
            raise CatalogApprovalError(f"cannot load catalog approval schema: {exc}") from exc
    return _schema_cache


def _validate_against_schema(record: Any) -> None:
    try:
        jsonschema.validate(record, _approval_schema())
    except jsonschema.ValidationError as exc:
        where = "/".join(str(part) for part in exc.absolute_path) or "record"
        raise CatalogApprovalError(f"schema violation at {where}: {exc.message}") from exc


def verify_catalog_change(
    record: dict[str, Any],
    trusted_reviewers: dict[str, TrustedReviewer],
    *,
    runtime_catalog_hash: str,
    expected_policy_hash: str,
    expected_catalog_id: str,
    validity_instant: int | None = None,
    revoked_key_ids: frozenset[str] = frozenset(),
    expected_sequence: int | None = None,
    expected_previous_record_hash: str | None = None,
    expected_previous_catalog_hash: str | None = None,
) -> dict[str, Any]:
    """Verify policy, chain, reviewer signatures, freshness, and runtime binding.

    The approval policy is never taken on the record's word: `expected_policy_hash`
    and `expected_catalog_id` come from verifier-side configuration, so a record
    cannot declare its own threshold or distinctness rules. The chain checkpoints
    stay optional because they must come from an external pin or transparency
    receipt, which the record itself cannot supply.

    `approved_at` and `expires_at` bound when a signature could have been produced,
    not how long the record stays verifiable. `validity_instant` is the instant the
    caller judges that against, a pinned checkpoint or transparency-receipt timestamp
    where one exists, and each approval's own `approved_at` where none is supplied,
    so a record remains replayable after its approvals expire. Revocation is
    separate and is always judged at verification time.

    Structure is the schema's to decide. The checks below cover only what JSON
    Schema cannot express: the runtime hash binding, the policy pin, reviewer
    identity and key rules, and the signatures.
    """
    _validate_against_schema(record)
    if record["catalog_id"] != expected_catalog_id:
        raise CatalogApprovalMismatch("record does not apply to the expected catalog")
    if expected_sequence is not None and record["sequence"] != expected_sequence:
        raise CatalogApprovalMismatch("record is not the expected sequence number")
    if expected_previous_record_hash is not None and record["previous_record_hash"] != expected_previous_record_hash:
        raise CatalogApprovalMismatch("record is not the expected next chain element")
    if expected_previous_catalog_hash is not None and record["previous_catalog_hash"] != expected_previous_catalog_hash:
        raise CatalogApprovalMismatch("previous_catalog_hash does not match the expected checkpoint")
    if record["new_catalog_hash"] != runtime_catalog_hash:
        raise CatalogApprovalMismatch("new_catalog_hash does not match runtime catalog hash")

    policy = record["approval_policy"]
    threshold = policy["threshold"]
    if compute_policy_hash(policy) != policy["policy_hash"]:
        raise CatalogApprovalError("approval_policy.policy_hash does not cover the policy body")
    if policy["policy_hash"] != _require_digest(expected_policy_hash, "expected_policy_hash"):
        raise CatalogApprovalMismatch("record cites a policy the verifier does not trust")
    approvals = record["approvals"]
    if len(approvals) < threshold:
        raise CatalogApprovalMismatch("approval threshold is not satisfied")
    principals: set[str] = set()
    roles: set[str] = set()
    keys_used: set[str] = set()
    valid = 0
    for approval in approvals:
        key_id = approval["key_id"]
        reviewer = trusted_reviewers.get(key_id)
        # Revocation is deliberately not judged at validity_instant. Whether a key was
        # valid when it signed and whether it is revoked now are different questions.
        if key_id in revoked_key_ids:
            raise CatalogApprovalMismatch(f"reviewer key {key_id!r} is revoked")
        if reviewer is None:
            raise CatalogApprovalMismatch(f"reviewer key {key_id!r} is not trusted")
        if approval["principal_id"] != reviewer.principal_id or approval["issuer"] != reviewer.issuer:
            raise CatalogApprovalMismatch("approval principal or issuer does not match trusted key")
        if reviewer.role is not None and approval["role"] != reviewer.role:
            raise CatalogApprovalMismatch("approval role does not match trusted key")
        if approval["expires_at"] <= approval["approved_at"]:
            raise CatalogApprovalError("approval validity interval is invalid")
        instant = approval["approved_at"] if validity_instant is None else validity_instant
        if instant < approval["approved_at"] or instant >= approval["expires_at"]:
            raise CatalogApprovalMismatch("approval was not valid at the instant being verified")
        signature = _decode(approval["signature"])
        try:
            reviewer.key.verify(signature, _approval_input(record, approval))
        except InvalidSignature as exc:
            raise CatalogApprovalMismatch("approval signature is invalid") from exc
        if policy["distinct_principals"] and approval["principal_id"] in principals:
            raise CatalogApprovalMismatch("approval set repeats a principal under a distinct-principal policy")
        if policy["distinct_roles"] and approval["role"] in roles:
            raise CatalogApprovalMismatch("approval set repeats a role under a distinct-role policy")
        if key_id in keys_used:
            raise CatalogApprovalMismatch("approval set reuses a reviewer key")
        valid += 1
        principals.add(approval["principal_id"])
        roles.add(approval["role"])
        keys_used.add(key_id)
    return {"verified": True, "valid_approvals": valid, "new_catalog_hash": record["new_catalog_hash"]}
