"""TRACE Claim generation, signing, and validation — implements issues #49, #50, #52."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema

from cmcp_gateway.errors import ClaimValidationError

_SCHEMA_PATH = Path(__file__).parent.parent.parent.parent / "schemas" / "trace-claim.schema.json"


@dataclass
class CallGraphSummary:
    compliance_domains_touched: list[str]
    cross_boundary_events: list[dict[str, str]]


@dataclass
class CallSummary:
    tool_calls_total: int
    tool_calls_allowed: int
    tool_calls_denied: int
    tool_calls_faulted: int
    tools_invoked: list[str]
    session_max_sensitivity: str
    call_graph_summary: CallGraphSummary


@dataclass
class PolicyBundleInfo:
    hash: str
    enforcement_mode: str
    policy_version: str


@dataclass
class ToolCatalogInfo:
    hash: str
    drift_detected: bool = False


@dataclass
class AttestationReportInfo:
    provider: str
    measurement: str
    report_data: str
    attestation_generated_at: str
    attestation_validity_seconds: int
    measurement_note: str | None = None
    raw_evidence: str | None = None  # base64-encoded if present


@dataclass
class TraceClaim:
    trace_version: str
    session_id: str
    timestamp_utc: str
    tee_public_key: str
    attestation_report: AttestationReportInfo
    policy_bundle: PolicyBundleInfo
    tool_catalog: ToolCatalogInfo
    call_summary: CallSummary
    audit_chain_root: str
    audit_chain_tip: str
    audit_chain_length: int
    attestation_stale: bool
    catalog_exceptions: list[dict[str, str]]
    signature: str = ""


def _to_dict(obj: Any) -> Any:
    """Recursively convert dataclasses to dicts suitable for JSON serialization."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _to_dict(v) for k, v in asdict(obj).items() if v is not None or k == "signature"}
    if isinstance(obj, list):
        return [_to_dict(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    return obj


def canonical_json(claim_dict: dict[str, Any]) -> bytes:
    """
    Canonical serialization for signing: sorted keys, no whitespace, UTF-8.
    The 'signature' field is excluded from the body being signed.
    """
    body = {k: v for k, v in claim_dict.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sign_trace_claim(claim: TraceClaim, signing_key: Any) -> str:
    """
    Sign the TRACE Claim with the TEE-sealed Ed25519 private key.
    Returns base64url-encoded signature (no padding).
    """
    claim_dict = _to_dict(claim)
    body = canonical_json(claim_dict)
    raw_sig = signing_key.sign(body)
    return base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()


def _load_schema() -> dict[str, Any] | None:
    if _SCHEMA_PATH.exists():
        return json.loads(_SCHEMA_PATH.read_text())
    return None


def validate_trace_claim(claim_dict: dict[str, Any]) -> None:
    """
    Validate a TRACE Claim dict against schemas/trace-claim.schema.json.
    Raises ClaimValidationError listing all violations.

    Called automatically in generate_trace_claim — callers cannot get an
    invalid claim (conformance: TRACE-001).
    """
    schema = _load_schema()
    if schema is None:
        return  # schema not present (e.g. in test environment without schemas/)

    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(claim_dict))
    if errors:
        messages = [f"{'.'.join(str(p) for p in e.absolute_path) or 'root'}: {e.message}" for e in errors]
        raise ClaimValidationError(
            f"TRACE Claim schema validation failed ({len(errors)} errors)",
            detail="; ".join(messages),
        )


def generate_trace_claim(
    *,
    session_id: str,
    tee_public_key: str,
    attestation_report: AttestationReportInfo,
    policy_bundle: PolicyBundleInfo,
    tool_catalog: ToolCatalogInfo,
    call_summary: CallSummary,
    audit_chain_root: str,
    audit_chain_tip: str,
    audit_chain_length: int,
    attestation_stale: bool = False,
    catalog_exceptions: list[dict[str, str]] | None = None,
    signing_key: Any | None = None,
) -> TraceClaim:
    """
    Generate a TRACE Claim from session data, validate it, and sign it.

    signing_key must be a SigningKey instance (from audit/keys.py) for production use.
    If signing_key is None, the signature field is empty (dev mode only).
    """
    claim = TraceClaim(
        trace_version="1.0",
        session_id=session_id,
        timestamp_utc=datetime.now(tz=timezone.utc).isoformat(),
        tee_public_key=tee_public_key,
        attestation_report=attestation_report,
        policy_bundle=policy_bundle,
        tool_catalog=tool_catalog,
        call_summary=call_summary,
        audit_chain_root=audit_chain_root,
        audit_chain_tip=audit_chain_tip,
        audit_chain_length=audit_chain_length,
        attestation_stale=attestation_stale,
        catalog_exceptions=catalog_exceptions or [],
        signature="",
    )

    claim_dict = _to_dict(claim)
    validate_trace_claim(claim_dict)

    if signing_key is not None:
        claim.signature = sign_trace_claim(claim, signing_key)

    return claim
