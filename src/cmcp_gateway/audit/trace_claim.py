"""TRACE Claim (cmcp profile) — GatewayClaim envelope wrapping canonical TRACE fields."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from agentrust_trace.models import JWK, ConfirmationKey, PolicyInfo, RuntimeInfo, ToolTranscript
from pydantic import BaseModel, ConfigDict, Field

# ── Provider → canonical platform mapping ─────────────────────────────────────

_PROVIDER_MAP: dict[str, str] = {
    "sev-snp": "amd-sev-snp",
    "tdx": "intel-tdx",
    "opaque": "intel-tdx",
    "tpm": "tpm2",
    "software-only": "tpm2",
}

_SW_ONLY_MEASUREMENT = "sha256:" + "0" * 64
_SW_ONLY_FIRMWARE = "software-only-dev-mode"

# ── Input DTOs (unchanged interface for callers) ───────────────────────────────


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
    raw_evidence: str | None = None


# ── Pydantic output models ─────────────────────────────────────────────────────


class CallGraphOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    compliance_domains_touched: list[str]
    cross_boundary_events: list[dict[str, str]]


class CallSummaryOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_calls_total: int
    tool_calls_allowed: int
    tool_calls_denied: int
    tool_calls_faulted: int
    tools_invoked: list[str]
    session_max_sensitivity: str
    call_graph_summary: CallGraphOut


class AuditChainSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root: str
    tip: str
    length: int


class CatalogSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hash: str
    drift_detected: bool = False


class GatewayTrace(BaseModel):
    """Phase 1 TRACE fields applicable to the cmcp gateway context."""

    model_config = ConfigDict(extra="forbid")

    eat_profile: Literal["tag:agentrust.io,2026:trace-v0.1"]
    iat: Annotated[int, Field(ge=1700000000)]
    subject: Annotated[str, Field(pattern=r"^spiffe://")]
    runtime: RuntimeInfo
    policy: PolicyInfo
    data_class: str
    tool_transcript: ToolTranscript | None = None
    cnf: ConfirmationKey


class GatewayAddenda(BaseModel):
    """cmcp-specific fields outside the canonical TRACE spec."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    audit_chain: AuditChainSummary
    call_summary: CallSummaryOut
    catalog: CatalogSummary
    attestation_generated_at: str
    attestation_validity_seconds: int
    attestation_stale: bool
    catalog_exceptions: list[dict[str, str]] = Field(default_factory=list)


class GatewayClaim(BaseModel):
    """cmcp TRACE profile — canonical trust fields nested inside a gateway envelope."""

    model_config = ConfigDict(extra="forbid")

    cmcp_version: str = "1.0"
    trace: GatewayTrace
    gateway: GatewayAddenda
    signature: str = ""


# ── Serialization and signing ──────────────────────────────────────────────────


def _to_dict(claim: GatewayClaim) -> dict[str, Any]:
    return claim.model_dump(exclude_none=True)


def canonical_json(claim_dict: dict[str, Any]) -> bytes:
    """Canonical serialization for signing: sorted keys, no whitespace, UTF-8.

    The 'signature' field is excluded from the body being signed.
    """
    body = {k: v for k, v in claim_dict.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sign_trace_claim(claim: GatewayClaim, signing_key: Any) -> str:
    """Sign the GatewayClaim with the TEE-sealed Ed25519 private key.

    Returns base64url-encoded signature (no padding).
    """
    claim_dict = _to_dict(claim)
    body = canonical_json(claim_dict)
    raw_sig = signing_key.sign(body)
    return base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()


# ── Builder helpers ────────────────────────────────────────────────────────────


def _build_runtime(report: AttestationReportInfo) -> RuntimeInfo:
    provider = report.provider
    platform = _PROVIDER_MAP.get(provider, "tpm2")

    if provider == "software-only":
        return RuntimeInfo(
            platform=platform,
            measurement=_SW_ONLY_MEASUREMENT,
            firmware_version=_SW_ONLY_FIRMWARE,
        )

    measurement = (
        report.measurement
        if report.measurement.startswith(("sha256:", "sha384:"))
        else f"sha256:{report.measurement}"
    )
    try:
        nonce = base64.urlsafe_b64encode(bytes.fromhex(report.report_data)).rstrip(b"=").decode()
    except ValueError:
        nonce = None

    return RuntimeInfo(platform=platform, measurement=measurement, nonce=nonce)


def _build_policy(bundle: PolicyBundleInfo) -> PolicyInfo:
    mode_map = {"enforcing": "enforce", "advisory": "advisory", "silent": "silent"}
    return PolicyInfo(
        bundle_hash=bundle.hash,
        enforcement_mode=mode_map.get(bundle.enforcement_mode, "advisory"),
        version=bundle.policy_version,
    )


def _build_cnf(signing_key: Any) -> ConfirmationKey:
    pub_hex: str = signing_key.public_key_hex
    x = base64.urlsafe_b64encode(bytes.fromhex(pub_hex)).rstrip(b"=").decode()
    kid = f"cmcp-{pub_hex[:8]}"
    return ConfirmationKey(jwk=JWK(kty="OKP", crv="Ed25519", x=x, kid=kid))


# ── Public API ─────────────────────────────────────────────────────────────────


def generate_trace_claim(
    *,
    session_id: str,
    signing_key: Any,
    attestation_report: AttestationReportInfo,
    policy_bundle: PolicyBundleInfo,
    tool_catalog: ToolCatalogInfo,
    call_summary: CallSummary,
    audit_chain_root: str,
    audit_chain_tip: str,
    audit_chain_length: int,
    attestation_stale: bool = False,
    catalog_exceptions: list[dict[str, str]] | None = None,
    do_sign: bool = True,
) -> GatewayClaim:
    """Generate a GatewayClaim from session data, validate it via Pydantic, and optionally sign it.

    signing_key must be a SigningKey instance (audit/keys.py) — it is always required
    to build the JWK confirmation key in trace.cnf.  Set do_sign=False to produce an
    unsigned claim (e.g. in tests).
    """
    tool_transcript_hash = (
        audit_chain_tip
        if audit_chain_tip.startswith(("sha256:", "sha384:"))
        else f"sha256:{audit_chain_tip}"
    )

    trace = GatewayTrace(
        eat_profile="tag:agentrust.io,2026:trace-v0.1",
        iat=int(datetime.now(tz=UTC).timestamp()),
        subject=f"spiffe://cmcp.gateway/session/{session_id}",
        runtime=_build_runtime(attestation_report),
        policy=_build_policy(policy_bundle),
        data_class=call_summary.session_max_sensitivity,
        tool_transcript=ToolTranscript(
            hash=tool_transcript_hash,
            call_count=call_summary.tool_calls_total,
        ),
        cnf=_build_cnf(signing_key),
    )

    gateway = GatewayAddenda(
        session_id=session_id,
        audit_chain=AuditChainSummary(
            root=audit_chain_root,
            tip=audit_chain_tip,
            length=audit_chain_length,
        ),
        call_summary=CallSummaryOut(
            tool_calls_total=call_summary.tool_calls_total,
            tool_calls_allowed=call_summary.tool_calls_allowed,
            tool_calls_denied=call_summary.tool_calls_denied,
            tool_calls_faulted=call_summary.tool_calls_faulted,
            tools_invoked=call_summary.tools_invoked,
            session_max_sensitivity=call_summary.session_max_sensitivity,
            call_graph_summary=CallGraphOut(
                compliance_domains_touched=call_summary.call_graph_summary.compliance_domains_touched,
                cross_boundary_events=call_summary.call_graph_summary.cross_boundary_events,
            ),
        ),
        catalog=CatalogSummary(
            hash=tool_catalog.hash,
            drift_detected=tool_catalog.drift_detected,
        ),
        attestation_generated_at=attestation_report.attestation_generated_at,
        attestation_validity_seconds=attestation_report.attestation_validity_seconds,
        attestation_stale=attestation_stale,
        catalog_exceptions=catalog_exceptions or [],
    )

    claim = GatewayClaim(trace=trace, gateway=gateway)

    if do_sign:
        claim.signature = sign_trace_claim(claim, signing_key)

    return claim
