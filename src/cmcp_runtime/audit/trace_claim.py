"""TRACE Claim (cmcp profile) - RuntimeClaim envelope wrapping canonical TRACE fields."""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from agentrust_trace.models import JWK, ConfirmationKey, PolicyInfo, RuntimeInfo
from pydantic import BaseModel, ConfigDict, Field

AgentSubjectSource = Literal["config", "svid", "manifest-dev"]

try:
    _RUNTIME_VERSION: str = importlib.metadata.version("cmcp-runtime")  # was cmcp-gateway
except importlib.metadata.PackageNotFoundError:
    _RUNTIME_VERSION = "unknown"

# ── Provider → canonical platform mapping ─────────────────────────────────────

_PROVIDER_MAP: dict[str, str] = {
    "sev-snp": "amd-sev-snp",
    # Azure CVM is SEV-SNP behind a Hyper-V paravisor (vTPM-rooted, not
    # direct-silicon). It has its own canonical platform value (agentrust-trace
    # >=0.4) so a consumer keying on runtime.platform knows the root of trust is
    # vTPM-rooted rather than a guest-controlled SNP report_data.
    "azure-cvm-sev-snp": "azure-cvm-sev-snp",
    "tdx": "intel-tdx",
    "opaque": "intel-tdx",
    "tpm": "tpm2",
    # Dev mode is its own platform value: a consumer keying trust on
    # runtime.platform must never mistake a non-attested record for TPM-backed.
    "software-only": "software-only",
}

_SW_ONLY_MEASUREMENT = "sha256:" + "0" * 64
_SW_ONLY_FIRMWARE = "software-only-dev-mode"

# ── Input DTOs (unchanged interface for callers) ───────────────────────────────


@dataclass
class CallGraphSummary:
    compliance_domains_touched: list[str]
    cross_boundary_events: list[dict[str, Any]]
    #: Clarifies that edges are temporal adjacency, not data provenance (issue #94).
    edges_represent: str | None = None


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


@dataclass
class AgentIdentityInfo:
    manifest_id: str
    agent_id: str
    authenticated_subject: str
    subject_source: AgentSubjectSource
    issuer: str
    issuer_key_id: str
    policy_bundle_hash: str
    tool_catalog_hash: str


# ── Pydantic output models ─────────────────────────────────────────────────────


class CallGraphOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    compliance_domains_touched: list[str]
    cross_boundary_events: list[dict[str, Any]]
    #: Clarifies that edges are temporal adjacency, not data provenance (issue #94).
    edges_represent: str | None = None


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


class AgentIdentityOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_id: str
    agent_id: Annotated[str, Field(pattern=r"^spiffe://")]
    authenticated_subject: Annotated[str, Field(pattern=r"^spiffe://")]
    subject_source: AgentSubjectSource
    issuer: Annotated[str, Field(pattern=r"^spiffe://")]
    issuer_key_id: str
    policy_bundle_hash: str
    tool_catalog_hash: str


class ToolTranscriptEntry(BaseModel):
    """One privacy-preserving entry in the bound tool transcript (issue #126).

    Derived from the audit chain, never from raw tool-call parameters or response
    bodies: it carries only the tool name, the data class the call touched, and the
    policy decision. No request/response payloads, so the transcript leaks no PII.
    """

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    data_class: str
    decision: Literal["allow", "deny", "redact", "advisory_deny", "fault", "n/a"]


class ToolTranscriptOut(BaseModel):
    """cmcp tool_transcript: the canonical TRACE fields plus the privacy-preserving
    entries array (issue #126). ``hash`` binds the full transcript to the audit chain
    tip; ``entries`` lets a regulator read the per-call decision trail offline.
    """

    model_config = ConfigDict(extra="forbid")

    hash: Annotated[str, Field(pattern=r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")]
    call_count: Annotated[int, Field(ge=0)] | None = None
    transcript_uri: str | None = None
    entries: list[ToolTranscriptEntry] | None = None


class GatewayTrace(BaseModel):
    """Phase 1 TRACE fields applicable to the cmcp runtime context."""

    model_config = ConfigDict(extra="forbid")

    eat_profile: Literal["tag:agentrust.io,2026:trace-v0.1"]
    iat: Annotated[int, Field(ge=1700000000)]
    subject: Annotated[str, Field(pattern=r"^spiffe://")]
    runtime: RuntimeInfo
    policy: PolicyInfo
    data_class: str
    tool_transcript: ToolTranscriptOut | None = None
    cnf: ConfirmationKey


class CallLogSummary(BaseModel):
    """Per-session call log summary included in the gateway addenda."""

    model_config = ConfigDict(extra="forbid")

    total_calls: int
    tools_called: list[str]
    suspicious_sequences_detected: int


class GatewayAddenda(BaseModel):
    """cmcp-specific fields outside the canonical TRACE spec."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    gateway_version: str
    sequence_number: int  # AUDIT-005: monotonically increasing across all claims from this instance
    prev_claim_hash: str | None = None  # AUDIT-005: sha256 of previous claim's canonical JSON
    audit_chain: AuditChainSummary
    call_summary: CallSummaryOut
    catalog: CatalogSummary
    attestation_generated_at: str
    attestation_validity_seconds: int
    attestation_stale: bool
    catalog_exceptions: list[dict[str, str]] = Field(default_factory=list)
    call_log_summary: CallLogSummary | None = None
    agent_identity: AgentIdentityOut | None = None
    kill_switch_triggered: bool = False


class RuntimeClaim(BaseModel):
    """cmcp TRACE profile - canonical trust fields nested inside a gateway envelope."""

    model_config = ConfigDict(extra="forbid")

    cmcp_version: str = "1.0"
    trace: GatewayTrace
    gateway: GatewayAddenda
    signature: str = ""


# ── Serialization and signing ──────────────────────────────────────────────────


def _to_dict(claim: RuntimeClaim) -> dict[str, Any]:
    return claim.model_dump(exclude_none=True)


def canonical_json(claim_dict: dict[str, Any]) -> bytes:
    """Canonical serialization for signing: sorted keys, no whitespace, UTF-8.

    The 'signature' field is excluded from the body being signed.
    """
    body = {k: v for k, v in claim_dict.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sign_trace_claim(claim: RuntimeClaim, signing_key: Any) -> str:
    """Sign the RuntimeClaim with the TEE-sealed Ed25519 private key.

    Returns base64url-encoded signature (no padding).
    """
    claim_dict = _to_dict(claim)
    body = canonical_json(claim_dict)
    raw_sig = signing_key.sign(body)
    return base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()


# ── Builder helpers ────────────────────────────────────────────────────────────


def _build_runtime(report: AttestationReportInfo) -> RuntimeInfo:
    provider = report.provider
    if provider not in _PROVIDER_MAP:
        raise ValueError(
            f"Attestation provider '{provider}' is not in the allowed set "
            f"{sorted(_PROVIDER_MAP.keys())}. "
            "Rejecting claim construction to prevent spoofed attestation reports."
        )
    platform = _PROVIDER_MAP[provider]

    if provider == "software-only":
        return RuntimeInfo(
            platform=platform,  # type: ignore[arg-type]
            measurement=_SW_ONLY_MEASUREMENT,
            firmware_version=_SW_ONLY_FIRMWARE,
        )

    measurement = (
        report.measurement
        if report.measurement.startswith(("sha256:", "sha384:"))
        else f"sha256:{report.measurement}"
    )
    # CRYPTO-003: raise on malformed report_data instead of silently dropping the nonce.
    # A missing nonce removes the binding between the attestation report and the session;
    # a malformed report_data indicates a broken or compromised TEE shim.
    try:
        nonce = base64.urlsafe_b64encode(bytes.fromhex(report.report_data)).rstrip(b"=").decode()
    except ValueError as exc:
        raise ValueError(
            f"TEE attestation report contains malformed report_data: {exc!r}. "
            "The nonce binding to the session cannot be established. "
            "Check the TEE provider implementation."
        ) from exc

    return RuntimeInfo(platform=platform, measurement=measurement, nonce=nonce)  # type: ignore[arg-type]


def _build_policy(bundle: PolicyBundleInfo) -> PolicyInfo:
    mode_map = {"enforcing": "enforce", "advisory": "advisory", "silent": "silent"}
    return PolicyInfo(
        bundle_hash=bundle.hash,
        enforcement_mode=mode_map.get(bundle.enforcement_mode, "advisory"),  # type: ignore[arg-type]
        version=bundle.policy_version,
    )


def canonical_entries(entries: list[ToolTranscriptEntry]) -> bytes:
    """Canonical JSON of the transcript entries array, for offline hash verification."""
    body = [e.model_dump() for e in entries]
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def transcript_entries_hash(entries: list[ToolTranscriptEntry]) -> str:
    """SHA-256 over the canonical entries array, as a ``sha256:`` digest string.

    A verifier recomputes this from the entries and checks it against the digest the
    profile carries. Distinct from ``tool_transcript.hash`` (the audit-chain tip): this
    one binds the human-readable per-call view, the chain tip binds the full transcript.
    """
    return "sha256:" + hashlib.sha256(canonical_entries(entries)).hexdigest()


def _build_cnf(signing_key: Any) -> ConfirmationKey:
    pub_hex: str = signing_key.public_key_hex
    x = base64.urlsafe_b64encode(bytes.fromhex(pub_hex)).rstrip(b"=").decode()
    kid = f"cmcp-{pub_hex[:8]}"
    return ConfirmationKey(jwk=JWK(kty="OKP", crv="Ed25519", x=x, kid=kid))


def _build_subject(signing_key: Any) -> str:
    return f"spiffe://cmcp.gateway/tee/{signing_key.public_key_hex[:16]}"


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
    transcript_entries: list[ToolTranscriptEntry] | None = None,
    attestation_stale: bool = False,
    catalog_exceptions: list[dict[str, str]] | None = None,
    call_log_summary: CallLogSummary | None = None,
    agent_identity: AgentIdentityInfo | None = None,
    sequence_number: int = 1,
    prev_claim_hash: str | None = None,
    kill_switch_triggered: bool = False,
    do_sign: bool = True,
) -> RuntimeClaim:
    """Generate a RuntimeClaim from session data, validate it via Pydantic, and optionally sign it.

    signing_key must be a SigningKey instance (audit/keys.py) - it is always required
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
        subject=_build_subject(signing_key),
        runtime=_build_runtime(attestation_report),
        policy=_build_policy(policy_bundle),
        data_class=call_summary.session_max_sensitivity,
        tool_transcript=ToolTranscriptOut(
            hash=tool_transcript_hash,
            call_count=call_summary.tool_calls_total,
            entries=transcript_entries,
        ),
        cnf=_build_cnf(signing_key),
    )

    gateway = GatewayAddenda(
        session_id=session_id,
        gateway_version=_RUNTIME_VERSION,
        sequence_number=sequence_number,
        prev_claim_hash=prev_claim_hash,
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
                edges_represent=call_summary.call_graph_summary.edges_represent,
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
        kill_switch_triggered=kill_switch_triggered,
        call_log_summary=call_log_summary,
        agent_identity=(
            AgentIdentityOut(
                manifest_id=agent_identity.manifest_id,
                agent_id=agent_identity.agent_id,
                authenticated_subject=agent_identity.authenticated_subject,
                subject_source=agent_identity.subject_source,
                issuer=agent_identity.issuer,
                issuer_key_id=agent_identity.issuer_key_id,
                policy_bundle_hash=agent_identity.policy_bundle_hash,
                tool_catalog_hash=agent_identity.tool_catalog_hash,
            )
            if agent_identity is not None
            else None
        ),
    )

    claim = RuntimeClaim(trace=trace, gateway=gateway)

    if do_sign:
        claim.signature = sign_trace_claim(claim, signing_key)

    return claim
