"""TRACE Claim (cmcp profile) - RuntimeClaim envelope wrapping canonical TRACE fields."""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import json
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

import rfc8785
from agentrust_trace.models import (
    JWK,
    Appraisal,
    BuildProvenance,
    ConfirmationKey,
    ModelInfo,
    PolicyInfo,
    RuntimeInfo,
)
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    model_validator,
)

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
    #: Key id (``sha256:<hex>`` of the raw Ed25519 public key) the policy in force
    #: verified under, or None where no policy signing key is pinned.
    signing_key_id: str | None = None
    #: Policy signing keys revoked in this gateway process, in the order revoked.
    revoked_signing_key_ids: list[str] = field(default_factory=list)


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
    # Base64 evidence, surfaced in the claim as gateway.attestation_evidence.
    raw_evidence: str | None = None
    quote_signature: str | None = None
    cert_chain: str | None = None
    ek_cert_chain: str | None = None


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
    # AARM R2: digest of the issuer-signed declared intent (agent-manifest spec
    # 3.9), or None when the issuer declared none. The digest, never the
    # statement: this claim is built to be shared, and an intent statement is
    # business context.
    intent_hash: str | None = None
    # #425: RFC 7638 JWK thumbprint of the agent's own signing key, "sha256:<hex>".
    # Distinct from issuer_key_id (the key that signed the manifest). Always None
    # today: no code path supplies agent key bytes, and it must never be set while
    # subject_source is a non-live-authenticated source (config, manifest-dev) - see
    # AgentIdentityOut for the full contract.
    agent_key_thumbprint: str | None = None
    enforcement_mode: str | None = None


# ── Pydantic output models ─────────────────────────────────────────────────────



#: The largest integer RFC 8785 (I-JSON) serializes exactly.
MAX_SAFE_INTEGER = 2**53 - 1


def _json_integer(value: Any) -> Any:
    # JSON Schema's integer is any number with no fractional part, so 1.0 counts;
    # a bool or a string never does (strict mode refuses those).
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _safe_integer(value: int) -> int:
    if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        raise ValueError("integer outside the RFC 8785 safe range")
    return value


class NullMemberError(ValueError):
    """A claim member that is null; ``path`` names it for diagnostics."""

    def __init__(self, path: str) -> None:
        super().__init__(f"null at {path}: leave the member out instead")
        self.path = path


#: Free-form evidence the JSON Schema leaves open, nulls included.
_FREE_FORM = ("gateway", "call_summary", "call_graph_summary", "cross_boundary_events")


#: Deeper than any claim nests: a claim is about six levels deep. The bound keeps
#: an untrusted object graph from exhausting the recursion of later steps.
_MAX_DEPTH = 64
#: Values walked again because a container is shared by more than one member.
#: JSON parsed from text never shares, so this only limits a native object graph,
#: whose serialized form repeats each shared container: [x, x] nested n deep is
#: n + 1 objects and 2**(n + 1) values. Unshared values are not limited.
_MAX_REPEATED_VALUES = 10_000


class ClaimShapeError(ValueError):
    """A claim that is not a JSON document: a member contains itself, nests too
    deeply, or is not a JSON value. ``path`` names the member for diagnostics."""

    def __init__(self, path: str, problem: str) -> None:
        super().__init__(f"{path or 'the claim'} {problem}")
        self.path = path


def _json_value_error(node: Any) -> str | None:
    """Why a leaf is not a JSON value, or None."""
    if node is None or isinstance(node, (bool, int, str)):
        return None
    if isinstance(node, float):
        return None if math.isfinite(node) else f"is {node}, which JSON cannot hold"
    return f"is a {type(node).__name__}, not a JSON value"


def _walk(value: Any, *, nulls: bool, json_only: bool) -> str | None:
    """Check that *value* is a JSON tree; with *nulls*, also return the first
    member that is null outside the free-form evidence; with *json_only*, also
    that every member name is a string and every value a JSON value.

    Walks iteratively, so no input can exhaust the stack. A container met again
    on its own path is a cycle, which JSON cannot express; one shared between
    two places is not, and is walked at each, as its JSON form repeats it.
    Raises ClaimShapeError for a cycle, nesting deeper than _MAX_DEPTH, more
    than _MAX_REPEATED_VALUES values walked again through shared containers, or
    (with *json_only*) a value JSON cannot hold, free-form evidence included.
    """
    # (node, path, inside free-form evidence, inside a repeat, leaving): leaving
    # entries take a container off the active path once its children are done;
    # "inside a repeat" marks values under a container already walked once.
    stack: list[tuple[Any, tuple[str, ...], bool, bool, bool]] = [
        (value, (), False, False, False)
    ]
    active: set[int] = set()
    seen: set[int] = set()
    repeated = 0
    while stack:
        node, path, free, repeat, leaving = stack.pop()
        if leaving:
            active.discard(id(node))
            continue
        container = isinstance(node, (dict, list, tuple))
        repeat = repeat or (container and id(node) in seen)
        if repeat:
            repeated += 1
            if repeated > _MAX_REPEATED_VALUES:
                raise ClaimShapeError(
                    ".".join(path),
                    f"shares containers past {_MAX_REPEATED_VALUES} repeated values",
                )
        if nulls and node is None and path and not free:
            return ".".join(path)
        if isinstance(node, dict):
            if json_only and not all(isinstance(k, str) for k in node):
                raise ClaimShapeError(".".join(path), "has a member name that is not a string")
            children: list[tuple[str, Any]] = [(str(k), v) for k, v in node.items()]
        elif isinstance(node, (list, tuple)):  # a tuple serializes as the array it is
            children = [(str(i), v) for i, v in enumerate(node)]
        else:
            problem = _json_value_error(node) if json_only else None
            if problem:
                raise ClaimShapeError(".".join(path), problem)
            continue
        if id(node) in active:
            raise ClaimShapeError(".".join(path), "contains itself")
        if len(path) >= _MAX_DEPTH:
            raise ClaimShapeError(".".join(path), f"nests deeper than {_MAX_DEPTH} levels")
        active.add(id(node))
        seen.add(id(node))
        stack.append((node, path, free, repeat, True))
        inner = free or path == _FREE_FORM
        # Reversed, so members are visited in order and the first null is found first.
        stack.extend(
            (child, (*path, key), inner, repeat, False) for key, child in reversed(children)
        )
    return None


def _null_path(value: Any) -> str | None:
    """The first member that is null, outside the free-form evidence, or None.
    Leaves are not type-checked here: the model validates them, and the gateway
    builds claims from model objects rather than JSON."""
    return _walk(value, nulls=True, json_only=False)


def check_json_tree(value: Any) -> None:
    """Raise ClaimShapeError unless *value* is a JSON document: a tree with no
    container that contains itself, nesting no deeper than _MAX_DEPTH, at most
    _MAX_REPEATED_VALUES values repeated through shared containers, string member
    names, and only JSON values (finite numbers) at its leaves."""
    _walk(value, nulls=False, json_only=True)


def _has_unsafe_integer(value: Any) -> bool:
    """Any number with no fractional part beyond the safe range, at any depth.

    Iterative, and each container is looked at once, so a cycle ends the walk.
    """
    stack = [value]
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if isinstance(node, (dict, list)):
            if id(node) not in seen:
                seen.add(id(node))
                stack.extend(node.values() if isinstance(node, dict) else node)
            continue
        if isinstance(node, bool) or not isinstance(node, (int, float)):
            continue
        if isinstance(node, float) and not node.is_integer():
            continue
        if abs(node) > MAX_SAFE_INTEGER:
            return True
    return False


#: An integer as the JSON Schema reads it, within the safe range for every version.
JsonInt = Annotated[int, BeforeValidator(_json_integer), AfterValidator(_safe_integer)]


class ClaimBuildProvenance(BuildProvenance):
    """``slsa_level`` decided as the schema decides it, with any agentrust-trace
    installed: 0.11.0 turns the string ``"1"`` into ``1``, which the published
    claim schema rejects, so a verifier would report a schema check it failed."""

    model_config = ConfigDict(extra="forbid", strict=True)

    slsa_level: Annotated[JsonInt, Field(ge=0, le=3)]
Count = Annotated[JsonInt, Field(ge=0)]


class CallGraphOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    compliance_domains_touched: list[str]
    cross_boundary_events: list[dict[str, Any]]
    #: Clarifies that edges are temporal adjacency, not data provenance (issue #94).
    edges_represent: str | None = None


class CallSummaryOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tool_calls_total: Count
    tool_calls_allowed: Count
    tool_calls_denied: Count
    tool_calls_faulted: Count
    tools_invoked: list[str]
    session_max_sensitivity: str
    call_graph_summary: CallGraphOut


class AuditChainSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    root: str
    tip: str
    length: Count


class CatalogSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    hash: Annotated[str, Field(pattern=r"^sha(256|384):[0-9a-f]+")]
    drift_detected: bool


class AgentIdentityOut(BaseModel):
    """gateway.agent_identity: the Agent Manifest binding for this session.

    agent_key_thumbprint (#425): RFC 7638 JWK thumbprint of the agent's own signing
    key, rendered as "sha256:<hex>" - see tee/base.py's jwk_thumbprint() for the
    reference pre-image (canonical JSON of the OKP {crv, kty, x} members). Optional
    and, as of this field's introduction, always None: no runtime code path has
    agent key bytes to hash yet. A future producer of this field MUST only set it
    when subject_source names a live-authenticated source (currently just "svid"),
    never "config" or "manifest-dev" - cmcp_verify.verify_trace_claim fails closed
    on any claim that violates this.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    manifest_id: str
    agent_id: Annotated[str, Field(pattern=r"^spiffe://")]
    authenticated_subject: Annotated[str, Field(pattern=r"^spiffe://")]
    subject_source: AgentSubjectSource
    issuer: Annotated[str, Field(pattern=r"^spiffe://")]
    issuer_key_id: str
    policy_bundle_hash: str
    tool_catalog_hash: str
    intent_hash: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")] | None = None
    agent_key_thumbprint: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")] | None = None
    enforcement_mode: str | None = None


_KEY_ID = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class PolicySigningOut(BaseModel):
    """gateway.policy_signing: which policy signing key the policy in force at
    claim time verified under, and which keys this gateway process has revoked.

    Emitted only where a policy signing key is pinned. With ``key_id`` in
    ``revoked_key_ids`` the claim records a session whose tool calls were refused
    because the policy in force had lost its signer.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    key_id: _KEY_ID | None = None
    revoked_key_ids: list[_KEY_ID] = Field(default_factory=list)


class ToolTranscriptEntry(BaseModel):
    """One privacy-preserving entry in the bound tool transcript (issue #126).

    Derived from the audit chain, never from raw tool-call parameters or response
    bodies: it carries only the tool name, the data class the call touched, and the
    policy decision. No request/response payloads, so the transcript leaks no PII.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    tool_name: str
    data_class: str
    decision: Literal["allow", "deny", "redact", "advisory_deny", "fault", "n/a"]


class ToolTranscriptOut(BaseModel):
    """cmcp tool_transcript: the canonical TRACE fields. ``hash`` binds the full
    transcript to the audit chain tip.

    ``entries`` is only read from 1.0 claims. From 1.1 the per-call trail
    (issue #126) lives in ``gateway.transcript_entries``, outside the TRACE block.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    hash: Annotated[str, Field(pattern=r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")]
    call_count: Count | None = None
    transcript_uri: str | None = None
    entries: list[ToolTranscriptEntry] | None = None


class GatewayTrace(BaseModel):
    """Phase 1 TRACE fields applicable to the cmcp runtime context."""

    model_config = ConfigDict(extra="forbid", strict=True)

    eat_profile: Literal["tag:agentrust-io.com,2026:trace-v0.2"]
    iat: Annotated[JsonInt, Field(ge=1700000000)]
    subject: Annotated[str, Field(pattern=r"^spiffe://")]
    runtime: RuntimeInfo
    policy: PolicyInfo
    data_class: str
    tool_transcript: ToolTranscriptOut | None = None
    cnf: ConfirmationKey
    # 1.1 only. ``model`` stays absent until the gateway sees model calls, and
    # ``build_provenance`` until it has measured its own code.
    model: ModelInfo | None = None
    build_provenance: ClaimBuildProvenance | None = None
    appraisal: Appraisal | None = None


class CallLogSummary(BaseModel):
    """Per-session call log summary included in the gateway addenda."""

    model_config = ConfigDict(extra="forbid", strict=True)

    total_calls: Count
    tools_called: list[str]
    suspicious_sequences_detected: Count


class AttestationEvidence(BaseModel):
    """Signed platform evidence, base64, carried in the cmcp envelope.

    This does not live under ``trace.runtime`` because ``RuntimeInfo`` belongs to
    agentrust-trace and is ``extra="forbid"`` -- a claim carrying evidence there
    is rejected as CLAIM_MALFORMED before platform verification runs, which is
    what kept the chain verifiers unreachable (#370). ``GatewayAddenda`` is
    cmcp's own model and is the documented home for fields outside the canonical
    TRACE spec, so the evidence rides here instead.

    Every field is optional: evidence predating these fields, and platforms whose
    report carries its own signature envelope, degrade to ``unverified`` rather
    than erroring.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    raw_evidence: str | None = None  # the exact bytes the platform signed
    quote_signature: str | None = None  # marshalled TPMT_SIGNATURE (TPM)
    cert_chain: str | None = None  # leaf-first PEM: AK/VCEK -> ... -> root
    ek_cert_chain: str | None = None  # EK's own path to the manufacturer CA


class KillSwitchState(BaseModel):
    """What the kill switch was set to do for this session, and what it did.

    Present only when the kill switch is enabled, so claims from gateways
    without it are byte-identical to what they were before this field existed.
    A verifier that requires an armed kill switch checks for its presence.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    enabled: bool
    window_seconds: Annotated[JsonInt, Field(ge=1)]
    deny_rate_threshold: Annotated[float, Field(gt=0, le=1)]
    min_calls: Annotated[JsonInt, Field(ge=1)]
    #: What stopped the session: "deny_rate" when the threshold was crossed,
    #: "operator" when an operator tripped it. None when it did not trip.
    trigger: Literal["deny_rate", "operator"] | None = None


#: Required TRACE fields a 1.1 claim may leave out, in ``trace_omitted`` order.
TraceOmitted = Literal["model", "build_provenance"]
_OMITTABLE: tuple[TraceOmitted, ...] = ("model", "build_provenance")


class GatewayAddenda(BaseModel):
    """cmcp-specific fields outside the canonical TRACE spec."""

    model_config = ConfigDict(extra="forbid", strict=True)

    session_id: str
    gateway_version: str
    sequence_number: Annotated[JsonInt, Field(ge=1)]  # AUDIT-005: monotonically increasing across all claims from this instance
    prev_claim_hash: str | None = None  # AUDIT-005: sha256 of previous claim's canonical JSON
    audit_chain: AuditChainSummary
    call_summary: CallSummaryOut
    catalog: CatalogSummary
    attestation_generated_at: str
    attestation_validity_seconds: Count
    attestation_stale: bool
    catalog_exceptions: list[dict[str, str]]
    call_log_summary: CallLogSummary | None = None
    agent_identity: AgentIdentityOut | None = None
    kill_switch_triggered: bool = False
    kill_switch: KillSwitchState | None = None
    attestation_evidence: AttestationEvidence | None = None
    policy_signing: PolicySigningOut | None = None
    # 1.1 only: the per-call trail, and the required TRACE fields the gateway
    # left out because it did not observe them.
    transcript_entries: list[ToolTranscriptEntry] | None = None
    trace_omitted: list[TraceOmitted] | None = None


ClaimVersion = Literal["1.0", "1.1"]
#: Claim format the gateway emits. 1.1 signs over RFC 8785 (JCS) and signs only
#: observed TRACE fields; 1.0 claims are still read and verified.
CLAIM_VERSION: ClaimVersion = "1.1"


class RuntimeClaim(BaseModel):
    """cmcp TRACE profile - canonical trust fields nested inside a gateway envelope."""

    model_config = ConfigDict(extra="forbid", strict=True)

    # Required, never defaulted: it selects the bytes the signature covers.
    cmcp_version: ClaimVersion
    trace: GatewayTrace
    gateway: GatewayAddenda
    signature: str

    @model_validator(mode="before")
    @classmethod
    def _no_null(cls, data: Any) -> Any:
        # JSON Schema allows null nowhere in a claim but inside free-form events,
        # and the producer leaves absent members out, so null is never a value.
        if isinstance(data, dict):
            where = _null_path(data)
            if where:
                raise NullMemberError(where)
        return data

    @model_validator(mode="after")
    def _shape_matches_version(self) -> RuntimeClaim:
        trace, gateway = self.trace, self.gateway
        transcript = trace.tool_transcript
        if self.cmcp_version == "1.0":
            if any(
                v is not None
                for v in (
                    trace.model,
                    trace.build_provenance,
                    trace.appraisal,
                    gateway.transcript_entries,
                    gateway.trace_omitted,
                )
            ):
                raise ValueError("1.0 claims carry none of the 1.1 fields")
            return self
        if transcript is not None and transcript.entries is not None:
            raise ValueError("1.1 claims carry transcript entries in gateway.transcript_entries")
        if trace.appraisal is None or gateway.trace_omitted is None:
            raise ValueError("1.1 claims need trace.appraisal and gateway.trace_omitted")
        # A set: order carries no meaning, a repeat is refused.
        missing = {name for name in _OMITTABLE if getattr(trace, name) is None}
        omitted = gateway.trace_omitted
        if len(set(omitted)) != len(omitted) or set(omitted) != missing:
            raise ValueError("gateway.trace_omitted must list exactly the omitted TRACE fields")
        # The signature covers the RFC 8785 form, so a 1.1 claim must have one:
        # integers within +-(2**53 - 1), finite numbers, valid Unicode.
        body = self.model_dump(exclude_none=True)
        body.pop("signature", None)
        try:
            rfc8785.dumps(body)
        except rfc8785.CanonicalizationError as exc:
            raise ValueError(f"1.1 claims need an RFC 8785 canonical form: {exc}") from exc
        if _has_unsafe_integer(body):
            # rfc8785 serializes a float such as 1e20, but the JSON Schema reads any
            # number with no fraction as an integer and bounds it, so refuse it too.
            raise ValueError("1.1 claims need integers within the RFC 8785 safe range")
        return self


# ── Serialization and signing ──────────────────────────────────────────────────


def _to_dict(claim: RuntimeClaim) -> dict[str, Any]:
    return claim.model_dump(exclude_none=True)


#: ``type`` of the signed receipt a gateway returns when the kill switch refuses a call.
REFUSAL_RECEIPT_TYPE = "cmcp.kill-switch.refusal/v1"


def canonical_json(claim_dict: dict[str, Any]) -> bytes:
    """Canonical serialization for signing, without the 'signature' field.

    A 1.1 claim uses RFC 8785 (JCS), as TRACE verifiers do. A 1.0 claim, and a
    document with no ``cmcp_version`` such as a refusal receipt, keep the 1.0
    form (sorted keys, ASCII escapes), so they still verify. Any other version
    is refused rather than given bytes it was never signed over.
    """
    body = {k: v for k, v in claim_dict.items() if k != "signature"}
    version = claim_dict.get("cmcp_version")
    if version == "1.1":
        return rfc8785.dumps(body)
    if version not in (None, "1.0"):
        raise ValueError(f"unsupported cmcp_version {version!r}")
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def sign_trace_claim(claim: RuntimeClaim, signing_key: Any) -> str:
    """Sign the RuntimeClaim with the TEE-sealed Ed25519 private key.

    Returns base64url-encoded signature (no padding).
    """
    claim_dict = _to_dict(claim)
    body = canonical_json(claim_dict)
    raw_sig = signing_key.sign(body)
    return base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()


# ── Builder helpers ────────────────────────────────────────────────────────────


def _build_evidence(report: AttestationReportInfo) -> AttestationEvidence | None:
    """Collect the signed evidence, or None when the report carries none.

    Returning None keeps it out of the serialized claim entirely (the claim is
    dumped with ``exclude_none``), so software-only and evidence-less claims are
    byte-identical to what they were before this field existed.
    """
    if not any(
        (report.raw_evidence, report.quote_signature, report.cert_chain, report.ek_cert_chain)
    ):
        return None
    return AttestationEvidence(
        raw_evidence=report.raw_evidence,
        quote_signature=report.quote_signature,
        cert_chain=report.cert_chain,
        ek_cert_chain=report.ek_cert_chain,
    )


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


_ENFORCEMENT_MODE_MAP = {"enforcing": "enforce", "advisory": "advisory", "silent": "silent"}


def _build_policy(bundle: PolicyBundleInfo) -> PolicyInfo:
    # Every mode the claim can carry asserts that something evaluated the policy.
    # An unrecognised value is refused rather than signed as one of them, the
    # same way _build_runtime refuses an unknown provider (AUDIT-003).
    mode = _ENFORCEMENT_MODE_MAP.get(bundle.enforcement_mode)
    if mode is None:
        raise ValueError(
            f"Enforcement mode {bundle.enforcement_mode!r} is not in the allowed set "
            f"{sorted(_ENFORCEMENT_MODE_MAP)}. "
            "Rejecting claim construction rather than signing a policy posture "
            "that was never evaluated."
        )
    return PolicyInfo(
        bundle_hash=bundle.hash,
        enforcement_mode=mode,  # type: ignore[arg-type]
        version=bundle.policy_version,
    )


def _build_policy_signing(bundle: PolicyBundleInfo) -> PolicySigningOut | None:
    """None where no policy signing key is pinned, which keeps those claims
    byte-identical to what they were before this field existed."""
    if bundle.signing_key_id is None and not bundle.revoked_signing_key_ids:
        return None
    return PolicySigningOut(
        key_id=bundle.signing_key_id,
        revoked_key_ids=list(bundle.revoked_signing_key_ids),
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
    kill_switch: KillSwitchState | None = None,
    gateway_code_digest: str | None = None,
    do_sign: bool = True,
) -> RuntimeClaim:
    """Generate a RuntimeClaim from session data, validate it via Pydantic, and optionally sign it.

    signing_key must be a SigningKey instance (audit/keys.py) - it is always required
    to build the JWK confirmation key in trace.cnf.  Set do_sign=False to produce an
    unsigned claim (e.g. in tests).

    The claim signs only what the gateway observed. ``model`` is always left out
    (the gateway never sees model calls), ``build_provenance`` is left out unless
    *gateway_code_digest* (the measured code, hex) is given, and both are named
    in ``gateway.trace_omitted``. ``appraisal`` says no appraisal was made.
    """
    tool_transcript_hash = (
        audit_chain_tip
        if audit_chain_tip.startswith(("sha256:", "sha384:"))
        else f"sha256:{audit_chain_tip}"
    )

    subject = _build_subject(signing_key)
    # Members the gateway did not observe are left out, never sent as null.
    measured: dict[str, Any] = {}
    if gateway_code_digest is not None:
        # SLSA level 0: the code was measured, its build was not attested.
        measured["build_provenance"] = ClaimBuildProvenance(
            slsa_level=0, digest=f"sha256:{gateway_code_digest}"
        )
    trace = GatewayTrace(
        eat_profile="tag:agentrust-io.com,2026:trace-v0.2",
        iat=int(datetime.now(tz=UTC).timestamp()),
        subject=subject,
        runtime=_build_runtime(attestation_report),
        policy=_build_policy(policy_bundle),
        data_class=call_summary.session_max_sensitivity,
        tool_transcript=ToolTranscriptOut(
            hash=tool_transcript_hash,
            call_count=call_summary.tool_calls_total,
        ),
        cnf=_build_cnf(signing_key),
        appraisal=Appraisal(status="none", verifier=subject),
        **measured,
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
        kill_switch=kill_switch,
        attestation_evidence=_build_evidence(attestation_report),
        policy_signing=_build_policy_signing(policy_bundle),
        **({} if transcript_entries is None else {"transcript_entries": transcript_entries}),
        trace_omitted=[name for name in _OMITTABLE if getattr(trace, name) is None],
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
                intent_hash=agent_identity.intent_hash,
                agent_key_thumbprint=agent_identity.agent_key_thumbprint,
                enforcement_mode=agent_identity.enforcement_mode,
            )
            if agent_identity is not None
            else None
        ),
    )

    claim = RuntimeClaim(cmcp_version=CLAIM_VERSION, trace=trace, gateway=gateway, signature="")

    if do_sign:
        claim.signature = sign_trace_claim(claim, signing_key)

    return claim
