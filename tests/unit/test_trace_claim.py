"""Tests for TRACE Claim generation and signing (cmcp TRACE profile)."""

from __future__ import annotations

import base64
import json

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    RuntimeClaim,
    ToolCatalogInfo,
    _to_dict,
    canonical_json,
    generate_trace_claim,
)


def _make_report() -> AttestationReportInfo:
    return AttestationReportInfo(
        provider="software-only",
        measurement="DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION",
        report_data="aa" * 32,
        attestation_generated_at="2026-06-04T00:00:00+00:00",
        attestation_validity_seconds=86400,
    )


def _make_call_summary() -> CallSummary:
    return CallSummary(
        tool_calls_total=2,
        tool_calls_allowed=1,
        tool_calls_denied=1,
        tool_calls_faulted=0,
        tools_invoked=["crm.query"],
        session_max_sensitivity="pii",
        call_graph_summary=CallGraphSummary(
            compliance_domains_touched=["pii"],
            cross_boundary_events=[],
        ),
    )


def _make_claim(signing_key: SigningKey | None = None) -> RuntimeClaim:
    key = signing_key or SigningKey()
    sign = signing_key is not None
    chain = AuditChain("sess-001")
    return generate_trace_claim(
        session_id="sess-001",
        signing_key=key,
        attestation_report=_make_report(),
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "0" * 64,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "1" * 64),
        call_summary=_make_call_summary(),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        do_sign=sign,
    )


# ── canonical_json ────────────────────────────────────────────────────────────


def test_canonical_json_is_deterministic():
    d = {"b": 2, "a": 1, "signature": "sig"}
    assert canonical_json(d) == canonical_json(d)


def test_canonical_json_excludes_signature():
    d = {"a": 1, "signature": "should-be-excluded"}
    result = json.loads(canonical_json(d))
    assert "signature" not in result
    assert "a" in result


def test_canonical_json_sorted_keys():
    d = {"z": 3, "a": 1, "m": 2}
    result = canonical_json(d).decode()
    assert result.index('"a"') < result.index('"m"') < result.index('"z"')


# ── generate_trace_claim ──────────────────────────────────────────────────────


def test_generate_claim_version():
    claim = _make_claim()
    assert claim.cmcp_version == "1.0"


def test_generate_claim_RUNTIME_VERSION():
    """CONF-006: gateway_version must appear in GatewayAddenda."""
    claim = _make_claim()
    assert isinstance(claim.gateway.gateway_version, str)
    assert len(claim.gateway.gateway_version) > 0


def test_generate_claim_RUNTIME_VERSION_is_string_or_unknown():
    """CONF-006: gateway_version is a non-empty string; 'unknown' is the valid fallback."""
    from cmcp_runtime.audit.trace_claim import _RUNTIME_VERSION
    assert isinstance(_RUNTIME_VERSION, str)
    assert len(_RUNTIME_VERSION) > 0



# ── AUDIT-005: sequence_number and prev_claim_hash ────────────────────────────


def test_generate_claim_sequence_number_default():
    """AUDIT-005: sequence_number defaults to 1."""
    claim = _make_claim()
    assert claim.gateway.sequence_number == 1


def test_generate_claim_sequence_number_custom():
    """AUDIT-005: sequence_number is included in the claim."""
    key = SigningKey()
    chain = AuditChain("sess-001")
    claim = generate_trace_claim(
        session_id="sess-001",
        signing_key=key,
        attestation_report=_make_report(),
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "0" * 64,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "1" * 64),
        call_summary=_make_call_summary(),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        sequence_number=7,
        do_sign=False,
    )
    assert claim.gateway.sequence_number == 7


def test_generate_claim_prev_claim_hash_default_none():
    """AUDIT-005: prev_claim_hash is None when not provided."""
    claim = _make_claim()
    assert claim.gateway.prev_claim_hash is None


def test_generate_claim_prev_claim_hash_set():
    """AUDIT-005: prev_claim_hash is included when provided."""
    key = SigningKey()
    chain = AuditChain("sess-001")
    prev_hash = "sha256:" + "a" * 64
    claim = generate_trace_claim(
        session_id="sess-001",
        signing_key=key,
        attestation_report=_make_report(),
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "0" * 64,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "1" * 64),
        call_summary=_make_call_summary(),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        prev_claim_hash=prev_hash,
        do_sign=False,
    )
    assert claim.gateway.prev_claim_hash == prev_hash


def test_generate_claim_session_id():
    claim = _make_claim()
    assert claim.gateway.session_id == "sess-001"


def test_generate_claim_cnf_jwk():
    key = SigningKey()
    claim = _make_claim(signing_key=key)
    assert claim.trace.cnf.jwk.kty == "OKP"
    assert claim.trace.cnf.jwk.crv == "Ed25519"
    assert claim.trace.cnf.jwk.x is not None
    # JWK x must decode to the same bytes as the public key
    x_b64 = claim.trace.cnf.jwk.x + "=="
    assert base64.urlsafe_b64decode(x_b64) == bytes.fromhex(key.public_key_hex)


def test_generate_claim_unsigned_has_empty_signature():
    claim = _make_claim(signing_key=None)
    assert claim.signature == ""


def test_generate_claim_signed_has_signature():
    key = SigningKey()
    claim = _make_claim(signing_key=key)
    assert len(claim.signature) > 0


def test_generate_claim_signature_verifiable():
    """TRACE-002 - signature verifies against trace.cnf.jwk."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = SigningKey()
    claim = _make_claim(signing_key=key)

    claim_dict = _to_dict(claim)
    body = canonical_json(claim_dict)
    sig_bytes = base64.urlsafe_b64decode(claim.signature + "==")

    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex))
    pub.verify(sig_bytes, body)  # raises InvalidSignature if wrong


def test_generate_claim_tee_key_consistent_in_session():
    """ATTEST-003 - same JWK across all claims produced with the same signing key."""
    key = SigningKey()
    c1 = _make_claim(signing_key=key)
    c2 = _make_claim(signing_key=key)
    assert c1.trace.cnf.jwk.x == c2.trace.cnf.jwk.x


def test_generate_claim_audit_chain_fields():
    chain = AuditChain("sess-002")
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
    key = SigningKey()
    claim = generate_trace_claim(
        session_id="sess-002",
        signing_key=key,
        attestation_report=_make_report(),
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "0" * 64,
            enforcement_mode="advisory",
            policy_version="0.1",
        ),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "1" * 64),
        call_summary=_make_call_summary(),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        do_sign=False,
    )
    assert claim.gateway.audit_chain.root == chain.chain_root
    assert claim.gateway.audit_chain.tip == chain.chain_tip
    assert claim.gateway.audit_chain.length == 2  # session_start + tool_call


def test_generate_claim_enforcement_mode_mapped():
    """'enforcing' in PolicyBundleInfo maps to 'enforce' in the canonical TRACE field."""
    key = SigningKey()
    chain = AuditChain("sess-001")
    claim = generate_trace_claim(
        session_id="sess-001",
        signing_key=key,
        attestation_report=_make_report(),
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "0" * 64,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "1" * 64),
        call_summary=_make_call_summary(),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        do_sign=False,
    )
    assert claim.trace.policy.enforcement_mode == "enforce"


def test_generate_claim_software_only_platform():
    """software-only provider gets its own platform value, never tpm2."""
    claim = _make_claim()
    assert claim.trace.runtime.platform == "software-only"
    assert claim.trace.runtime.firmware_version == "software-only-dev-mode"


# ── RuntimeClaim Pydantic validation ─────────────────────────────────────────


def test_gateway_claim_roundtrips_through_dict():
    """RuntimeClaim serializes and re-validates cleanly."""
    claim = _make_claim()
    d = _to_dict(claim)
    RuntimeClaim.model_validate(d)


def test_to_dict_includes_signature_field():
    """signature="" must appear in serialized dict even when empty."""
    claim = _make_claim(signing_key=None)
    d = _to_dict(claim)
    assert "signature" in d
    assert d["signature"] == ""


# ── CRYPTO-003: nonce binding ─────────────────────────────────────────────────


def test_build_runtime_valid_report_data_produces_nonce():
    """CRYPTO-003: valid hex report_data must produce a nonce in RuntimeInfo."""
    from cmcp_runtime.audit.trace_claim import AttestationReportInfo, _build_runtime
    report = AttestationReportInfo(
        provider="sev-snp",
        measurement="sha256:" + "a" * 64,
        report_data="deadbeef" * 8,  # valid hex
        attestation_generated_at="2026-06-06T00:00:00+00:00",
        attestation_validity_seconds=86400,
    )
    runtime = _build_runtime(report)
    assert runtime.nonce is not None


def test_build_runtime_malformed_report_data_raises():
    """CRYPTO-003: malformed report_data must raise ValueError, not set nonce=None."""
    import pytest

    from cmcp_runtime.audit.trace_claim import AttestationReportInfo, _build_runtime
    report = AttestationReportInfo(
        provider="sev-snp",
        measurement="sha256:" + "a" * 64,
        report_data="not-hex!!",
        attestation_generated_at="2026-06-06T00:00:00+00:00",
        attestation_validity_seconds=86400,
    )
    with pytest.raises(ValueError, match="malformed report_data"):
        _build_runtime(report)


# ── AUDIT-003: unknown provider rejected ──────────────────────────────────────


def test_build_runtime_unknown_provider_raises():
    """AUDIT-003: unknown attestation provider must be rejected, not silently accepted."""
    import pytest

    from cmcp_runtime.audit.trace_claim import AttestationReportInfo, _build_runtime
    report = AttestationReportInfo(
        provider="unknown-cloud-magic",
        measurement="sha256:" + "a" * 64,
        report_data="aa" * 32,
        attestation_generated_at="2026-06-06T00:00:00+00:00",
        attestation_validity_seconds=86400,
    )
    with pytest.raises(ValueError, match="not in the allowed set"):
        _build_runtime(report)


def test_build_runtime_all_known_providers_accepted():
    """AUDIT-003: every provider in the allowed set must succeed without raising."""
    from cmcp_runtime.audit.trace_claim import (
        _PROVIDER_MAP,
        AttestationReportInfo,
        _build_runtime,
    )
    for provider in _PROVIDER_MAP:
        report = AttestationReportInfo(
            provider=provider,
            measurement="sha256:" + "a" * 64,
            report_data="aa" * 32,
            attestation_generated_at="2026-06-06T00:00:00+00:00",
            attestation_validity_seconds=86400,
        )
        _build_runtime(report)  # must not raise


# ── tool_transcript entries (#126) ──────────────────────────────────────────────


def _three_entries() -> list:
    from cmcp_runtime.audit.trace_claim import ToolTranscriptEntry

    return [
        ToolTranscriptEntry(tool_name="document_reader", data_class="confidential", decision="allow"),
        ToolTranscriptEntry(tool_name="credit_score_lookup", data_class="confidential", decision="allow"),
        ToolTranscriptEntry(tool_name="risk_report_writer", data_class="internal", decision="advisory_deny"),
    ]


def _claim_with_entries() -> RuntimeClaim:
    chain = AuditChain("sess-126")
    return generate_trace_claim(
        session_id="sess-126",
        signing_key=SigningKey(),
        attestation_report=_make_report(),
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "0" * 64, enforcement_mode="enforcing", policy_version="1.0.0"
        ),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "1" * 64),
        call_summary=_make_call_summary(),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        transcript_entries=_three_entries(),
        do_sign=False,
    )


def test_transcript_entries_present_and_ordered():
    claim = _claim_with_entries()
    entries = claim.trace.tool_transcript.entries
    assert entries is not None
    assert [e.tool_name for e in entries] == [
        "document_reader",
        "credit_score_lookup",
        "risk_report_writer",
    ]
    assert [e.decision for e in entries] == ["allow", "allow", "advisory_deny"]


def test_transcript_hash_is_audit_chain_tip():
    """Acceptance #1: tool_transcript.hash binds to the audit chain tip."""
    chain = AuditChain("sess-126")
    claim = generate_trace_claim(
        session_id="sess-126",
        signing_key=SigningKey(),
        attestation_report=_make_report(),
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "0" * 64, enforcement_mode="enforcing", policy_version="1.0.0"
        ),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "1" * 64),
        call_summary=_make_call_summary(),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        transcript_entries=_three_entries(),
        do_sign=False,
    )
    assert claim.trace.tool_transcript.hash == f"sha256:{chain.chain_tip}"
    assert claim.gateway.audit_chain.tip == chain.chain_tip


def test_transcript_entries_carry_no_payloads():
    """Privacy: serialized entries expose only tool_name, data_class, decision."""
    claim = _claim_with_entries()
    dumped = claim.model_dump(exclude_none=True)
    for entry in dumped["trace"]["tool_transcript"]["entries"]:
        assert set(entry.keys()) == {"tool_name", "data_class", "decision"}


def test_transcript_entries_hash_roundtrip():
    """A verifier can recompute the entries digest offline."""
    from cmcp_runtime.audit.trace_claim import transcript_entries_hash

    entries = _three_entries()
    h = transcript_entries_hash(entries)
    assert h.startswith("sha256:")
    assert transcript_entries_hash(entries) == h
    # A different decision changes the digest (tamper-evident).
    entries[2].decision = "allow"
    assert transcript_entries_hash(entries) != h


def test_transcript_entries_optional():
    """call_count is still set when no entries are supplied (backward compatible)."""
    claim = _make_claim()
    assert claim.trace.tool_transcript.entries is None
    assert claim.trace.tool_transcript.call_count == 2
