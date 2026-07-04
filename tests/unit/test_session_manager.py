"""Unit tests for SessionManager (issues #60 and #55)."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from cmcp_runtime.agent_manifest import AgentManifestBinding
from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.session.manager import SessionManager
from cmcp_runtime.session.state import SessionState

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_attestation_report(*, stale: bool = False) -> MagicMock:
    """Return a mock AttestationReport with software-only provider values."""
    report = MagicMock()
    report.provider = "software-only"
    report.measurement = "DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION"
    report.report_data = "aa" * 32
    report.raw_evidence = None
    report.measurement_note = "software-only mode: not hardware-backed"
    report.attestation_validity_seconds = 86400
    if stale:
        # Set generated_at far in the past so the report is expired.
        report.attestation_generated_at = datetime(2020, 1, 1, tzinfo=UTC)
    else:
        report.attestation_generated_at = datetime.now(UTC)
    return report


def _make_ctx(*, stale_attestation: bool = False) -> MagicMock:
    """Return a fully-wired mock RuntimeContext."""
    signing_key = SigningKey()

    policy_bundle = MagicMock()
    policy_bundle.bundle.bundle_hash = "sha256:" + "a" * 64
    policy_bundle.bundle.manifest.version = "1.0.0"

    catalog_entry = MagicMock()
    catalog_entry.compliance_domain = "external"
    catalog_entry.catalog_exception = False

    catalog = MagicMock()
    catalog.catalog_hash = "sha256:" + "b" * 64
    catalog.entries = {}

    config = MagicMock()
    config.attestation.enforcement_mode = "enforcing"

    ctx = MagicMock()
    ctx.signing_key = signing_key
    ctx.attestation_report = _make_attestation_report(stale=stale_attestation)
    ctx.policy_bundle = policy_bundle
    ctx.catalog = catalog
    ctx.config = config
    tee_provider = MagicMock()
    tee_provider.get_attestation_report.return_value = MagicMock()
    ctx.tee_provider = tee_provider
    ctx.agent_manifest = None
    return ctx


# ── create_session ─────────────────────────────────────────────────────────────


def test_create_session_returns_state_and_chain() -> None:
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    assert isinstance(state, SessionState)
    assert isinstance(chain, AuditChain)


def test_create_session_ids_match() -> None:
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    assert state.session_id == chain.entries[0].session_id


def test_create_session_produces_unique_ids() -> None:
    mgr = SessionManager(_make_ctx())
    state1, _ = mgr.create_session()
    state2, _ = mgr.create_session()
    assert state1.session_id != state2.session_id


def test_create_session_chain_has_session_start() -> None:
    mgr = SessionManager(_make_ctx())
    _, chain = mgr.create_session()
    assert chain.entries[0].entry_type == "session_start"


def test_create_session_carries_agent_manifest_binding() -> None:
    ctx = _make_ctx()
    ctx.agent_manifest = AgentManifestBinding(
        manifest_id="0197739a-8c00-7000-8000-000000000001",
        agent_id="spiffe://factory.example/agent/material-movement/dev",
        authenticated_subject="spiffe://factory.example/agent/material-movement/dev",
        subject_source="config",
        issuer="spiffe://factory.example/signing-authority/development",
        issuer_key_id="a" * 64,
        policy_bundle_hash="sha256:" + "a" * 64,
        tool_catalog_hash="sha256:" + "b" * 64,
    )
    mgr = SessionManager(ctx)
    state, _ = mgr.create_session()
    assert state.session_id


# ── close_session ─────────────────────────────────────────────────────────────


def test_close_session_produces_gateway_claim() -> None:
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    claim = mgr.close_session(state.session_id, state, chain)
    assert claim["cmcp_version"] == "1.0"
    assert "trace" in claim
    assert "gateway" in claim
    assert "signature" in claim


def test_close_session_claim_is_signed() -> None:
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    claim = mgr.close_session(state.session_id, state, chain)
    assert len(claim["signature"]) > 0


def test_close_session_appends_session_end_entry() -> None:
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    mgr.close_session(state.session_id, state, chain)
    entry_types = [e.entry_type for e in chain.entries]
    assert "session_end" in entry_types


def test_close_session_stores_claim_by_session_id() -> None:
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    claim = mgr.close_session(state.session_id, state, chain)
    retrieved = mgr.get_trace_claim(state.session_id)
    assert retrieved == claim


def test_close_session_claim_session_id_matches() -> None:
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    claim = mgr.close_session(state.session_id, state, chain)
    assert claim["gateway"]["session_id"] == state.session_id


def test_close_session_claim_includes_agent_identity_binding() -> None:
    ctx = _make_ctx()
    ctx.agent_manifest = AgentManifestBinding(
        manifest_id="0197739a-8c00-7000-8000-000000000001",
        agent_id="spiffe://factory.example/agent/material-movement/dev",
        authenticated_subject="spiffe://factory.example/agent/material-movement/dev",
        subject_source="config",
        issuer="spiffe://factory.example/signing-authority/development",
        issuer_key_id="a" * 64,
        policy_bundle_hash="sha256:" + "a" * 64,
        tool_catalog_hash="sha256:" + "b" * 64,
    )
    mgr = SessionManager(ctx)
    state, chain = mgr.create_session()
    claim = mgr.close_session(state.session_id, state, chain)
    assert claim["gateway"]["agent_identity"]["manifest_id"] == ctx.agent_manifest.manifest_id
    assert claim["gateway"]["agent_identity"]["agent_id"] == ctx.agent_manifest.agent_id
    assert claim["gateway"]["agent_identity"]["subject_source"] == "config"


def test_close_session_attestation_stale_flag_false_when_fresh() -> None:
    mgr = SessionManager(_make_ctx(stale_attestation=False))
    state, chain = mgr.create_session()
    claim = mgr.close_session(state.session_id, state, chain)
    assert claim["gateway"]["attestation_stale"] is False


def test_close_session_attestation_stale_flag_true_when_expired() -> None:
    mgr = SessionManager(_make_ctx(stale_attestation=True))
    state, chain = mgr.create_session()
    claim = mgr.close_session(state.session_id, state, chain)
    assert claim["gateway"]["attestation_stale"] is True


def test_close_session_signature_verifiable() -> None:
    """Signature on the claim must verify against the embedded JWK public key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from cmcp_runtime.audit.trace_claim import RuntimeClaim, _to_dict, canonical_json

    ctx = _make_ctx()
    mgr = SessionManager(ctx)
    state, chain = mgr.create_session()
    claim_dict = mgr.close_session(state.session_id, state, chain)

    # Re-validate through pydantic to get the proper model
    claim = RuntimeClaim.model_validate(claim_dict)
    body = canonical_json(_to_dict(claim))
    sig_bytes = base64.urlsafe_b64decode(claim.signature + "==")

    pub = Ed25519PublicKey.from_public_bytes(ctx.signing_key.public_key_bytes)
    pub.verify(sig_bytes, body)  # raises InvalidSignature if wrong


# ── get_trace_claim ────────────────────────────────────────────────────────────


def test_get_trace_claim_returns_none_for_unknown_session() -> None:
    mgr = SessionManager(_make_ctx())
    assert mgr.get_trace_claim("nonexistent-session-id") is None


def test_get_trace_claim_returns_claim_for_closed_session() -> None:
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    mgr.close_session(state.session_id, state, chain)
    result = mgr.get_trace_claim(state.session_id)
    assert result is not None
    assert result["cmcp_version"] == "1.0"


# ── get_audit_bundle ──────────────────────────────────────────────────────────


def test_audit_bundle_contains_required_keys() -> None:
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    bundle = mgr.get_audit_bundle(state.session_id, chain)
    assert set(bundle.keys()) == {"session_id", "entries", "bundle_signature"}


def test_audit_bundle_session_id_matches() -> None:
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    bundle = mgr.get_audit_bundle(state.session_id, chain)
    assert bundle["session_id"] == state.session_id


def test_audit_bundle_entries_count_matches_chain() -> None:
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
    bundle = mgr.get_audit_bundle(state.session_id, chain)
    assert len(bundle["entries"]) == chain.length


def test_audit_bundle_signature_is_valid() -> None:
    """Bundle signature must verify: sign(sha256(canonical_json(entries)))."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    ctx = _make_ctx()
    mgr = SessionManager(ctx)
    state, chain = mgr.create_session()
    bundle = mgr.get_audit_bundle(state.session_id, chain)

    entries_dicts = bundle["entries"]
    canonical = json.dumps(
        entries_dicts,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    digest = hashlib.sha256(canonical).digest()

    sig_bytes = base64.urlsafe_b64decode(bundle["bundle_signature"] + "==")
    pub = Ed25519PublicKey.from_public_bytes(ctx.signing_key.public_key_bytes)
    pub.verify(sig_bytes, digest)  # raises InvalidSignature if wrong


def test_audit_bundle_broken_chain_raises_value_error() -> None:
    """If the audit chain is tampered with, get_audit_bundle must raise ValueError."""
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")

    # Tamper with the chain.
    chain.entries[0].tool_name = "injected_tool"

    with pytest.raises(ValueError, match="integrity check failed"):
        mgr.get_audit_bundle(state.session_id, chain)


# ── AUDIT-006: chain-root binding into the attested report_data ────────────────


def test_close_session_uses_per_session_report_committing_chain_root() -> None:
    """AUDIT-006 end-to-end: a TEE that returns a per-session report whose
    report_data commits the chain root makes close_session() build the claim from
    THAT report, and the resulting claim passes the verifier's chain-root binding.
    """
    from cmcp_runtime.tee.base import AttestationReport
    from cmcp_verify.verify import (
        ApprovedHashes,
        VerificationError,
        verify_trace_claim,
    )

    ctx = _make_ctx()

    def _report_from_nonce(nonce: bytes) -> AttestationReport:
        # Tagged sev-snp so the nonce is surfaced as trace.runtime.nonce and the
        # verifier runs the AUDIT-006 binding check (software-only drops the nonce).
        return AttestationReport(
            provider="sev-snp",
            measurement="ab" * 32,
            report_data=nonce.hex(),
            raw_evidence=None,
            attestation_generated_at=datetime.now(UTC),
            attestation_validity_seconds=86400,
        )

    ctx.tee_provider.get_attestation_report.side_effect = _report_from_nonce

    mgr = SessionManager(ctx)
    state, chain = mgr.create_session()
    assert chain.session_report is not None
    assert chain.session_report is not ctx.attestation_report

    claim = mgr.close_session(state.session_id, state, chain)

    # report_data[32:64] in the claim commits the chain root.
    nonce_b64 = claim["trace"]["runtime"]["nonce"]
    pad = 4 - (len(nonce_b64) % 4)
    nonce_bytes = base64.urlsafe_b64decode(
        nonce_b64 + ("=" * pad if pad != 4 else "")
    )
    assert nonce_bytes[32:64] == hashlib.sha256(
        bytes.fromhex(chain.chain_root)
    ).digest()

    approved = ApprovedHashes(
        policy_bundle_hash=ctx.policy_bundle.bundle.bundle_hash,
        tool_catalog_hash=ctx.catalog.catalog_hash,
    )
    result = verify_trace_claim(
        claim, approved, trusted_public_key_hex=ctx.signing_key.public_key_hex
    )
    assert "audit_chain_binding" in result.verified_fields, result.details
    assert result.failure_reason != VerificationError.CHAIN_ROOT_NOT_BOUND


def test_close_session_falls_back_to_startup_report_when_tee_fails() -> None:
    """If the per-session TEE call fails, close_session() falls back to the shared
    startup report (no chain-root commitment) and the chain still anchors locally.
    """
    ctx = _make_ctx()
    ctx.tee_provider.get_attestation_report.side_effect = RuntimeError("TEE down")

    mgr = SessionManager(ctx)
    state, chain = mgr.create_session()
    assert chain.session_report is None
    assert chain.tee_anchor == chain.chain_root

    claim = mgr.close_session(state.session_id, state, chain)
    # Falls back to the startup (software-only) report.
    assert claim["trace"]["runtime"]["platform"] == "software-only"
