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
    report.measurement_note = "software-only mode — not hardware-backed"
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
        issuer="spiffe://factory.example/signing-authority/development",
        issuer_key_id="a" * 64,
        policy_bundle_hash="sha256:" + "a" * 64,
        tool_catalog_hash="sha256:" + "b" * 64,
    )
    mgr = SessionManager(ctx)
    state, _ = mgr.create_session()
    assert state.agent_manifest_id == "0197739a-8c00-7000-8000-000000000001"
    assert state.agent_id == "spiffe://factory.example/agent/material-movement/dev"


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
