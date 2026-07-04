"""Tests for AUDIT-002: audit chain external TEE anchor (chain substitution prevention)."""

from __future__ import annotations

import hashlib
import logging
from unittest.mock import MagicMock

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.session.manager import SessionManager

# ── AuditChain.set_tee_anchor ─────────────────────────────────────────────────


def test_set_tee_anchor_accepts_matching_chain_root():
    chain = AuditChain("sess-anchor-001")
    chain.set_tee_anchor(chain.chain_root)
    assert chain.tee_anchor == chain.chain_root


def test_set_tee_anchor_rejects_mismatched_value():
    chain = AuditChain("sess-anchor-002")
    with pytest.raises(ValueError, match="does not match current chain_root"):
        chain.set_tee_anchor("a" * 64)


def test_tee_anchor_none_before_set():
    chain = AuditChain("sess-anchor-003")
    assert chain.tee_anchor is None


# ── verify_chain with anchor ──────────────────────────────────────────────────


def test_verify_chain_passes_when_anchor_matches(caplog):
    chain = AuditChain("sess-anchor-004")
    chain.set_tee_anchor(chain.chain_root)
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
    assert chain.verify_chain() is True


def test_verify_chain_warns_when_no_anchor(caplog):
    """Happy internal-only chain: passes but logs a warning about missing anchor."""
    chain = AuditChain("sess-anchor-005")
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
    with caplog.at_level(logging.WARNING, logger="cmcp_runtime.audit.chain"):
        result = chain.verify_chain()
    assert result is True
    assert "AUDIT-002" in caplog.text
    assert "no TEE anchor" in caplog.text


def test_verify_chain_fails_on_chain_substitution():
    """
    Attack path: discard _entries and replace with a fresh chain.

    An attacker who replaces the internal entry list with a freshly constructed
    chain passes internal hash checks but fails the external anchor comparison
    because the new chain_root is different from the anchored value.
    """
    # Build the real chain and anchor it.
    real_chain = AuditChain("sess-anchor-006")
    real_chain.set_tee_anchor(real_chain.chain_root)
    real_chain.append("tool_call", call_id="c1", tool_name="legitimate_tool", policy_decision="allow")

    # Simulate attacker building a fresh self-consistent chain.
    attacker_chain = AuditChain("sess-anchor-006")
    attacker_chain.append("tool_call", call_id="c1", tool_name="evil_tool", policy_decision="allow")

    # Graft the attacker's entries onto the real chain object (keeping the anchor).
    real_chain._entries = attacker_chain._entries  # type: ignore[attr-defined]

    # Internal hash links are valid (the attacker built a self-consistent chain),
    # but the chain_root no longer matches the TEE anchor.
    assert real_chain.verify_chain() is False


def test_verify_chain_still_detects_internal_tampering_with_anchor():
    """Tampering with entry fields still fails even when an anchor is set."""
    chain = AuditChain("sess-anchor-007")
    chain.set_tee_anchor(chain.chain_root)
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
    chain.entries[1].tool_name = "injected"
    assert chain.verify_chain() is False


# ── SessionManager integration ────────────────────────────────────────────────


def _make_tee_provider_mock() -> MagicMock:
    """Return a mock TEE provider that records nonces passed to get_attestation_report."""
    provider = MagicMock()
    provider.get_attestation_report.return_value = MagicMock()
    return provider


def _make_ctx_with_tee() -> MagicMock:
    """Return a mock RuntimeContext that includes a trackable tee_provider."""
    signing_key = SigningKey()

    policy_bundle = MagicMock()
    policy_bundle.bundle_hash = "sha256:" + "a" * 64
    policy_bundle.manifest.version = "1.0.0"

    catalog = MagicMock()
    catalog.catalog_hash = "sha256:" + "b" * 64
    catalog.entries = {}

    config = MagicMock()
    config.attestation.enforcement_mode = "enforcing"

    from datetime import UTC, datetime

    report = MagicMock()
    report.provider = "software-only"
    report.measurement = "DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION"
    report.report_data = "aa" * 32
    report.raw_evidence = None
    report.measurement_note = "software-only mode"
    report.attestation_validity_seconds = 86400
    report.attestation_generated_at = datetime.now(UTC)

    ctx = MagicMock()
    ctx.signing_key = signing_key
    ctx.attestation_report = report
    ctx.policy_bundle = policy_bundle
    ctx.catalog = catalog
    ctx.config = config
    ctx.tee_provider = _make_tee_provider_mock()
    return ctx


def test_create_session_sets_tee_anchor():
    """create_session must call set_tee_anchor so that verify_chain has an external check."""
    ctx = _make_ctx_with_tee()
    mgr = SessionManager(ctx)
    _, chain = mgr.create_session()
    assert chain.tee_anchor is not None
    assert chain.tee_anchor == chain.chain_root


def test_create_session_calls_tee_provider_with_chain_root_nonce():
    """create_session must pass the AUDIT-006 audit-bound nonce to the TEE provider.

    nonce = jwk_thumbprint(key) (32) || SHA-256(chain_root) (32) = 64 bytes.
    """
    ctx = _make_ctx_with_tee()
    mgr = SessionManager(ctx)
    _, chain = mgr.create_session()

    ctx.tee_provider.get_attestation_report.assert_called_once()
    call_args = ctx.tee_provider.get_attestation_report.call_args
    nonce_arg = call_args[0][0]
    assert isinstance(nonce_arg, bytes)
    assert len(nonce_arg) == 64


def test_create_session_anchor_nonce_encodes_chain_root():
    """AUDIT-006: report_data[32:64] must equal SHA-256(chain_root_bytes).

    The first 32 bytes are the RFC 7638 JWK thumbprint of the gateway key (key
    binding, unchanged); the second 32 bytes commit the chain root.
    """
    from cmcp_runtime.tee.base import jwk_thumbprint

    ctx = _make_ctx_with_tee()
    mgr = SessionManager(ctx)
    _, chain = mgr.create_session()

    chain_root = chain.chain_root
    expected_nonce = (
        jwk_thumbprint(ctx.signing_key.public_key_bytes)
        + hashlib.sha256(bytes.fromhex(chain_root)).digest()
    )

    actual_nonce = ctx.tee_provider.get_attestation_report.call_args[0][0]
    assert actual_nonce == expected_nonce
    assert actual_nonce[32:64] == hashlib.sha256(bytes.fromhex(chain_root)).digest()


def test_verify_chain_passes_after_create_session():
    """End-to-end: a session created via SessionManager passes verify_chain."""
    ctx = _make_ctx_with_tee()
    mgr = SessionManager(ctx)
    _, chain = mgr.create_session()
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
    assert chain.verify_chain() is True


def test_verify_chain_fails_after_chain_substitution_via_session_manager():
    """
    Attack path via SessionManager: replace the chain with a freshly built one.

    After create_session() sets the anchor, an attacker who swaps _entries with
    a fresh chain will get a different root that does not match the anchor.
    """
    ctx = _make_ctx_with_tee()
    mgr = SessionManager(ctx)
    _, real_chain = mgr.create_session()
    real_chain.append("tool_call", call_id="c1", tool_name="legitimate", policy_decision="allow")

    # Attacker builds a replacement chain with identical session_id.
    replacement = AuditChain(real_chain._session_id)  # type: ignore[attr-defined]
    replacement.append("tool_call", call_id="c1", tool_name="evil_tool", policy_decision="allow")

    # Graft replacement entries: anchor is still the original root.
    real_chain._entries = replacement._entries  # type: ignore[attr-defined]

    assert real_chain.verify_chain() is False


def test_tee_provider_failure_still_sets_anchor(caplog):
    """If the TEE provider raises, create_session must still set the anchor and log a warning."""
    ctx = _make_ctx_with_tee()
    ctx.tee_provider.get_attestation_report.side_effect = RuntimeError("TEE unavailable")

    mgr = SessionManager(ctx)
    with caplog.at_level(logging.WARNING, logger="cmcp_runtime.session.manager"):
        _, chain = mgr.create_session()

    assert chain.tee_anchor is not None
    assert "chain root is not hardware-bound into report_data" in caplog.text
