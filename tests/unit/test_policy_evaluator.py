"""Tests for Cedar policy evaluation via AGT (issues #68, #73)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cmcp_gateway.config import AttestationConfig, Config, EnforcementMode
from cmcp_gateway.errors import PolicyDeny
from cmcp_gateway.policy.bundle import PolicyBundle, PolicyManifest, PolicyStore
from cmcp_gateway.policy.evaluator import PolicyDecision, PolicyEvaluator


def _make_bundle(policy_content: str = 'permit(principal, action, resource);') -> PolicyBundle:
    return PolicyBundle(
        manifest=PolicyManifest(
            version="1.0.0",
            authored_at="2026-06-05T00:00:00Z",
            author_identity="test",
            commit_sha="abc",
        ),
        policy_files={"allow.cedar": policy_content},
        schema_content='{"cMCP": {}}',
        bundle_hash="sha256:" + "0" * 64,
    )


def _make_config(mode: EnforcementMode = EnforcementMode.ENFORCING) -> Config:
    cfg = Config()
    cfg.attestation = AttestationConfig(enforcement_mode=mode)
    return cfg


ALLOW_CONTEXT = {
    "tool_name": "crm.query",
    "session_max_sensitivity": "public",
    "workflow_id": "default",
}


# ── Enforcing mode ────────────────────────────────────────────────────────────

def test_enforcing_allow():
    with patch("cmcp_gateway.policy.evaluator.CedarBackend") as MockBackend:
        mock = MagicMock()
        mock.evaluate.return_value = MagicMock(
            allowed=True, reason="permit rule", evaluation_ms=0.5
        )
        MockBackend.return_value = mock

        evaluator = PolicyEvaluator(_make_bundle(), _make_config(EnforcementMode.ENFORCING))
        decision = evaluator.evaluate(ALLOW_CONTEXT)

    assert decision.allowed is True
    assert decision.would_have_denied is False


def test_enforcing_deny_raises():
    with patch("cmcp_gateway.policy.evaluator.CedarBackend") as MockBackend:
        mock = MagicMock()
        mock.evaluate.return_value = MagicMock(
            allowed=False, reason="forbid rule", evaluation_ms=0.3
        )
        MockBackend.return_value = mock

        evaluator = PolicyEvaluator(_make_bundle(), _make_config(EnforcementMode.ENFORCING))
        with pytest.raises(PolicyDeny, match="Policy denied"):
            evaluator.evaluate(ALLOW_CONTEXT)


# ── Advisory mode ─────────────────────────────────────────────────────────────

def test_advisory_deny_allows_through():
    """In advisory mode, Cedar denials are allowed but flagged."""
    with patch("cmcp_gateway.policy.evaluator.CedarBackend") as MockBackend:
        mock = MagicMock()
        mock.evaluate.return_value = MagicMock(
            allowed=False, reason="forbid rule", evaluation_ms=0.2
        )
        MockBackend.return_value = mock

        evaluator = PolicyEvaluator(_make_bundle(), _make_config(EnforcementMode.ADVISORY))
        decision = evaluator.evaluate(ALLOW_CONTEXT)

    assert decision.allowed is True
    assert decision.would_have_denied is True


def test_advisory_allow_does_not_flag():
    with patch("cmcp_gateway.policy.evaluator.CedarBackend") as MockBackend:
        mock = MagicMock()
        mock.evaluate.return_value = MagicMock(
            allowed=True, reason=None, evaluation_ms=0.1
        )
        MockBackend.return_value = mock

        evaluator = PolicyEvaluator(_make_bundle(), _make_config(EnforcementMode.ADVISORY))
        decision = evaluator.evaluate(ALLOW_CONTEXT)

    assert decision.allowed is True
    assert decision.would_have_denied is False


# ── Silent mode ───────────────────────────────────────────────────────────────

def test_silent_deny_allows_through_no_log(caplog):
    with patch("cmcp_gateway.policy.evaluator.CedarBackend") as MockBackend:
        mock = MagicMock()
        mock.evaluate.return_value = MagicMock(
            allowed=False, reason="forbid", evaluation_ms=0.1
        )
        MockBackend.return_value = mock

        evaluator = PolicyEvaluator(_make_bundle(), _make_config(EnforcementMode.SILENT))
        with caplog.at_level("INFO"):
            decision = evaluator.evaluate(ALLOW_CONTEXT)

    assert decision.allowed is True
    assert "ADVISORY deny" not in caplog.text


# ── CedarBackend receives policy content ─────────────────────────────────────

def test_cedar_backend_receives_sorted_policy_content():
    """CedarBackend gets sorted policy file contents concatenated."""
    with patch("cmcp_gateway.policy.evaluator.CedarBackend") as MockBackend:
        mock = MagicMock()
        mock.evaluate.return_value = MagicMock(allowed=True, reason=None, evaluation_ms=0.0)
        MockBackend.return_value = mock

        bundle = _make_bundle()
        bundle.policy_files = {
            "z-last.cedar": "permit(principal, action, resource);",
            "a-first.cedar": "// comment",
        }
        PolicyEvaluator(bundle, _make_config())

    _, kwargs = MockBackend.call_args
    content = kwargs.get("policy_content", "")
    assert "// comment" in content
    assert content.index("// comment") < content.index("permit(")


# ── Properties ────────────────────────────────────────────────────────────────

def test_evaluator_exposes_bundle_hash():
    with patch("cmcp_gateway.policy.evaluator.CedarBackend"):
        e = PolicyEvaluator(_make_bundle(), _make_config())
    assert e.bundle_hash == "sha256:" + "0" * 64


def test_evaluator_exposes_enforcement_mode():
    with patch("cmcp_gateway.policy.evaluator.CedarBackend"):
        e = PolicyEvaluator(_make_bundle(), _make_config(EnforcementMode.ADVISORY))
    assert e.enforcement_mode == EnforcementMode.ADVISORY


# ── PolicyDecision ────────────────────────────────────────────────────────────

def test_decision_conformance_policy_003():
    """POLICY-003: advisory mode logs would_have_denied=True."""
    with patch("cmcp_gateway.policy.evaluator.CedarBackend") as MockBackend:
        mock = MagicMock()
        mock.evaluate.return_value = MagicMock(
            allowed=False, reason="test forbid", evaluation_ms=0.0
        )
        MockBackend.return_value = mock
        e = PolicyEvaluator(_make_bundle(), _make_config(EnforcementMode.ADVISORY))
        d = e.evaluate(ALLOW_CONTEXT)

    assert isinstance(d, PolicyDecision)
    assert d.allowed is True
    assert d.would_have_denied is True
    assert d.enforcement_mode == EnforcementMode.ADVISORY


# ── PolicyStore integration (POLICY-001 hot-reload) ───────────────────────────

def _make_bundle_with_hash(hash_hex: str) -> PolicyBundle:
    return PolicyBundle(
        manifest=PolicyManifest(
            version="1.0.0",
            authored_at="2026-06-07T00:00:00Z",
            author_identity="test",
            commit_sha="abc",
        ),
        policy_files={"allow.cedar": "permit(principal, action, resource);"},
        schema_content='{"cMCP": {}}',
        bundle_hash=f"sha256:{hash_hex}",
    )


def test_evaluator_accepts_policy_store():
    """PolicyEvaluator must accept a PolicyStore directly."""
    with patch("cmcp_gateway.policy.evaluator.CedarBackend"):
        store = PolicyStore(bundle=_make_bundle(), bundle_path="", reload_interval_seconds=0)
        e = PolicyEvaluator(store, _make_config())
    assert e.bundle_hash == "sha256:" + "0" * 64


def test_evaluator_refreshes_backend_on_bundle_change():
    """When the store's bundle hash changes, _maybe_reload rebuilds the CedarBackend."""
    old_hash = "a" * 64
    new_hash = "b" * 64
    old_bundle = _make_bundle_with_hash(old_hash)
    new_bundle = _make_bundle_with_hash(new_hash)

    store = PolicyStore(bundle=old_bundle, bundle_path="", reload_interval_seconds=0)

    with patch("cmcp_gateway.policy.evaluator.CedarBackend") as MockBackend:
        mock_backend = MagicMock()
        mock_backend.evaluate.return_value = MagicMock(
            allowed=True, reason=None, evaluation_ms=0.1
        )
        MockBackend.return_value = mock_backend

        evaluator = PolicyEvaluator(store, _make_config())
        # Backend was constructed once at init.
        assert MockBackend.call_count == 1

        # Swap the bundle in the store to simulate a hot-reload.
        store._bundle = new_bundle

        # evaluate() calls _maybe_reload() which detects the hash change and
        # rebuilds the backend.
        evaluator.evaluate(ALLOW_CONTEXT)

    # Backend must have been re-created: call_count goes to 2.
    assert MockBackend.call_count == 2
    assert evaluator.bundle_hash == f"sha256:{new_hash}"
