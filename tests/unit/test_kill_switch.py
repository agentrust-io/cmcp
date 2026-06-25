"""Unit tests for KillSwitchEvaluator and SessionManager integration (issue #341)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from cmcp_runtime.agent_manifest import AgentManifestBinding
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.config import KillSwitchConfig
from cmcp_runtime.errors import KillSwitchTripped
from cmcp_runtime.kill_switch import KillSwitchEvaluator
from cmcp_runtime.session.manager import SessionManager

# ── Helpers ────────────────────────────────────────────────────────────────────

_AGENT_ID = "spiffe://example.com/agent/rogue-bot"


def _ks_config(*, enabled: bool = True, threshold: float = 0.9, min_calls: int = 5, window: int = 300) -> KillSwitchConfig:
    return KillSwitchConfig(
        enabled=enabled,
        window_seconds=window,
        deny_rate_threshold=threshold,
        min_calls=min_calls,
    )


def _make_manifest(agent_id: str = _AGENT_ID) -> AgentManifestBinding:
    return AgentManifestBinding(
        manifest_id="0197739a-8c00-7000-8000-000000000001",
        agent_id=agent_id,
        authenticated_subject=agent_id,
        subject_source="config",
        issuer="spiffe://example.com/signing-authority/prod",
        issuer_key_id="a" * 64,
        policy_bundle_hash="sha256:" + "a" * 64,
        tool_catalog_hash="sha256:" + "b" * 64,
    )


def _make_ctx(*, ks_config: KillSwitchConfig | None = None, agent_manifest: AgentManifestBinding | None = None) -> MagicMock:
    from datetime import UTC, datetime

    signing_key = SigningKey()

    policy_bundle = MagicMock()
    policy_bundle.bundle.bundle_hash = "sha256:" + "a" * 64
    policy_bundle.bundle.manifest.version = "1.0.0"

    catalog = MagicMock()
    catalog.catalog_hash = "sha256:" + "b" * 64
    catalog.entries = {}
    catalog.exceptions = []

    config = MagicMock()
    config.attestation.enforcement_mode = "enforcing"
    config.kill_switch = ks_config or _ks_config()

    attestation_report = MagicMock()
    attestation_report.provider = "software-only"
    attestation_report.measurement = "DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION"
    attestation_report.report_data = "aa" * 32
    attestation_report.raw_evidence = None
    attestation_report.measurement_note = "software-only mode"
    attestation_report.attestation_validity_seconds = 86400
    attestation_report.attestation_generated_at = datetime.now(UTC)

    tee_provider = MagicMock()
    tee_provider.get_attestation_report.return_value = MagicMock()

    ctx = MagicMock()
    ctx.signing_key = signing_key
    ctx.attestation_report = attestation_report
    ctx.policy_bundle = policy_bundle
    ctx.catalog = catalog
    ctx.config = config
    ctx.tee_provider = tee_provider
    ctx.agent_manifest = agent_manifest
    ctx.audit_store = None
    return ctx


# ── KillSwitchEvaluator unit tests ────────────────────────────────────────────


class TestKillSwitchEvaluator:
    def test_disabled_always_returns_false(self) -> None:
        ev = KillSwitchEvaluator(_ks_config(enabled=False))
        ev.record_calls(_AGENT_ID, allowed=0, denied=100)
        assert ev.evaluate(_AGENT_ID) is False

    def test_below_min_calls_not_tripped(self) -> None:
        ev = KillSwitchEvaluator(_ks_config(min_calls=10))
        ev.record_calls(_AGENT_ID, allowed=0, denied=5)
        assert ev.evaluate(_AGENT_ID) is False

    def test_below_threshold_not_tripped(self) -> None:
        ev = KillSwitchEvaluator(_ks_config(threshold=0.9, min_calls=5))
        ev.record_calls(_AGENT_ID, allowed=5, denied=4)  # 44% deny rate
        assert ev.evaluate(_AGENT_ID) is False

    def test_at_threshold_is_tripped(self) -> None:
        ev = KillSwitchEvaluator(_ks_config(threshold=0.9, min_calls=10))
        ev.record_calls(_AGENT_ID, allowed=1, denied=9)  # exactly 90%
        assert ev.evaluate(_AGENT_ID) is True

    def test_above_threshold_is_tripped(self) -> None:
        ev = KillSwitchEvaluator(_ks_config(threshold=0.8, min_calls=5))
        ev.record_calls(_AGENT_ID, allowed=0, denied=10)  # 100%
        assert ev.evaluate(_AGENT_ID) is True

    def test_is_blocked_after_tripped(self) -> None:
        ev = KillSwitchEvaluator(_ks_config(threshold=0.9, min_calls=10))
        ev.record_calls(_AGENT_ID, allowed=1, denied=9)
        ev.evaluate(_AGENT_ID)
        assert ev.is_blocked(_AGENT_ID) is True

    def test_is_not_blocked_before_trip(self) -> None:
        ev = KillSwitchEvaluator(_ks_config())
        assert ev.is_blocked(_AGENT_ID) is False

    def test_unblock_clears_flag_and_events(self) -> None:
        ev = KillSwitchEvaluator(_ks_config(threshold=0.9, min_calls=10))
        ev.record_calls(_AGENT_ID, allowed=1, denied=9)
        ev.evaluate(_AGENT_ID)
        assert ev.is_blocked(_AGENT_ID) is True
        ev.unblock(_AGENT_ID)
        assert ev.is_blocked(_AGENT_ID) is False
        # Events cleared — below min_calls after unblock
        assert ev.evaluate(_AGENT_ID) is False

    def test_separate_agent_ids_are_independent(self) -> None:
        other = "spiffe://example.com/agent/well-behaved"
        ev = KillSwitchEvaluator(_ks_config(threshold=0.9, min_calls=5))
        ev.record_calls(_AGENT_ID, allowed=0, denied=10)
        ev.evaluate(_AGENT_ID)
        ev.record_calls(other, allowed=10, denied=0)
        assert ev.is_blocked(_AGENT_ID) is True
        assert ev.is_blocked(other) is False

    def test_record_allowed_and_denied_accumulate(self) -> None:
        ev = KillSwitchEvaluator(_ks_config(threshold=0.8, min_calls=5))
        ev.record_calls(_AGENT_ID, allowed=5, denied=0)  # 0% deny
        assert ev.evaluate(_AGENT_ID) is False
        # Add enough denies to cross threshold
        ev.record_calls(_AGENT_ID, allowed=0, denied=20)  # now ~80% deny over 25 total
        assert ev.evaluate(_AGENT_ID) is True

    def test_window_expired_events_ignored(self) -> None:
        import time
        ev = KillSwitchEvaluator(_ks_config(threshold=0.9, min_calls=5, window=1))
        ev.record_calls(_AGENT_ID, allowed=0, denied=10)
        # Sleep past the window
        time.sleep(1.1)
        # Now add clean events
        ev.record_calls(_AGENT_ID, allowed=10, denied=0)
        assert ev.evaluate(_AGENT_ID) is False


# ── SessionManager kill switch integration tests ───────────────────────────────


class TestSessionManagerKillSwitch:
    def test_close_session_no_manifest_kill_switch_not_triggered(self) -> None:
        """Anonymous sessions never trigger the kill switch."""
        ctx = _make_ctx(ks_config=_ks_config(threshold=0.5, min_calls=1), agent_manifest=None)
        mgr = SessionManager(ctx)
        state, chain = mgr.create_session()
        chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="deny")
        claim = mgr.close_session(state.session_id, state, chain)
        assert claim["gateway"]["kill_switch_triggered"] is False

    def test_close_session_below_threshold_not_triggered(self) -> None:
        ctx = _make_ctx(
            ks_config=_ks_config(threshold=0.9, min_calls=5),
            agent_manifest=_make_manifest(),
        )
        mgr = SessionManager(ctx)
        state, chain = mgr.create_session()
        # 3 allows, 2 denies = 40% deny rate — below 90%
        for i in range(3):
            chain.append("tool_call", call_id=f"a{i}", tool_name="t", policy_decision="allow")
        for i in range(2):
            chain.append("tool_call", call_id=f"d{i}", tool_name="t", policy_decision="deny")
        claim = mgr.close_session(state.session_id, state, chain)
        assert claim["gateway"]["kill_switch_triggered"] is False

    def test_close_session_at_threshold_triggered(self) -> None:
        ctx = _make_ctx(
            ks_config=_ks_config(threshold=0.9, min_calls=10),
            agent_manifest=_make_manifest(),
        )
        mgr = SessionManager(ctx)
        state, chain = mgr.create_session()
        # 1 allow, 9 denies = exactly 90%
        chain.append("tool_call", call_id="a0", tool_name="t", policy_decision="allow")
        for i in range(9):
            chain.append("tool_call", call_id=f"d{i}", tool_name="t", policy_decision="deny")
        claim = mgr.close_session(state.session_id, state, chain)
        assert claim["gateway"]["kill_switch_triggered"] is True

    def test_kill_switch_triggers_audit_entry(self) -> None:
        ctx = _make_ctx(
            ks_config=_ks_config(threshold=0.9, min_calls=10),
            agent_manifest=_make_manifest(),
        )
        mgr = SessionManager(ctx)
        state, chain = mgr.create_session()
        chain.append("tool_call", call_id="a0", tool_name="t", policy_decision="allow")
        for i in range(9):
            chain.append("tool_call", call_id=f"d{i}", tool_name="t", policy_decision="deny")
        mgr.close_session(state.session_id, state, chain)
        entry_types = [e.entry_type for e in chain.entries]
        assert "break_glass_used" in entry_types

    def test_kill_switch_sets_state_flag(self) -> None:
        ctx = _make_ctx(
            ks_config=_ks_config(threshold=0.9, min_calls=10),
            agent_manifest=_make_manifest(),
        )
        mgr = SessionManager(ctx)
        state, chain = mgr.create_session()
        chain.append("tool_call", call_id="a0", tool_name="t", policy_decision="allow")
        for i in range(9):
            chain.append("tool_call", call_id=f"d{i}", tool_name="t", policy_decision="deny")
        mgr.close_session(state.session_id, state, chain)
        assert state.kill_switch_triggered is True

    def test_create_session_rejected_after_kill_switch(self) -> None:
        ctx = _make_ctx(
            ks_config=_ks_config(threshold=0.9, min_calls=10),
            agent_manifest=_make_manifest(),
        )
        mgr = SessionManager(ctx)
        # First session: trip the kill switch
        state, chain = mgr.create_session()
        chain.append("tool_call", call_id="a0", tool_name="t", policy_decision="allow")
        for i in range(9):
            chain.append("tool_call", call_id=f"d{i}", tool_name="t", policy_decision="deny")
        mgr.close_session(state.session_id, state, chain)
        # Second session: must raise KillSwitchTripped
        with pytest.raises(KillSwitchTripped):
            mgr.create_session()

    def test_create_session_anonymous_never_blocked(self) -> None:
        ctx = _make_ctx(
            ks_config=_ks_config(threshold=0.0, min_calls=1),
            agent_manifest=None,
        )
        mgr = SessionManager(ctx)
        # Even with 0.0 threshold, anonymous sessions are never blocked
        state, chain = mgr.create_session()
        chain.append("tool_call", call_id="d0", tool_name="t", policy_decision="deny")
        mgr.close_session(state.session_id, state, chain)
        # Must not raise
        state2, _ = mgr.create_session()
        assert state2 is not None

    def test_kill_switch_disabled_never_triggers(self) -> None:
        ctx = _make_ctx(
            ks_config=_ks_config(enabled=False, threshold=0.0, min_calls=1),
            agent_manifest=_make_manifest(),
        )
        mgr = SessionManager(ctx)
        state, chain = mgr.create_session()
        for i in range(10):
            chain.append("tool_call", call_id=f"d{i}", tool_name="t", policy_decision="deny")
        claim = mgr.close_session(state.session_id, state, chain)
        assert claim["gateway"]["kill_switch_triggered"] is False
        # Must not raise on second session
        mgr.create_session()

    def test_kill_switch_error_carries_agent_id(self) -> None:
        agent_id = "spiffe://example.com/agent/bad-actor"
        ctx = _make_ctx(
            ks_config=_ks_config(threshold=0.9, min_calls=10),
            agent_manifest=_make_manifest(agent_id),
        )
        mgr = SessionManager(ctx)
        state, chain = mgr.create_session()
        chain.append("tool_call", call_id="a0", tool_name="t", policy_decision="allow")
        for i in range(9):
            chain.append("tool_call", call_id=f"d{i}", tool_name="t", policy_decision="deny")
        mgr.close_session(state.session_id, state, chain)
        with pytest.raises(KillSwitchTripped) as exc_info:
            mgr.create_session()
        assert agent_id in exc_info.value.detail

    def test_advisory_deny_counts_toward_kill_switch(self) -> None:
        """advisory_deny counts as a deny in kill switch evaluation (matches close_session logic)."""
        ctx = _make_ctx(
            ks_config=_ks_config(threshold=0.9, min_calls=10),
            agent_manifest=_make_manifest(),
        )
        mgr = SessionManager(ctx)
        state, chain = mgr.create_session()
        chain.append("tool_call", call_id="a0", tool_name="t", policy_decision="allow")
        for i in range(4):
            chain.append("tool_call", call_id=f"d{i}", tool_name="t", policy_decision="deny")
        for i in range(5):
            chain.append("tool_call", call_id=f"ad{i}", tool_name="t", policy_decision="advisory_deny")
        claim = mgr.close_session(state.session_id, state, chain)
        assert claim["gateway"]["kill_switch_triggered"] is True
