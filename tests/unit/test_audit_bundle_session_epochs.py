"""A verified claim/bundle pair must describe one session, or carry the reset.

A credentialed reset closes one session and opens a successor on the same
hash-linked chain: entries before the boundary keep the closed session's
identifier, the ``session_reset`` entry names both identifiers, and entries
after it carry the successor's. The verifier checks that every change of
``session_id`` in a bundle is explained by such an entry, and that the chain
ends in the session the claim was issued for. Without that check a bundle
whose entries belong to another session verified against any claim whose
root, tip and counts matched.
"""

from __future__ import annotations

from cmcp_runtime.session.manager import SessionManager
from cmcp_verify import verify_audit_bundle
from tests.unit.test_session_manager import _make_ctx


def _session_with_a_call():
    mgr = SessionManager(_make_ctx())
    state, chain = mgr.create_session()
    chain.append("tool_call", call_id="c1", tool_name="t", policy_decision="allow")
    return mgr, state, chain


def _close(mgr, state, chain, session_id=None):
    sid = session_id or state.session_id
    claim = mgr.close_session(sid, state, chain)
    return claim, mgr.get_audit_bundle(sid, chain)


def _epoch_failures(result):
    return [f for f in result.failures if "session" in f]


def test_single_session_bundle_verifies():
    mgr, state, chain = _session_with_a_call()
    claim, bundle = _close(mgr, state, chain)
    result = verify_audit_bundle(bundle, claim)
    assert result.verified, result.failures


def test_reset_with_recorded_transition_verifies():
    mgr, state, chain = _session_with_a_call()
    old_id = state.session_id
    new_id = "successor-session"
    chain.append(
        "session_reset",
        policy_decision="n/a",
        detail={"closed_session_id": old_id, "successor_session_id": new_id},
    )
    chain.rotate_session_id(new_id)
    state.session_id = new_id
    chain.append("tool_call", call_id="c2", tool_name="t", policy_decision="allow")
    claim, bundle = _close(mgr, state, chain)

    assert {e["session_id"] for e in bundle["entries"]} == {old_id, new_id}
    result = verify_audit_bundle(bundle, claim)
    assert result.verified, result.failures


def test_session_change_without_a_transition_is_rejected():
    mgr, state, chain = _session_with_a_call()
    new_id = "successor-session"
    chain.rotate_session_id(new_id)
    state.session_id = new_id
    claim, bundle = _close(mgr, state, chain)

    result = verify_audit_bundle(bundle, claim)
    assert not result.verified
    assert _epoch_failures(result)


def test_claim_for_a_different_session_than_the_chain_is_rejected():
    mgr, state, chain = _session_with_a_call()
    claim, bundle = _close(mgr, state, chain, session_id="some-other-session")

    result = verify_audit_bundle(bundle, claim)
    assert not result.verified
    assert _epoch_failures(result)


def test_transition_that_does_not_close_the_current_session_is_rejected():
    mgr, state, chain = _session_with_a_call()
    new_id = "successor-session"
    chain.append(
        "session_reset",
        policy_decision="n/a",
        detail={"closed_session_id": "not-this-session", "successor_session_id": new_id},
    )
    chain.rotate_session_id(new_id)
    state.session_id = new_id
    claim, bundle = _close(mgr, state, chain)

    result = verify_audit_bundle(bundle, claim)
    assert not result.verified
    assert _epoch_failures(result)


def test_bundle_without_claim_still_checks_transitions():
    mgr, state, chain = _session_with_a_call()
    chain.rotate_session_id("successor-session")
    chain.append("tool_call", call_id="c2", tool_name="t", policy_decision="allow")
    bundle = mgr.get_audit_bundle(state.session_id, chain)

    result = verify_audit_bundle(bundle)
    assert not result.verified
    assert _epoch_failures(result)
