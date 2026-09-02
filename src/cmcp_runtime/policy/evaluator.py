"""Cedar policy evaluation for cMCP - implements issues #68, #73, #472."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cmcp_runtime.config import Config, EnforcementMode
from cmcp_runtime.errors import PolicyDeny
from cmcp_runtime.policy.annotations import parse_policy_annotations
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyStore
from cmcp_runtime.policy.cedar import CedarBackend
from cmcp_runtime.policy.decisions import Decision, decision_for_deny
from cmcp_runtime.session.state import effective_sensitivity_order

if TYPE_CHECKING:
    from cmcp_runtime.session.state import SessionState

logger = logging.getLogger(__name__)


@dataclass
class PolicyDecision:
    """Result of a Cedar policy evaluation."""

    allowed: bool
    enforcement_mode: EnforcementMode
    rule_matched: str | None
    advice: dict[str, Any]
    evaluation_ms: float
    # In advisory mode, allowed=True even when Cedar said deny:
    would_have_denied: bool = False
    # AARM R4 decision type. ALLOW when Cedar permitted. On a deny this is
    # DENY, STEP_UP, or DEFER per the matched policies' annotations, including
    # in advisory and silent modes where the call is let through: the recorded
    # decision reflects what policy decided, and `allowed` reflects what
    # enforcement did. MODIFY is set by the caller once the inspection pipeline
    # has actually altered a response, since the evaluator cannot know that at
    # ingress. See cmcp_runtime.policy.decisions.
    decision: Decision = Decision.ALLOW


class PolicyEvaluator:
    """
    Wraps cMCP's narrow Cedar adapter with cMCP enforcement modes.

    The bundle is loaded and hash-verified by load_policy_bundle() before this
    class is instantiated. CedarBackend receives the already-loaded policy content
    so the measured hash covers exactly the bytes that will be evaluated.
    """

    def __init__(
        self,
        bundle: PolicyBundle | PolicyStore,
        config: Config,
        # Return value is ignored, so the hook is free to report what it did.
        on_reload: Callable[[], object] | None = None,
    ) -> None:
        self._mode = config.attestation.enforcement_mode
        # #552: called after every policy-bundle reload so the platform can re-commit
        # what is now in force. On SEV-SNP, TDX and Azure CVM the gateway measurement
        # lives in the attestation report's report_data, which has no append-only
        # history, so the report is only ever as current as the last time it was
        # produced. None where nothing needs telling.
        self._on_reload = on_reload
        # #479: same effective vocabulary SessionManager derives from this same
        # Config, so a session's max_sensitivity and this sensitivity_level_int
        # can never disagree about what a custom label ranks as.
        self._sensitivity_order = effective_sensitivity_order(config.sensitivity.vocabulary)

        # Normalise: always work with a PolicyStore internally.
        if isinstance(bundle, PolicyStore):
            self._store = bundle
        else:
            self._store = PolicyStore(
                bundle=bundle,
                bundle_path="",
                reload_interval_seconds=0,
            )

        initial_bundle = self._store.bundle
        self._current_hash = initial_bundle.bundle_hash

        # Concatenate all Cedar policy files into one string for CedarBackend.
        # Files are sorted by name to match the hash computation in bundle.py.
        combined_policy = "\n\n".join(
            content for _, content in sorted(initial_bundle.policy_files.items())
        )

        self._backend = CedarBackend(policy_content=combined_policy)
        self._annotations = parse_policy_annotations(combined_policy)
        logger.info(
            "PolicyEvaluator ready: bundle_hash=%s enforcement=%s backend=%s",
            initial_bundle.bundle_hash,
            self._mode.value,
            self._backend.__class__.__name__,
        )

    def _maybe_reload(self) -> None:
        """Check for a stale bundle and rebuild the CedarBackend if the hash changed."""
        reloaded = self._store.reload_if_stale()
        bundle = self._store.bundle
        if bundle.bundle_hash != self._current_hash:
            combined_policy = "\n\n".join(
                content for _, content in sorted(bundle.policy_files.items())
            )
            self._backend = CedarBackend(policy_content=combined_policy)
            self._annotations = parse_policy_annotations(combined_policy)
            self._current_hash = bundle.bundle_hash
            logger.info("PolicyEvaluator backend refreshed: new_hash=%s", self._current_hash)
        # #552 asks for a refresh on **every** policy-bundle reload, not only on the
        # ones that moved the hash, so this sits outside the branch above.
        # ``reload_if_stale`` returns True exactly when the bundle was re-read from
        # disk, which is what "a reload" means here: False when reloading is off,
        # when the interval has not elapsed, and when the read failed.
        if reloaded:
            self._notify_reload()

    def _notify_reload(self) -> None:
        """Re-commit what is running after a policy-bundle reload (#552).

        Fires on every reload, including one that found the bundle unchanged.
        ``report_data`` holds one value and no history, so what a verifier gets is
        only ever the last report the gateway produced. Re-signing on each reload is
        what keeps that report an assertion about now rather than about whenever the
        policy last happened to change. TPM is not handled by this callback: its NV
        pair is startup-scoped today, is not refreshed here, and must not be
        represented as current after a policy reload.

        This runs on the enforcement path, so the tool call that observes the reload
        pays for the re-attestation. It is bounded by the reload interval, not by
        request rate: ``reload_if_stale`` stamps its clock before the attempt, so the
        cost is one TEE call per ``policy_reload_interval_seconds``, and none at all
        in the default configuration where reloading is off.

        A failing callback is logged and swallowed on purpose. The callback re-binds
        the gateway measurement into a hardware report; if the TEE cannot produce one
        right now, refusing traffic would trade a *detectable* weakness for an outage.
        Stale report_data no longer matches the measurement a verifier recomputes, so
        the claim is rejected at verification instead. This is the same trade AUDIT-006
        makes in SessionManager.create_session for a failed per-session attestation.
        """
        if self._on_reload is None:
            return
        try:
            self._on_reload()
        except Exception:  # noqa: BLE001 - enforcement must not depend on the TEE
            logger.warning(
                "#552: post-reload attestation hook failed; report_data still commits "
                "the previous policy bundle and verification will reject it",
                exc_info=True,
            )

    def _advice_for_deny(self, policy_ids: tuple[str, ...]) -> dict[str, str]:
        """
        Best-effort: recover the annotations of the forbid policies that caused
        a deny, to return as structured advice (e.g. HITL escalation payloads).

        Matched policy ids come from the same cedarpy authorization result used
        for the decision. This method remains best-effort and returns {} when
        annotations or diagnostics are unavailable.
        """
        if not self._annotations:
            return {}
        try:
            advice: dict[str, str] = {}
            for policy_id in policy_ids:
                advice.update(self._annotations.get(policy_id, {}))
            return advice
        except Exception:
            logger.debug("Advice extraction failed", exc_info=True)
            return {}

    def evaluate(self, context: dict[str, Any]) -> PolicyDecision:
        """
        Evaluate a tool call against the Cedar policy bundle.

        context must contain at minimum:
          - tool_name: str
          - session_max_sensitivity: str
          - workflow_id: str  (defaults to "default")

        Raises PolicyDeny if enforcement_mode is ENFORCING and Cedar denies.
        In ADVISORY mode, always returns allowed=True but sets would_have_denied.
        In SILENT mode, always returns allowed=True with no logging.
        """
        self._maybe_reload()
        result = self._backend.evaluate(context)
        allowed_by_cedar = result.allowed
        evaluation_ms = result.evaluation_ms or 0.0
        rule = result.reason or None

        # Apply enforcement mode
        if allowed_by_cedar:
            return PolicyDecision(
                allowed=True,
                enforcement_mode=self._mode,
                rule_matched=rule,
                advice={},
                evaluation_ms=evaluation_ms,
            )

        # Cedar denied - recover advice annotations from the matched policies,
        # then apply enforcement mode.
        advice = self._advice_for_deny(tuple(getattr(result, "policy_ids", ())))

        if self._mode == EnforcementMode.ENFORCING:
            raise PolicyDeny(
                f"Policy denied tool call: {context.get('tool_name', '?')}",
                detail=f"rule={rule} eval_ms={evaluation_ms:.2f}",
                advice=advice,
            )

        # Policy decided a non-allow outcome. Record which one even though
        # advisory and silent modes let the call through: `decision` is what
        # policy decided, `allowed` is what enforcement did.
        denied_as = decision_for_deny(advice)

        if self._mode == EnforcementMode.ADVISORY:
            logger.info(
                "ADVISORY %s (allowed through): tool=%s rule=%s",
                denied_as.value, context.get("tool_name"), rule,
            )
            return PolicyDecision(
                allowed=True,
                enforcement_mode=self._mode,
                rule_matched=rule,
                advice=advice,
                evaluation_ms=evaluation_ms,
                would_have_denied=True,
                decision=denied_as,
            )

        # SILENT mode - allow, no log
        return PolicyDecision(
            allowed=True,
            enforcement_mode=self._mode,
            rule_matched=rule,
            advice=advice,
            evaluation_ms=evaluation_ms,
            would_have_denied=True,
            decision=denied_as,
        )

    def authorize_egress(
        self,
        tool_name: str,
        response_bytes: bytes,
        session: SessionState,
        workflow_id: str | None = None,
    ) -> PolicyDecision:
        """
        Evaluate Cedar egress policies after a tool response is received.

        Uses the same CedarBackend as ingress evaluation but passes egress-specific
        context fields so Cedar policies can distinguish direction.  The principal
        and action are implicit in the context dict the backend receives.

        workflow_id carries the same call identity as the ingress evaluation:
        without it, workflow-scoped permits (default-deny bundles with no
        catch-all) can never match at egress and every response would be denied.

        Returns PolicyDecision(allowed=True/False, ...).  In ENFORCING mode a deny
        raises PolicyDeny; in ADVISORY/SILENT a deny is flagged via would_have_denied.
        """
        self._maybe_reload()
        context: dict[str, Any] = {
            "tool_name": tool_name,
            # Same resource entity as ingress (see PolicyProxy._build_cedar_context)
            # so a resource-scoped permit matches at egress too; without it an
            # allowed tool response would be denied on the way back.
            "resource": tool_name,
            "egress": True,
            "sensitivity_level": self._sensitivity_order.get(session.max_sensitivity, 0),
            "injection_events": len(session.injection_events),
            "reset_count": session.reset_count,
            "response_size_bytes": len(response_bytes),
        }
        if workflow_id is not None:
            context["workflow_id"] = workflow_id
        return self.evaluate(context)

    @property
    def bundle_hash(self) -> str:
        return self._store.bundle.bundle_hash

    @property
    def enforcement_mode(self) -> EnforcementMode:
        return self._mode
