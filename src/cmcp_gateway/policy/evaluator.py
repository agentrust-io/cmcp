"""
Cedar policy evaluation via AGT's CedarBackend — implements issues #68, #73.

AGT provides three evaluation modes: cedarpy (native Python), cli (subprocess),
and builtin (mock). cMCP selects the best available mode at instantiation and
measures the policy bundle hash into the TEE attestation report separately.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agent_os.policies.backends import CedarBackend

from cmcp_gateway.config import Config, EnforcementMode
from cmcp_gateway.errors import PolicyDeny
from cmcp_gateway.policy.bundle import PolicyBundle, PolicyStore
from cmcp_gateway.session.state import SENSITIVITY_ORDER

if TYPE_CHECKING:
    from cmcp_gateway.session.state import SessionState

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


class PolicyEvaluator:
    """
    Wraps AGT's CedarBackend with cMCP enforcement modes.

    The bundle is loaded and hash-verified by load_policy_bundle() before this
    class is instantiated. CedarBackend receives the already-loaded policy content
    so the measured hash covers exactly the bytes that will be evaluated.
    """

    def __init__(self, bundle: PolicyBundle | PolicyStore, config: Config) -> None:
        self._mode = config.attestation.enforcement_mode

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

        self._backend = CedarBackend(
            policy_content=combined_policy,
            mode="auto",  # cedarpy > cli > builtin
        )
        logger.info(
            "PolicyEvaluator ready: bundle_hash=%s enforcement=%s backend=%s",
            initial_bundle.bundle_hash,
            self._mode.value,
            self._backend.__class__.__name__,
        )

    def _maybe_reload(self) -> None:
        """Check for a stale bundle and rebuild the CedarBackend if the hash changed."""
        self._store.reload_if_stale()
        bundle = self._store.bundle
        if bundle.bundle_hash != self._current_hash:
            combined_policy = "\n\n".join(
                content for _, content in sorted(bundle.policy_files.items())
            )
            self._backend = CedarBackend(policy_content=combined_policy, mode="auto")
            self._current_hash = bundle.bundle_hash
            logger.info("PolicyEvaluator backend refreshed: new_hash=%s", self._current_hash)

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

        # Cedar denied — apply enforcement mode
        if self._mode == EnforcementMode.ENFORCING:
            raise PolicyDeny(
                f"Policy denied tool call: {context.get('tool_name', '?')}",
                detail=f"rule={rule} eval_ms={evaluation_ms:.2f}",
            )

        if self._mode == EnforcementMode.ADVISORY:
            logger.info(
                "ADVISORY deny (allowed through): tool=%s rule=%s",
                context.get("tool_name"), rule,
            )
            return PolicyDecision(
                allowed=True,
                enforcement_mode=self._mode,
                rule_matched=rule,
                advice={},
                evaluation_ms=evaluation_ms,
                would_have_denied=True,
            )

        # SILENT mode — allow, no log
        return PolicyDecision(
            allowed=True,
            enforcement_mode=self._mode,
            rule_matched=rule,
            advice={},
            evaluation_ms=evaluation_ms,
            would_have_denied=True,
        )

    def authorize_egress(
        self,
        tool_name: str,
        response_bytes: bytes,
        session: SessionState,
    ) -> PolicyDecision:
        """
        Evaluate Cedar egress policies after a tool response is received.

        Uses the same CedarBackend as ingress evaluation but passes egress-specific
        context fields so Cedar policies can distinguish direction.  The principal
        and action are implicit in the context dict the backend receives.

        Returns PolicyDecision(allowed=True/False, ...).  In ENFORCING mode a deny
        raises PolicyDeny; in ADVISORY/SILENT a deny is flagged via would_have_denied.
        """
        self._maybe_reload()
        context: dict[str, Any] = {
            "tool_name": tool_name,
            "egress": True,
            "sensitivity_level": SENSITIVITY_ORDER.get(session.max_sensitivity, 0),
            "injection_events": len(session.injection_events),
            "reset_count": session.reset_count,
            "response_size_bytes": len(response_bytes),
        }
        return self.evaluate(context)

    @property
    def bundle_hash(self) -> str:
        return self._store.bundle.bundle_hash

    @property
    def enforcement_mode(self) -> EnforcementMode:
        return self._mode
