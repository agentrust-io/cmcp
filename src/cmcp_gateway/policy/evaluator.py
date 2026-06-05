"""
Cedar policy evaluation via AGT's CedarBackend — implements issues #68, #73.

AGT provides three evaluation modes: cedarpy (native Python), cli (subprocess),
and builtin (mock). cMCP selects the best available mode at instantiation and
measures the policy bundle hash into the TEE attestation report separately.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from agent_os.policies.backends import CedarBackend

from cmcp_gateway.config import Config, EnforcementMode
from cmcp_gateway.errors import PolicyDeny
from cmcp_gateway.policy.bundle import PolicyBundle

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

    def __init__(self, bundle: PolicyBundle, config: Config) -> None:
        self._mode = config.attestation.enforcement_mode
        self._bundle = bundle

        # Concatenate all Cedar policy files into one string for CedarBackend.
        # Files are sorted by name to match the hash computation in bundle.py.
        combined_policy = "\n\n".join(
            content for _, content in sorted(bundle.policy_files.items())
        )

        self._backend = CedarBackend(
            policy_content=combined_policy,
            mode="auto",  # cedarpy > cli > builtin
        )
        logger.info(
            "PolicyEvaluator ready: bundle_hash=%s enforcement=%s backend=%s",
            bundle.bundle_hash,
            self._mode.value,
            self._backend.__class__.__name__,
        )

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

    @property
    def bundle_hash(self) -> str:
        return self._bundle.bundle_hash

    @property
    def enforcement_mode(self) -> EnforcementMode:
        return self._mode
