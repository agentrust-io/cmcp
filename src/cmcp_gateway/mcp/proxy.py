"""
MCP gateway proxy using AGT's MCPGateway + StatelessKernel — implements #48, #53, #54.

AGT's MCPGateway handles MCP protocol enforcement (tool allow/deny, parameter
sanitization, rate limiting, response scanning). cMCP wraps it so that every
enforcement decision flows through the audit chain and TRACE Claim machinery.

Network topology:
  Agent Host (MCP client) → CMCPProxy (this module, inside TEE)
                              → AGT MCPGateway (policy + scanning)
                                → upstream MCP servers (HTTP/SSE)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

from agent_os.mcp_gateway import GovernancePolicy, MCPGateway, ApprovalStatus
from agent_os.mcp_response_scanner import MCPResponseScanner

from cmcp_gateway.audit.chain import AuditChain
from cmcp_gateway.catalog.loader import ToolCatalog
from cmcp_gateway.config import Config, EnforcementMode
from cmcp_gateway.errors import PolicyDeny, TeeFault, ToolNotInCatalog
from cmcp_gateway.policy.evaluator import PolicyEvaluator
from cmcp_gateway.session.state import SessionState

logger = logging.getLogger(__name__)


@dataclass
class CallResult:
    """Outcome of a proxied MCP tool call."""

    call_id: str
    tool_name: str
    allowed: bool
    would_have_denied: bool
    response: Any | None
    deny_reason: str | None
    latency_us: int
    audit_entry_hash: str


class CMCPProxy:
    """
    Wraps AGT's MCPGateway so every tool call is:
      1. Checked against the attested catalog
      2. Evaluated by the Cedar PolicyEvaluator
      3. Forwarded through AGT's MCPGateway (rate limiting, sanitization, scanning)
      4. Logged to the TEE-sealed AuditChain
      5. Session state updated via inspection handoff

    One CMCPProxy instance per gateway session.
    """

    def __init__(
        self,
        catalog: ToolCatalog,
        policy_evaluator: PolicyEvaluator,
        session: SessionState,
        audit_chain: AuditChain,
        config: Config,
    ) -> None:
        self._catalog = catalog
        self._policy = policy_evaluator
        self._session = session
        self._audit = audit_chain
        self._config = config
        self._enforcement = config.attestation.enforcement_mode

        # Build AGT GovernancePolicy from cMCP catalog
        allowed_tools = list(catalog.entries.keys())
        gov_policy = GovernancePolicy(
            allowed_tools=allowed_tools,
        )

        # AGT MCPGateway — handles protocol, sanitization, rate limiting
        self._mcp_gateway = MCPGateway(
            policy=gov_policy,
            response_scanner=MCPResponseScanner(),
        )

    def _build_cedar_context(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Build the Cedar evaluation context from call details + session state."""
        entry = self._catalog.lookup(tool_name)
        return {
            "tool_name": tool_name,
            "server_identity": entry.server.url if entry else "",
            "compliance_domain": entry.compliance_domain if entry else "external",
            "baa_covered": (not entry.requires_baa) if entry else False,
            "destination_class": "external",
            "session_max_sensitivity": self._session.max_sensitivity,
            "workflow_id": getattr(self._session, "workflow_id", "default"),
        }

    async def call_tool(
        self,
        call_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> CallResult:
        """
        Execute one MCP tool call through the full enforcement pipeline.

        Pipeline:
          1. Catalog lookup (fast-path deny if not in catalog)
          2. Cedar policy evaluation
          3. AGT MCPGateway enforcement (sanitization, rate limit, scan)
          4. Forward to upstream (via AGT)
          5. Audit chain write
          6. Session state update

        Returns CallResult regardless of allow/deny so the caller can always
        write a complete audit entry.
        """
        import time

        t0 = time.perf_counter()
        sensitivity_before = self._session.max_sensitivity
        would_have_denied = False

        # Step 1: catalog lookup
        entry = self._catalog.lookup(tool_name)
        if entry is None:
            deny_reason = f"Tool '{tool_name}' not in attested catalog"
            self._audit.append(
                "tool_call",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=None,
                policy_decision="deny",
                policy_rule_matched="catalog_miss",
                request_payload_hash=None,
                session_sensitivity_before=sensitivity_before,
                session_sensitivity_after=self._session.max_sensitivity,
            )
            return CallResult(
                call_id=call_id,
                tool_name=tool_name,
                allowed=False,
                would_have_denied=False,
                response=None,
                deny_reason=deny_reason,
                latency_us=int((time.perf_counter() - t0) * 1_000_000),
                audit_entry_hash=self._audit.chain_tip,
            )

        # Step 2: Cedar policy evaluation
        cedar_context = self._build_cedar_context(tool_name, arguments)
        policy_rule: str | None = None
        try:
            decision = self._policy.evaluate(cedar_context)
            policy_rule = decision.rule_matched
            would_have_denied = decision.would_have_denied
        except PolicyDeny as exc:
            self._audit.append(
                "tool_call",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=entry.server.url,
                policy_decision="deny",
                policy_rule_matched=str(exc),
                session_sensitivity_before=sensitivity_before,
                session_sensitivity_after=self._session.max_sensitivity,
            )
            return CallResult(
                call_id=call_id,
                tool_name=tool_name,
                allowed=False,
                would_have_denied=False,
                response=None,
                deny_reason=str(exc),
                latency_us=int((time.perf_counter() - t0) * 1_000_000),
                audit_entry_hash=self._audit.chain_tip,
            )

        # Step 3: AGT MCPGateway enforcement
        # AGT handles per-agent rate limiting, parameter sanitization, and
        # response scanning. We pass tool_name as the action and arguments as params.
        try:
            agt_result = await self._mcp_gateway.call_tool(
                tool_name=tool_name,
                arguments=arguments,
                agent_id=self._session.session_id,
            )
        except Exception as exc:
            # AGT denied or errored — map to our error types
            logger.warning("AGT MCPGateway rejected call: tool=%s error=%s", tool_name, exc)
            self._audit.append(
                "tool_call",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=entry.server.url,
                policy_decision="deny",
                policy_rule_matched=f"agt_gateway:{type(exc).__name__}",
                session_sensitivity_before=sensitivity_before,
                session_sensitivity_after=self._session.max_sensitivity,
            )
            return CallResult(
                call_id=call_id,
                tool_name=tool_name,
                allowed=False,
                would_have_denied=would_have_denied,
                response=None,
                deny_reason=str(exc),
                latency_us=int((time.perf_counter() - t0) * 1_000_000),
                audit_entry_hash=self._audit.chain_tip,
            )

        # Step 4: session update from response sensitivity
        response_sensitivity = getattr(agt_result, "sensitivity_tags", [])
        injection_detected = getattr(agt_result, "injection_detected", False)
        self._session.update_from_inspection(
            call_id=call_id,
            sensitivity_tags=response_sensitivity or [entry.sensitivity_level],
            injection_detected=injection_detected,
            response_allowed=True,
        )

        # Step 5: audit chain write
        policy_decision = "advisory_deny" if would_have_denied else "allow"
        latency_us = int((time.perf_counter() - t0) * 1_000_000)
        self._audit.append(
            "tool_call",
            call_id=call_id,
            tool_name=tool_name,
            server_identity=entry.server.url,
            policy_decision=policy_decision,
            policy_rule_matched=policy_rule,
            latency_us=latency_us,
            session_sensitivity_before=sensitivity_before,
            session_sensitivity_after=self._session.max_sensitivity,
        )

        return CallResult(
            call_id=call_id,
            tool_name=tool_name,
            allowed=True,
            would_have_denied=would_have_denied,
            response=agt_result,
            deny_reason=None,
            latency_us=latency_us,
            audit_entry_hash=self._audit.chain_tip,
        )
