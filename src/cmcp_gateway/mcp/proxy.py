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

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from agent_os.mcp_gateway import GovernancePolicy, MCPGateway  # type: ignore[attr-defined]
from agent_os.mcp_response_scanner import MCPResponseScanner

from cmcp_gateway.audit.chain import AuditChain
from cmcp_gateway.catalog.loader import ToolCatalog
from cmcp_gateway.config import Config
from cmcp_gateway.errors import PolicyDeny
from cmcp_gateway.policy.evaluator import PolicyEvaluator
from cmcp_gateway.session.call_log import CallLog, CallRecord
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
        call_log: CallLog | None = None,
    ) -> None:
        self._catalog = catalog
        self._policy = policy_evaluator
        self._session = session
        self._audit = audit_chain
        self._config = config
        self._enforcement = config.attestation.enforcement_mode
        self._call_log: CallLog = call_log if call_log is not None else CallLog(session_id=session.session_id)

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
        self,
        tool_name: str,
        arguments: dict[str, Any],
        workflow_id: str | None = None,
    ) -> dict[str, Any]:
        """Build the Cedar evaluation context from call details + session state."""
        entry = self._catalog.lookup(tool_name)
        ctx: dict[str, Any] = {
            "tool_name": tool_name,
            "arguments": arguments,
            "server_identity": entry.server.url if entry else "",
            "compliance_domain": entry.compliance_domain if entry else "external",
            "baa_covered": (not entry.requires_baa) if entry else False,
            "destination_class": "external",
            "session_max_sensitivity": self._session.max_sensitivity,
        }
        if workflow_id is not None:
            ctx["workflow_id"] = workflow_id
        return ctx

    def _record_call(
        self,
        tool_name: str,
        called_at: datetime,
        duration_ms: float,
        allowed: bool,
        sensitivity_before: str,
        stage_results: dict[str, str],
    ) -> None:
        """
        Append a CallRecord to the session call log and check for suspicious
        sequences. On detection: write a suspicious_call_sequence audit entry
        and increment session.suspicious_sequences.
        """
        sensitivity_raised = self._session.max_sensitivity != sensitivity_before
        self._call_log.record(
            CallRecord(
                tool_name=tool_name,
                called_at=called_at,
                duration_ms=duration_ms,
                allowed=allowed,
                sensitivity_raised=sensitivity_raised,
                stage_results=stage_results,
            )
        )
        if self._call_log.suspicious_sequence():
            consecutive = self._call_log.consecutive_count(tool_name)
            self._audit.append(
                "suspicious_call_sequence",
                tool_name=tool_name,
                detail={"repeated_tool": tool_name, "consecutive_calls": consecutive},
                session_sensitivity_before=self._session.max_sensitivity,
                session_sensitivity_after=self._session.max_sensitivity,
            )
            self._session.suspicious_sequences += 1

    async def call_tool(
        self,
        call_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        workflow_id: str | None = None,
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
          7. Call log record + suspicious-sequence check

        Returns CallResult regardless of allow/deny so the caller can always
        write a complete audit entry.
        """
        import time

        t0 = time.perf_counter()
        called_at = datetime.now(UTC)
        sensitivity_before = self._session.max_sensitivity
        would_have_denied = False

        _payload_bytes = json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode()
        request_payload_hash = f"sha256:{hashlib.sha256(_payload_bytes).hexdigest()}"

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
                request_payload_hash=request_payload_hash,
                session_sensitivity_before=sensitivity_before,
                session_sensitivity_after=self._session.max_sensitivity,
                workflow_id=workflow_id,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            self._record_call(
                tool_name=tool_name,
                called_at=called_at,
                duration_ms=elapsed_ms,
                allowed=False,
                sensitivity_before=sensitivity_before,
                stage_results={"catalog": "deny"},
            )
            return CallResult(
                call_id=call_id,
                tool_name=tool_name,
                allowed=False,
                would_have_denied=False,
                response=None,
                deny_reason=deny_reason,
                latency_us=int(elapsed_ms * 1000),
                audit_entry_hash=self._audit.chain_tip,
            )

        # Step 2: Cedar policy evaluation
        cedar_context = self._build_cedar_context(tool_name, arguments, workflow_id)
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
                request_payload_hash=request_payload_hash,
                session_sensitivity_before=sensitivity_before,
                session_sensitivity_after=self._session.max_sensitivity,
                workflow_id=workflow_id,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            self._record_call(
                tool_name=tool_name,
                called_at=called_at,
                duration_ms=elapsed_ms,
                allowed=False,
                sensitivity_before=sensitivity_before,
                stage_results={"policy": "deny"},
            )
            return CallResult(
                call_id=call_id,
                tool_name=tool_name,
                allowed=False,
                would_have_denied=False,
                response=None,
                deny_reason=str(exc),
                latency_us=int(elapsed_ms * 1000),
                audit_entry_hash=self._audit.chain_tip,
            )
        except Exception as exc:
            # POLICY-003: Cedar backend raised an unexpected exception (e.g. malformed
            # policy). Write a fault audit entry so the incident is traceable, then
            # re-raise so server.py can return a generic 500.
            logger.error("CEDAR_FAULT: tool=%s error=%s", tool_name, exc, exc_info=True)
            self._audit.append(
                "fault",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=entry.server.url,
                policy_decision="fault",
                policy_rule_matched=f"cedar_exception:{type(exc).__name__}",
                request_payload_hash=request_payload_hash,
                session_sensitivity_before=sensitivity_before,
                session_sensitivity_after=self._session.max_sensitivity,
                detail={"exception_type": type(exc).__name__},
            )
            raise

        # Step 3: AGT MCPGateway enforcement
        # AGT handles per-agent rate limiting, parameter sanitization, and
        # response scanning. We pass tool_name as the action and arguments as params.
        try:
            agt_result = await self._mcp_gateway.call_tool(  # type: ignore[attr-defined]
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
                request_payload_hash=request_payload_hash,
                session_sensitivity_before=sensitivity_before,
                session_sensitivity_after=self._session.max_sensitivity,
                workflow_id=workflow_id,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            self._record_call(
                tool_name=tool_name,
                called_at=called_at,
                duration_ms=elapsed_ms,
                allowed=False,
                sensitivity_before=sensitivity_before,
                stage_results={"agt_gateway": "deny"},
            )
            return CallResult(
                call_id=call_id,
                tool_name=tool_name,
                allowed=False,
                would_have_denied=would_have_denied,
                response=None,
                deny_reason=str(exc),
                latency_us=int(elapsed_ms * 1000),
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

        # Step 5: egress Cedar policy check
        # Derive response bytes for size accounting and egress evaluation.
        # Prefer a bytes-typed modified_response (Stage 2 redaction output);
        # fall back to str() so we never block on an un-serialisable AGT object.
        modified = getattr(agt_result, "modified_response", None)
        if isinstance(modified, bytes):
            response_bytes: bytes = modified
        else:
            response_bytes = str(agt_result).encode()

        try:
            egress_decision = self._policy.authorize_egress(
                tool_name, response_bytes, self._session
            )
            egress_would_deny = egress_decision.would_have_denied
        except PolicyDeny as exc:
            egress_deny_reason = str(exc)
            self._audit.append(
                "egress_denied",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=entry.server.url,
                policy_decision="deny",
                policy_rule_matched=egress_deny_reason,
                request_payload_hash=request_payload_hash,
                session_sensitivity_before=sensitivity_before,
                session_sensitivity_after=self._session.max_sensitivity,
            )
            return CallResult(
                call_id=call_id,
                tool_name=tool_name,
                allowed=False,
                would_have_denied=False,
                response=None,
                deny_reason=egress_deny_reason,
                latency_us=int((time.perf_counter() - t0) * 1_000_000),
                audit_entry_hash=self._audit.chain_tip,
            )

        # Merge egress advisory flag into the overall would_have_denied
        would_have_denied = would_have_denied or egress_would_deny

        # Step 6: audit chain write
        policy_decision: Any = "advisory_deny" if would_have_denied else "allow"
        latency_us = int((time.perf_counter() - t0) * 1_000_000)
        self._audit.append(
            "tool_call",
            call_id=call_id,
            tool_name=tool_name,
            server_identity=entry.server.url,
            policy_decision=policy_decision,
            policy_rule_matched=policy_rule,
            latency_us=latency_us,
            request_payload_hash=request_payload_hash,
            session_sensitivity_before=sensitivity_before,
            session_sensitivity_after=self._session.max_sensitivity,
            workflow_id=workflow_id,
        )

        # Step 6: call log record + suspicious-sequence check
        elapsed_ms = (time.perf_counter() - t0) * 1000
        self._record_call(
            tool_name=tool_name,
            called_at=called_at,
            duration_ms=elapsed_ms,
            allowed=True,
            sensitivity_before=sensitivity_before,
            stage_results={"policy": str(policy_decision)},
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
