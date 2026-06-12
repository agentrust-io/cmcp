"""
MCP gateway proxy using AGT's MCPGateway + StatelessKernel - implements #48, #53, #54.

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

import httpx
from agent_os.mcp_gateway import GovernancePolicy, MCPGateway  # type: ignore[attr-defined]
from agent_os.mcp_response_scanner import MCPResponseScanner

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import CatalogEntry, ToolCatalog
from cmcp_runtime.config import Config
from cmcp_runtime.errors import PolicyDeny, UpstreamToolError, UpstreamUnavailable
from cmcp_runtime.policy.evaluator import PolicyEvaluator
from cmcp_runtime.session.call_log import CallLog, CallRecord, SessionCallLog
from cmcp_runtime.session.state import SessionState

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
    # Annotations from the forbid policies that matched (deny or advisory).
    # Sourced from the hash-pinned policy bundle, safe to reflect to callers.
    advice: dict[str, str] | None = None


def _cedar_safe(value: Any) -> Any:
    """
    Coerce a JSON value into types Cedar can ingest.

    Cedar has no float or null type: a single float anywhere in the request
    context makes cedarpy reject the whole request, which fails closed and
    denies the call. Floats are preserved as strings; None values are dropped
    (policies use `has` checks, so absence is the correct representation).
    """
    if isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        return str(value)
    if isinstance(value, dict):
        return {k: _cedar_safe(v) for k, v in value.items() if v is not None}
    if isinstance(value, list | tuple):
        return [_cedar_safe(v) for v in value if v is not None]
    return str(value)


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
        session_call_log: SessionCallLog | None = None,
        attestation_generated_at: datetime | None = None,
        attestation_validity_seconds: int = 86400,
        catalog_hash: str | None = None,
        attestation_platform: str = "unknown",
    ) -> None:
        self._catalog = catalog
        self._policy = policy_evaluator
        self._session = session
        self._audit = audit_chain
        self._config = config
        self._enforcement = config.attestation.enforcement_mode
        self._call_log: CallLog = call_log if call_log is not None else CallLog(session_id=session.session_id)
        self._session_call_log: SessionCallLog = (
            session_call_log if session_call_log is not None
            else SessionCallLog(session_id=session.session_id)
        )
        self._attestation_generated_at = attestation_generated_at
        self._attestation_validity_seconds = attestation_validity_seconds
        self._catalog_hash = catalog_hash or catalog.catalog_hash
        self._attestation_platform = attestation_platform

        # Build AGT GovernancePolicy from cMCP catalog
        allowed_tools = list(catalog.entries.keys())
        gov_policy = GovernancePolicy(
            allowed_tools=allowed_tools,
        )

        # AGT MCPGateway - handles protocol, sanitization, rate limiting
        self._mcp_gateway = MCPGateway(
            policy=gov_policy,
            response_scanner=MCPResponseScanner(),
        )

        # Shared async HTTP client for upstream forwarding; created lazily so
        # proxy construction stays sync and tests need no event loop.
        self._http: httpx.AsyncClient | None = None

    def rebind_session(self, session: SessionState, audit_chain: AuditChain) -> None:
        """
        Point the proxy at a fresh session after the previous one was closed.

        Call logs are recreated for the new session id; catalog, policy
        evaluator, and gateway are unchanged.
        """
        self._session = session
        self._audit = audit_chain
        self._call_log = CallLog(session_id=session.session_id)
        self._session_call_log = SessionCallLog(session_id=session.session_id)

    async def _forward_to_upstream(
        self,
        call_id: str,
        entry: CatalogEntry,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> str:
        """
        Forward the tool call to the attested upstream MCP server (JSON-RPC 2.0
        tools/call over HTTP POST to the catalog entry's server.url).

        Returns the concatenated text content of the MCP result.

        Raises UpstreamUnavailable on transport errors / non-2xx / non-JSON,
        UpstreamToolError when the upstream returns a JSON-RPC error object.
        """
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        payload = {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        try:
            resp = await self._http.post(entry.server.url, json=payload)
            resp.raise_for_status()
            body = resp.json()
        except httpx.HTTPError as exc:
            raise UpstreamUnavailable(
                f"Upstream MCP server unreachable: {entry.server.url}",
                detail=str(exc),
            ) from exc
        except ValueError as exc:
            raise UpstreamUnavailable(
                f"Upstream returned non-JSON body: {entry.server.url}",
                detail=str(exc),
            ) from exc
        if not isinstance(body, dict):
            raise UpstreamUnavailable(
                f"Upstream returned non-object JSON-RPC body: {entry.server.url}"
            )
        if "error" in body:
            error = body["error"] if isinstance(body["error"], dict) else {}
            raise UpstreamToolError(
                f"Upstream tool error from {tool_name}: "
                f"{str(error.get('message', 'unknown'))[:200]}"
            )
        result = body.get("result", {})
        content = result.get("content", []) if isinstance(result, dict) else []
        texts = [
            c.get("text", "")
            for c in content
            if isinstance(c, dict) and c.get("type") == "text"
        ]
        if texts:
            return "\n".join(texts)
        return json.dumps(result, default=str)

    def _check_health(self) -> str | None:
        """
        Check attestation staleness and catalog drift.

        Returns a reason string if unhealthy, or None if healthy.
        Side-effects: sets flags on session and appends audit entries on first detection.
        """
        # Attestation staleness check
        if self._attestation_generated_at is not None and not self._session.attestation_stale:
            age = datetime.now(UTC) - self._attestation_generated_at
            if age.total_seconds() > self._attestation_validity_seconds:
                logger.warning(
                    "Attestation stale: age_seconds=%.0f validity_seconds=%d",
                    age.total_seconds(),
                    self._attestation_validity_seconds,
                )
                self._session.attestation_stale = True
                self._audit.append(
                    "attestation_stale",
                    session_sensitivity_before=self._session.max_sensitivity,
                    session_sensitivity_after=self._session.max_sensitivity,
                )

        if self._session.attestation_stale:
            return "attestation_stale"

        # Catalog drift check
        if not self._session.catalog_drift:
            current_hash = self._catalog.catalog_hash
            if current_hash != self._catalog_hash:
                logger.warning(
                    "Catalog drift detected: expected=%s actual=%s",
                    self._catalog_hash,
                    current_hash,
                )
                self._session.catalog_drift = True
                self._audit.append(
                    "catalog_drift",
                    session_sensitivity_before=self._session.max_sensitivity,
                    session_sensitivity_after=self._session.max_sensitivity,
                )

        if self._session.catalog_drift:
            return "catalog_drift"

        return None

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
            "arguments": _cedar_safe(arguments),
            "server_identity": entry.server.url if entry else "",
            "compliance_domain": entry.compliance_domain if entry else "external",
            "baa_covered": (not entry.requires_baa) if entry else False,
            "destination_class": "external",
            "session_max_sensitivity": self._session.max_sensitivity,
            "attestation_platform": self._attestation_platform,
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
        *,
        call_id: str | None = None,
        catalog_entry: Any | None = None,
        policy_decision: str = "n/a",
        response_sensitivity_tags: list[str] | None = None,
    ) -> None:
        """
        Append a CallRecord to the session call log and check for suspicious
        sequences. On detection: write a suspicious_call_sequence audit entry
        and increment session.suspicious_sequences.

        Also records to the SessionCallLog for TRACE Claim call_graph_summary.
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
        # SessionCallLog: record with richer fields for call_graph_summary.
        if call_id is not None:
            self._session_call_log.record_call(
                call_id=call_id,
                catalog_entry=catalog_entry,
                policy_decision=policy_decision,
                response_sensitivity_tags=response_sensitivity_tags,
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

        # Step 0: health check (attestation staleness, catalog drift)
        unhealthy_reason = self._check_health()
        if unhealthy_reason is not None:
            return CallResult(
                call_id=call_id,
                tool_name=tool_name,
                allowed=False,
                would_have_denied=False,
                response=None,
                deny_reason=unhealthy_reason,
                latency_us=int((time.perf_counter() - t0) * 1_000_000),
                audit_entry_hash=self._audit.chain_tip,
            )

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
                call_id=call_id,
                catalog_entry=None,
                policy_decision="deny",
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

        # Step 1b: break-glass warning - log and audit every call via an exception entry
        if entry.catalog_exception:
            logger.warning(
                "BREAK_GLASS_ACTIVE: tool=%s call_id=%s server=%s",
                tool_name,
                call_id,
                entry.server.url,
            )
            self._audit.append(
                "break_glass_used",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=entry.server.url,
                policy_decision="allow",
                session_sensitivity_before=sensitivity_before,
                session_sensitivity_after=self._session.max_sensitivity,
                workflow_id=workflow_id,
            )

        # Step 2: Cedar policy evaluation
        cedar_context = self._build_cedar_context(tool_name, arguments, workflow_id)
        policy_rule: str | None = None
        ingress_advice: dict[str, str] = {}
        try:
            decision = self._policy.evaluate(cedar_context)
            policy_rule = decision.rule_matched
            would_have_denied = decision.would_have_denied
            ingress_advice = decision.advice
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
                call_id=call_id,
                catalog_entry=entry,
                policy_decision="deny",
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
                advice=exc.advice or None,
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

        # Step 3a: AGT MCPGateway pre-call interception - per-agent rate
        # limiting, parameter sanitization, allow/deny. Fail-closed inside AGT.
        agt_allowed, agt_reason = self._mcp_gateway.intercept_tool_call(
            agent_id=self._session.session_id,
            tool_name=tool_name,
            params=arguments,
        )
        if not agt_allowed:
            logger.warning(
                "AGT MCPGateway rejected call: tool=%s reason=%s", tool_name, agt_reason
            )
            self._audit.append(
                "tool_call",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=entry.server.url,
                policy_decision="deny",
                policy_rule_matched=f"agt_gateway:{agt_reason[:200]}",
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
                call_id=call_id,
                catalog_entry=entry,
                policy_decision="deny",
            )
            return CallResult(
                call_id=call_id,
                tool_name=tool_name,
                allowed=False,
                would_have_denied=would_have_denied,
                response=None,
                deny_reason=agt_reason,
                latency_us=int(elapsed_ms * 1000),
                audit_entry_hash=self._audit.chain_tip,
            )

        # Step 3b: forward to the attested upstream MCP server.
        try:
            response_text = await self._forward_to_upstream(
                call_id, entry, tool_name, arguments
            )
        except (UpstreamUnavailable, UpstreamToolError) as exc:
            logger.warning("Upstream call failed: tool=%s error=%s", tool_name, exc)
            self._audit.append(
                "fault",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=entry.server.url,
                policy_decision="fault",
                policy_rule_matched=f"upstream:{exc.code}",
                request_payload_hash=request_payload_hash,
                session_sensitivity_before=sensitivity_before,
                session_sensitivity_after=self._session.max_sensitivity,
                detail={"error_code": exc.code},
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            self._record_call(
                tool_name=tool_name,
                called_at=called_at,
                duration_ms=elapsed_ms,
                allowed=False,
                sensitivity_before=sensitivity_before,
                stage_results={"upstream": "fault"},
                call_id=call_id,
                catalog_entry=entry,
                policy_decision="fault",
            )
            return CallResult(
                call_id=call_id,
                tool_name=tool_name,
                allowed=False,
                would_have_denied=would_have_denied,
                response=None,
                deny_reason=f"upstream_error:{exc.code}",
                latency_us=int(elapsed_ms * 1000),
                audit_entry_hash=self._audit.chain_tip,
            )

        # Step 3c: response size guard (DOS-002) before scanning.
        if len(response_text.encode()) > self._config.max_response_size_bytes:
            self._audit.append(
                "tool_call",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=entry.server.url,
                policy_decision="deny",
                policy_rule_matched="response_size_exceeded",
                request_payload_hash=request_payload_hash,
                response_inspection_result="size_exceeded",
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
                stage_results={"inspection": "size_exceeded"},
                call_id=call_id,
                catalog_entry=entry,
                policy_decision="deny",
            )
            return CallResult(
                call_id=call_id,
                tool_name=tool_name,
                allowed=False,
                would_have_denied=would_have_denied,
                response=None,
                deny_reason="response_size_exceeded",
                latency_us=int(elapsed_ms * 1000),
                audit_entry_hash=self._audit.chain_tip,
            )

        # Step 3d: AGT response interception - injection / credential / PII scan.
        scan = self._mcp_gateway.intercept_tool_response(
            agent_id=self._session.session_id,
            tool_name=tool_name,
            response_content=response_text,
        )
        injection_detected = bool(scan.threats)
        if not scan.allowed:
            async with self._session.mutation_lock:
                self._session.update_from_inspection(
                    call_id=call_id,
                    sensitivity_tags=[entry.sensitivity_level],
                    injection_detected=injection_detected,
                    response_allowed=False,
                )
            threat_categories = ",".join(
                sorted({str(t.get("category", "unknown")) for t in scan.threats})
            )
            self._audit.append(
                "tool_call",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=entry.server.url,
                policy_decision="deny",
                policy_rule_matched=f"response_scan:{threat_categories[:200]}",
                request_payload_hash=request_payload_hash,
                response_inspection_result="injection_detected",
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
                stage_results={"response_scan": "deny"},
                call_id=call_id,
                catalog_entry=entry,
                policy_decision="deny",
            )
            return CallResult(
                call_id=call_id,
                tool_name=tool_name,
                allowed=False,
                would_have_denied=would_have_denied,
                response=None,
                deny_reason="response_blocked_by_scanner",
                latency_us=int(elapsed_ms * 1000),
                audit_entry_hash=self._audit.chain_tip,
            )
        # Scanner may have sanitized the content (ResponsePolicy.SANITIZE).
        agt_result: str = scan.content if scan.content is not None else response_text

        # Step 4: session update from response sensitivity
        # AUTH-002: lock protects against race with concurrent session reset requests.
        # Sensitivity comes from the attested catalog entry's declared level.
        response_sensitivity = [entry.sensitivity_level]
        injection_scanner = "agt_response_scanner" if injection_detected else None
        injection_pattern = (
            ",".join(sorted({str(t.get("category", "unknown")) for t in scan.threats}))
            if injection_detected
            else None
        )
        injection_threshold = None
        async with self._session.mutation_lock:
            self._session.update_from_inspection(
                call_id=call_id,
                sensitivity_tags=response_sensitivity,
                injection_detected=injection_detected,
                response_allowed=True,
            )

        # Step 5: egress Cedar policy check
        response_bytes: bytes = agt_result.encode()

        try:
            egress_decision = self._policy.authorize_egress(
                tool_name, response_bytes, self._session, workflow_id=workflow_id
            )
            egress_would_deny = egress_decision.would_have_denied
            egress_advice = egress_decision.advice
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
                advice=exc.advice or None,
            )

        # Merge egress advisory flag into the overall would_have_denied
        would_have_denied = would_have_denied or egress_would_deny
        advisory_advice = {**ingress_advice, **egress_advice}

        # Step 6: audit chain write
        policy_decision: Any = "advisory_deny" if would_have_denied else "allow"
        latency_us = int((time.perf_counter() - t0) * 1_000_000)
        # #293: bind the outcome into the audit entry. Hash exactly the bytes the
        # egress check saw (post-scan, possibly sanitized) so a verifier can match
        # the audited response against what the caller actually received.
        response_payload_hash = f"sha256:{hashlib.sha256(response_bytes).hexdigest()}"
        # INJECT-003: include injection scanner and pattern in audit detail when detected
        injection_detail: dict[str, str | int | float] | None = (
            {
                "injection_scanner": str(injection_scanner or "unknown")[:128],
                "matched_pattern": str(injection_pattern or "unknown")[:256],
                # INJECT-007: include threshold so the decision is replayable under config changes
                **({"injection_threshold": float(injection_threshold)} if isinstance(injection_threshold, int | float) else {}),
            }
            if injection_detected
            else None
        )
        self._audit.append(
            "tool_call",
            call_id=call_id,
            tool_name=tool_name,
            server_identity=entry.server.url,
            policy_decision=policy_decision,
            policy_rule_matched=policy_rule,
            latency_us=latency_us,
            request_payload_hash=request_payload_hash,
            response_payload_hash=response_payload_hash,
            session_sensitivity_before=sensitivity_before,
            session_sensitivity_after=self._session.max_sensitivity,
            workflow_id=workflow_id,
            detail=injection_detail,
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
            call_id=call_id,
            catalog_entry=entry,
            policy_decision=str(policy_decision),
            response_sensitivity_tags=list(response_sensitivity or []),
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
            advice=advisory_advice or None,
        )
