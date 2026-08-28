"""MCP gateway proxy with cMCP-owned runtime enforcement.

Every enforcement decision flows through the audit chain and TRACE Claim
machinery. AGT is used only as isolated CI/release governance tooling.

Network topology:
  Agent Host (MCP client) → CMCPProxy (this module, inside TEE)
                              → cMCP runtime gateway (policy + scanning)
                                → upstream MCP servers (HTTP/SSE)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import httpx

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import (
    CatalogEntry,
    ToolCatalog,
    advertised_definition_digest,
    approved_definition_digest,
)
from cmcp_runtime.catalog.scanner import CatalogScanner
from cmcp_runtime.config import Config, DriftPolicy
from cmcp_runtime.errors import PolicyDeny, UpstreamToolError, UpstreamUnavailable
from cmcp_runtime.mcp import tls_pinning
from cmcp_runtime.mcp.stdio import StdioServer
from cmcp_runtime.mcp.streamable_http import (
    build_request,
    parameter_headers,
    parse_response,
)
from cmcp_runtime.policy.decisions import audit_value
from cmcp_runtime.policy.evaluator import PolicyEvaluator
from cmcp_runtime.provenance import ProvenanceResult, check_server_provenance
from cmcp_runtime.runtime_gateway import GovernancePolicy, MCPGateway, MCPResponseScanner
from cmcp_runtime.session.call_log import CallLog, CallRecord, SessionCallLog
from cmcp_runtime.session.state import SessionState, _max_sensitivity

logger = logging.getLogger(__name__)

_EXTERNAL_EVIDENCE_FIELDS: frozenset[str] = frozenset(
    {
        "issuer",
        "issuer_key_id",
        "signature",
        "evidence_hash",
        "evidence_type",
        "linked_call_id",
    }
)


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


class _EffectBoundaryState(StrEnum):
    """Monotonic evidence states for one upstream tool invocation."""

    PRE_TRANSPORT = "pre_transport"
    TRANSPORT_MAY_HAVE_STARTED = "transport_may_have_started"
    TRANSPORT_RESPONSE_RECEIVED = "transport_response_received"
    TERMINAL_DURABLE = "terminal_durable"


@dataclass
class _CallFinalizationState:
    """Per-invocation facts needed for honest terminal finalization."""

    failure_stage: str = "call_entry"
    effect_boundary_state: _EffectBoundaryState = _EffectBoundaryState.PRE_TRANSPORT
    request_payload_hash: str | None = None
    response_payload_hash: str | None = None
    server_identity: str | None = None
    external_execution_evidence: dict[str, str] | None = None
    terminal_entry_id: str | None = None

    @property
    def terminal_disposition(self) -> str:
        return (
            "not_attempted"
            if self.effect_boundary_state is _EffectBoundaryState.PRE_TRANSPORT
            else "outcome_unknown"
        )

    @property
    def effect_boundary_label(self) -> str:
        return {
            _EffectBoundaryState.PRE_TRANSPORT: "not_reached",
            _EffectBoundaryState.TRANSPORT_MAY_HAVE_STARTED: "transport_may_have_started",
            _EffectBoundaryState.TRANSPORT_RESPONSE_RECEIVED: "transport_response_received",
            _EffectBoundaryState.TERMINAL_DURABLE: "terminal_durable",
        }[self.effect_boundary_state]


def _server_execution_key(entry: CatalogEntry) -> tuple[str, ...]:
    """Return the security-relevant identity used to pool one upstream."""
    server = entry.server
    if server.is_stdio:
        spawn = server.spawn
        return (
            "stdio",
            spawn.command if spawn else "",
            *(spawn.args if spawn else ()),
            "measure_target=" + (spawn.measure_target if spawn and spawn.measure_target else ""),
            "binary_digest=" + (spawn.binary_digest if spawn and spawn.binary_digest else ""),
        )
    return (
        "network",
        server.transport,
        server.url,
        server.tls_fingerprint,
        server.spiffe_id or "",
        server.rotation_mode,
    )


def _server_provenance_key(entry: CatalogEntry) -> tuple[str, ...]:
    """Bind a cached provenance verdict to endpoint and configured authority."""
    server = entry.server
    publisher_key = (
        json.dumps(server.publisher_jwk, sort_keys=True, separators=(",", ":"))
        if server.publisher_jwk is not None
        else ""
    )
    return (
        *_server_execution_key(entry),
        "record=" + (server.provenance_record_path or ""),
        "publisher_jwk=" + publisher_key,
    )


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


def _extract_external_execution_evidence(response_text: str) -> dict[str, str] | None:
    """Return a well-formed external execution receipt from a JSON response, if present."""
    try:
        decoded = json.loads(response_text)
    except json.JSONDecodeError:
        return None
    if not isinstance(decoded, dict):
        return None

    receipt = decoded.get("external_execution_evidence")
    if receipt is None:
        return None
    if not isinstance(receipt, dict):
        logger.warning("EXTERNAL_EVIDENCE_IGNORED: external_execution_evidence is not an object")
        return None
    if set(receipt) != _EXTERNAL_EVIDENCE_FIELDS:
        logger.warning("EXTERNAL_EVIDENCE_IGNORED: external_execution_evidence fields mismatch")
        return None
    if not all(isinstance(receipt[field], str) for field in _EXTERNAL_EVIDENCE_FIELDS):
        logger.warning(
            "EXTERNAL_EVIDENCE_IGNORED: external_execution_evidence values must be strings"
        )
        return None
    return {field: receipt[field] for field in sorted(_EXTERNAL_EVIDENCE_FIELDS)}


class CMCPProxy:
    """
    Enforces every tool call through the cMCP runtime gateway:
      1. Checked against the attested catalog
      2. Evaluated by the Cedar PolicyEvaluator
      3. Checked for rate limits, dangerous parameters, and unsafe responses
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
        catalog_scanner: CatalogScanner | None = None,
    ) -> None:
        self._catalog = catalog
        self._policy = policy_evaluator
        self._session = session
        self._audit = audit_chain
        self._config = config
        self._enforcement = config.attestation.enforcement_mode
        self._call_log: CallLog = (
            call_log if call_log is not None else CallLog(session_id=session.session_id)
        )
        self._session_call_log: SessionCallLog = (
            session_call_log
            if session_call_log is not None
            else SessionCallLog(session_id=session.session_id)
        )
        self._attestation_generated_at = attestation_generated_at
        self._attestation_validity_seconds = attestation_validity_seconds
        self._catalog_hash = catalog_hash or catalog.catalog_hash
        self._attestation_platform = attestation_platform

        # Build the runtime policy from the attested cMCP catalog.
        allowed_tools = list(catalog.entries.keys())
        gov_policy = GovernancePolicy(
            allowed_tools=allowed_tools,
        )

        # cMCP-owned protocol, sanitization, and rate-limit enforcement.
        self._mcp_gateway = MCPGateway(
            policy=gov_policy,
            response_scanner=MCPResponseScanner(),
        )

        # Async HTTP clients for upstream forwarding, keyed by TLS pin so each
        # pinned upstream gets a transport that enforces its own catalog
        # fingerprint (#281). Created lazily so proxy construction stays sync
        # and tests need no event loop.
        self._http_clients: dict[str, httpx.AsyncClient] = {}
        # Spawned stdio servers, one child per server for the life of this
        # session and never pooled across sessions: a server that holds anything
        # in memory would carry it from one agent's session into the next, and
        # the audit chain cannot see that happen (docs/spec/stdio-transport.md).
        self._stdio_servers: dict[tuple[str, ...], StdioServer] = {}
        # Provenance outcome per server, decided once per session on first use.
        # Cached because the answer cannot change within a session without the
        # server being replaced underneath us, and re-listing tools on every call
        # would make the check expensive enough to be turned off.
        self._provenance: dict[tuple[str, ...], ProvenanceResult] = {}
        # Servers already warned about unenforceable pinning (warn once each).
        self._tls_pin_warned: set[str] = set()
        # #521: servers whose advertised tool definitions have been compared against
        # the catalog. Cached per server for the same reason provenance is: one
        # tools/list round trip per server per session is affordable, one per call
        # is not, and a check expensive enough to hurt is a check that gets disabled.
        self._drift_checked: set[tuple[str, ...]] = set()
        self._catalog_scanner = catalog_scanner

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

    def _warn_pin_unenforced(self, server_url: str, reason: str) -> None:
        """Log TLS_PIN_UNENFORCED once per server URL (#281, dev/demo paths)."""
        if server_url in self._tls_pin_warned:
            return
        self._tls_pin_warned.add(server_url)
        logger.warning("TLS_PIN_UNENFORCED: server=%s: %s", server_url, reason)

    def _client_for_upstream(self, entry: CatalogEntry) -> httpx.AsyncClient:
        """
        Return (creating on first use) the HTTP client for this catalog entry,
        enforcing the catalog TLS fingerprint pin (#281).

        - https + real pin: client with tls_pinning.PinnedTransport. The peer
          certificate's SHA-256 fingerprint is checked at TLS handshake time,
          before any request bytes are written; a mismatch aborts the
          connection (fail closed). Standard CA verification still applies -
          the pin is additive.
        - https + PLACEHOLDER_FINGERPRINT: unpinned dev mode. The examples ship
          this all-"A" placeholder, meaning "no pin recorded yet"; warn once
          per server and proceed with standard CA verification only.
        - https + malformed pin: fail closed (UpstreamUnavailable) - a pin that
          cannot be compared must never silently degrade to unpinned.
        - http: pinning is impossible without TLS; warn once per server
          (dev/demo only) and proceed.

        Every branch keys the cached client on ``_server_execution_key(entry)``
        (the same "security-relevant identity used to pool one upstream" that
        ``_stdio_for`` keys its spawned children on), not only the pinned
        branch. A cache keyed on the literal string ``"unpinned"`` would give
        every plain-http and placeholder-pinned server in this session's
        catalog the *same* ``httpx.AsyncClient`` - and therefore the same
        cookie jar and connection-pool limits - regardless of how unrelated
        those upstreams are. Two catalog entries that happen to share one real
        pinned fingerprint correctly share a client: a matching pin *is* the
        same verified peer. Two that merely share the fact that neither is
        pinned are not the same peer, and must not share state meant to be
        scoped to one.
        """
        server_url = entry.server.url
        fingerprint = entry.server.tls_fingerprint
        scheme = httpx.URL(server_url).scheme.lower()
        identity = _server_execution_key(entry)
        if scheme != "https":
            self._warn_pin_unenforced(
                server_url,
                "upstream is not https, TLS fingerprint pinning is impossible - "
                "plain-http upstreams are for local dev/demo only",
            )
            key = f"unpinned:{identity}"
        elif fingerprint == tls_pinning.PLACEHOLDER_FINGERPRINT:
            self._warn_pin_unenforced(
                server_url,
                "catalog tls_fingerprint is the unpinned-dev placeholder - peer "
                "identity is verified by CA trust only, not pinned to the catalog",
            )
            key = f"unpinned:{identity}"
        elif not tls_pinning.FINGERPRINT_PATTERN.match(fingerprint):
            raise UpstreamUnavailable(
                f"Catalog tls_fingerprint for {server_url} is malformed - refusing to connect",
                detail=f"tls_fingerprint={fingerprint[:64]!r}",
            )
        else:
            key = f"pin:{fingerprint}"

        client = self._http_clients.get(key)
        if client is None:
            timeout = httpx.Timeout(30.0)
            if key.startswith("unpinned:"):
                client = httpx.AsyncClient(
                    timeout=timeout, verify=tls_pinning.default_ssl_context()
                )
            else:
                client = httpx.AsyncClient(
                    timeout=timeout, transport=tls_pinning.PinnedTransport(fingerprint)
                )
            self._http_clients[key] = client
        return client

    async def _stdio_for(self, entry: CatalogEntry) -> StdioServer:
        """The child for this server, spawned on first use in this session."""
        key = _server_execution_key(entry)
        server = self._stdio_servers.get(key)
        if server is None:
            if entry.server.spawn is None:
                raise UpstreamUnavailable(
                    f"catalog entry {entry.tool_name!r} declares stdio transport with no "
                    "spawn block; there is nothing to start"
                )
            server = StdioServer(
                entry.server.spawn,
                allow_unmeasured=self._config.attestation.allow_unmeasured_spawn,
            )
            await server.start()
            self._stdio_servers[key] = server
        return server

    async def aclose(self) -> None:
        """Terminate spawned children. A session that ends leaves nothing running."""
        for server in self._stdio_servers.values():
            await server.close()
        self._stdio_servers.clear()

    async def _advertised_tools(self, entry: CatalogEntry) -> list[dict[str, Any]] | None:
        """What the server offers *this gateway*, for the provenance comparison.

        Returns ``None`` when the server will not say, which the caller records as
        ``unchecked`` rather than as a pass. Never falls back to the catalog's own
        approved definitions: comparing a record against our approval instead of
        against the server is the substitution that turns the check into theatre.
        """
        if entry.server.is_stdio:
            return await (await self._stdio_for(entry)).list_tools()
        try:
            client = self._client_for_upstream(entry)
            payload, headers = build_request("provenance-tools-list", "tools/list", {})
            resp = await client.post(
                entry.server.url,
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            result = parse_response(resp, "provenance-tools-list").get("result")
        except Exception as exc:  # noqa: BLE001 - any failure means "could not check"
            logger.warning("could not list tools for provenance check: %s", exc)
            return None
        tools = result.get("tools") if isinstance(result, dict) else None
        return tools if isinstance(tools, list) else None

    async def _check_upstream_drift(self, entry: CatalogEntry) -> bool:
        """Compare what a server advertises against what we approved (P4.2).

        Runs once per server per session, on first contact. Returns True when the
        call must be denied.

        The authoritative comparison is a digest of the semantic triple
        (description, input schema, output schema), computed with the standard
        library on both sides. The native scanner classifies the kind of change;
        the independent digest comparison remains the enforcing control.

        A server that will not answer ``tools/list`` is recorded as unchecked and
        is NOT denied. Denying would take out every deployment whose servers do
        not implement it, and this check would be switched off within a day. That
        is a real gap and LIMITATIONS.md says so rather than leaving it implied.
        """
        key = _server_provenance_key(entry)
        if key in self._drift_checked:
            return self._session.catalog_drift
        self._drift_checked.add(key)

        advertised = await self._advertised_tools(entry)
        if advertised is None:
            logger.info(
                "upstream drift: server=%s outcome=unchecked (server would not list tools)",
                key,
            )
            return self._session.catalog_drift

        by_name = {
            t.get("name"): t
            for t in advertised
            if isinstance(t, dict) and isinstance(t.get("name"), str)
        }
        drifted: list[tuple[str, str]] = []
        for tool_name, catalog_entry in self._catalog.entries.items():
            if _server_provenance_key(catalog_entry) != key:
                continue
            offered = by_name.get(tool_name)
            if offered is None:
                drifted.append((tool_name, "withdrawn"))
                continue
            if advertised_definition_digest(offered) != approved_definition_digest(
                catalog_entry.approved_definition
            ):
                drifted.append((tool_name, "definition_changed"))

        if not drifted:
            logger.info("upstream drift: server=%s outcome=match", key)
            return self._session.catalog_drift

        fail_closed = self._config.catalog.drift_policy is DriftPolicy.FAIL_CLOSED
        for tool_name, kind in drifted:
            classification = kind
            if self._catalog_scanner is not None and (offered := by_name.get(tool_name)):
                result = self._catalog_scanner.check_drift(
                    tool_name=tool_name,
                    server_name=catalog_entry.server.display_name or catalog_entry.server.url,
                    current_definition=offered,
                )
                if result.available and result.threats:
                    classification = ";".join(t.get("threat_type", "?") for t in result.threats)
            logger.error(
                "UPSTREAM_CATALOG_DRIFT tool=%s server=%s kind=%s policy=%s",
                tool_name,
                key,
                classification,
                self._config.catalog.drift_policy.value,
            )
            if tool_name not in self._session.upstream_drift_tools:
                self._session.upstream_drift_tools.append(tool_name)
            self._audit.append(
                "catalog_drift",
                tool_name=tool_name,
                detail={"kind": kind, "classification": classification, "source": "upstream"},
                session_sensitivity_before=self._session.max_sensitivity,
                session_sensitivity_after=self._session.max_sensitivity,
            )

        if fail_closed:
            self._session.catalog_drift = True
        return self._session.catalog_drift

    async def _check_provenance(self, entry: CatalogEntry) -> ProvenanceResult:
        key = _server_provenance_key(entry)
        result = self._provenance.get(key)
        if result is None:
            advertised = (
                await self._advertised_tools(entry) if entry.server.provenance_record_path else None
            )
            result = check_server_provenance(
                entry.server.provenance_record_path,
                entry.server.publisher_jwk,
                advertised,
            )
            self._provenance[key] = result
            logger.info(
                "provenance: server=%s outcome=%s kind=%s",
                key,
                result.outcome.value,
                result.kind or "-",
            )
        return result

    async def _forward_to_upstream(
        self,
        call_id: str,
        entry: CatalogEntry,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        finalization: _CallFinalizationState | None = None,
    ) -> str:
        """
        Forward the tool call to the attested upstream MCP server (JSON-RPC 2.0
        tools/call over HTTP POST to the catalog entry's server.url).

        Returns the concatenated text content of the MCP result.

        Raises UpstreamUnavailable on transport errors / non-2xx / non-JSON /
        TLS fingerprint pin mismatch (#281, fail closed before the request is
        sent), UpstreamToolError when the upstream returns a JSON-RPC error
        object.
        """
        provenance = await self._check_provenance(entry)
        required = self._config.attestation.required_provenance_kind
        if not provenance.meets(required):
            raise UpstreamUnavailable(
                f"server provenance is {provenance.outcome.value} and this deployment "
                f"requires {required}: {entry.server.display_name}",
                detail=provenance.detail,
            )

        if entry.server.is_stdio:
            server = await self._stdio_for(entry)
            if finalization is not None:
                finalization.failure_stage = "stdio_server_call"
                finalization.effect_boundary_state = _EffectBoundaryState.TRANSPORT_MAY_HAVE_STARTED
            return await server.call(call_id, tool_name, arguments)

        client = self._client_for_upstream(entry)
        payload, headers = build_request(
            call_id,
            "tools/call",
            {"name": tool_name, "arguments": arguments},
            name=tool_name,
        )
        headers.update(parameter_headers(entry.approved_definition.input_schema, arguments))
        if finalization is not None:
            finalization.failure_stage = "http_transport"
            finalization.effect_boundary_state = _EffectBoundaryState.TRANSPORT_MAY_HAVE_STARTED
        try:
            resp = await client.post(entry.server.url, json=payload, headers=headers)
            if finalization is not None:
                finalization.effect_boundary_state = (
                    _EffectBoundaryState.TRANSPORT_RESPONSE_RECEIVED
                )
            resp.raise_for_status()
            body = parse_response(resp, call_id)
        except tls_pinning.TLSPinMismatchError as exc:
            if finalization is not None:
                finalization.failure_stage = "tls_pin_verification_pre_send"
                finalization.effect_boundary_state = _EffectBoundaryState.PRE_TRANSPORT
            raise UpstreamUnavailable(
                f"Upstream TLS certificate fingerprint does not match the attested "
                f"catalog pin: {entry.server.url} - connection rejected before the "
                "request was sent (possible MITM)",
                detail=str(exc),
            ) from exc
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
            c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"
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
        call_data_class: str | None = None,
    ) -> dict[str, Any]:
        """Build Cedar context, conservatively including this call's class."""
        entry = self._catalog.lookup(tool_name)
        effective_sensitivity = self._session.max_sensitivity
        if entry is not None:
            effective_sensitivity = _max_sensitivity(
                effective_sensitivity,
                call_data_class or entry.sensitivity_level,
                self._session.sensitivity_order,
            )
        ctx: dict[str, Any] = {
            "tool_name": tool_name,
            # Cedar resource entity: the backend builds Resource::"<resource>" from
            # this, so policies can match a tool by name, e.g.
            #   forbid(principal, action, resource == Resource::"salesforce.contacts");
            # Without it the resource defaults to Resource::"default" and no
            # resource-scoped policy can ever match.
            "resource": tool_name,
            "arguments": _cedar_safe(arguments),
            "server_identity": entry.server.url if entry else "",
            "compliance_domain": entry.compliance_domain if entry else "external",
            "baa_covered": (not entry.requires_baa) if entry else False,
            "destination_class": "external",
            # Policy sees the running session maximum raised by this call's
            # effective class. A caller declaration is never trusted to lower
            # either the catalog floor or sensitivity accumulated earlier.
            "session_max_sensitivity": effective_sensitivity,
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

    def _append_call_terminal(
        self,
        finalization: _CallFinalizationState,
        entry_type: str,
        **fields: Any,
    ) -> None:
        """Persist one terminal for this invocation, independent of call_id reuse."""
        if finalization.terminal_entry_id is not None:
            raise RuntimeError("terminal audit entry already persisted for this invocation")
        entry = self._audit.append(entry_type, **fields)  # type: ignore[arg-type]
        finalization.terminal_entry_id = entry.entry_id
        finalization.effect_boundary_state = _EffectBoundaryState.TERMINAL_DURABLE

    def _finalize_unexpected_call_failure(
        self,
        finalization: _CallFinalizationState,
        exc: BaseException,
        *,
        call_id: str,
        tool_name: str,
        workflow_id: str | None,
    ) -> None:
        """Best-effort durable fault without laundering an uncertain outcome."""
        if finalization.terminal_entry_id is not None:
            return
        pointer_state = (
            "bound"
            if finalization.external_execution_evidence is not None
            else "unavailable_or_unbound"
        )
        try:
            self._append_call_terminal(
                finalization,
                "fault",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=finalization.server_identity,
                policy_decision="fault",
                policy_rule_matched=f"unexpected:{type(exc).__name__}",
                request_payload_hash=finalization.request_payload_hash,
                response_payload_hash=finalization.response_payload_hash,
                session_sensitivity_before=self._session.max_sensitivity,
                session_sensitivity_after=self._session.max_sensitivity,
                detail={
                    "exception_type": type(exc).__name__,
                    "failure_stage": finalization.failure_stage,
                    "effect_boundary": finalization.effect_boundary_label,
                    "effect_boundary_state": finalization.effect_boundary_state.value,
                    "terminal_disposition": finalization.terminal_disposition,
                    "external_execution_evidence_state": pointer_state,
                },
                workflow_id=workflow_id,
                external_execution_evidence=(finalization.external_execution_evidence),
            )
        except (Exception, asyncio.CancelledError) as persistence_exc:
            exc.add_note(
                "terminal audit persistence failed with "
                f"{type(persistence_exc).__name__} during "
                f"{finalization.failure_stage}"
            )
            raise exc from persistence_exc

    async def call_tool(
        self,
        call_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        workflow_id: str | None = None,
        declared_data_class: str | None = None,
    ) -> CallResult:
        """Run one call and guarantee one terminal on failure or cancellation."""
        finalization = _CallFinalizationState()
        try:
            return await self._call_tool_impl(
                call_id,
                tool_name,
                arguments,
                workflow_id,
                declared_data_class,
                _finalization=finalization,
            )
        except BaseException as exc:
            if not isinstance(exc, (Exception, asyncio.CancelledError)):
                raise
            self._finalize_unexpected_call_failure(
                finalization,
                exc,
                call_id=call_id,
                tool_name=tool_name,
                workflow_id=workflow_id,
            )
            raise

    async def _call_tool_impl(
        self,
        call_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        workflow_id: str | None = None,
        declared_data_class: str | None = None,
        *,
        _finalization: _CallFinalizationState,
    ) -> CallResult:
        """
        Execute one MCP tool call through the full enforcement pipeline.

        Pipeline:
          1. Catalog lookup (fast-path deny if not in catalog)
          2. Cedar policy evaluation
          3. cMCP runtime enforcement (sanitization, rate limit, scan)
          4. Forward to upstream
          5. Audit chain write
          6. Session state update
          7. Call log record + suspicious-sequence check

        declared_data_class (#479 piece 2): an optional class the caller declares
        for this specific call via _cmcp.data_class, raising this call's effective
        class above the tool's catalogued sensitivity_level. It can never lower
        the effective class and an unrecognised value is harmless: both properties
        fall directly out of _max_sensitivity's semantics, no separate validation
        needed here.

        Returns CallResult regardless of allow/deny so the caller can always
        write a complete audit entry.
        """
        import time

        t0 = time.perf_counter()
        called_at = datetime.now(UTC)
        sensitivity_before = self._session.max_sensitivity
        would_have_denied = False

        # Step 0: health check (attestation staleness, catalog drift)
        _finalization.failure_stage = "health_check"
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

        _finalization.failure_stage = "request_serialization"
        _payload_bytes = json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode()
        request_payload_hash = f"sha256:{hashlib.sha256(_payload_bytes).hexdigest()}"
        _finalization.request_payload_hash = request_payload_hash

        # Step 1: catalog lookup
        _finalization.failure_stage = "catalog_lookup"
        entry = self._catalog.lookup(tool_name)
        if entry is None:
            deny_reason = f"Tool '{tool_name}' not in attested catalog"
            self._append_call_terminal(
                _finalization,
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

        _finalization.server_identity = entry.server.url

        # Step 1a (#521): does this server still offer what we approved? First
        # contact with each server only, so the cost is one tools/list per server
        # per session. Placed after the catalog lookup because it needs the entry
        # to know which server to ask, and before the policy decision because a
        # server that has been swapped underneath us should not reach Cedar at all.
        _finalization.failure_stage = "upstream_drift_check"
        if await self._check_upstream_drift(entry):
            elapsed_ms = (time.perf_counter() - t0) * 1000
            self._record_call(
                tool_name=tool_name,
                called_at=called_at,
                duration_ms=elapsed_ms,
                allowed=False,
                sensitivity_before=sensitivity_before,
                stage_results={"catalog": "deny"},
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
                deny_reason="catalog_drift",
                latency_us=int(elapsed_ms * 1000),
                audit_entry_hash=self._audit.chain_tip,
            )

        # #479 piece 2: this call's own class, catalog floor raised by any
        # declared_data_class. _max_sensitivity can only return the higher of
        # the two labels, ties favour the catalog value, so an unrecognised or
        # lower declared value is harmless without any separate validation.
        effective_data_class: str | None = (
            _max_sensitivity(
                entry.sensitivity_level, declared_data_class, self._session.sensitivity_order
            )
            if declared_data_class is not None
            else None
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
        _finalization.failure_stage = "policy_evaluation"
        cedar_context = self._build_cedar_context(
            tool_name, arguments, workflow_id, effective_data_class
        )
        policy_rule: str | None = None
        ingress_advice: dict[str, str] = {}
        try:
            decision = self._policy.evaluate(cedar_context)
            policy_rule = decision.rule_matched
            would_have_denied = decision.would_have_denied
            ingress_advice = decision.advice
        except PolicyDeny as exc:
            # AARM R4: the call is blocked either way, and which of DENY,
            # STEP_UP, or DEFER applies comes from the matched policies'
            # annotations and is classified on the exception. Recording the
            # specific decision is what lets an auditor tell "refused" apart
            # from "needs an approver", which the caller also learns from
            # `advice` below.
            denied_as = audit_value(exc.aarm_decision)
            self._append_call_terminal(
                _finalization,
                "tool_call",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=entry.server.url,
                policy_decision=denied_as,
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
                stage_results={"policy": denied_as},
                call_id=call_id,
                catalog_entry=entry,
                policy_decision=denied_as,
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
            self._finalize_unexpected_call_failure(
                _finalization,
                exc,
                call_id=call_id,
                tool_name=tool_name,
                workflow_id=workflow_id,
            )
            raise

        # Step 3a: native pre-call interception: per-agent rate limiting,
        # parameter sanitization, and allow/deny. Fail closed on internal errors.
        _finalization.failure_stage = "ingress_gateway"
        agt_allowed, agt_reason = self._mcp_gateway.intercept_tool_call(
            agent_id=self._session.session_id,
            tool_name=tool_name,
            params=arguments,
        )
        if not agt_allowed:
            logger.warning("Runtime gateway rejected call: tool=%s reason=%s", tool_name, agt_reason)
            self._append_call_terminal(
                _finalization,
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
        _finalization.failure_stage = "upstream_invocation"
        try:
            response_text = await self._forward_to_upstream(
                call_id,
                entry,
                tool_name,
                arguments,
                finalization=_finalization,
            )
            _finalization.effect_boundary_state = _EffectBoundaryState.TRANSPORT_RESPONSE_RECEIVED
        except (UpstreamUnavailable, UpstreamToolError) as exc:
            logger.warning("Upstream call failed: tool=%s error=%s", tool_name, exc)
            self._append_call_terminal(
                _finalization,
                "fault",
                call_id=call_id,
                tool_name=tool_name,
                server_identity=entry.server.url,
                policy_decision="fault",
                policy_rule_matched=f"upstream:{exc.code}",
                request_payload_hash=request_payload_hash,
                session_sensitivity_before=sensitivity_before,
                session_sensitivity_after=self._session.max_sensitivity,
                detail={
                    "error_code": exc.code,
                    "failure_stage": _finalization.failure_stage,
                    "effect_boundary": _finalization.effect_boundary_label,
                    "effect_boundary_state": _finalization.effect_boundary_state.value,
                    "terminal_disposition": _finalization.terminal_disposition,
                    "external_execution_evidence_state": "unavailable_or_unbound",
                },
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
        _finalization.failure_stage = "response_size_check"
        if len(response_text.encode()) > self._config.max_response_size_bytes:
            self._append_call_terminal(
                _finalization,
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

        # Step 3d: native response interception: injection / credential / PII scan.
        _finalization.failure_stage = "response_scan"
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
                    sensitivity_tags=(
                        [entry.sensitivity_level, declared_data_class]
                        if declared_data_class is not None
                        else [entry.sensitivity_level]
                    ),
                    injection_detected=injection_detected,
                    response_allowed=False,
                )
            threat_categories = ",".join(
                sorted({str(t.get("category", "unknown")) for t in scan.threats})
            )
            self._append_call_terminal(
                _finalization,
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
                effective_data_class=effective_data_class,
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

        # Bind post-scan facts before any cancellable or fallible session/egress
        # processing. The hash is bound first so an evidence-parser failure still
        # preserves the exact response bytes that were available.
        _finalization.failure_stage = "response_binding"
        response_bytes: bytes = agt_result.encode()
        _finalization.response_payload_hash = f"sha256:{hashlib.sha256(response_bytes).hexdigest()}"
        _finalization.failure_stage = "external_evidence_extraction"
        _finalization.external_execution_evidence = _extract_external_execution_evidence(agt_result)

        # Step 4: session update from response sensitivity
        # AUTH-002: lock protects against race with concurrent session reset requests.
        # Sensitivity comes from the attested catalog entry's declared level, raised
        # by declared_data_class if the caller declared one (#479 piece 2).
        response_sensitivity = (
            [entry.sensitivity_level, declared_data_class]
            if declared_data_class is not None
            else [entry.sensitivity_level]
        )
        injection_scanner = "agt_response_scanner" if injection_detected else None
        injection_pattern = (
            ",".join(sorted({str(t.get("category", "unknown")) for t in scan.threats}))
            if injection_detected
            else None
        )
        injection_threshold = None
        _finalization.failure_stage = "session_update"
        async with self._session.mutation_lock:
            self._session.update_from_inspection(
                call_id=call_id,
                sensitivity_tags=response_sensitivity,
                injection_detected=injection_detected,
                response_allowed=True,
            )

        # Step 5: egress Cedar policy check
        _finalization.failure_stage = "egress_policy"
        try:
            egress_decision = self._policy.authorize_egress(
                tool_name, response_bytes, self._session, workflow_id=workflow_id
            )
            egress_would_deny = egress_decision.would_have_denied
            egress_advice = egress_decision.advice
        except PolicyDeny as exc:
            egress_deny_reason = str(exc)
            self._append_call_terminal(
                _finalization,
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
        _finalization.failure_stage = "terminal_persistence"
        policy_decision: Any = "advisory_deny" if would_have_denied else "allow"
        latency_us = int((time.perf_counter() - t0) * 1_000_000)
        # #293: bind the outcome into the audit entry. Hash exactly the bytes the
        # egress check saw (post-scan, possibly sanitized) so a verifier can match
        # the audited response against what the caller actually received.
        response_payload_hash = _finalization.response_payload_hash
        # Evidence class: what a verifier can conclude about where this response
        # came from. tls-pinned when a network upstream has a real cert pin;
        # spawn-measured when the gateway digested a stdio server's entrypoint
        # against the catalog before exec'ing it. The two are not comparable and
        # are deliberately not collapsed: one identifies an endpoint, the other
        # identifies code.
        from cmcp_runtime.mcp import tls_pinning as _tls_mod

        if entry is not None and entry.server.is_stdio:
            spawned = self._stdio_servers.get(_server_execution_key(entry))
            # A stdio response with no spawned server on record is not something
            # to guess about; hash-only is the honest floor.
            evidence_class = (
                spawned.evidence_class
                if spawned is not None and spawned.evidence_class
                else "hash-only"
            )
        else:
            _fp = entry.server.tls_fingerprint if entry else ""
            evidence_class = (
                "tls-pinned"
                if entry
                and entry.server.url.startswith("https://")
                and _fp
                and _fp != _tls_mod.PLACEHOLDER_FINGERPRINT
                else "hash-only"
            )
        # INJECT-003: include injection scanner and pattern in audit detail when detected
        injection_detail: dict[str, str | int | float] | None = (
            {
                "injection_scanner": str(injection_scanner or "unknown")[:128],
                "matched_pattern": str(injection_pattern or "unknown")[:256],
                # INJECT-007: include threshold so the decision is replayable under config changes
                **(
                    {"injection_threshold": float(injection_threshold)}
                    if isinstance(injection_threshold, int | float)
                    else {}
                ),
            }
            if injection_detected
            else None
        )
        _finalization.failure_stage = "terminal_persistence"
        self._append_call_terminal(
            _finalization,
            "tool_call",
            call_id=call_id,
            tool_name=tool_name,
            server_identity=entry.server.url,
            policy_decision=policy_decision,
            policy_rule_matched=policy_rule,
            latency_us=latency_us,
            request_payload_hash=request_payload_hash,
            response_payload_hash=response_payload_hash,
            evidence_class=evidence_class,
            session_sensitivity_before=sensitivity_before,
            session_sensitivity_after=self._session.max_sensitivity,
            workflow_id=workflow_id,
            detail=injection_detail,
            external_execution_evidence=_finalization.external_execution_evidence,
            effective_data_class=effective_data_class,
        )

        # Step 6: call log record + suspicious-sequence check
        _finalization.failure_stage = "post_terminal_bookkeeping"
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
