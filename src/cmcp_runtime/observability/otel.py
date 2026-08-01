"""
OpenTelemetry export of audit-chain entries (AARM requirement R8).

R8 asks that action telemetry be exported in a standard format. This module
mirrors each audit entry as an OTel span, which gives operators the usual
pipeline (OTLP collector, backend of choice) without changing how the entry is
recorded or hashed.

Three properties are deliberate.

**The audit chain stays authoritative.** Export is a read-only mirror attached
as a sink. ``AuditEntry`` gains no field, so entry hashes are unchanged and
existing chains still verify. A telemetry backend that loses data cannot alter
the evidence, and an operator who can write to the telemetry backend still
cannot forge a receipt. Telemetry is for operating the gateway; the chain and
the TRACE Claim are for proving what happened.

**No payloads leave the enclave.** Entries carry SHA-256 digests rather than
request or response bodies, and this exporter forwards only the digest fields
and the decision metadata. That holds even though the collector endpoint is
usually outside the trust boundary.

**Failures are swallowed.** A telemetry outage must not fail a tool call or
break the chain, so every export is wrapped. Errors are logged once at debug
level to avoid a log flood when a collector is down for hours.

OpenTelemetry is an optional dependency. Without it, ``OTEL_AVAILABLE`` is
False and the exporter degrades to a no-op, so ``pip install cmcp-runtime``
stays lean and a deployment opts in with ``pip install cmcp-runtime[otel]``.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cmcp_runtime.audit.chain import AuditEntry

logger = logging.getLogger(__name__)

# Bound to the OTel API when it is installed and left as None otherwise, so the
# rest of the module can branch on OTEL_AVAILABLE without import guards at each
# use. Typed Any because the fallback is a different shape from the real API.
_otel_trace: Any = None
_SpanKind: Any = None
_Status: Any = None
_StatusCode: Any = None
_PLACEHOLDER_PROVIDERS: tuple[type, ...] = ()

try:  # pragma: no cover - import-time branch depends on the environment
    from opentelemetry import trace as _imported_trace
    from opentelemetry.trace import SpanKind, Status, StatusCode

    _otel_trace = _imported_trace
    _SpanKind, _Status, _StatusCode = SpanKind, Status, StatusCode
    OTEL_AVAILABLE = True

    # get_tracer_provider() returns one of these until something installs a real
    # SDK provider; spans from them are NonRecordingSpans that go nowhere. They
    # are how `enabled` tells "OTel is importable" from "spans are exported".
    #
    # Resolved by getattr rather than a top-level import on purpose. These two
    # names are a convenience, not a requirement, and folding them into the
    # import above would mean a release that renames either one turns export off
    # entirely -- reintroducing the silent no-op this module exists to avoid. An
    # empty tuple degrades `enabled` to optimistic, which is the milder failure.
    _PLACEHOLDER_PROVIDERS = tuple(
        candidate
        for candidate in (
            getattr(_imported_trace, "NoOpTracerProvider", None),
            getattr(_imported_trace, "ProxyTracerProvider", None),
        )
        if isinstance(candidate, type)
    )
except ImportError:  # pragma: no cover
    OTEL_AVAILABLE = False

__all__ = [
    "OTEL_AVAILABLE",
    "OtelAuditExporter",
    "configure_tracer_provider",
    "otel_sink_from_env",
]

#: Values of CMCP_OTEL_ENABLED that turn export on, case-insensitively.
_TRUTHY = frozenset({"1", "true", "yes", "on"})

#: Audit entry fields that are safe to export. Everything omitted is either a
#: payload-adjacent value or internal chain bookkeeping that a telemetry
#: backend has no use for. Kept as an allowlist so a future field added to
#: AuditEntry is not exported by accident.
_EXPORTED_FIELDS = (
    "entry_id",
    "sequence_number",
    "session_id",
    "call_id",
    "entry_type",
    "tool_name",
    "server_identity",
    "policy_decision",
    "policy_rule_matched",
    "latency_us",
    "request_payload_hash",
    "response_payload_hash",
    "response_inspection_result",
    "session_sensitivity_before",
    "session_sensitivity_after",
    "workflow_id",
    "evidence_class",
    "entry_hash",
    "prev_entry_hash",
)

#: Decisions and entry types that mark the span as an error, so a dashboard can
#: alert on blocked calls without parsing attributes.
_ERROR_DECISIONS = frozenset({"deny", "advisory_deny", "fault"})


class OtelAuditExporter:
    """
    Mirrors audit entries to OpenTelemetry as spans.

    Attach with ``AuditChain(session_id, sinks=[exporter])`` or by appending
    ``exporter`` to an existing chain's sinks. The instance is callable so it
    satisfies the sink protocol directly.
    """

    def __init__(self, tracer_name: str = "cmcp.audit") -> None:
        self._tracer: Any = _otel_trace.get_tracer(tracer_name) if OTEL_AVAILABLE else None
        self._warned = False

    @property
    def enabled(self) -> bool:
        """
        True when a span emitted now would actually be recorded and exported.

        Deliberately stricter than "opentelemetry imported". Without an SDK
        provider installed the tracer is a proxy that yields NonRecordingSpans,
        so export is silently a no-op; reporting True there told an operator
        telemetry was working when nothing was leaving the process (#456).
        """
        if self._tracer is None:
            return False
        return not isinstance(_otel_trace.get_tracer_provider(), _PLACEHOLDER_PROVIDERS)

    def __call__(self, entry: AuditEntry) -> None:
        self.export(entry)

    def export(self, entry: AuditEntry) -> None:
        """Emit one span for ``entry``. Never raises."""
        tracer = self._tracer
        if tracer is None:
            return
        try:
            self._export(tracer, entry)
        except Exception:  # pragma: no cover - defensive
            if not self._warned:
                logger.debug("OTel audit export failed; further failures are silent", exc_info=True)
                self._warned = True

    def _export(self, tracer: Any, entry: AuditEntry) -> None:
        name = f"cmcp.{entry.entry_type}"
        with tracer.start_as_current_span(name, kind=_SpanKind.INTERNAL) as span:
            # Skip the attribute work when the span is a NonRecordingSpan (no
            # provider installed) or the sampler dropped it. This runs once per
            # audit entry on the call path, so the ~19 discarded set_attribute
            # calls are worth avoiding.
            if not span.is_recording():
                return
            for field_name in _EXPORTED_FIELDS:
                value = getattr(entry, field_name, None)
                if value is not None:
                    span.set_attribute(f"cmcp.{field_name}", value)
            decision = entry.policy_decision
            if decision in _ERROR_DECISIONS:
                span.set_status(_Status(_StatusCode.ERROR, f"policy_decision={decision}"))


def _export_requested() -> bool:
    """True when ``CMCP_OTEL_ENABLED`` asks for export."""
    return os.environ.get("CMCP_OTEL_ENABLED", "").strip().lower() in _TRUTHY


def configure_tracer_provider() -> bool:
    """
    Install an SDK tracer provider so exported spans have somewhere to go.

    Call once during process startup, before any session is created. Attaching
    the sink is not sufficient on its own: ``trace.get_tracer()`` returns a
    proxy that drops every span until a real provider is installed, which is
    why ``CMCP_OTEL_ENABLED=1`` alone produced no telemetry at all (#456).

    Returns True when spans will be exported after this call. No-ops when
    export was not requested, when the optional dependency is missing, or when
    something else already installed a provider - an embedder that configures
    its own pipeline keeps it, and this function never replaces it.

    The endpoint and the rest of the pipeline come from the standard
    ``OTEL_EXPORTER_OTLP_*`` environment variables, so cMCP introduces no
    second way to point telemetry at a collector.

    Shutdown behaviour, measured against a live collector and a dead one: the
    SDK flushes the batch queue at exit, so spans still buffered when the
    gateway is signalled do arrive rather than being dropped. When the collector
    is unreachable that flush retries with backoff before giving up, which added
    roughly 6s to gateway shutdown in testing (~8.8s against a dead collector
    versus ~2.2s against a healthy one). It terminates on its own and is well
    inside a default Kubernetes grace period; operators who need it tighter can
    set ``OTEL_BSP_EXPORT_TIMEOUT``.
    """
    if not _export_requested():
        return False
    if not OTEL_AVAILABLE:
        logger.warning(
            "CMCP_OTEL_ENABLED is set but opentelemetry is not installed; "
            "telemetry export is disabled. Install with: pip install cmcp-runtime[otel]"
        )
        return False

    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:  # pragma: no cover - depends on the environment
        logger.warning(
            "CMCP_OTEL_ENABLED is set but the OpenTelemetry SDK and OTLP exporter are "
            "not installed; telemetry export is disabled. "
            "Install with: pip install cmcp-runtime[otel]"
        )
        return False

    if not isinstance(_otel_trace.get_tracer_provider(), _PLACEHOLDER_PROVIDERS):
        logger.info("A tracer provider is already installed; leaving it in place")
        return True

    try:
        resource = Resource.create(
            {"service.name": os.environ.get("OTEL_SERVICE_NAME", "cmcp-gateway")}
        )
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        _otel_trace.set_tracer_provider(provider)
    except Exception:  # pragma: no cover - defensive
        # The SDK validates OTEL_EXPORTER_OTLP_* at construction and raises on
        # values it cannot parse: OTEL_EXPORTER_OTLP_TIMEOUT=abc and
        # OTEL_EXPORTER_OTLP_COMPRESSION=bogus both raise ValueError. This runs
        # from `cmcp start`, so letting that propagate would mean a typo in a
        # telemetry variable takes the gateway down at boot. Telemetry is never
        # allowed to do that; log it and run without export instead.
        logger.warning(
            "OTel tracer provider could not be configured; telemetry export is "
            "disabled and the gateway will run without it. Check the "
            "OTEL_EXPORTER_OTLP_* environment variables.",
            exc_info=True,
        )
        return False

    logger.info("OTel tracer provider installed; audit entries will be exported as spans")
    return True


def otel_sink_from_env() -> Callable[[Any], None] | None:
    """
    Build an exporter when the environment asks for one.

    Returns None when OpenTelemetry is absent or when ``CMCP_OTEL_ENABLED`` is
    unset or falsey, so telemetry is opt-in rather than something a deployment
    discovers it is doing. Recognised truthy values are ``1``, ``true``,
    ``yes``, and ``on``, case-insensitively.

    Attaching the returned sink exports nothing unless a tracer provider is
    installed; see :func:`configure_tracer_provider`.
    """
    if not _export_requested():
        return None
    if not OTEL_AVAILABLE:
        logger.warning(
            "CMCP_OTEL_ENABLED is set but opentelemetry is not installed; "
            "telemetry export is disabled. Install with: pip install cmcp-runtime[otel]"
        )
        return None
    exporter = OtelAuditExporter()
    logger.info("OTel audit export enabled")
    return exporter
