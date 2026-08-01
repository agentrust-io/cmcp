"""
AARM v1.0 conformance tests for the decision vocabulary (R4) and telemetry
export (R8).

These cover the mapping and plumbing that R4 and R8 add. They do not attempt to
be the AARM Conformance Agent's test suite, which runs against a deployed
gateway and includes timeout behaviour across all five decision types.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.errors import PolicyDeny
from cmcp_runtime.observability import otel as otel_module
from cmcp_runtime.observability.otel import OtelAuditExporter, otel_sink_from_env
from cmcp_runtime.policy.decisions import (
    AARM_DECISION_ANNOTATION,
    Decision,
    audit_value,
    claim_value,
    decision_for_deny,
)

SCHEMA_PATH = pathlib.Path(__file__).parent.parent / "schemas" / "audit-entry.schema.json"


class TestR4DecisionVocabulary:
    """R4: the policy engine must produce five decision types."""

    def test_all_five_aarm_decisions_exist(self) -> None:
        assert {d.value for d in Decision} == {
            "allow",
            "deny",
            "modify",
            "step_up",
            "defer",
        }

    def test_bare_deny_is_deny(self) -> None:
        assert decision_for_deny(None) is Decision.DENY
        assert decision_for_deny({}) is Decision.DENY
        assert decision_for_deny({"reason": "not permitted"}) is Decision.DENY

    @pytest.mark.parametrize("key", ["approver", "escalate", "escalation", "hitl"])
    def test_escalation_annotation_infers_step_up(self, key: str) -> None:
        assert decision_for_deny({key: "risk-desk@example.org"}) is Decision.STEP_UP

    def test_explicit_annotation_wins_over_inference(self) -> None:
        # An approver key would otherwise infer STEP_UP.
        advice = {"approver": "risk-desk", AARM_DECISION_ANNOTATION: "defer"}
        assert decision_for_deny(advice) is Decision.DEFER

    def test_explicit_annotation_cannot_flip_a_deny_to_allow(self) -> None:
        """A policy that denied must not be able to declare itself permitted."""
        for claimed in ("allow", "modify"):
            advice = {AARM_DECISION_ANNOTATION: claimed}
            assert decision_for_deny(advice) is Decision.DENY

    def test_malformed_annotation_falls_back_to_inference(self) -> None:
        """A typo must not become a failure to decide."""
        assert decision_for_deny({AARM_DECISION_ANNOTATION: "stepup"}) is Decision.DENY
        assert (
            decision_for_deny({AARM_DECISION_ANNOTATION: "nonsense", "approver": "x"})
            is Decision.STEP_UP
        )

    def test_annotation_value_is_case_and_space_insensitive(self) -> None:
        assert decision_for_deny({AARM_DECISION_ANNOTATION: "  STEP_UP "}) is Decision.STEP_UP

    def test_modify_records_as_redact(self) -> None:
        """MODIFY reuses the existing audit value for the mechanism cMCP applies."""
        assert audit_value(Decision.MODIFY) == "redact"

    def test_other_decisions_record_under_their_own_name(self) -> None:
        for decision in (Decision.ALLOW, Decision.DENY, Decision.STEP_UP, Decision.DEFER):
            assert audit_value(decision) == decision.value

    def test_policy_deny_classifies_itself(self) -> None:
        plain = PolicyDeny("blocked", advice={"reason": "no"})
        assert plain.aarm_decision is Decision.DENY

        escalating = PolicyDeny("blocked", advice={"approver": "risk-desk"})
        assert escalating.aarm_decision is Decision.STEP_UP

    def test_policy_deny_with_no_advice_classifies_as_deny(self) -> None:
        assert PolicyDeny("blocked").aarm_decision is Decision.DENY


class TestClaimBoundaryNarrowing:
    """
    A TRACE Claim v1.0 cannot carry step_up or defer. The audit chain keeps the
    specific decision and the claim reports the coarser one, so a new decision
    value can never produce a claim that fails schema validation.
    """

    def test_new_decisions_narrow_to_deny(self) -> None:
        assert claim_value("step_up") == "deny"
        assert claim_value("defer") == "deny"

    def test_pinned_vocabulary_passes_through_unchanged(self) -> None:
        for value in ("allow", "deny", "redact", "advisory_deny", "fault", "n/a"):
            assert claim_value(value) == value

    def test_none_becomes_not_applicable(self) -> None:
        assert claim_value(None) == "n/a"

    def test_unrecognised_value_fails_closed_to_deny(self) -> None:
        """A future decision value must not leak into a claim it would invalidate."""
        assert claim_value("some_future_decision") == "deny"

    def test_every_audit_value_narrows_into_the_claim_vocabulary(self) -> None:
        pinned = {"allow", "deny", "redact", "advisory_deny", "fault", "n/a"}
        for decision in Decision:
            assert claim_value(audit_value(decision)) in pinned

    def test_narrowing_preserves_the_blocked_or_allowed_distinction(self) -> None:
        """Narrowing may lose detail; it must not turn a block into an allow."""
        for decision in (Decision.DENY, Decision.STEP_UP, Decision.DEFER):
            assert claim_value(audit_value(decision)) == "deny"
        assert claim_value(audit_value(Decision.ALLOW)) == "allow"


class TestAuditSchemaAcceptsNewDecisions:
    """The recorded vocabulary and the published schema must not drift apart."""

    def test_schema_enum_covers_every_audit_value(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        allowed = set(schema["properties"]["policy_decision"]["enum"])
        for decision in Decision:
            assert audit_value(decision) in allowed, (
                f"{decision.value} maps to {audit_value(decision)!r}, "
                "which audit-entry.schema.json does not permit"
            )

    def test_widening_kept_the_legacy_values(self) -> None:
        """Entries written before the widening must still validate."""
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        allowed = set(schema["properties"]["policy_decision"]["enum"])
        assert {"allow", "deny", "redact", "advisory_deny", "fault", "n/a"} <= allowed


class TestR8TelemetryExport:
    """R8: export action telemetry in a standard format."""

    def test_sinks_receive_every_entry(self) -> None:
        seen: list[str] = []
        chain = AuditChain("session-1", sinks=[lambda e: seen.append(e.entry_type)])
        # session_start is appended by the constructor.
        assert seen == ["session_start"]
        chain.append("tool_call", tool_name="t", policy_decision="allow")
        assert seen == ["session_start", "tool_call"]

    def test_a_failing_sink_cannot_break_the_chain(self) -> None:
        """Telemetry must never fail a tool call or corrupt the audit chain."""

        def exploding(entry: object) -> None:
            raise RuntimeError("collector down")

        chain = AuditChain("session-2", sinks=[exploding])
        chain.append("tool_call", tool_name="t", policy_decision="allow")
        assert chain.verify_chain()

    def test_a_failing_sink_does_not_starve_later_sinks(self) -> None:
        seen: list[str] = []

        def exploding(entry: object) -> None:
            raise RuntimeError("collector down")

        chain = AuditChain("session-3", sinks=[exploding, lambda e: seen.append(e.entry_id)])
        chain.append("tool_call", tool_name="t", policy_decision="allow")
        assert len(seen) == 2  # session_start plus the tool_call

    def test_add_sink_attaches_after_construction(self) -> None:
        chain = AuditChain("session-4")
        seen: list[str] = []
        chain.add_sink(lambda e: seen.append(e.entry_type))
        chain.append("tool_call", tool_name="t", policy_decision="allow")
        assert seen == ["tool_call"]

    def test_exporter_is_inert_without_opentelemetry_installed(self) -> None:
        """The exporter must be safe to attach whether or not OTel is present."""
        exporter = OtelAuditExporter()
        chain = AuditChain("session-5", sinks=[exporter])
        chain.append("tool_call", tool_name="t", policy_decision="allow")
        assert chain.verify_chain()

    def test_env_sink_is_off_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CMCP_OTEL_ENABLED", raising=False)
        assert otel_sink_from_env() is None

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "maybe"])
    def test_env_sink_rejects_non_truthy_values(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("CMCP_OTEL_ENABLED", value)
        assert otel_sink_from_env() is None

    def test_exported_fields_exclude_payloads(self) -> None:
        """Digests may leave the enclave; bodies may not."""
        from cmcp_runtime.observability.otel import _EXPORTED_FIELDS

        for field_name in _EXPORTED_FIELDS:
            assert "payload" not in field_name or field_name.endswith("_hash")
        assert "detail" not in _EXPORTED_FIELDS
        assert "external_execution_evidence" not in _EXPORTED_FIELDS


class TestOtelSpansActuallyExport:
    """
    #456: every test above passes against a feature that exports nothing.

    They assert the sink plumbing and the inert path, which is exactly the state
    the exporter was released in: no provider was ever installed and no sink was
    ever attached to a production chain, so `CMCP_OTEL_ENABLED=1` produced no
    telemetry. These tests exercise the recording path instead.

    The global tracer provider is process-wide and refuses to be replaced, so
    rather than calling set_tracer_provider these swap the module's handle on the
    OTel API for one backed by an in-memory provider.
    """

    @pytest.fixture
    def recorded(self, monkeypatch: pytest.MonkeyPatch):
        """Yield a callable returning the spans exported so far."""
        pytest.importorskip("opentelemetry.sdk")
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )

        from cmcp_runtime.observability import otel as otel_module

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))

        class _Shim:
            @staticmethod
            def get_tracer(name: str):
                return provider.get_tracer(name)

            @staticmethod
            def get_tracer_provider():
                return provider

        monkeypatch.setattr(otel_module, "_otel_trace", _Shim)
        return exporter.get_finished_spans

    def test_one_span_per_audit_entry_with_expected_attributes(self, recorded) -> None:
        chain = AuditChain("otel-live-1", sinks=[OtelAuditExporter()])
        chain.append(
            "tool_call",
            call_id="c-allow",
            tool_name="echo",
            policy_decision="allow",
            latency_us=1234,
            request_payload_hash="a" * 64,
        )

        spans = recorded()
        assert [s.name for s in spans] == ["cmcp.session_start", "cmcp.tool_call"]

        attrs = spans[1].attributes
        assert attrs["cmcp.tool_name"] == "echo"
        assert attrs["cmcp.policy_decision"] == "allow"
        assert attrs["cmcp.call_id"] == "c-allow"
        assert attrs["cmcp.latency_us"] == 1234
        assert attrs["cmcp.request_payload_hash"] == "a" * 64
        # The chain must be unaffected by having been mirrored.
        assert chain.verify_chain()

    def test_every_attribute_survives_the_otlp_type_constraint(self, recorded) -> None:
        """set_attribute drops values it cannot represent; nothing may be dropped."""
        from cmcp_runtime.observability.otel import _EXPORTED_FIELDS

        chain = AuditChain("otel-live-2", sinks=[OtelAuditExporter()])
        entry = chain.append(
            "tool_call",
            call_id="c1",
            tool_name="echo",
            server_identity="mock",
            policy_decision="allow",
            policy_rule_matched="allow-all",
            latency_us=7,
            request_payload_hash="a" * 64,
            response_payload_hash="b" * 64,
            response_inspection_result="pass",
            workflow_id="w1",
        )

        attrs = recorded()[-1].attributes
        for field_name in _EXPORTED_FIELDS:
            if getattr(entry, field_name, None) is not None:
                assert f"cmcp.{field_name}" in attrs, f"{field_name} was dropped by the SDK"
                assert isinstance(attrs[f"cmcp.{field_name}"], (str, int, float, bool))

    @pytest.mark.parametrize("decision", ["deny", "advisory_deny", "fault"])
    def test_refused_calls_set_span_status_to_error(self, recorded, decision: str) -> None:
        from opentelemetry.trace import StatusCode

        chain = AuditChain("otel-live-3", sinks=[OtelAuditExporter()])
        chain.append("tool_call", tool_name="blocked", policy_decision=decision)

        span = recorded()[-1]
        assert span.status.status_code is StatusCode.ERROR
        assert span.status.description == f"policy_decision={decision}"

    def test_allowed_calls_do_not_set_error_status(self, recorded) -> None:
        from opentelemetry.trace import StatusCode

        chain = AuditChain("otel-live-4", sinks=[OtelAuditExporter()])
        chain.append("tool_call", tool_name="echo", policy_decision="allow")
        assert recorded()[-1].status.status_code is not StatusCode.ERROR

    def test_session_manager_attaches_the_sink(
        self, recorded, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        The gap in #456: the exporter worked, but nothing ever attached it to the
        chain a running gateway uses, so a live collector received nothing.
        """
        from unittest.mock import MagicMock

        from cmcp_runtime.session.manager import SessionManager

        monkeypatch.setenv("CMCP_OTEL_ENABLED", "1")
        ctx = MagicMock()
        ctx.tee_provider.get_attestation_report.return_value = None

        SessionManager(ctx).create_session()

        assert "cmcp.session_start" in [s.name for s in recorded()]

    def test_session_manager_attaches_nothing_when_export_is_off(
        self, recorded, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import MagicMock

        from cmcp_runtime.session.manager import SessionManager

        monkeypatch.delenv("CMCP_OTEL_ENABLED", raising=False)
        ctx = MagicMock()
        ctx.tee_provider.get_attestation_report.return_value = None

        SessionManager(ctx).create_session()

        assert recorded() == ()


class TestExporterEnabledReportsRecording:
    """`enabled` claimed True while spans were being discarded (#456)."""

    def test_enabled_is_false_without_a_tracer_provider(self) -> None:
        # Guarded on the module's own flag rather than importorskip: the
        # opentelemetry namespace package can remain importable after the API
        # is uninstalled, so importorskip does not mean the API is usable.
        if not otel_module.OTEL_AVAILABLE:
            pytest.skip("opentelemetry is not installed")
        # No provider installed in the test process, so nothing is exported.
        assert OtelAuditExporter().enabled is False

    def test_configure_tracer_provider_is_a_noop_when_export_is_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cmcp_runtime.observability.otel import configure_tracer_provider

        monkeypatch.delenv("CMCP_OTEL_ENABLED", raising=False)
        assert configure_tracer_provider() is False

    def test_enabled_degrades_to_optimistic_if_placeholders_cannot_be_resolved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        The placeholder provider classes are resolved by getattr, so a release
        that renames them costs this one signal rather than switching export off.
        Deliberately the milder failure: `enabled` over-reports instead of the
        module deciding OpenTelemetry is absent.
        """
        if not otel_module.OTEL_AVAILABLE:
            pytest.skip("opentelemetry is not installed")

        monkeypatch.setattr(otel_module, "_PLACEHOLDER_PROVIDERS", ())
        assert otel_module.OtelAuditExporter().enabled is True

    @pytest.mark.parametrize(
        ("var", "value"),
        [
            ("OTEL_EXPORTER_OTLP_TIMEOUT", "abc"),
            ("OTEL_EXPORTER_OTLP_COMPRESSION", "bogus"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "this is not valid"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "not-a-url::://x"),
        ],
    )
    def test_a_malformed_otlp_variable_cannot_take_the_gateway_down(
        self, monkeypatch: pytest.MonkeyPatch, var: str, value: str
    ) -> None:
        """
        configure_tracer_provider() runs from `cmcp start`. The SDK validates
        OTEL_EXPORTER_OTLP_* at construction and raises on values it cannot
        parse, so an unguarded call would mean a typo in a telemetry variable
        stops the gateway booting. Telemetry must never be able to do that.
        """
        if not otel_module.OTEL_AVAILABLE:
            pytest.skip("opentelemetry is not installed")

        monkeypatch.setenv("CMCP_OTEL_ENABLED", "1")
        monkeypatch.setenv(var, value)
        # Force the construction path rather than the already-installed early
        # return, which would make this test vacuous.
        monkeypatch.setattr(otel_module, "_PLACEHOLDER_PROVIDERS", (object,))
        monkeypatch.setattr(
            otel_module._otel_trace, "get_tracer_provider", lambda: object()
        )
        # Keep the process-global provider untouched: the values that parse
        # cleanly would otherwise install one and leak into later tests.
        monkeypatch.setattr(
            otel_module._otel_trace, "set_tracer_provider", lambda provider: None
        )

        # Only some of these raise inside the SDK, and which ones is the SDK's
        # business. The contract under test is that none of them propagate.
        try:
            result = otel_module.configure_tracer_provider()
        except Exception as exc:  # pragma: no cover - the failure being guarded
            pytest.fail(
                f"{var}={value!r} propagated {exc!r}; a malformed telemetry "
                "variable must not stop the gateway booting"
            )
        assert isinstance(result, bool)
