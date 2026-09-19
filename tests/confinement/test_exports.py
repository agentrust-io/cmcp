"""Observe real audit persistence, emitted spans and failure diagnostics."""

import json
import logging
import sqlite3
from dataclasses import asdict
from uuid import uuid4

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.store import SqliteAuditStore
from cmcp_runtime.observability.otel import OtelAuditExporter
from tests.confinement.gateway import make_gateway


def test_failing_audit_observer_does_not_log_private_repr_or_exception(caplog):
    secret = "synthetic-private-" + uuid4().hex

    class Observer:
        def __repr__(self):
            return secret

        def __call__(self, entry):
            raise RuntimeError(secret)

    with caplog.at_level(logging.DEBUG):
        chain = AuditChain("safe-session", sinks=[Observer()])
    assert len(chain.entries) == 1
    assert "Audit sink" in caplog.text
    assert secret not in caplog.text


def test_otel_failure_diagnostics_do_not_include_exception_payload(caplog):
    secret = "synthetic-private-" + uuid4().hex

    class BrokenTracer:
        def start_as_current_span(self, *args, **kwargs):
            raise RuntimeError(secret)

    exporter = OtelAuditExporter()
    exporter._tracer = BrokenTracer()
    with caplog.at_level(logging.DEBUG):
        chain = AuditChain("safe-session", sinks=[exporter])
    assert len(chain.entries) == 1
    assert "OTel audit export failed" in caplog.text
    assert secret not in caplog.text


@pytest.mark.parametrize("mode", ["echo", "error", "malformed", "stderr"])
async def test_gateway_payload_absent_from_actual_audit_spans_and_logs(tmp_path, caplog, mode):
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    secret = "canary-" + uuid4().hex
    recording = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(recording))
    exporter = OtelAuditExporter()
    exporter._tracer = provider.get_tracer("cmcp.confinement")
    store = SqliteAuditStore(tmp_path / "audit.db")
    sink = tmp_path / "received.jsonl"
    proxy, dispatch = make_gateway(sink, audit_store=store, audit_sinks=[exporter])
    try:
        with caplog.at_level(logging.DEBUG):
            result = await dispatch("permitted.tool", {"value": secret, "mode": mode})
            denied = await dispatch("public.tool", {"value": secret, "mode": mode})
            await proxy.aclose()
        assert result["allowed"] == (mode in {"echo", "stderr"})
        assert not denied["allowed"]
        assert secret in sink.read_text()  # positive: the source really reached the tool
        chain = json.dumps([asdict(entry) for entry in proxy._audit.entries])
        with sqlite3.connect(tmp_path / "audit.db") as reader:
            persisted = "\n".join(row[0] for row in reader.execute("SELECT payload FROM audit_entries"))
        provider.force_flush()
        spans = recording.get_finished_spans()
        assert len(spans) == len(proxy._audit.entries) >= 3
        exported = "\n".join(span.to_json() for span in spans)
        for observed in (chain, persisted, exported, caplog.text):
            assert secret not in observed
        assert any(entry.request_payload_hash for entry in proxy._audit.entries)
    finally:
        await proxy.aclose()
        store.close()
        provider.shutdown()
