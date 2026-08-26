"""Regression gates for issue #571 terminal finalization semantics."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.store import SqliteAuditStore
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.errors import UpstreamUnavailable
from cmcp_runtime.mcp import tls_pinning
from cmcp_runtime.mcp.proxy import _EffectBoundaryState
from cmcp_runtime.policy.evaluator import PolicyDecision, PolicyEvaluator
from cmcp_runtime.session.state import SessionState

TERMINAL_TYPES = {"tool_call", "fault", "egress_denied"}


def _decision() -> PolicyDecision:
    return PolicyDecision(
        allowed=True,
        enforcement_mode=EnforcementMode.ENFORCING,
        rule_matched=None,
        advice={},
        evaluation_ms=0.1,
        would_have_denied=False,
    )


def _evaluator(exception: BaseException | None = None) -> PolicyEvaluator:
    evaluator = MagicMock(spec=PolicyEvaluator)
    if exception is None:
        evaluator.evaluate.return_value = _decision()
    else:
        evaluator.evaluate.side_effect = exception
    evaluator.authorize_egress.return_value = _decision()
    evaluator.bundle_hash = "sha256:" + "0" * 64
    evaluator.enforcement_mode = EnforcementMode.ENFORCING
    return evaluator


def _make_proxy(chain: AuditChain, evaluator: PolicyEvaluator | None = None):
    from cmcp_runtime.mcp.proxy import CMCPProxy

    entry = CatalogEntry(
        tool_name="test.echo",
        server=ServerIdentity(
            display_name="Local",
            url="https://local.invalid/mcp",
            tls_fingerprint="SHA256:" + "A" * 43 + "=",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description="echo", input_schema={}, output_schema=None
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="public",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-08-25T00:00:00Z",
        approved_by="issue-571-finalization",
    )
    catalog = ToolCatalog(entries={"test.echo": entry}, catalog_hash="sha256:" + "1" * 64)
    config = Config(attestation=AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING))
    with (
        patch("cmcp_runtime.mcp.proxy.MCPGateway") as gateway,
        patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"),
    ):
        scan = MagicMock()
        scan.allowed = True
        scan.threats = []
        scan.content = None
        gateway.return_value.intercept_tool_call.return_value = (True, None)
        gateway.return_value.intercept_tool_response.return_value = scan
        proxy = CMCPProxy(
            catalog,
            evaluator or _evaluator(),
            SessionState(session_id="issue-571"),
            chain,
            config,
        )
    proxy._check_upstream_drift = AsyncMock(return_value=False)
    return proxy


def _terminals(chain: AuditChain) -> list[Any]:
    return [entry for entry in chain.entries[1:] if entry.entry_type in TERMINAL_TYPES]


def _sqlite_payloads(path: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(path)
    try:
        return [
            json.loads(row[0])
            for row in connection.execute(
                "SELECT payload FROM audit_entries ORDER BY sequence_number"
            ).fetchall()
        ]
    finally:
        connection.close()


def _provenance(*, meets_requirement: bool) -> MagicMock:
    result = MagicMock()
    result.meets.return_value = meets_requirement
    result.outcome.value = "verified" if meets_requirement else "missing"
    result.detail = "private-r6-test"
    return result


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize(
    ("side", "expected", "stage"),
    [
        ("pre", "not_attempted", "policy_evaluation"),
        ("post", "outcome_unknown", "upstream_invocation"),
    ],
)
@pytest.mark.asyncio
async def test_same_exception_two_sided_boundary_and_storage_parity(
    backend: str, side: str, expected: str, stage: str, tmp_path: Path
) -> None:
    database = tmp_path / f"{backend}-{side}.sqlite3"
    store = SqliteAuditStore(database) if backend == "sqlite" else None
    chain = AuditChain("issue-571", store=store)
    failure = RecursionError("same-exception")
    proxy = _make_proxy(chain, _evaluator(failure if side == "pre" else None))

    async def fail_after_boundary(*_args: Any, **kwargs: Any) -> str:
        finalization = kwargs["finalization"]
        finalization.effect_boundary_state = _EffectBoundaryState.TRANSPORT_MAY_HAVE_STARTED
        raise failure

    proxy._forward_to_upstream = AsyncMock(
        side_effect=fail_after_boundary if side == "post" else None,
        return_value="{}",
    )

    with pytest.raises(RecursionError, match="same-exception"):
        await proxy.call_tool("same-call", "test.echo", {})

    terminals = _terminals(chain)
    assert len(terminals) == 1
    terminal = terminals[0]
    assert terminal.entry_type == "fault"
    assert terminal.detail["terminal_disposition"] == expected
    assert terminal.detail["failure_stage"] == stage
    assert terminal.detail["effect_boundary"] == (
        "not_reached" if side == "pre" else "transport_may_have_started"
    )
    assert terminal.detail["effect_boundary_state"] == (
        "pre_transport" if side == "pre" else "transport_may_have_started"
    )
    assert terminal.response_payload_hash is None
    assert proxy._forward_to_upstream.await_count == (0 if side == "pre" else 1)
    assert chain.verify_chain()
    if store is not None:
        assert _sqlite_payloads(database) == [asdict(entry) for entry in chain.entries]
        store.close()


@pytest.mark.asyncio
async def test_cancellation_before_upstream_is_not_attempted() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._check_upstream_drift = AsyncMock(side_effect=asyncio.CancelledError())

    with pytest.raises(asyncio.CancelledError):
        await proxy.call_tool("cancel-pre", "test.echo", {})

    terminal = _terminals(chain)[0]
    assert terminal.detail["terminal_disposition"] == "not_attempted"
    assert terminal.detail["failure_stage"] == "upstream_drift_check"


@pytest.mark.asyncio
async def test_cancellation_while_awaiting_upstream_is_outcome_unknown() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    started = asyncio.Event()

    async def blocked_forward(*_args: Any, **kwargs: Any) -> str:
        kwargs[
            "finalization"
        ].effect_boundary_state = _EffectBoundaryState.TRANSPORT_MAY_HAVE_STARTED
        started.set()
        await asyncio.Future()
        raise AssertionError("unreachable")

    proxy._forward_to_upstream = blocked_forward
    task = asyncio.create_task(proxy.call_tool("cancel-await", "test.echo", {}))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    terminal = _terminals(chain)[0]
    assert terminal.detail["terminal_disposition"] == "outcome_unknown"
    assert terminal.detail["failure_stage"] == "upstream_invocation"
    assert terminal.detail["effect_boundary"] == "transport_may_have_started"


@pytest.mark.asyncio
async def test_cancellation_after_terminal_persistence_does_not_duplicate() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._forward_to_upstream = AsyncMock(return_value="{}")
    proxy._record_call = MagicMock(side_effect=asyncio.CancelledError())

    with pytest.raises(asyncio.CancelledError) as caught:
        await proxy.call_tool("cancel-after-terminal", "test.echo", {})

    assert caught.value.__cause__ is None
    assert not getattr(caught.value, "__notes__", [])
    terminals = _terminals(chain)
    assert len(terminals) == 1
    assert terminals[0].entry_type == "tool_call"


@pytest.mark.asyncio
async def test_http_status_failure_records_transport_response_received() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=True))
    request = httpx.Request("POST", "https://local.invalid/mcp")
    response = httpx.Response(503, request=request, content=b'{"error":"unavailable"}')
    client = MagicMock()
    client.post = AsyncMock(return_value=response)
    proxy._client_for_upstream = MagicMock(return_value=client)

    result = await proxy.call_tool("status-fault", "test.echo", {})

    assert result.allowed is False
    terminal = _terminals(chain)[0]
    assert terminal.response_payload_hash is None
    assert terminal.detail["effect_boundary"] == "transport_response_received"
    assert terminal.detail["effect_boundary_state"] == "transport_response_received"
    assert terminal.detail["terminal_disposition"] == "outcome_unknown"


@pytest.mark.asyncio
async def test_parse_failure_records_transport_response_received() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=True))
    request = httpx.Request("POST", "https://local.invalid/mcp")
    response = httpx.Response(200, request=request, content=b'{"jsonrpc":"2.0"}')
    client = MagicMock()
    client.post = AsyncMock(return_value=response)
    proxy._client_for_upstream = MagicMock(return_value=client)

    with (
        patch("cmcp_runtime.mcp.proxy.parse_response", side_effect=RecursionError("parse")),
        pytest.raises(RecursionError, match="parse"),
    ):
        await proxy.call_tool("parse-fault", "test.echo", {})

    terminal = _terminals(chain)[0]
    assert terminal.response_payload_hash is None
    assert terminal.detail["effect_boundary"] == "transport_response_received"
    assert terminal.detail["effect_boundary_state"] == "transport_response_received"
    assert terminal.detail["terminal_disposition"] == "outcome_unknown"


@pytest.mark.asyncio
async def test_cancelled_error_from_fault_persistence_preserves_original() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._forward_to_upstream = AsyncMock(return_value="{}")
    original_append = chain.append

    def cancel_fault(entry_type: str, **fields: Any):
        if entry_type == "fault":
            raise asyncio.CancelledError("audit-cancelled")
        return original_append(entry_type, **fields)

    chain.append = cancel_fault  # type: ignore[method-assign]
    with (
        patch(
            "cmcp_runtime.mcp.proxy._extract_external_execution_evidence",
            side_effect=RecursionError("late-parser-fault"),
        ),
        pytest.raises(RecursionError, match="late-parser-fault") as caught,
    ):
        await proxy.call_tool("cancelled-persistence", "test.echo", {})

    assert isinstance(caught.value.__cause__, asyncio.CancelledError)
    assert any("terminal audit persistence failed" in note for note in caught.value.__notes__)
    assert _terminals(chain) == []


@pytest.mark.asyncio
async def test_runtime_error_after_terminal_persistence_does_not_duplicate() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._forward_to_upstream = AsyncMock(return_value="{}")
    proxy._record_call = MagicMock(side_effect=RuntimeError("post-terminal"))

    with pytest.raises(RuntimeError, match="post-terminal"):
        await proxy.call_tool("runtime-after-terminal", "test.echo", {})

    terminals = _terminals(chain)
    assert len(terminals) == 1
    assert terminals[0].entry_type == "tool_call"


@pytest.mark.asyncio
async def test_fault_persistence_preserves_original_exception_as_primary() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._forward_to_upstream = AsyncMock(return_value="{}")
    original_append = chain.append

    def fail_fault(entry_type: str, **fields: Any):
        if entry_type == "fault":
            raise OSError("audit-store-unavailable")
        return original_append(entry_type, **fields)

    chain.append = fail_fault  # type: ignore[method-assign]
    with (
        patch(
            "cmcp_runtime.mcp.proxy._extract_external_execution_evidence",
            side_effect=RecursionError("hostile-response-parse"),
        ),
        pytest.raises(RecursionError, match="hostile-response-parse") as caught,
    ):
        await proxy.call_tool("persist-fault", "test.echo", {})

    assert isinstance(caught.value.__cause__, OSError)
    assert "audit-store-unavailable" in str(caught.value.__cause__)
    assert any("terminal audit persistence failed" in note for note in caught.value.__notes__)
    assert _terminals(chain) == []


@pytest.mark.parametrize("system_exit", [KeyboardInterrupt(), SystemExit(23)])
@pytest.mark.asyncio
async def test_system_exceptions_during_fault_persistence_remain_primary(
    system_exit: BaseException,
) -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._forward_to_upstream = AsyncMock(return_value="{}")
    original_append = chain.append

    def interrupt_fault(entry_type: str, **fields: Any):
        if entry_type == "fault":
            raise system_exit
        return original_append(entry_type, **fields)

    chain.append = interrupt_fault  # type: ignore[method-assign]
    with (
        patch(
            "cmcp_runtime.mcp.proxy._extract_external_execution_evidence",
            side_effect=RecursionError("late-parser-fault"),
        ),
        pytest.raises(type(system_exit)) as caught,
    ):
        await proxy.call_tool("system-exit", "test.echo", {})

    assert caught.value is system_exit
    assert caught.value.__cause__ is None
    assert _terminals(chain) == []


@pytest.mark.asyncio
async def test_exact_response_hash_is_kept_for_late_processing_fault() -> None:
    response = '{"controller":"accepted"}'
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._forward_to_upstream = AsyncMock(return_value=response)
    with (
        patch(
            "cmcp_runtime.mcp.proxy._extract_external_execution_evidence",
            side_effect=RecursionError("late-parser-fault"),
        ),
        pytest.raises(RecursionError),
    ):
        await proxy.call_tool("late-fault", "test.echo", {})

    terminal = _terminals(chain)[0]
    expected = "sha256:" + hashlib.sha256(response.encode()).hexdigest()
    assert terminal.response_payload_hash == expected
    assert terminal.detail["failure_stage"] == "external_evidence_extraction"


@pytest.mark.asyncio
async def test_bound_pointer_survives_later_terminal_persistence_fault() -> None:
    receipt = {
        "issuer": "spiffe://factory.example/controller/cell-7",
        "issuer_key_id": "a" * 64,
        "signature": "sig",
        "evidence_hash": "sha256:" + "b" * 64,
        "evidence_type": "controller-execution-receipt/v1",
        "linked_call_id": "pointer-call",
    }
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._forward_to_upstream = AsyncMock(
        return_value=json.dumps({"external_execution_evidence": receipt})
    )
    original_append = chain.append
    failed_once = False

    def fail_first_success(entry_type: str, **fields: Any):
        nonlocal failed_once
        if entry_type == "tool_call" and not failed_once:
            failed_once = True
            raise RuntimeError("first-terminal-persistence-fault")
        return original_append(entry_type, **fields)

    chain.append = fail_first_success  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="first-terminal-persistence-fault"):
        await proxy.call_tool("pointer-call", "test.echo", {})

    terminal = _terminals(chain)[0]
    assert terminal.entry_type == "fault"
    assert terminal.external_execution_evidence == receipt
    assert terminal.detail["external_execution_evidence_state"] == "bound"
    assert terminal.detail["terminal_disposition"] == "outcome_unknown"


@pytest.mark.asyncio
async def test_duplicate_local_call_ids_are_isolated_per_concurrent_invocation() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)

    async def fail_after_yield(*_args: Any, **kwargs: Any) -> str:
        kwargs[
            "finalization"
        ].effect_boundary_state = _EffectBoundaryState.TRANSPORT_MAY_HAVE_STARTED
        await asyncio.sleep(0)
        raise RecursionError("concurrent-fault")

    proxy._forward_to_upstream = fail_after_yield
    results = await asyncio.gather(
        proxy.call_tool("duplicate", "test.echo", {}),
        proxy.call_tool("duplicate", "test.echo", {}),
        return_exceptions=True,
    )

    assert all(isinstance(result, RecursionError) for result in results)
    terminals = _terminals(chain)
    assert len(terminals) == 2
    assert {entry.call_id for entry in terminals} == {"duplicate"}
    assert all(entry.detail["terminal_disposition"] == "outcome_unknown" for entry in terminals)
    assert len({entry.entry_id for entry in terminals}) == 2
    assert chain.verify_chain()


@pytest.mark.asyncio
async def test_provenance_refusal_is_proven_pre_transport() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=False))
    proxy._client_for_upstream = MagicMock()

    result = await proxy.call_tool("provenance-refused", "test.echo", {})

    assert result.allowed is False
    proxy._client_for_upstream.assert_not_called()
    terminal = _terminals(chain)[0]
    assert terminal.detail["terminal_disposition"] == "not_attempted"
    assert terminal.detail["effect_boundary"] == "not_reached"


@pytest.mark.asyncio
async def test_malformed_pin_is_proven_pre_transport() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=True))
    proxy._client_for_upstream = MagicMock(side_effect=UpstreamUnavailable("malformed pin"))

    result = await proxy.call_tool("malformed-pin", "test.echo", {})

    assert result.allowed is False
    terminal = _terminals(chain)[0]
    assert terminal.detail["terminal_disposition"] == "not_attempted"
    assert terminal.detail["effect_boundary_state"] == "pre_transport"


@pytest.mark.asyncio
async def test_tls_pin_mismatch_resets_to_proven_pre_send() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=True))
    client = MagicMock()
    client.post = AsyncMock(
        side_effect=tls_pinning.TLSPinMismatchError(
            expected="SHA256:" + "A" * 43 + "=",
            actual="SHA256:" + "B" * 43 + "=",
        )
    )
    proxy._client_for_upstream = MagicMock(return_value=client)

    result = await proxy.call_tool("tls-mismatch", "test.echo", {})

    assert result.allowed is False
    assert client.post.await_count == 1
    terminal = _terminals(chain)[0]
    assert terminal.detail["terminal_disposition"] == "not_attempted"
    assert terminal.detail["failure_stage"] == "tls_pin_verification_pre_send"
    assert terminal.detail["effect_boundary"] == "not_reached"


@pytest.mark.asyncio
async def test_request_construction_failure_is_pre_transport() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=True))
    client = MagicMock()
    client.post = AsyncMock()
    proxy._client_for_upstream = MagicMock(return_value=client)

    with (
        patch(
            "cmcp_runtime.mcp.proxy.build_request",
            side_effect=RuntimeError("request-construction"),
        ),
        pytest.raises(RuntimeError, match="request-construction"),
    ):
        await proxy.call_tool("request-fault", "test.echo", {})

    assert client.post.await_count == 0
    terminal = _terminals(chain)[0]
    assert terminal.detail["terminal_disposition"] == "not_attempted"
    assert terminal.detail["effect_boundary_state"] == "pre_transport"


@pytest.mark.asyncio
async def test_stdio_spawn_or_measurement_failure_is_pre_transport() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    entry = proxy._catalog.lookup("test.echo")
    assert entry is not None
    entry.server.transport = "stdio"
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=True))
    proxy._stdio_for = AsyncMock(side_effect=OSError("stdio-pre-call"))

    with pytest.raises(OSError, match="stdio-pre-call"):
        await proxy.call_tool("stdio-pre", "test.echo", {})

    terminal = _terminals(chain)[0]
    assert terminal.detail["terminal_disposition"] == "not_attempted"
    assert terminal.detail["effect_boundary"] == "not_reached"


@pytest.mark.asyncio
async def test_header_construction_failure_is_pre_transport() -> None:
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=True))
    client = MagicMock()
    client.post = AsyncMock()
    proxy._client_for_upstream = MagicMock(return_value=client)

    with (
        patch(
            "cmcp_runtime.mcp.proxy.parameter_headers",
            side_effect=RuntimeError("header-construction"),
        ),
        pytest.raises(RuntimeError, match="header-construction"),
    ):
        await proxy.call_tool("header-fault", "test.echo", {})

    assert client.post.await_count == 0
    terminal = _terminals(chain)[0]
    assert terminal.detail["terminal_disposition"] == "not_attempted"
    assert terminal.detail["effect_boundary"] == "not_reached"


@pytest.mark.asyncio
async def test_commit_then_raise_is_bounded_not_exactly_once(
    tmp_path: Path,
) -> None:
    database = tmp_path / "commit-then-raise.sqlite3"
    store = SqliteAuditStore(database)
    chain = AuditChain("issue-571", store=store)
    proxy = _make_proxy(chain)
    proxy._forward_to_upstream = AsyncMock(return_value="{}")
    original_store_append = store.append
    raised = False

    def commit_then_raise(entry: Any) -> None:
        nonlocal raised
        original_store_append(entry)
        if entry.entry_type == "tool_call" and not raised:
            raised = True
            raise RuntimeError("commit-acknowledgement-lost")

    store.append = commit_then_raise  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="commit-acknowledgement-lost"):
        await proxy.call_tool("commit-then-raise", "test.echo", {})

    memory_terminals = _terminals(chain)
    sqlite_terminals = [
        entry for entry in _sqlite_payloads(database) if entry["entry_type"] in TERMINAL_TYPES
    ]
    assert len(memory_terminals) == 1
    assert memory_terminals[0].entry_type == "fault"
    assert len(sqlite_terminals) == 2
    assert [entry["entry_type"] for entry in sqlite_terminals] == ["tool_call", "fault"]
    assert sqlite_terminals[0]["sequence_number"] == sqlite_terminals[1]["sequence_number"]
    assert sqlite_terminals[0]["entry_id"] != sqlite_terminals[1]["entry_id"]
    store.close()
