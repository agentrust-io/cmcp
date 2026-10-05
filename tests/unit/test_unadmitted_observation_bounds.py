"""PR #723: bound audit recording, preserving full-name comparison semantics."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.store import SqliteAuditStore
from cmcp_runtime.catalog.loader import ApprovedDefinition
from cmcp_runtime.config import DriftPolicy
from cmcp_runtime.mcp.proxy import NAME_OBSERVATION_CAP, TOOL_NAME_RECORD_MAX_LENGTH
from tests.unit.test_upstream_catalog_drift import (
    O3_ENTRY_TYPE,
    _advertise,
    _catalog,
    _extra,
    _o3_call_proxy,
    _o3_entries,
)

_CONTEXT_KEYS = {
    "source", "measured_catalog_hash", "admission_basis",
    "active_admitted_count", "active_exception_count", "status",
}


def _names(count):
    return [f"unadmitted_{index:05d}" for index in range(count)]


def _string_values(value):
    """Inspect decoded persistence, so JSON escapes cannot hide leaked names."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)


async def _persisted_comparison(tmp_path, names):
    proxy, session, _ = _o3_call_proxy()
    advertised = [*_advertise(), *map(_extra, names)]
    proxy._advertised_tools = AsyncMock(return_value=advertised)
    store = SqliteAuditStore(tmp_path / "bounded-audit.db")
    try:
        chain = AuditChain(session.session_id, store=store)
        proxy._audit = chain
        chain.set_tee_anchor(chain.chain_root)
        assert await proxy._check_upstream_drift(proxy._catalog.entries["lookup_customer"]) is False
        assert session.catalog_drift is False
        assert session.upstream_drift_tools == []
        assert [tool["name"] for tool in advertised] == ["lookup_customer", *names]
        assert chain.verify_chain()
    finally:
        store.close()
    reopened = SqliteAuditStore(tmp_path / "bounded-audit.db")
    try:
        payloads = [json.loads(row[0]) for row in reopened._conn.execute(
            "SELECT payload FROM audit_entries ORDER BY sequence_number"
        ).fetchall()]
    finally:
        reopened.close()
    return payloads


def test_recording_bounds_are_explicit_fixed_choices():
    assert NAME_OBSERVATION_CAP == 64
    assert TOOL_NAME_RECORD_MAX_LENGTH == 256


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [0, 1, 63, 64, 65, 1041])
async def test_recording_cardinality_and_count_only_remainder(tmp_path, count):
    """T1-T5/M1-M3/M6: exact populations and complete persisted-content checks."""
    names = list(reversed(_names(count)))
    payloads = await _persisted_comparison(tmp_path, names)
    observations = [row for row in payloads if row["entry_type"] == O3_ENTRY_TYPE]
    individual = [row for row in observations if row["tool_name"] is not None]
    summaries = [row for row in observations if row["tool_name"] is None]
    expected_names = sorted(set(names))[:64]
    assert [row["tool_name"] for row in individual] == expected_names
    assert len(individual) == min(count, 64)
    for row in observations:
        assert row["detail"]["source"] == "upstream"
        assert row["detail"]["measured_catalog_hash"] == _catalog().catalog_hash
        assert row["detail"]["admission_basis"] == "active_catalog_entries"
        assert row["detail"]["active_admitted_count"] == 1
        assert row["detail"]["active_exception_count"] == 0
    for row in individual:
        assert set(row["detail"]) == _CONTEXT_KEYS | {"recorded_name_truncated"}
        assert row["detail"]["status"] == "observed_unadmitted"
        assert row["detail"]["recorded_name_truncated"] is False
        assert row["detail"]["active_admitted_count"] == 1
        assert row["detail"]["active_exception_count"] == 0
        assert row["call_id"] is None
        assert row["policy_decision"] is None
    if count <= 64:
        assert summaries == []
        assert all("omitted_name_count" not in row["detail"] for row in individual)
    else:
        assert len(summaries) == 1
        summary = summaries[0]
        assert summary["detail"]["status"] == "observed_unadmitted_summary"
        assert type(summary["detail"]["omitted_name_count"]) is int
        assert summary["detail"]["omitted_name_count"] == count - 64
        assert set(summary["detail"]) == _CONTEXT_KEYS | {"omitted_name_count"}
        assert len(observations) == 65
        # Check all persisted fields, not just the individual tool_name column.
        strings = set(_string_values(payloads))
        for omitted in set(names) - set(expected_names):
            assert all(omitted not in value for value in strings)


@pytest.mark.asyncio
async def test_recorded_sample_uses_sorted_full_unique_names(tmp_path):
    names = ["é_extra", "Z_extra", "a_extra", *_names(70), "Z_extra"]
    payloads = await _persisted_comparison(tmp_path, names)
    individual = [row for row in payloads if row["entry_type"] == O3_ENTRY_TYPE
                  and row["tool_name"] is not None]
    assert [row["tool_name"] for row in individual] == sorted(set(names))[:64]
    summary = next(row for row in payloads if row["entry_type"] == O3_ENTRY_TYPE
                   and row["tool_name"] is None)
    assert summary["detail"]["omitted_name_count"] == len(set(names)) - 64


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["x" * 255, "x" * 256, "x" * 257,
                                  "界" * 300, "x" * 255 + "\ud800" + "tail"])
async def test_recorded_name_length_and_truncation_are_persisted(tmp_path, name):
    """T6/M4: boundaries and total hashing for names accepted as Python str."""
    payloads = await _persisted_comparison(tmp_path, [name])
    observation = next(row for row in payloads if row["entry_type"] == O3_ENTRY_TYPE)
    assert observation["tool_name"] == name[:256]
    assert len(observation["tool_name"]) <= 256
    truncated = len(name) > 256
    assert observation["detail"]["recorded_name_truncated"] is truncated
    if truncated:
        assert all(name not in value for value in _string_values(payloads))
        assert observation["detail"]["tool_name_original_length"] == len(name)
        assert observation["detail"]["tool_name_sha256"] == hashlib.sha256(
            name.encode("utf-8", errors="surrogatepass")
        ).hexdigest()
        assert set(observation["detail"]) == _CONTEXT_KEYS | {
            "recorded_name_truncated", "tool_name_original_length", "tool_name_sha256",
        }
    else:
        assert "tool_name_sha256" not in observation["detail"]
        assert "tool_name_original_length" not in observation["detail"]


@pytest.mark.asyncio
async def test_prefix_collision_keeps_two_distinct_original_names(tmp_path):
    """T7/M5: equal displayed prefixes cannot merge source-name observations."""
    prefix = "collision_" + "x" * 246
    assert len(prefix) == 256
    originals = [prefix + "A", prefix + "B"]
    payloads = await _persisted_comparison(tmp_path, list(reversed(originals)))
    rows = [row for row in payloads if row["entry_type"] == O3_ENTRY_TYPE]
    assert len(rows) == 2
    assert [row["tool_name"] for row in rows] == [prefix, prefix]
    assert all(row["detail"]["recorded_name_truncated"] is True for row in rows)
    assert [row["detail"]["tool_name_sha256"] for row in rows] == [
        hashlib.sha256(name.encode()).hexdigest() for name in originals
    ]
    assert rows[0]["detail"]["tool_name_sha256"] != rows[1]["detail"]["tool_name_sha256"]


@pytest.mark.asyncio
@pytest.mark.parametrize("exception", [False, True])
async def test_long_admitted_name_and_colliding_extra_keep_semantics(exception):
    """T7-T8/M5: admission/drift still use the full approved/exception names."""
    catalog = _catalog()
    prefix = "x" * 256
    admitted, extra = prefix + "A", prefix + "B"
    catalog.entries[admitted] = replace(
        catalog.entries["lookup_customer"], tool_name=admitted, catalog_exception=exception,
        approved_definition=ApprovedDefinition(
            description="Additional lookup.", input_schema={}, output_schema=None,
        ),
    )
    proxy, session, chain = _o3_call_proxy(catalog)
    proxy._advertised_tools.return_value = [*_advertise(), _extra(admitted), _extra(extra)]
    assert await proxy._check_upstream_drift(catalog.entries["lookup_customer"]) is False
    assert session.catalog_drift is False
    assert session.upstream_drift_tools == []
    assert set(catalog.entries) == {"lookup_customer", admitted}
    observations = _o3_entries(chain)
    assert len(observations) == 1
    assert observations[0].tool_name == prefix
    assert observations[0].detail["tool_name_sha256"] == hashlib.sha256(extra.encode()).hexdigest()
    assert observations[0].detail["active_admitted_count"] == 2
    assert observations[0].detail["active_exception_count"] == int(exception)
    assert not any(row.entry_type == "catalog_drift" for row in chain.entries)


@pytest.mark.asyncio
@pytest.mark.parametrize("drift_policy", [DriftPolicy.FAIL_CLOSED, DriftPolicy.WARN_ONLY])
@pytest.mark.parametrize("kind", ["definition_changed", "withdrawn"])
async def test_over_bound_population_preserves_definition_and_withdrawal_drift(drift_policy, kind):
    proxy, session, chain = _o3_call_proxy(drift_policy=drift_policy)
    approved = _advertise("changed definition") if kind == "definition_changed" else []
    proxy._advertised_tools.return_value = [*approved, *map(_extra, _names(65))]
    denied = drift_policy is DriftPolicy.FAIL_CLOSED
    assert await proxy._check_upstream_drift(proxy._catalog.entries["lookup_customer"]) is denied
    assert session.catalog_drift is denied
    assert session.upstream_drift_tools == ["lookup_customer"]
    drift = [row for row in chain.entries if row.entry_type == "catalog_drift"]
    assert len(drift) == 1
    assert drift[0].tool_name == "lookup_customer"
    assert drift[0].detail["kind"] == kind
    assert len(_o3_entries(chain)) == 65
    assert _o3_entries(chain)[-1].detail["omitted_name_count"] == 1


@pytest.mark.asyncio
async def test_unchecked_discovery_has_no_name_or_summary_observation():
    proxy, session, chain = _o3_call_proxy()
    proxy._advertised_tools.return_value = None
    assert await proxy._check_upstream_drift(proxy._catalog.entries["lookup_customer"]) is False
    assert session.catalog_drift is False
    assert _o3_entries(chain) == []


@pytest.mark.asyncio
async def test_summary_append_failure_keeps_existing_failure_semantics(tmp_path, monkeypatch):
    proxy, session, _ = _o3_call_proxy()
    proxy._advertised_tools.return_value = [*_advertise(), *map(_extra, _names(65))]
    store = SqliteAuditStore(tmp_path / "summary-failure.db")
    try:
        chain = AuditChain(session.session_id, store=store)
        proxy._audit = chain
        real_append = store.append
        failure = RuntimeError("summary persistence failure")

        def fail_summary(entry):
            if entry.entry_type == O3_ENTRY_TYPE and entry.tool_name is None:
                raise failure
            real_append(entry)

        monkeypatch.setattr(store, "append", fail_summary)
        with pytest.raises(RuntimeError) as caught:
            await proxy.call_tool("c1", "lookup_customer", {})
        assert caught.value is failure
        proxy._forward_to_upstream.assert_not_awaited()
        assert proxy._drift_checked == set()
        assert session.catalog_drift is False
        assert session.upstream_drift_tools == []
        assert len(_o3_entries(chain)) == 64
        rows = [json.loads(row[0]) for row in store._conn.execute(
            "SELECT payload FROM audit_entries WHERE entry_type = ?", (O3_ENTRY_TYPE,)
        ).fetchall()]
        assert len(rows) == 64
        assert all(row["tool_name"] is not None for row in rows)
        fault = [row for row in chain.entries if row.entry_type == "fault"]
        assert len(fault) == 1
        assert fault[0].detail["failure_stage"] == "upstream_drift_check"
        assert fault[0].detail["exception_type"] == "RuntimeError"
        assert chain.verify_chain()
    finally:
        store.close()


@pytest.mark.asyncio
async def test_over_bound_concurrent_then_sequential_first_contact_deduplicates():
    proxy, session, chain = _o3_call_proxy()
    both_waiting, release = asyncio.Event(), asyncio.Event()
    arrivals = 0

    async def discover(entry):
        nonlocal arrivals
        arrivals += 1
        if arrivals == 2:
            both_waiting.set()
        await release.wait()
        return [*_advertise(), *map(_extra, _names(65))]

    proxy._advertised_tools = AsyncMock(side_effect=discover)
    tasks = [asyncio.create_task(proxy.call_tool(f"c{i}", "lookup_customer", {}))
             for i in range(2)]
    try:
        await asyncio.wait_for(both_waiting.wait(), timeout=2)
        assert _o3_entries(chain) == []
        release.set()
        assert all(result.allowed for result in await asyncio.wait_for(asyncio.gather(*tasks), 2))
    finally:
        release.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    assert (await proxy.call_tool("c2", "lookup_customer", {})).allowed is True
    assert arrivals == 2
    assert len(_o3_entries(chain)) == 65
    assert len([row for row in _o3_entries(chain) if row.tool_name is None]) == 1
    assert _o3_entries(chain)[-1].detail["omitted_name_count"] == 1
    assert session.catalog_drift is False
    assert session.upstream_drift_tools == []
