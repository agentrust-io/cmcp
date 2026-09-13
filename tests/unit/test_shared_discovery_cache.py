"""Session-scoped discovery sharing; transport/signature coverage lives separately.

These unit tests replace only acquisition, not the cache under test. A completed
empty catalog, an unchecked result, and a cancelled acquisition are distinct.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.config import DriftPolicy
from cmcp_runtime.provenance import ProvenanceOutcome, ProvenanceResult
from cmcp_runtime.session.state import SessionState
from tests.unit.test_upstream_catalog_drift import _advertise, _catalog, _proxy


@pytest.mark.parametrize("outcome", [[], None], ids=["empty-catalog", "unchecked"])
async def test_completed_empty_and_unchecked_results_are_cached(outcome):
    catalog = _catalog()
    proxy, _, _ = _proxy(catalog, drift_policy=DriftPolicy.FAIL_CLOSED)
    proxy._discover_tools = AsyncMock(return_value=outcome)
    entry = catalog.entries["lookup_customer"]

    assert await proxy._advertised_tools(entry) == outcome
    assert await proxy._advertised_tools(entry) == outcome
    proxy._discover_tools.assert_awaited_once_with(entry)


async def test_concurrent_drift_checks_wait_for_one_completed_comparison():
    """A first-contact marker is not permission to skip an in-flight check."""
    catalog = _catalog()
    proxy, session, chain = _proxy(catalog, drift_policy=DriftPolicy.FAIL_CLOSED)
    entry = catalog.entries["lookup_customer"]
    started, release, second_started = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def discover(_entry):
        started.set()
        await release.wait()
        return _advertise("Changed upstream definition")

    async def second_check():
        second_started.set()
        return await proxy._check_upstream_drift(entry)

    proxy._discover_tools = AsyncMock(side_effect=discover)
    first = asyncio.create_task(proxy._check_upstream_drift(entry))
    await asyncio.wait_for(started.wait(), timeout=1)
    second = asyncio.create_task(second_check())
    try:
        await asyncio.wait_for(second_started.wait(), timeout=1)
        assert not first.done()
        assert not second.done()
        assert not proxy._drift_checked
    finally:
        release.set()
        results = await asyncio.wait_for(asyncio.gather(first, second), timeout=1)

    assert results == [True, True]
    assert session.catalog_drift is True
    assert len([item for item in chain.entries if item.entry_type == "catalog_drift"]) == 1
    proxy._discover_tools.assert_awaited_once_with(entry)


async def test_cancelled_acquisition_is_not_cached_and_waiter_retries():
    catalog = _catalog()
    proxy, session, _ = _proxy(catalog, drift_policy=DriftPolicy.FAIL_CLOSED)
    entry = catalog.entries["lookup_customer"]
    started, second_started = asyncio.Event(), asyncio.Event()
    attempts = 0

    async def discover(_entry):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            started.set()
            await asyncio.Event().wait()
        return _advertise()

    async def second_check():
        second_started.set()
        return await proxy._check_upstream_drift(entry)

    proxy._discover_tools = AsyncMock(side_effect=discover)
    first = asyncio.create_task(proxy._check_upstream_drift(entry))
    await asyncio.wait_for(started.wait(), timeout=1)
    second = asyncio.create_task(second_check())
    await asyncio.wait_for(second_started.wait(), timeout=1)
    assert not second.done()
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert await asyncio.wait_for(second, timeout=1) is False
    assert await proxy._advertised_tools(entry) == _advertise()
    assert session.catalog_drift is False
    assert proxy._discover_tools.await_count == 2


async def test_cancelled_waiter_does_not_cancel_the_shared_acquisition():
    catalog = _catalog()
    proxy, _, _ = _proxy(catalog, drift_policy=DriftPolicy.FAIL_CLOSED)
    entry = catalog.entries["lookup_customer"]
    started, release, waiter_started = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def discover(_entry):
        started.set()
        await release.wait()
        return _advertise()

    async def wait_for_catalog():
        waiter_started.set()
        return await proxy._advertised_tools(entry)

    proxy._discover_tools = AsyncMock(side_effect=discover)
    owner = asyncio.create_task(proxy._advertised_tools(entry))
    await asyncio.wait_for(started.wait(), timeout=1)
    waiter = asyncio.create_task(wait_for_catalog())
    try:
        await asyncio.wait_for(waiter_started.wait(), timeout=1)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert not owner.done()
    finally:
        release.set()
        assert await asyncio.wait_for(owner, timeout=1) == _advertise()

    assert await proxy._advertised_tools(entry) == _advertise()
    proxy._discover_tools.assert_awaited_once_with(entry)


@pytest.mark.parametrize(
    "server_change",
    [
        {"url": "https://other.example/mcp"},
        {"tls_fingerprint": "sha256:" + "d" * 64},
        {"provenance_record_path": "another-record.json"},
        {"publisher_jwk": {"kty": "EC", "kid": "another-authority"}},
    ],
    ids=["endpoint", "tls-pin", "record", "publisher-authority"],
)
async def test_discovery_cache_does_not_cross_server_or_provenance_identity(server_change):
    catalog = _catalog()
    proxy, _, _ = _proxy(catalog, drift_policy=DriftPolicy.FAIL_CLOSED)
    entry = catalog.entries["lookup_customer"]
    other = replace(entry, server=replace(entry.server, **server_change))
    proxy._discover_tools = AsyncMock(side_effect=[_advertise(), []])

    assert await proxy._advertised_tools(entry) == _advertise()
    assert await proxy._advertised_tools(other) == []
    assert await proxy._advertised_tools(entry) == _advertise()
    assert await proxy._advertised_tools(other) == []
    assert proxy._discover_tools.await_count == 2


async def test_tools_and_display_labels_sharing_server_identity_share_discovery():
    catalog = _catalog()
    proxy, _, _ = _proxy(catalog, drift_policy=DriftPolicy.FAIL_CLOSED)
    entry = catalog.entries["lookup_customer"]
    other = replace(
        entry, tool_name="another_tool", server=replace(entry.server, display_name="alias")
    )
    proxy._discover_tools = AsyncMock(return_value=_advertise())

    assert await proxy._advertised_tools(entry) == _advertise()
    assert await proxy._advertised_tools(other) == _advertise()
    proxy._discover_tools.assert_awaited_once_with(entry)


async def test_slow_discovery_does_not_block_a_different_server():
    catalog = _catalog()
    proxy, _, _ = _proxy(catalog, drift_policy=DriftPolicy.FAIL_CLOSED)
    entry = catalog.entries["lookup_customer"]
    other = replace(entry, server=replace(entry.server, url="https://other.example/mcp"))
    started, release = asyncio.Event(), asyncio.Event()

    async def discover(candidate):
        if candidate.server.url == entry.server.url:
            started.set()
            await release.wait()
            return _advertise()
        return []

    proxy._discover_tools = AsyncMock(side_effect=discover)
    slow = asyncio.create_task(proxy._advertised_tools(entry))
    await asyncio.wait_for(started.wait(), timeout=1)
    try:
        assert await asyncio.wait_for(proxy._advertised_tools(other), timeout=1) == []
        assert not slow.done()
    finally:
        release.set()
        assert await asyncio.wait_for(slow, timeout=1) == _advertise()
    assert proxy._discover_tools.await_count == 2


async def test_rebind_rechecks_discovery_drift_and_provenance():
    """Acquisition and both downstream verdicts expire at the session boundary."""
    catalog = _catalog()
    proxy, old_session, old_chain = _proxy(catalog, drift_policy=DriftPolicy.FAIL_CLOSED)
    entry = catalog.entries["lookup_customer"]
    entry.server.provenance_record_path = "unit-test-record.json"
    proxy._discover_tools = AsyncMock(side_effect=[_advertise(), _advertise("Changed")])
    initial = ProvenanceResult(ProvenanceOutcome.VERIFIED, kind="publisher-asserted")
    changed = ProvenanceResult(ProvenanceOutcome.CATALOG_MISMATCH, kind="publisher-asserted")
    with patch(
        "cmcp_runtime.mcp.proxy.check_server_provenance", side_effect=[initial, changed]
    ) as check:
        assert await proxy._check_upstream_drift(entry) is False
        assert await proxy._check_provenance(entry) == initial
        assert proxy._discover_tools.await_count == 1

        session = SessionState(session_id="next-session")
        chain = AuditChain(session_id=session.session_id)
        proxy.rebind_session(session, chain)
        assert await proxy._check_upstream_drift(entry) is True
        assert await proxy._check_provenance(entry) == changed
        assert check.call_count == 2

    assert proxy._discover_tools.await_count == 2
    assert old_session.catalog_drift is False
    assert not any(item.entry_type == "catalog_drift" for item in old_chain.entries)
    assert session.catalog_drift is True
    assert len([item for item in chain.entries if item.entry_type == "catalog_drift"]) == 1


async def test_rebind_discards_old_inflight_result_and_retries_old_waiters():
    """Neither an old acquisition nor a waiter may publish into the next session."""
    catalog = _catalog()
    proxy, _, old_chain = _proxy(catalog, drift_policy=DriftPolicy.FAIL_CLOSED)
    entry = catalog.entries["lookup_customer"]
    started, release, second_started = asyncio.Event(), asyncio.Event(), asyncio.Event()
    attempts = 0

    async def discover(_entry):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            started.set()
            await release.wait()
            return _advertise("Old-session definition must not enter the new session")
        return _advertise()

    async def old_waiter():
        second_started.set()
        return await proxy._check_upstream_drift(entry)

    proxy._discover_tools = AsyncMock(side_effect=discover)
    old_fetch = asyncio.create_task(proxy._check_upstream_drift(entry))
    await asyncio.wait_for(started.wait(), timeout=1)
    old_waiting = asyncio.create_task(old_waiter())
    await asyncio.wait_for(second_started.wait(), timeout=1)
    session = SessionState(session_id="next-session")
    chain = AuditChain(session_id=session.session_id)
    proxy.rebind_session(session, chain)
    try:
        # The new session must not wait for the old session's acquisition lock.
        assert await asyncio.wait_for(proxy._check_upstream_drift(entry), timeout=1) is False
    finally:
        release.set()
        results = await asyncio.wait_for(asyncio.gather(old_fetch, old_waiting), timeout=1)

    assert results == [False, False]
    assert await proxy._advertised_tools(entry) == _advertise()
    assert proxy._discover_tools.await_count == 2
    assert session.catalog_drift is False
    assert not any(item.entry_type == "catalog_drift" for item in old_chain.entries)
    assert not any(item.entry_type == "catalog_drift" for item in chain.entries)
