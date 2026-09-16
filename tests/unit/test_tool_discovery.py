"""Issue #631: acquisition must finish before a catalog becomes comparable."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from cmcp_runtime.mcp import discovery
from cmcp_runtime.mcp.discovery import DiscoveryError, collect_tools


def _pages(*results):
    remaining = iter(results)

    async def fetch(request_id, params):
        return {"jsonrpc": "2.0", "id": request_id, "result": next(remaining)}

    return AsyncMock(side_effect=fetch)


@pytest.mark.parametrize("cursor", ["", "opaque /+==\n雪", "0"])
async def test_empty_page_with_opaque_cursor_is_not_terminal(cursor):
    tool = {"name": "lookup", "input_schema": {}, "extension": {"kept": True}}
    fetch = _pages({"tools": [], "nextCursor": cursor}, {"tools": [tool]})
    assert await collect_tools(fetch) == [tool]
    assert fetch.call_args_list[0].args[1] == {}
    assert fetch.call_args_list[1].args[1] == {"cursor": cursor}
    assert fetch.call_args_list[0].args[0] != fetch.call_args_list[1].args[0]


async def test_terminal_empty_page_completes_empty_catalog():
    assert await collect_tools(_pages({"tools": []})) == []


@pytest.mark.parametrize(
    "bad_page",
    [
        None,
        [],
        {},
        {"tools": None},
        {"tools": {}},
        {"tools": [None]},
        {"tools": [{"name": 1}]},
        {"tools": [{}]},
        {"tools": [{"name": ""}]},
        {"tools": [], "nextCursor": None},
        {"tools": [], "nextCursor": 0},
        {"tools": [], "nextCursor": []},
    ],
)
async def test_malformed_later_page_never_returns_partial_catalog(bad_page):
    fetch = _pages({"tools": [{"name": "lookup"}], "nextCursor": "next"}, bad_page)
    with pytest.raises(DiscoveryError):
        await collect_tools(fetch)
    assert fetch.await_count == 2


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        {},
        {"jsonrpc": "1.0", "id": "provenance-tools-list-0", "result": {"tools": []}},
        {"jsonrpc": "2.0", "id": "wrong", "result": {"tools": []}},
        {"jsonrpc": "2.0", "id": "provenance-tools-list-0", "error": {"message": "secret"}},
        {"jsonrpc": "2.0", "id": "provenance-tools-list-0", "error": None, "result": {"tools": []}},
    ],
)
async def test_malformed_or_error_envelope_is_not_a_listing(body):
    with pytest.raises(DiscoveryError, match="^invalid response envelope$"):
        await collect_tools(AsyncMock(return_value=body))


@pytest.mark.parametrize("cursors", [["secret", "secret"], ["secret", "other", "secret"]])
async def test_repeated_and_cyclic_cursors_terminate_without_exposing_cursor(cursors):
    fetch = _pages(*({"tools": [], "nextCursor": cursor} for cursor in cursors))
    with pytest.raises(DiscoveryError, match="^repeated continuation cursor$"):
        await collect_tools(fetch)
    assert fetch.await_count == len(cursors)


@pytest.mark.parametrize("same_page", [False, True])
async def test_duplicate_names_are_ambiguous_even_with_matching_definitions(same_page):
    tool = {"name": "lookup"}
    fetch = (
        _pages({"tools": [tool, tool]})
        if same_page
        else _pages({"tools": [tool], "nextCursor": "next"}, {"tools": [tool]})
    )
    with pytest.raises(DiscoveryError, match="^duplicate tool name$"):
        await collect_tools(fetch)


async def test_exact_page_budget_can_complete_but_cannot_return_partial(monkeypatch):
    monkeypatch.setattr(discovery, "MAX_DISCOVERY_PAGES", 2)
    first = {"tools": [{"name": "lookup"}], "nextCursor": "one"}
    complete = _pages(first, {"tools": []})
    assert await collect_tools(complete) == first["tools"]
    continuing = _pages(first, {"tools": [], "nextCursor": "two"})
    with pytest.raises(DiscoveryError, match="^discovery page limit exceeded$"):
        await collect_tools(continuing)
    assert continuing.await_count == 2


@pytest.mark.parametrize("failure", [RuntimeError("upstream failure"), asyncio.CancelledError()])
async def test_transport_failure_and_cancellation_propagate(failure):
    with pytest.raises(type(failure)):
        await collect_tools(AsyncMock(side_effect=failure))
