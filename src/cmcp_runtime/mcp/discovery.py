"""Acquire a complete tools/list before drift or provenance comparison.

This is acquisition validation, not approval or a catalog hash construction.
No partial result escapes: every page must be attributable and well-shaped,
and pagination must terminate within the local page budget.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

# A page bound also terminates servers that issue endlessly distinct cursors.
# It is not a wall-clock deadline or a guarantee of an atomic server snapshot.
MAX_DISCOVERY_PAGES = 1000

PageFetcher = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


class DiscoveryError(ValueError):
    """A bounded local reason; never embed upstream payloads or cursor values."""


async def collect_tools(fetch_page: PageFetcher) -> list[dict[str, Any]]:
    """Return only an exhausted, unambiguous listing; otherwise raise.

    Transport failures and cancellation propagate to the owning transport.
    Cursors are opaque strings, including the empty string. Only absence of
    nextCursor terminates a listing; an empty page alone does not.
    """
    tools: list[dict[str, Any]] = []
    names: set[str] = set()
    cursors: set[str] = set()
    params: dict[str, Any] = {}
    for page in range(MAX_DISCOVERY_PAGES):
        request_id = f"provenance-tools-list-{page}"
        body = await fetch_page(request_id, params)
        if (
            not isinstance(body, dict)
            or body.get("jsonrpc") != "2.0"
            or body.get("id") != request_id
            or "error" in body
        ):
            raise DiscoveryError("invalid response envelope")
        result = body.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            raise DiscoveryError("invalid tools page")
        for tool in result["tools"]:
            if (
                not isinstance(tool, dict)
                or not isinstance(tool.get("name"), str)
                or not tool["name"]
            ):
                raise DiscoveryError("invalid tool name")
            if tool["name"] in names:
                raise DiscoveryError("duplicate tool name")
            names.add(tool["name"])
            tools.append(tool)
        if "nextCursor" not in result:
            return tools
        cursor = result["nextCursor"]
        if not isinstance(cursor, str):
            raise DiscoveryError("invalid continuation cursor")
        if cursor in cursors:
            raise DiscoveryError("repeated continuation cursor")
        cursors.add(cursor)
        params = {"cursor": cursor}
    raise DiscoveryError("discovery page limit exceeded")
