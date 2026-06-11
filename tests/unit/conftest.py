"""Shared unit-test helpers for mocking the CMCPProxy gateway seam.

The proxy's step 3 calls three seams:
  1. _mcp_gateway.intercept_tool_call(agent_id=, tool_name=, params=) -> (bool, str)  [sync]
  2. proxy._forward_to_upstream(call_id, entry, tool_name, arguments) -> str          [async]
  3. _mcp_gateway.intercept_tool_response(agent_id=, tool_name=, response_content=)
     -> object with .allowed (bool), .content (str|None), .threats (list[dict]),
        .action (str)                                                                  [sync]
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock


def wire_mock_gateway(
    proxy,
    *,
    response_text: str = "tool response",
    call_allowed: bool = True,
    call_reason: str = "ok",
    scan_allowed: bool = True,
    threats: list[dict] | None = None,
    scan_content: str | None = None,
):
    """Replace the proxy's AGT gateway + upstream forwarding with mocks."""
    proxy._mcp_gateway = MagicMock()
    proxy._mcp_gateway.intercept_tool_call = MagicMock(
        return_value=(call_allowed, call_reason)
    )
    proxy._forward_to_upstream = AsyncMock(return_value=response_text)
    proxy._mcp_gateway.intercept_tool_response = MagicMock(
        return_value=MagicMock(
            allowed=scan_allowed,
            content=scan_content if scan_content is not None else response_text,
            threats=threats or [],
            action="allowed" if scan_allowed else "blocked",
        )
    )
    return proxy
