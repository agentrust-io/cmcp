"""stdio-to-HTTP bridge for configuring existing MCP clients behind cMCP."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, TextIO

import httpx


def _error(request_id: Any, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32000, "message": message}}


def bridge_stream(
    source: TextIO,
    sink: TextIO,
    *,
    gateway_url: str,
    bearer_token: str,
    client: httpx.Client,
) -> None:
    """Forward newline-delimited JSON-RPC without diagnostics on stdout."""
    headers = {"Authorization": f"Bearer {bearer_token}"}
    for raw_line in source:
        request_id: Any = None
        try:
            message = json.loads(raw_line)
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise ValueError("input is not a JSON-RPC 2.0 object")
            request_id = message.get("id")
            response = client.post(gateway_url, json=message, headers=headers)
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
                raise ValueError("gateway response is not a JSON-RPC 2.0 object")
        except (json.JSONDecodeError, ValueError) as exc:
            body = _error(request_id, f"cMCP bridge protocol error: {exc}")
        except httpx.HTTPStatusError as exc:
            body = _error(request_id, f"cMCP gateway returned HTTP {exc.response.status_code}")
        except httpx.HTTPError as exc:
            sys.stderr.write(f"cMCP bridge transport error: {exc}\n")
            body = _error(request_id, "cMCP gateway unavailable")
        sink.write(json.dumps(body, separators=(",", ":")) + "\n")
        sink.flush()


def run_bridge(gateway_url: str, token_env: str) -> None:
    """Run with a bearer token read only from the named environment variable."""
    token = os.environ.get(token_env)
    if not token:
        raise RuntimeError(f"required bearer token environment variable {token_env} is unset")
    with httpx.Client(timeout=httpx.Timeout(30.0)) as client:
        bridge_stream(sys.stdin, sys.stdout, gateway_url=gateway_url,
                      bearer_token=token, client=client)
