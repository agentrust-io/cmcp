"""MCP 2026-07-28 Streamable HTTP request and response helpers."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import httpx

from cmcp_runtime import __version__

PROTOCOL_VERSION = "2026-07-28"
_META_VERSION = "io.modelcontextprotocol/protocolVersion"
_META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
_META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
_HEADER_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _header_value(value: str) -> str:
    """Encode a value using MCP's Base64 sentinel when plain ASCII is unsafe."""
    safe = (
        value == value.strip()
        and all(char == "\t" or 0x20 <= ord(char) <= 0x7E for char in value)
        and not (value.startswith("=?base64?") and value.endswith("?="))
    )
    if safe:
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"=?base64?{encoded}?="


def build_request(
    request_id: str,
    method: str,
    params: dict[str, Any],
    *,
    name: str | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Build a modern stateless MCP request and its mirrored HTTP headers."""
    body_params = dict(params)
    body_params["_meta"] = {
        _META_VERSION: PROTOCOL_VERSION,
        _META_CLIENT_INFO: {"name": "cmcp-runtime", "version": __version__},
        _META_CLIENT_CAPABILITIES: {},
    }
    body = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": body_params,
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
        "Mcp-Method": method,
    }
    if name is not None:
        headers["Mcp-Name"] = _header_value(name)
    return body, headers


def parameter_headers(
    input_schema: dict[str, Any], arguments: dict[str, Any]
) -> dict[str, str]:
    """Mirror statically reachable ``x-mcp-header`` tool parameters."""
    headers: dict[str, str] = {}
    seen: set[str] = set()

    def visit(schema: dict[str, Any], value: Any) -> None:
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return
        instance = value if isinstance(value, dict) else {}
        for property_name, child in properties.items():
            if not isinstance(child, dict):
                continue
            annotation = child.get("x-mcp-header")
            if annotation is not None:
                if (
                    not isinstance(annotation, str)
                    or not _HEADER_TOKEN.fullmatch(annotation)
                    or annotation.lower() in seen
                    or child.get("type") not in ("string", "integer", "boolean")
                ):
                    raise ValueError(f"invalid x-mcp-header annotation: {annotation!r}")
                seen.add(annotation.lower())
                if property_name in instance and instance[property_name] is not None:
                    raw = instance[property_name]
                    expected = child["type"]
                    if expected == "boolean" and isinstance(raw, bool):
                        rendered = "true" if raw else "false"
                    elif expected == "integer" and isinstance(raw, int) and not isinstance(raw, bool):
                        if abs(raw) > 2**53 - 1:
                            raise ValueError("x-mcp-header integer exceeds JavaScript safe range")
                        rendered = str(raw)
                    elif expected == "string" and isinstance(raw, str):
                        rendered = raw
                    else:
                        raise ValueError(
                            f"x-mcp-header value for {property_name!r} does not match {expected}"
                        )
                    headers[f"Mcp-Param-{annotation}"] = _header_value(rendered)
            visit(child, instance.get(property_name))

    visit(input_schema, arguments)
    return headers


def parse_response(response: httpx.Response, request_id: str) -> dict[str, Any]:
    """Parse a JSON or request-scoped SSE response and return the final reply."""
    media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type == "application/json":
        body = response.json()
        if not isinstance(body, dict):
            raise ValueError("MCP JSON response is not an object")
        return body
    if media_type != "text/event-stream":
        raise ValueError(f"unsupported MCP response content type: {media_type or 'missing'}")

    data_lines: list[str] = []
    for line in response.text.splitlines() + [""]:
        if line == "":
            if data_lines:
                event = json.loads("\n".join(data_lines))
                data_lines.clear()
                if (
                    isinstance(event, dict)
                    and str(event.get("id")) == str(request_id)
                    and ("result" in event or "error" in event)
                ):
                    return event
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            value = line[5:]
            data_lines.append(value[1:] if value.startswith(" ") else value)
    raise ValueError("MCP SSE stream ended without a matching final response")
