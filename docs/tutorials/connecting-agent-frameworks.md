# Connecting Agent Frameworks

This page is for developers who write their own agent code. It shows how to point an agent built with LangChain, LlamaIndex or a plain HTTP client at the cMCP gateway, so every tool call the agent makes is checked against your rules and logged. You get working examples for each and a way to read what the gateway reports back on every call.

Already using an app configured with an `mcpServers` block? Start with
[Try cMCP from an existing MCP client](existing-mcp-clients.md) instead; no agent code
is required.

## What you'll learn

- How the gateway presents itself as a standard MCP endpoint
- How to configure bearer token auth in your agent
- How to read the `_cmcp` metadata block that every response carries
- LangChain, LlamaIndex, and raw `httpx` examples

## Prerequisites

```bash
pip install cmcp-runtime
```

Start the gateway in dev mode:

```bash
CMCP_DEV_MODE=1 CMCP_BEARER_TOKEN=dev-token cmcp start --config cmcp-config.yaml
```

Confirm it is up:

```bash
curl http://localhost:8443/health
# {"status": "ok"}
```

---

## How the gateway looks to an agent

To your agent, the gateway looks like any other MCP server reached over HTTP. It listens at `listen_addr` (by default `127.0.0.1:8443` in dev mode, otherwise `0.0.0.0:8443`). These endpoints matter for agent code:

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/mcp` | POST | Bearer token | All MCP JSON-RPC calls (`tools/call`, `tools/list`, `initialize`) |
| `/tools/list` | GET | Bearer token | Convenience read of the attested catalog |
| `/health` | GET | None | Liveness probe |

Every request to `/mcp` must carry an access token in the header `Authorization: Bearer <token>`, and the token must match `CMCP_BEARER_TOKEN`. Requests without a valid token get HTTP 401.

---

## Tool discovery

Before making tool calls, retrieve the list of approved tools:

```bash
curl -s http://localhost:8443/tools/list \
  -H "Authorization: Bearer dev-token" | python -m json.tool
```

Or via MCP JSON-RPC:

```bash
curl -s -X POST http://localhost:8443/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dev-token" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

The response lists only the tools in the catalog (`catalog.json`, the operator's list of approved tools). A tool that is not in the catalog cannot be called, whatever the agent asks for.

---

## The `_cmcp` response block

Every allowed tool call returns a normal MCP `result`, plus an extra `_cmcp` block in which the gateway reports what it did:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{"type": "text", "text": "<tool response>"}],
    "_cmcp": {
      "call_id": "a3f8c1d2-...",
      "audit_entry_hash": "sha256:7f3c9a...",
      "would_have_denied": false,
      "latency_us": 12400,
      "session_id": "s-abc123",
      "workflow_id": "my-agent-run"
    }
  }
}
```

| Field | Meaning |
|---|---|
| `call_id` | Unique ID for this tool call; matches the audit chain entry |
| `audit_entry_hash` | SHA-256 of the audit entry committed to the chain for this call |
| `would_have_denied` | `true` when the gateway is in `advisory` mode and policy would have denied the call |
| `latency_us` | Gateway processing latency in microseconds (excludes upstream round-trip) |
| `session_id` | The active session this call belongs to |
| `workflow_id` | Echoed from `_cmcp.workflow_id` in the request, if provided |

When `would_have_denied` is `true`, there may also be an `advice` field holding notes from the rule that matched.

### Pass `workflow_id` from your agent

Set `_cmcp.workflow_id` in the request `params` to label tool calls as part of one named agent run:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "salesforce.contacts",
    "arguments": {"query": "Acme Corp"},
    "_cmcp": {"workflow_id": "sales-enrichment-v2"}
  }
}
```

`workflow_id` appears in the audit chain entries for every call made under that identifier.

### Declare a per call data class

Each tool in the catalog has a `sensitivity_level`, the kind of data it normally handles. When one particular call handles more sensitive data than that, say so by setting `_cmcp.data_class` in the request `params`. An example is a single tool that sometimes carries personal data (`pii`) and sometimes `confidential` data ([#479](https://github.com/agentrust-io/cmcp/issues/479)):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "model.chat",
    "arguments": {"prompt": "..."},
    "_cmcp": {"data_class": "confidential"}
  }
}
```

The value you declare can only raise the sensitivity for this call, never lower it below the tool's catalogue level. It also raises the session's `max_sensitivity` for the rest of the session.

??? info "Technical detail: how the declared class is combined"
    The declared value composes with any labels a deployment has added under `sensitivity.vocabulary` in config. An unrecognised value is silently ignored rather than rejected, the same treatment an unrecognised built in content pattern tag gets: it simply cannot rank above the catalogued floor. The effective class, not the raw declaration, is what appears in the signed transcript for that call.

---

## Raw `httpx` client

```python
import httpx
import json

GATEWAY = "http://localhost:8443"
TOKEN = "dev-token"


def call_tool(tool_name: str, arguments: dict, workflow_id: str | None = None) -> dict:
    params: dict = {"name": tool_name, "arguments": arguments}
    if workflow_id:
        params["_cmcp"] = {"workflow_id": workflow_id}

    with httpx.Client() as client:
        resp = client.post(
            f"{GATEWAY}/mcp",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {TOKEN}",
            },
            content=json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": params,
            }),
            timeout=30,
        )
    resp.raise_for_status()
    data = resp.json()

    if "error" in data:
        error = data["error"]
        error_code = error.get("data", {}).get("error_code", "UNKNOWN")
        raise RuntimeError(f"{error_code}: {error['message']}")

    result = data["result"]
    cmcp_meta = result.get("_cmcp", {})
    print(f"call_id={cmcp_meta.get('call_id')} latency={cmcp_meta.get('latency_us')}µs")

    return result
```

---

## LangChain

Use LangChain's MCP support if your version has it, or wrap the gateway in a custom tool:

```python
from langchain.tools import BaseTool
from pydantic import BaseModel
import httpx, json
from typing import Any


class CMCPTool(BaseTool):
    """Wraps a single cMCP-gated tool as a LangChain tool."""

    name: str
    description: str
    gateway_url: str
    bearer_token: str
    workflow_id: str | None = None

    class ArgsSchema(BaseModel):
        arguments: dict[str, Any]

    def _run(self, arguments: dict[str, Any]) -> str:
        params: dict = {"name": self.name, "arguments": arguments}
        if self.workflow_id:
            params["_cmcp"] = {"workflow_id": self.workflow_id}

        resp = httpx.post(
            f"{self.gateway_url}/mcp",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.bearer_token}",
            },
            content=json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": params,
            }),
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        if "error" in data:
            error_code = data["error"].get("data", {}).get("error_code", "UNKNOWN")
            raise RuntimeError(f"Tool denied: {error_code}")

        content = data["result"]["content"]
        return content[0]["text"] if content else ""
```

Instantiate per approved tool:

```python
salesforce_tool = CMCPTool(
    name="salesforce.contacts",
    description="Query Salesforce CRM contacts",
    gateway_url="http://localhost:8443",
    bearer_token="dev-token",
    workflow_id="lc-agent-run-001",
)
```

---

## LlamaIndex

```python
from llama_index.tools import FunctionTool
import httpx, json


def make_cmcp_fn(tool_name: str, gateway_url: str, bearer_token: str):
    def call(**arguments) -> str:
        resp = httpx.post(
            f"{gateway_url}/mcp",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {bearer_token}",
            },
            content=json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            }),
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RuntimeError(data["error"]["message"])
        content = data["result"]["content"]
        return content[0]["text"] if content else ""

    call.__name__ = tool_name
    return call


crm_tool = FunctionTool.from_defaults(
    fn=make_cmcp_fn("salesforce.contacts", "http://localhost:8443", "dev-token"),
    name="salesforce.contacts",
    description="Query Salesforce CRM contacts",
)
```

---

## Handle denied calls

When your rules refuse a call, the gateway returns HTTP 403:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Request denied by policy",
    "data": {
      "error_code": "POLICY_DENY",
      "call_id": "a3f8c1d2-...",
      "advice": {"escalate_to": "compliance-team@example.com"}
    }
  }
}
```

`error_code` is either `POLICY_DENY` (a `forbid` rule matched) or `TOOL_NOT_IN_CATALOG` (the tool is not in the approved catalog). The `advice` field, when present, holds notes from the rule. They come from your own policy files, whose fingerprint is fixed when the gateway starts, and never from the caller, so they are safe to log and act on.

---

## Summary

| Framework | Integration point |
|---|---|
| Any HTTP client | `POST /mcp` with `Authorization: Bearer <token>` |
| LangChain | Custom `BaseTool` wrapping the HTTP call |
| LlamaIndex | `FunctionTool.from_defaults` wrapping a closure |

Every tool call through the gateway gets an `audit_entry_hash`, its fingerprint in the log. After the session ends, download the full log from `GET /audit/export?session_id=<id>` and check it against the signed session record from `GET /sessions/<id>/trace-claim`.

Related tutorials: the [Cedar policy walkthrough](./cedar-policy-walkthrough.md) covers writing the rules that govern these calls, and [Tool catalog authoring](./tool-catalog-authoring.md) covers what goes in `catalog.json` and how each tool's fingerprint is computed.
