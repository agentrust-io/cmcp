# Connecting Agent Frameworks

Wire a real agent: LangChain, LlamaIndex, or a plain HTTP client: to the cMCP gateway so every tool call passes through policy enforcement.

## What you'll learn

- How the gateway presents itself as a standard MCP endpoint
- How to configure bearer token auth in your agent
- How to read the `_cmcp` metadata block that every response carries
- LangChain, LlamaIndex, and raw `httpx` examples

## Prerequisites

```
pip install cmcp-runtime
```

Start the gateway in dev mode:

```
CMCP_DEV_MODE=1 CMCP_BEARER_TOKEN=dev-token cmcp start --config cmcp-config.yaml
```

Confirm it is up:

```
curl http://localhost:8443/health
# {"status": "ok"}
```

______________________________________________________________________

## How the gateway looks to an agent

The gateway runs at `listen_addr` (default `127.0.0.1:8443` in dev mode, otherwise `0.0.0.0:8443`) and exposes a standard MCP over HTTP/SSE transport. Two endpoints matter for agent frameworks:

| Endpoint      | Method | Auth         | Purpose                                                           |
| ------------- | ------ | ------------ | ----------------------------------------------------------------- |
| `/mcp`        | POST   | Bearer token | All MCP JSON-RPC calls (`tools/call`, `tools/list`, `initialize`) |
| `/tools/list` | GET    | Bearer token | Convenience read of the attested catalog                          |
| `/health`     | GET    | None         | Liveness probe                                                    |

Every request to `/mcp` must include `Authorization: Bearer <token>` where the token matches `CMCP_BEARER_TOKEN`. Requests without a valid token receive HTTP 401.

______________________________________________________________________

## Tool discovery

Before making tool calls, retrieve the list of approved tools:

```
curl -s http://localhost:8443/tools/list \
  -H "Authorization: Bearer dev-token" | python -m json.tool
```

Or via MCP JSON-RPC:

```
curl -s -X POST http://localhost:8443/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dev-token" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

The response lists only tools in the attested catalog: any tool not in `catalog.json` cannot be called regardless of what the agent requests.

______________________________________________________________________

## The `_cmcp` response block

Every allowed tool call returns a standard MCP `result` with a `_cmcp` metadata extension:

```
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

| Field               | Meaning                                                                             |
| ------------------- | ----------------------------------------------------------------------------------- |
| `call_id`           | Unique ID for this tool call; matches the audit chain entry                         |
| `audit_entry_hash`  | SHA-256 of the audit entry committed to the chain for this call                     |
| `would_have_denied` | `true` when the gateway is in `advisory` mode and policy would have denied the call |
| `latency_us`        | Gateway processing latency in microseconds (excludes upstream round-trip)           |
| `session_id`        | The active session this call belongs to                                             |
| `workflow_id`       | Echoed from `_cmcp.workflow_id` in the request, if provided                         |

When `would_have_denied` is `true`, an `advice` field may also be present with annotations from the matching policy rule.

### Pass `workflow_id` from your agent

Set `_cmcp.workflow_id` in the request `params` to associate tool calls with a named agent run:

```
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

______________________________________________________________________

## Raw `httpx` client

```
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

______________________________________________________________________

## LangChain

Use LangChain's `MCP` integration if available, or wrap the gateway with a custom tool:

```
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

```
salesforce_tool = CMCPTool(
    name="salesforce.contacts",
    description="Query Salesforce CRM contacts",
    gateway_url="http://localhost:8443",
    bearer_token="dev-token",
    workflow_id="lc-agent-run-001",
)
```

______________________________________________________________________

## LlamaIndex

```
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

______________________________________________________________________

## Handle denied calls

When a call is denied by policy, the gateway returns HTTP 403:

```
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

`error_code` is either `POLICY_DENY` (a Cedar forbid rule matched) or `TOOL_NOT_IN_CATALOG` (the tool name is not in the approved catalog). The `advice` field, when present, carries annotations from the policy rule: these come from the hash-pinned policy bundle, not from caller input, so they are safe to log and act on.

______________________________________________________________________

## Summary

| Framework       | Integration point                                |
| --------------- | ------------------------------------------------ |
| Any HTTP client | `POST /mcp` with `Authorization: Bearer <token>` |
| LangChain       | Custom `BaseTool` wrapping the HTTP call         |
| LlamaIndex      | `FunctionTool.from_defaults` wrapping a closure  |

Every tool call that passes through the gateway produces an `audit_entry_hash`. After the session ends, retrieve the full audit bundle at `GET /audit/export?session_id=<id>` and verify it with `GET /sessions/<id>/trace-claim`.

Related tutorials: [Cedar policy walkthrough](https://cmcp.agentrust-io.com/tutorials/cedar-policy-walkthrough/index.md): writing the policies that govern these calls. [Tool catalog authoring](https://cmcp.agentrust-io.com/tutorials/tool-catalog-authoring/index.md): what goes in `catalog.json` and how definition hashes are computed.
