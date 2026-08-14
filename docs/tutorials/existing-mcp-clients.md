# Try cMCP from an existing MCP client

Start the cMCP gateway, then configure a client that supports the standard
`mcpServers` stdio shape to launch the included bridge:

```json
{
  "mcpServers": {
    "governed-tools": {
      "command": "cmcp",
      "args": ["client-bridge", "--gateway-url", "https://gateway.example/mcp"],
      "env": {"CMCP_BEARER_TOKEN": "replace-with-the-gateway-token"}
    }
  }
}
```

Restart the client after changing its configuration. Its `tools/list` and
`tools/call` messages now pass through cMCP and appear in the gateway audit
chain; upstream addresses remain solely in the attested cMCP catalog.

## What this proves—and what it does not

The bridge is an evaluation aid. It runs on the user's machine, outside the
TEE and outside cMCP's measurement. A user who controls the client
configuration can remove it, so this does **not** prove cMCP cannot be
bypassed. Production enforcement requires controls that make the governed
gateway the only reachable path to upstream servers.

The bearer token is read from `CMCP_BEARER_TOKEN`; do not put it in command
arguments, where process-list tooling may expose it. Diagnostics go to stderr
so stdout remains strict newline-delimited JSON-RPC.

Design and trust boundary: [#510](https://github.com/agentrust-io/cmcp/issues/510).
