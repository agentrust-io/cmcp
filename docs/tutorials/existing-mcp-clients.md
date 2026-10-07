# Try cMCP from an existing MCP client

This page is for anyone who already uses an AI app that talks to tools over MCP
(Model Context Protocol, the common way AI agents call outside tools). With one
config change, every tool call your app makes goes through the cMCP gateway,
which checks it against your rules and logs it. You write no agent code.

Start the cMCP gateway, then add the entry below to your client's `mcpServers`
block (the standard place MCP apps list the tool servers they launch). It starts
the small bridge program that ships with cMCP:

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

Restart the client after changing its configuration. From then on, when the
app lists tools (`tools/list`) or calls one (`tools/call`), the request goes
through cMCP and is written to the gateway's audit chain, a tamper-evident log
where each entry is linked to the one before it. Your app never sees the real
addresses of the tool servers; those stay in cMCP's catalog, the list of
approved tools that is included in the gateway's attestation.

## What this proves, and what it does not

The bridge is for trying cMCP out. It runs on your own machine, outside the TEE
(the protected hardware area cMCP can run in) and outside what cMCP measures
and signs. Anyone who controls the client configuration can remove it, so this
setup does **not** prove that calls cannot go around cMCP. In production you
also need network or host controls that leave the gateway as the only way to
reach the tool servers.

The bridge reads the access token from the `CMCP_BEARER_TOKEN` environment
variable. Do not pass it as a command argument, because tools that list running
processes can show it. Diagnostic messages go to stderr, so stdout carries only
the newline-separated JSON-RPC messages the client expects.

Design and trust boundary: [#510](https://github.com/agentrust-io/cmcp/issues/510).
