# Tool Identity and Catalog Specification

This document specifies how the cMCP Gateway identifies upstream MCP servers, prevents tool name collisions, and routes tool calls. These mechanisms close the protocol-level gap in MCP (issue #40): MCP defines no signed manifest binding a tool name to a publisher. The gateway closes this by maintaining a catalog that binds each tool name to a specific upstream server identity.

---

## Section 1 — Server Identity Format

Each upstream MCP server has two identity anchors:

### TLS Fingerprint

The SHA-256 fingerprint of the server's TLS certificate public key:

```
SHA256:aabbccdd...
```

This is a key-pinning approach: the fingerprint is stable across certificate renewals as long as the public key is stable. If the server rotates its private key, the fingerprint changes. The gateway detects this as an identity change and requires a catalog update before routing calls to that server.

### SPIFFE SVID

A URI of the form:

```
spiffe://<trust-domain>/<namespace>/<service-name>
```

Example: `spiffe://corp.example/salesforce/mcp-server`

SPIFFE SVIDs are issued by a SPIRE server shared between the gateway and the upstream servers. The gateway verifies the SVID against the SPIRE trust bundle at connection time. SPIFFE is the preferred identity anchor when the deployment includes a SPIRE server.

### Phase 1 Requirement

In Phase 1, each catalog entry must include at least one identity anchor (`tls_fingerprint` or `spiffe_id`). Including both is preferred: the gateway verifies whichever anchors are present, and a mismatch on either is treated as an identity failure.

---

## Section 2 — Catalog Entry Schema

Each tool in the catalog has a full entry binding the tool name to its upstream server and approved definition:

```json
{
  "tool_name": "salesforce.query",
  "server": {
    "display_name": "Salesforce MCP Server",
    "url": "https://mcp.salesforce.com/mcp",
    "tls_fingerprint": "SHA256:aabbcc...",
    "spiffe_id": "spiffe://corp.example/salesforce/mcp-server"
  },
  "approved_definition": {
    "description": "Query Salesforce records by SOQL",
    "input_schema": {
      "type": "object",
      "properties": {
        "query": { "type": "string" }
      }
    },
    "output_schema": {
      "type": "object"
    }
  },
  "definition_hash": "sha256:...",
  "added_at": "2026-06-01T00:00:00Z",
  "approved_by": "security-team@example.com"
}
```

### Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool_name` | string | yes | Unique tool name as it appears in MCP. Must be unique across the entire catalog. |
| `server.display_name` | string | yes | Human-readable name for the upstream server. |
| `server.url` | string | yes | URL the gateway routes calls to for this tool. |
| `server.tls_fingerprint` | string | at least one of `tls_fingerprint` or `spiffe_id` | SHA-256 fingerprint of the server's TLS public key. |
| `server.spiffe_id` | string | at least one of `tls_fingerprint` or `spiffe_id` | SPIFFE SVID URI for the server. |
| `approved_definition` | object | yes | The approved tool definition (description and schemas) as reviewed by the security team. |
| `definition_hash` | string | yes | SHA-256 of `canonical_json(approved_definition)`. Used for mutation detection. |
| `added_at` | ISO8601 | yes | Timestamp when the entry was added to the catalog. |
| `approved_by` | string | yes | Identity of the approver (email or SPIFFE SVID). |

### Definition Hash and Mutation Detection

The `definition_hash` is computed at catalog approval time and included in the `tool_catalog.hash` measurement in the TRACE Claim. At runtime, the gateway fetches the live tool definition from the upstream server and compares it against `approved_definition`. If the live definition does not match:

- The call is denied.
- The audit log records the event as `definition_mismatch`.
- The TRACE Claim reflects the denial.

This closes the rug-pull attack vector (P4.2): a compromised upstream server cannot change a tool's behavior by altering its definition without being detected.

---

## Section 3 — Collision Detection

Tool name uniqueness is enforced at catalog load time (enclave startup).

**Rule**: each `tool_name` must map to exactly one upstream server. If two catalog entries share the same `tool_name`, the gateway refuses to start.

**Error message**:

```
Duplicate tool name in catalog: "salesforce.query" is registered by two different servers:
  - https://mcp.salesforce.com/mcp (tls_fingerprint: SHA256:aabbcc...)
  - https://legacy-crm.internal/mcp (tls_fingerprint: SHA256:112233...)
Each tool name must map to exactly one upstream server.
```

The gateway does not attempt to resolve the collision. It fails closed: no tools are available until the collision is resolved.

**Resolution**: namespace the tool names. Example:

| Original (colliding) | Namespaced |
|----------------------|------------|
| `salesforce.query` (from Salesforce MCP Server) | `salesforce_mcp.query` |
| `salesforce.query` (from legacy CRM) | `legacy_crm.query` |

Cedar policies and agent configurations must be updated to use the namespaced names.

### Why Fail-Closed

Silent collision resolution (e.g., last-write-wins or first-registered-wins) would allow a malicious or misconfigured server to shadow a legitimate tool. Refusing to start ensures that an operator must explicitly resolve the ambiguity. This closes the tool name collision attack vector (P2.3).

---

## Section 4 — Routing

When the gateway receives a tool call for `tool_name`:

1. Look up `tool_name` in the catalog.
   - If not found: deny the call, log as `tool_not_in_catalog`.

2. Extract `server.url`, `server.tls_fingerprint`, and `server.spiffe_id` from the catalog entry.

3. Open (or reuse) a connection to `server.url`.

4. Verify the server's identity:
   - If `tls_fingerprint` is set: verify the server's TLS certificate public key fingerprint matches `catalog[tool_name].server.tls_fingerprint`.
   - If `spiffe_id` is set: verify the server's SPIFFE SVID matches `catalog[tool_name].server.spiffe_id` via the SPIRE trust bundle.
   - If either verification that is configured fails: deny the call, log as `identity_mismatch`.

5. Fetch the live tool definition from the upstream server and compare against `approved_definition` using `definition_hash`.
   - If mismatch: deny the call, log as `definition_mismatch`.

6. Forward the tool call to the upstream server.

7. Return the response to the gateway's response inspection pipeline.

### Identity Mismatch Handling

An `identity_mismatch` event indicates one of:

- The upstream server's TLS certificate was rotated with a new key (legitimate rotation, requires catalog update).
- A man-in-the-middle or DNS hijack is in progress.
- The server was replaced with a different instance (legitimate infrastructure change, requires catalog update).

In all cases, the gateway denies the call and does not forward any data to the server until the catalog is updated and the enclave is restarted with the new measurement.
