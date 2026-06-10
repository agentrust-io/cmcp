# Tool Identity and Catalog Specification

---
Status: Draft v0.1
Last updated: 2026-06-04
Stability: Unstable , expect breaking changes before v1.0
---

This document specifies how the cMCP Runtime identifies upstream MCP servers, prevents tool name collisions, and routes tool calls. These mechanisms close the protocol-level gap in MCP (issue #40): MCP defines no signed manifest binding a tool name to a publisher. The runtime closes this by maintaining a catalog that binds each tool name to a specific upstream server identity.

---

## Section 1 -- Server Identity Format

Each upstream MCP server has two identity anchors:

### TLS Fingerprint

The SHA-256 fingerprint of the server's TLS certificate public key:

```
SHA256:aabbccdd...
```

The fingerprint is computed over the server's public key. Its behavior at cert renewal depends on the configured rotation mode -- see [Cert Rotation Policy](#cert-rotation-policy) below.

### SPIFFE SVID

A URI of the form:

```
spiffe://<trust-domain>/<namespace>/<service-name>
```

Example: `spiffe://corp.example/salesforce/mcp-server`

SPIFFE SVIDs are issued by a SPIRE server shared between the runtime and the upstream servers. The runtime verifies the SVID against the SPIRE trust bundle at connection time. SPIFFE is the preferred identity anchor when the deployment includes a SPIRE server.

### Phase 1 Requirement

In Phase 1, each catalog entry must include at least one identity anchor (`tls_fingerprint` or `spiffe_id`). Including both is preferred: the runtime verifies whichever anchors are present, and a mismatch on either is treated as an identity failure.

---

## Section 2 -- Catalog Entry Schema

Each tool in the catalog has a full entry binding the tool name to its upstream server and approved definition:

```json
{
  "tool_name": "salesforce.query",
  "server": {
    "display_name": "Salesforce MCP Server",
    "url": "https://mcp.salesforce.com/mcp",
    "tls_fingerprint": "SHA256:aabbcc...",
    "spiffe_id": "spiffe://corp.example/salesforce/mcp-server",
    "rotation_mode": "key-pinned"
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
| `server.url` | string | yes | URL the runtime routes calls to for this tool. |
| `server.tls_fingerprint` | string | at least one of `tls_fingerprint` or `spiffe_id` | SHA-256 fingerprint of the server's TLS public key. |
| `server.spiffe_id` | string | at least one of `tls_fingerprint` or `spiffe_id` | SPIFFE SVID URI for the server. |
| `server.rotation_mode` | string | no (default: `key-pinned`) | `key-pinned` or `cert-pinned`. Controls how cert renewal is handled. See [Cert Rotation Policy](#cert-rotation-policy). |
| `approved_definition` | object | yes | The approved tool definition (description and schemas) as reviewed by the security team. |
| `definition_hash` | string | yes | SHA-256 of `canonical_json(approved_definition)`. Used for mutation detection. |
| `added_at` | ISO8601 | yes | Timestamp when the entry was added to the catalog. |
| `approved_by` | string | yes | Identity of the approver (email or SPIFFE SVID). |

### Definition Hash and Mutation Detection

The `definition_hash` is computed at catalog approval time and included in the `tool_catalog.hash` measurement in the TRACE Claim. At runtime, the process fetches the live tool definition from the upstream server and compares it against `approved_definition`. If the live definition does not match:

- The call is denied.
- The audit log records the event as `definition_mismatch`.
- The TRACE Claim reflects the denial.

This closes the rug-pull attack vector (P4.2): a compromised upstream server cannot change a tool's behavior by altering its definition without being detected.

---

## Section 3 -- Collision Detection

Tool name uniqueness is enforced at catalog load time (enclave startup).

**Rule**: each `tool_name` must map to exactly one upstream server. If two catalog entries share the same `tool_name`, the runtime refuses to start.

**Error message**:

```
Duplicate tool name in catalog: "salesforce.query" is registered by two different servers:
  - https://mcp.salesforce.com/mcp (tls_fingerprint: SHA256:aabbcc...)
  - https://legacy-crm.internal/mcp (tls_fingerprint: SHA256:112233...)
Each tool name must map to exactly one upstream server.
```

The runtime does not attempt to resolve the collision. It fails closed: no tools are available until the collision is resolved.

**Resolution**: namespace the tool names. Example:

| Original (colliding) | Namespaced |
|----------------------|------------|
| `salesforce.query` (from Salesforce MCP Server) | `salesforce_mcp.query` |
| `salesforce.query` (from legacy CRM) | `legacy_crm.query` |

Cedar policies and agent configurations must be updated to use the namespaced names.

### Why Fail-Closed

Silent collision resolution (e.g., last-write-wins or first-registered-wins) would allow a malicious or misconfigured server to shadow a legitimate tool. Refusing to start ensures that an operator must explicitly resolve the ambiguity. This closes the tool name collision attack vector (P2.3).

---

## Section 4 -- Routing

When the runtime receives a tool call for `tool_name`:

1. Look up `tool_name` in the catalog.
   - If not found: deny the call, log as `tool_not_in_catalog`.

2. Extract `server.url`, `server.tls_fingerprint`, `server.spiffe_id`, and `server.rotation_mode` from the catalog entry.

3. Open (or reuse) a connection to `server.url`.

4. Verify the server's identity:
   - If `tls_fingerprint` is set: verify the server's TLS certificate public key fingerprint matches `catalog[tool_name].server.tls_fingerprint`. For `key-pinned` mode, the fingerprint is stable across cert renewals; for `cert-pinned` mode, a new cert triggers an identity mismatch even if the key is the same.
   - If `spiffe_id` is set: verify the server's SPIFFE SVID matches `catalog[tool_name].server.spiffe_id` via the SPIRE trust bundle.
   - If either verification that is configured fails: deny the call, log as `identity_mismatch`.

5. Fetch the live tool definition from the upstream server and compare against `approved_definition` using `definition_hash`.
   - If mismatch: deny the call, log as `definition_mismatch`.

6. Forward the tool call to the upstream server.

7. Return the response to the runtime's response inspection pipeline.

### Identity Mismatch Handling

An `identity_mismatch` event indicates one of:

- The upstream server's TLS certificate was rotated with a new key (legitimate rotation requiring catalog update, or key compromise).
- The upstream server's TLS certificate was renewed with the same key but `cert-pinned` mode is configured (legitimate renewal requiring catalog update).
- A man-in-the-middle or DNS hijack is in progress.
- The server was replaced with a different instance (legitimate infrastructure change, requires catalog update).

In all cases, the runtime denies the call and does not forward any data to the server until the catalog is updated and the enclave is restarted with the new measurement.

---

## Cert Rotation Policy

Two modes are supported. The operator selects one when adding a server to the catalog by setting `server.rotation_mode`.

**Mode A: Key-pinning (recommended)**
The catalog entry stores the fingerprint of the server's current public key. The server reuses the same keypair at cert renewal (renewing only the certificate, not the key). The fingerprint does not change at renewal. No catalog update required.
- Advantage: no operational disruption at cert renewal
- Risk: if the server's private key is compromised, the attacker can use the same key indefinitely until the catalog is manually updated
- Catalog field: `"rotation_mode": "key-pinned"`

**Mode B: Cert-pinning**
The catalog entry stores the fingerprint of the server's specific certificate (including its expiry). At cert renewal (even with the same keypair), the fingerprint changes. A catalog update and enclave restart are required.
- Advantage: automatic detection of any cert change, including unauthorized renewal
- Risk: operational overhead at every cert renewal; agents cannot call the tool until the catalog is updated
- Catalog field: `"rotation_mode": "cert-pinned"`

**Default:** Mode A (key-pinned) for HTTP/SSE MCP servers with long-lived endpoints. Mode B for short-lived or frequently rotated certs.

**For SPIFFE-based identity:** SPIFFE SVIDs are short-lived (typically 1 hour). The catalog entry stores the SPIFFE ID URI (not the SVID certificate itself). SPIRE issues new SVIDs automatically; the SPIFFE ID URI is stable across renewals. No cert rotation policy needed when SPIFFE is the primary identity anchor.
