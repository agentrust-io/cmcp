# Tool Catalog Authoring

The tool catalog is the operator-controlled allowlist of MCP tools the gateway will route. Every entry is hashed into the TRACE claim at startup; adding, removing, or changing any field changes `catalog_hash` and invalidates prior attestations.

## What you'll learn

- The full structure of `catalog.json` and what each field controls
- How `definition_hash` and `catalog_hash` are computed (so you can verify them independently)
- `schema_validation_mode` and what "redact" vs "strict" means
- A complete example with two tools from different risk tiers

## Prerequisites

```bash
pip install cmcp-runtime
```

---

## The catalog format

`catalog.json` is a JSON array of catalog entries:

```json
[
  {
    "tool_name": "salesforce.contacts",
    "server": { ... },
    "approved_definition": { ... },
    "definition_hash": "sha256:<hex>",
    "compliance_domain": "pii",
    "requires_baa": false,
    "sensitivity_level": "pii",
    "added_at": "2026-06-01T00:00:00Z",
    "approved_by": "security-team",
    "catalog_exception": null,
    "schema_validation_mode": "redact"
  }
]
```

All fields are required except `catalog_exception` (nullable).

---

## Field reference

### `tool_name`

The canonical name of the tool. **Must be lowercase.** The gateway rejects any catalog that contains uppercase characters in a tool name with a `ConfigError` at startup. This name must match exactly what the MCP server advertises and what agents send in `tools/call` requests.

### `server`

Identity of the upstream MCP server that provides this tool:

```json
{
  "display_name": "Salesforce MCP",
  "url": "https://salesforce-mcp.internal:443",
  "tls_fingerprint": "sha256:<hex of DER cert>",
  "spiffe_id": "spiffe://example.org/ns/prod/salesforce",
  "transport": "http-sse",
  "rotation_mode": "key-pinned"
}
```

| Field | Required | Description |
|---|---|---|
| `display_name` | Yes | Human-readable label for logs and TRACE claims |
| `url` | Yes | Full URL including port |
| `tls_fingerprint` | Yes | SHA-256 of the server's DER-encoded TLS certificate (see [TLS pinning](./tls-pinning.md)) |
| `spiffe_id` | No | SPIFFE/SVID identity if the server uses workload identity |
| `transport` | No | Default `"http-sse"` |
| `rotation_mode` | No | Default `"key-pinned"` |

### `approved_definition`

What the tool is allowed to do. This is what gets hashed into `definition_hash`:

```json
{
  "description": "Query CRM contacts by name, email, or account",
  "input_schema": {
    "type": "object",
    "properties": {
      "query": {"type": "string"},
      "limit": {"type": "integer", "maximum": 100}
    },
    "required": ["query"]
  },
  "output_schema": null
}
```

`input_schema` is a JSON Schema object. The gateway uses it for schema validation at call time (controlled by `schema_validation_mode`). `output_schema` validates the tool's response; `null` disables response schema validation.

### `definition_hash`

SHA-256 of the canonical JSON of `approved_definition`, prefixed with `sha256:`:

```python
import hashlib, json

def compute_definition_hash(approved_definition: dict) -> str:
    canonical = json.dumps(approved_definition, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return f"sha256:{digest}"
```

The gateway recomputes this at load time and rejects the catalog if any entry's stored hash does not match. This prevents silent modification of approved definitions after signing.

### `compliance_domain`

A string label grouping tools by their compliance context. Used by Cedar policies to write rules like "tools in domain `pii` require a PII handler principal attribute." Common values: `"pii"`, `"financial"`, `"phi"`, `"internal"`, `"external"`. The runtime does not validate the value — it is a policy input.

### `requires_baa`

Boolean. When `true`, Cedar policies can enforce that a Business Associate Agreement is in place before allowing calls. The runtime surfaces this to the policy engine as a context attribute; enforcement is via Cedar rules.

### `sensitivity_level`

String label for the data sensitivity of this tool's outputs. Common values: `"public"`, `"internal"`, `"confidential"`, `"pii"`. The session sensitivity tracker uses this: after a session calls a `"pii"` tool, all subsequent calls in the session carry `session_sensitivity: "pii"` in Cedar context.

### `added_at`

ISO 8601 timestamp when this entry was approved. Included in the canonical hash and surfaced in the TRACE claim.

### `approved_by`

String identifying who approved the entry (person, team, or process). Included in the canonical hash. Appears in break-glass audit entries.

### `catalog_exception`

Nullable string. When set, marks this entry as a break-glass exception with a reason. Exceptions added via the runtime API (`POST /catalog/exception`) are always visible in the TRACE claim even though they do not modify `catalog_hash`.

### `schema_validation_mode`

Controls what the gateway does when a tool call argument fails schema validation against `input_schema`:

| Value | Behavior |
|---|---|
| `"redact"` | Strip fields not in the schema, pass remaining arguments. Default. |
| `"strict"` | Reject the call with HTTP 422 if any argument fails validation |
| `"log"` | Log the violation but pass through unchanged |

Use `"strict"` for tools that handle sensitive data where unexpected fields could indicate an injection attempt. Use `"redact"` (the default) when agents may send extra fields the tool ignores. Use `"log"` only for baselining — it provides no enforcement.

---

## How `catalog_hash` is computed

The `catalog_hash` measured into the TRACE claim covers the full catalog, not individual entries:

```python
import hashlib, json

def compute_catalog_hash(entries: list[dict]) -> str:
    sorted_entries = sorted(entries, key=lambda e: e["tool_name"])
    canonical = json.dumps(sorted_entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return f"sha256:{digest}"
```

Steps:
1. Sort entries by `tool_name` (ascending, case-sensitive — but tool names are always lowercase)
2. Canonical JSON: `sort_keys=True`, no spaces (`separators=(",", ":")`)
3. SHA-256 of the UTF-8 bytes

You can verify the hash the gateway will compute before deploying:

```bash
cmcp validate-config --config cmcp-config.yaml
```

This prints the computed `catalog_hash`. Pin it in `CMCP_CATALOG_HASH` or in your attestation policy to detect unauthorized catalog changes.

---

## Complete two-tool example

```json
[
  {
    "tool_name": "crm.query",
    "server": {
      "display_name": "Internal CRM MCP",
      "url": "https://crm-mcp.prod.internal:443",
      "tls_fingerprint": "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
      "transport": "http-sse",
      "rotation_mode": "key-pinned"
    },
    "approved_definition": {
      "description": "Query CRM contacts and accounts",
      "input_schema": {
        "type": "object",
        "properties": {
          "query": {"type": "string", "maxLength": 512},
          "limit": {"type": "integer", "minimum": 1, "maximum": 50}
        },
        "required": ["query"]
      },
      "output_schema": null
    },
    "definition_hash": "sha256:7f3c9a1b2e4d8f6a0c5b7e9d3f1a4c8b2e6f0d4a8c1b3e5f7a9d2c4e6f8a0b2",
    "compliance_domain": "pii",
    "requires_baa": false,
    "sensitivity_level": "pii",
    "added_at": "2026-06-01T00:00:00Z",
    "approved_by": "security-team",
    "catalog_exception": null,
    "schema_validation_mode": "redact"
  },
  {
    "tool_name": "kyc.verify",
    "server": {
      "display_name": "KYC Verification Service",
      "url": "https://kyc-mcp.prod.internal:443",
      "tls_fingerprint": "sha256:c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
      "transport": "http-sse",
      "rotation_mode": "key-pinned"
    },
    "approved_definition": {
      "description": "Run KYC identity verification on a customer record",
      "input_schema": {
        "type": "object",
        "properties": {
          "customer_id": {"type": "string"},
          "check_level": {"type": "string", "enum": ["basic", "enhanced"]}
        },
        "required": ["customer_id", "check_level"]
      },
      "output_schema": null
    },
    "definition_hash": "sha256:9d2c4e6f8a0b2c4e6f8a0b2c4e6f8a0b2c4e6f8a0b2c4e6f8a0b2c4e6f8a0b2c",
    "compliance_domain": "financial",
    "requires_baa": false,
    "sensitivity_level": "confidential",
    "added_at": "2026-06-01T00:00:00Z",
    "approved_by": "compliance-officer",
    "catalog_exception": null,
    "schema_validation_mode": "strict"
  }
]
```

Note that `kyc.verify` uses `"strict"` because unexpected fields in a KYC call could indicate prompt injection; `crm.query` uses `"redact"` because agents may pass extra context fields the CRM ignores.

---

## Validate before deploying

```bash
# Validate catalog JSON structure and hash computation
cmcp validate-config --config cmcp-config.yaml

# Verify the bundle hash if you also want to pin policies
cmcp validate-bundle --bundle-path ./policies/ --expected-hash sha256:<hex>
```

Both commands exit non-zero on any validation error without starting the gateway.

---

## Summary

1. All `tool_name` values must be lowercase
2. `definition_hash` = SHA-256 of canonical JSON of `approved_definition` (sort_keys, no spaces)
3. `catalog_hash` = SHA-256 of canonical JSON of all entries sorted by `tool_name`
4. Use `"strict"` schema validation for high-sensitivity tools; `"redact"` is the safe default for others
5. `sensitivity_level` feeds session tracking; `compliance_domain` feeds Cedar policy context

Related tutorials: [Cedar policy walkthrough](./cedar-policy-walkthrough.md) — using `compliance_domain` and `sensitivity_level` in Cedar rules. [TLS pinning](./tls-pinning.md) — computing `tls_fingerprint` values.
