# Tool Catalog Authoring

This page is for operators who decide which tools an AI agent may use through cMCP. That list is the tool catalog (`catalog.json`): the gateway passes calls only to tools named in it. You learn what each field means, how to write entries for low-risk and high-risk tools, and how to compute the catalog's fingerprint so others can check which catalog was in force.

When cMCP starts, it takes a fingerprint (hash) of every catalog entry and puts it in the signed TRACE claim. Adding, removing or changing any field changes `catalog_hash`, so earlier attestations no longer match.

The JSON Schema that describes a valid catalog entry ships inside the Python package, and cMCP needs it to start. If the schema is missing or unreadable, cMCP refuses to load the catalog; it never falls back to a partial check.

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
    "catalog_exception": false,
    "schema_validation_mode": "redact"
  }
]
```

All fields are required. `catalog_exception` defaults to `false`. It is set only through the emergency override endpoint (`POST /catalog/exception`, the "break-glass" API), never in the file itself.

---

## Field reference

### `tool_name`

The tool's name. **Must be lowercase.** The gateway refuses to start (`ConfigError`) if any tool name contains a capital letter. The name must match exactly what the tool server offers and what agents send in `tools/call` requests.

### `server`

Which tool server provides this tool, and how to recognise it:

```json
{
  "display_name": "Salesforce MCP",
  "url": "https://salesforce-mcp.internal:443",
  "tls_fingerprint": "sha256:<hex of DER cert>",
  "spiffe_id": "spiffe://example.org/ns/prod/salesforce",
  "transport": "streamable-http",
  "rotation_mode": "key-pinned"
}
```

| Field | Required | Description |
|---|---|---|
| `display_name` | Yes | Human-readable label for logs and TRACE claims |
| `url` | Yes | Full URL including port |
| `tls_fingerprint` | Yes | SHA-256 of the server's DER-encoded TLS certificate (see [TLS pinning](./tls-pinning.md)) |
| `spiffe_id` | No | SPIFFE/SVID identity if the server uses workload identity |
| `transport` | Yes | Use `"streamable-http"` for current MCP servers, `"http-sse"` only for legacy 2024-11-05 deployments, or `"stdio"` for a measured child process. Unknown values fail startup. |
| `rotation_mode` | No | Default `"key-pinned"` |

### `approved_definition`

What the tool is allowed to do. This is the part that is fingerprinted into `definition_hash`:

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

`input_schema` is a JSON Schema describing the arguments the tool accepts; the gateway checks each call against it (how strictly is set by `schema_validation_mode`). `output_schema` describes the tool's response and is checked the same way; `null` turns that check off.

### `definition_hash`

SHA-256 of the canonical JSON of `approved_definition`, prefixed with `sha256:`:

```python
import hashlib, json

def compute_definition_hash(approved_definition: dict) -> str:
    canonical = json.dumps(approved_definition, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return f"sha256:{digest}"
```

The gateway recomputes this when it loads the catalog and refuses the catalog if any stored hash does not match. That way nobody can quietly change an approved definition after it was signed off.

### `compliance_domain`

A label that groups tools by the kind of rules they fall under. Your Cedar policies can use it, for example to say that tools in the `pii` domain may only be used by an agent cleared for personal data. Common values: `"pii"`, `"financial"`, `"phi"`, `"internal"`, `"external"`. cMCP does not check the value; it only passes it to your policy.

### `requires_baa`

`true` or `false`. When `true`, your Cedar policies can require a Business Associate Agreement (a US health-data contract) to be in place before calls are allowed. cMCP only passes the flag to the policy; the rules do the enforcing.

### `sensitivity_level`

How sensitive the data this tool returns is. Common values: `"public"`, `"internal"`, `"confidential"`, `"pii"`. cMCP remembers the highest level a session has touched: after a session calls a `"pii"` tool, every later call in that session carries `session_sensitivity: "pii"` into your Cedar rules.

The allowed values are the built-in list plus anything added in config under `sensitivity.vocabulary` (see [session-policy.md](../spec/session-policy.md#session-sensitivity-state-machine)), so a stricter level required by a particular regulator can be used once it is added there. An entry naming any other level fails to load, on purpose.

### `added_at`

When this entry was approved, as an ISO 8601 timestamp. It is part of the fingerprint and appears in the TRACE claim.

### `approved_by`

Who approved the entry (a person, team or process). It is part of the fingerprint and appears in log entries for emergency overrides.

### `catalog_exception`

A string, or null. When set, it marks this entry as an emergency exception and gives the reason. Exceptions added through the override endpoint (`POST /catalog/exception`) always show in the TRACE claim, even though they do not change `catalog_hash`.

### `schema_validation_mode`

What the gateway does when a call's arguments do not fit `input_schema`:

| Value | Behavior |
|---|---|
| `"redact"` | Strip fields not in the schema, pass remaining arguments. Default. |
| `"strict"` | Reject the call with HTTP 422 if any argument fails validation |
| `"log"` | Log the violation but pass through unchanged |

Use `"strict"` for tools that handle sensitive data, where an unexpected field could be a sign of prompt injection (hidden instructions planted in what the agent read). Use `"redact"` (the default) when agents may send extra fields the tool ignores. Use `"log"` only while getting a first picture of traffic, since it blocks nothing.

---

## How `catalog_hash` is computed

The `catalog_hash` in the TRACE claim is one fingerprint over the whole catalog, not one per entry:

```python
import hashlib, json

def compute_catalog_hash(entries: list[dict]) -> str:
    sorted_entries = sorted(entries, key=lambda e: e["tool_name"])
    canonical = json.dumps(sorted_entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return f"sha256:{digest}"
```

Steps:
1. Sort entries by `tool_name` (ascending and case-sensitive, though tool names are always lowercase)
2. Canonical JSON: `sort_keys=True`, no spaces (`separators=(",", ":")`)
3. SHA-256 of the UTF-8 bytes

Compute the hash before deploying with a short Python script:

```python
import hashlib, json

def catalog_hash(entries: list[dict]) -> str:
    sorted_entries = sorted(entries, key=lambda e: e["tool_name"])
    canonical = json.dumps(sorted_entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

with open("catalog.json") as f:
    entries = json.load(f)

print(catalog_hash(entries))
```

Pin it in `CMCP_CATALOG_HASH` or in your attestation policy so any unapproved catalog change is caught. After startup the hash also appears in the TRACE claim under `gateway.catalog.hash`.

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
    "catalog_exception": false,
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
    "catalog_exception": false,
    "schema_validation_mode": "strict"
  }
]
```

`kyc.verify` (an identity check) uses `"strict"` because unexpected fields in that call could signal prompt injection. `crm.query` uses `"redact"` because agents may pass extra fields the CRM ignores.

---

## Validate before deploying

Compute and pin the catalog hash before starting the gateway:

```bash
# Pin the catalog hash (required in production: see CMCP_CATALOG_HASH)
export CMCP_CATALOG_HASH="$(python -c "
import hashlib, json
entries = json.load(open('catalog.json'))
s = sorted(entries, key=lambda e: e['tool_name'])
c = json.dumps(s, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
print('sha256:' + hashlib.sha256(c.encode()).hexdigest())
")"

# Validate the Cedar policy bundle hash separately
cmcp validate-bundle --bundle-path ./policies/ --expected-hash sha256:<hex>

# Validate cmcp-config.yaml syntax
cmcp validate-config --config cmcp-config.yaml
```

If anything is wrong, both commands exit with an error and the gateway is not started.

---

## Summary

1. All `tool_name` values must be lowercase
2. `definition_hash` = SHA-256 of canonical JSON of `approved_definition` (sort_keys, no spaces)
3. `catalog_hash` = SHA-256 of canonical JSON of all entries sorted by `tool_name`
4. Use `"strict"` schema validation for high-sensitivity tools; `"redact"` is the safe default for others
5. `sensitivity_level` feeds session tracking; `compliance_domain` feeds Cedar policy context

Related tutorials: the [Cedar policy walkthrough](./cedar-policy-walkthrough.md) covers using `compliance_domain` and `sensitivity_level` in rules, and [TLS pinning](./tls-pinning.md) covers computing `tls_fingerprint` values.
