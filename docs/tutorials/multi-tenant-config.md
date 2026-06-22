# Multi-Tenant Deployment

Run cMCP with per-tenant policy isolation by deploying separate runtime instances, each with its own Cedar bundle, catalog, and audit chain.

## What you'll learn

- The config-level approach to per-tenant isolation (no multi-tenant API exists)
- How separate policy bundle hashes identify tenant policies in TRACE records
- An example with two tenants using different tool allowlists
- How audit chain isolation works per session
- What verifiers see when comparing claims across tenants

## Prerequisites

```bash
pip install cmcp-runtime
```

---

## Understand the isolation model

cMCP does not have a built-in multi-tenant API. Tenant isolation is achieved by running one gateway instance per tenant, each with its own configuration. Each instance:

- Loads its own Cedar policy bundle (different `policy_bundle_path`)
- Loads its own tool catalog (different `catalog_path`)
- Has its own `CMCP_POLICY_HASH` and `CMCP_CATALOG_HASH`
- Listens on a separate port (different `listen_addr`)
- Maintains separate session state and audit chains

This is the only supported isolation model. A single gateway instance with shared state does not provide tenant policy isolation.

---

## Lay out the directory structure

```
cmcp-tenants/
  tenant-a/
    cmcp-config.yaml
    policies/
      allow.cedar
      manifest.json
      schema.cedarschema
    catalog.json
  tenant-b/
    cmcp-config.yaml
    policies/
      allow.cedar
      manifest.json
      schema.cedarschema
    catalog.json
```

---

## Configure tenant A

Tenant A is a customer-facing workflow. It can call CRM and support tools only.

`tenant-a/cmcp-config.yaml`:

```yaml
attestation:
  provider: auto
  enforcement_mode: enforcing
policy_bundle_path: ./policies/
catalog_path: ./catalog.json
listen_addr: "0.0.0.0:8443"
```

`tenant-a/policies/allow.cedar`:

```cedar
permit (
  principal,
  action == cMCP::Action::"call_tool",
  resource
)
when {
  resource.tool_name in ["crm.get_customer", "support.create_ticket"]
};

forbid (
  principal,
  action == cMCP::Action::"call_tool",
  resource
);
```

`tenant-a/catalog.json` — includes only the two tools tenant A is allowed to call:

```json
[
  {
    "tool_name": "crm.get_customer",
    "server": {
      "display_name": "CRM Server",
      "url": "https://crm.internal/mcp",
      "tls_fingerprint": "SHA256:<crm-server-fingerprint>=",
      "transport": "http-sse",
      "rotation_mode": "key-pinned"
    },
    "approved_definition": { ... },
    "definition_hash": "sha256:<hash>",
    "sensitivity_level": "pii",
    "added_at": "2026-06-01T00:00:00Z",
    "approved_by": "platform-team@example.com"
  },
  {
    "tool_name": "support.create_ticket",
    ...
  }
]
```

---

## Configure tenant B

Tenant B is an internal analytics workflow. It can call data warehouse tools only.

`tenant-b/cmcp-config.yaml`:

```yaml
attestation:
  provider: auto
  enforcement_mode: enforcing
policy_bundle_path: ./policies/
catalog_path: ./catalog.json
listen_addr: "0.0.0.0:8444"
```

`tenant-b/policies/allow.cedar`:

```cedar
permit (
  principal,
  action == cMCP::Action::"call_tool",
  resource
)
when {
  resource.tool_name in ["snowflake.query", "bigquery.read"]
};

forbid (
  principal,
  action == cMCP::Action::"call_tool",
  resource
);
```

`tenant-b/catalog.json` — includes only the analytics tools.

---

## Start both instances

Each tenant gets its own set of env vars:

```bash
# Tenant A
CMCP_BEARER_TOKEN="$(openssl rand -hex 32)" \
CMCP_POLICY_HASH="sha256:<tenant-a-bundle-hash>" \
CMCP_CATALOG_HASH="sha256:<tenant-a-catalog-hash>" \
cmcp start --config tenant-a/cmcp-config.yaml &

# Tenant B
CMCP_BEARER_TOKEN="$(openssl rand -hex 32)" \
CMCP_POLICY_HASH="sha256:<tenant-b-bundle-hash>" \
CMCP_CATALOG_HASH="sha256:<tenant-b-catalog-hash>" \
cmcp start --config tenant-b/cmcp-config.yaml &
```

Each instance prints its own hashes at startup:

```
[cmcp] policy bundle loaded: sha256:<tenant-a-bundle-hash>
[cmcp] catalog loaded: 2 tools, sha256:<tenant-a-catalog-hash>
[cmcp] listening on 0.0.0.0:8443

[cmcp] policy bundle loaded: sha256:<tenant-b-bundle-hash>
[cmcp] catalog loaded: 2 tools, sha256:<tenant-b-catalog-hash>
[cmcp] listening on 0.0.0.0:8444
```

The bundle hashes differ because the policy files differ.

---

## Compare TRACE records across tenants

A TRACE claim from tenant A's gateway:

```json
{
  "trace": {
    "policy": {
      "bundle_hash": "sha256:<tenant-a-bundle-hash>",
      "enforcement_mode": "enforcing"
    }
  },
  "gateway": {
    "catalog": {
      "hash": "sha256:<tenant-a-catalog-hash>"
    },
    "call_summary": {
      "tools_invoked": ["crm.get_customer"]
    }
  }
}
```

A TRACE claim from tenant B's gateway:

```json
{
  "trace": {
    "policy": {
      "bundle_hash": "sha256:<tenant-b-bundle-hash>",
      "enforcement_mode": "enforcing"
    }
  },
  "gateway": {
    "catalog": {
      "hash": "sha256:<tenant-b-catalog-hash>"
    },
    "call_summary": {
      "tools_invoked": ["snowflake.query"]
    }
  }
}
```

When verifying, pass the approved hashes for the specific tenant:

```python
from cmcp_verify import verify_trace_claim, ApprovedHashes

# Verifying a tenant A claim
approved_a = ApprovedHashes(
    policy_bundle_hash="sha256:<tenant-a-bundle-hash>",
    tool_catalog_hash="sha256:<tenant-a-catalog-hash>",
)
result = verify_trace_claim(tenant_a_claim, approved_a)

# Verifying a tenant B claim
approved_b = ApprovedHashes(
    policy_bundle_hash="sha256:<tenant-b-bundle-hash>",
    tool_catalog_hash="sha256:<tenant-b-catalog-hash>",
)
result = verify_trace_claim(tenant_b_claim, approved_b)
```

If you accidentally verify a tenant B claim with tenant A's approved hashes, `policy_bundle.hash` and `tool_catalog.hash` will be in `unverified_fields` and the result will be `unverified`.

---

## Audit chain isolation

Each session gets its own `AuditChain` instance inside the gateway. Sessions from different tenants run on different gateway processes, so their audit chains are physically separate. The `session_id` is scoped to the gateway instance. There is no cross-tenant session state.

When you export the audit bundle for a session (`GET /audit/export`), the bundle contains only the entries for that session. The `gateway.audit_chain.root` and `.tip` in the TRACE claim refer to that session's chain only.

---

## Summary

Per-tenant isolation in cMCP is one gateway instance per tenant, each with its own config, Cedar bundle, catalog, and listener port. The policy bundle hash and catalog hash differ per tenant and are recorded in TRACE claims, making tenant identity tamper-evident to verifiers. Audit chains are session-scoped and process-isolated.

Related tutorials: [Cedar policy walkthrough](./cedar-policy-walkthrough.md) — writing the per-tenant Cedar policies. [Verify a TRACE claim](./verifying-a-trace-claim.md) — verifying tenant-specific claims with the correct approved hashes.
