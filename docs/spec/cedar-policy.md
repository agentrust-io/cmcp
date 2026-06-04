# Cedar Policy Specification

This document specifies the Cedar policy bundle format, policy expression examples, enforcement modes, evaluation decision flow, and related governance features for the cMCP Gateway.

---

## Section 1 — Policy Bundle Format

A policy bundle is a directory (or tarball) with the following structure:

```
bundle/
  policies/          # Cedar policy files (.cedar), one per policy or logical group
  schema.cedarschema # Cedar schema defining entity types, actions, and attributes
  manifest.json      # Provenance metadata
```

### manifest.json Format

```json
{
  "version": "<semver>",
  "authored_at": "<ISO8601>",
  "author_identity": "<SPIFFE SVID or git identity>",
  "commit_sha": "<git commit SHA>",
  "approval_chain": [
    {
      "approver": "<identity>",
      "approved_at": "<ISO8601>",
      "signature": "<base64-encoded signature>"
    }
  ]
}
```

`approval_chain` is optional. When present, each entry is a signed approval by an authorized reviewer. See Section 5 for how approvals are verified.

### Bundle Hash

The bundle hash is the authoritative measurement committed into the attestation report. It is computed as:

```
SHA-256(canonical_json({
  "manifest": <manifest.json contents>,
  "policy_files": {
    "<filename>": "<SHA-256 of file contents>"
    // ... entries sorted lexicographically by filename
  },
  "schema_hash": "<SHA-256 of schema.cedarschema>"
}))
```

`canonical_json` means RFC 8785 (JSON Canonicalization Scheme): no insignificant whitespace, keys sorted lexicographically at every level. This ensures the hash is deterministic regardless of serialization order.

This hash is what gets measured into the attestation report (see `policy_bundle.hash` in the TRACE Claim). Any modification to any policy file, the schema, or the manifest changes the hash, producing a measurement mismatch that verifiers can detect.

---

## Section 2 — Cedar Policy Expression Examples

The following examples show working Cedar policies for common enterprise use cases. All policies operate on the action `Action::"call_tool"`.

### Tool Allowlist

Permit calls only to named tools:

```cedar
permit(
  principal,
  action == Action::"call_tool",
  resource
)
when {
  resource.tool_name in ["salesforce.query", "snowflake.read"]
};
```

### Tool Denylist

Explicitly forbid a specific tool regardless of other permits:

```cedar
forbid(
  principal,
  action == Action::"call_tool",
  resource
)
when {
  resource.tool_name == "delete_customer_record"
};
```

### Field-Level Redaction

Permit the call but instruct the response inspector to redact sensitive fields:

```cedar
permit(
  principal,
  action == Action::"call_tool",
  resource
)
when {
  resource.tool_name == "crm.get_customer"
}
advice {
  redact_fields: ["ssn", "payment_history"]
};
```

The `advice` block is evaluated by the response inspection pipeline after the upstream call returns. See `response-inspection.md` for redaction semantics.

### Cross-System Compliance Boundary

Forbid tool calls to uncovered servers when the session carries HIPAA PHI sensitivity:

```cedar
forbid(
  principal,
  action == Action::"call_tool",
  resource
)
when {
  context.session_sensitivity == "hipaa_phi" &&
  resource.server_domain == "uncovered"
};
```

### Per-Workflow Scope

Permit tool calls only when the tool is in the workflow's allowed set:

```cedar
permit(
  principal,
  action == Action::"call_tool",
  resource
)
when {
  context.workflow_id == "customer_onboarding" &&
  resource.tool_name in context.workflow_allowed_tools
};
```

### Default-Deny Baseline

Cedar is default-deny: a call is denied unless at least one `permit` matches and no `forbid` matches. To make this explicit and auditable, include a baseline forbid:

```cedar
forbid(
  principal,
  action == Action::"call_tool",
  resource
);
```

This ensures that even if the policy bundle is empty or all permits are removed, all calls are denied rather than silently allowed.

---

## Section 3 — Enforcement Modes

Enforcement mode is set in the deployment configuration, bound into the attestation report, and cannot change without an enclave restart. This makes the active mode tamper-evident.

| Mode | Cedar deny behavior | Audit entry |
|------|--------------------|-|
| `enforcing` | Gateway rejects the call, returns a structured error to the agent | Logged with `decision=deny` |
| `advisory` | Gateway allows the call, forwards to upstream | Logged with `decision=deny_advisory` (would have been denied in enforcing mode) |
| `silent` | Gateway allows the call, forwards to upstream | Only a basic call log; no audit decision entry |

**Structured error (enforcing mode):**

```json
{
  "error": "tool_call_denied",
  "tool_name": "<tool>",
  "call_id": "<uuid>",
  "policy_bundle_version": "<semver>",
  "message": "Tool call denied by gateway policy."
}
```

The error does not include the matched rule name or policy text, to avoid leaking policy internals to the agent.

---

## Section 4 — Policy Evaluation Decision Flow

```
1.  Receive MCP tool call request
      inputs: tool_name, arguments, session_id, workflow_id (if present)

2.  Build Cedar evaluation context:
      {
        tool_name,
        server_identity,
        server_domain,
        session_sensitivity,
        workflow_id,
        workflow_allowed_tools,
        user_identity           // if available
      }

3.  Evaluate Cedar policies against:
      (principal, Action::"call_tool", resource) with context

4.  If decision = permit:
        proceed to egress DLP check (see egress policy documentation)

5.  If decision = deny:
        enforce per enforcement_mode (see Section 3)

6.  Log audit entry:
      { decision, rule_matched, latency_us, call_id }

7.  If decision = permit and DLP passes:
        forward call to upstream server

8.  Receive response from upstream server

9.  Run response inspection pipeline (see response-inspection.md)
      applies advice blocks (e.g., redact_fields)

10. Log response audit entry

11. Return (possibly redacted) response to agent
```

Latency budget: Cedar evaluation target is under 1 ms for bundles up to 500 policy rules. The gateway measures and logs `latency_us` for each evaluation to support SLA monitoring.

---

## Section 5 — Policy Provenance (closes #26)

The `manifest.json` provenance metadata is included in the bundle hash measurement (see Section 1). This means:

- **Author identity** (`author_identity`): tamper-evident. Changing the identity changes the bundle hash, producing a measurement mismatch that verifiers detect.
- **Authoring timestamp** (`authored_at`): tamper-evident for the same reason.
- **Git commit** (`commit_sha`): tamper-evident. Links the policy bundle to a specific point in version control history.
- **Approval signatures** (`approval_chain`): tamper-evident. Each approval signature covers the bundle hash; removing or altering an approval changes the manifest, which changes the bundle hash.

### Verifier Workflow

A verifier checking a TRACE Claim can perform the following steps:

1. Obtain the TRACE Claim and extract `policy_bundle.hash`.
2. Compare `policy_bundle.hash` against the approved hash on record (e.g., from the organization's policy registry).
3. Request the bundle tarball from the operator.
4. Recompute the bundle hash locally using the algorithm in Section 1 and verify it matches `policy_bundle.hash`.
5. Inspect `manifest.json` to confirm author, timestamp, commit SHA, and approval chain.
6. Optionally verify each approval signature against the approver's known public key.

If any step fails, the verifier rejects the TRACE Claim. This process requires no trust in the operator: the TEE measurement is the root of trust.

---

## Section 6 — Per-Workflow Cedar Policy Scope (closes #41)

### Workflow Identity

Workflow identity is established via session metadata. The agent includes a `workflow_id` in the session initiation request:

- HTTP transport: `X-MCP-Workflow-ID` header
- Session configuration: `workflow_id` field in the session init payload

If `workflow_id` is absent, the gateway defaults to `workflow_id = "default"`. The default workflow policy should be restrictive (allowlist only widely-approved tools).

### Evaluation Order

A tool call must pass both checks:

1. **Catalog-level**: the tool is registered in the approved tool catalog.
2. **Workflow-level**: the tool is allowed for the current `workflow_id` per Cedar policy.

Failing either check results in a deny decision.

### Workflow Entity in Cedar Schema

The per-workflow allowed-tools list can be modeled as an entity attribute in the Cedar schema:

```cedarschema
entity Workflow {
  allowed_tools: Set<String>,
  sensitivity_level: String
};
```

This allows Cedar policies to reference `context.workflow_allowed_tools` as derived from the `Workflow` entity loaded at evaluation time.

### Phase Boundaries

| Phase | Behavior |
|-------|----------|
| Phase 1 | Static workflow policies committed in the Cedar bundle. The `workflow_id` is trusted as declared by the agent. |
| Phase 2 | Dynamic workflow attestation: the agent cryptographically declares its current workflow; the gateway verifies the declaration before evaluating workflow-scoped policies. |

---

## Section 7 — Gateway as Sole MCP Endpoint (closes #39)

### Agent Host Configuration

The agent's MCP client is configured with exactly one MCP server URL: the gateway's URL. All upstream servers are invisible to the agent; the gateway handles routing internally.

Example `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cmcp-gateway": {
      "url": "http://localhost:8443/mcp",
      "transport": "http"
    }
  }
}
```

The agent never learns the upstream server URLs. From the agent's perspective, there is one MCP server. This prevents agents from bypassing the gateway by connecting directly to upstream servers.

### Adding a New Upstream Server

To add an upstream MCP server to the gateway catalog:

1. Add a catalog entry to `catalog.json` in version control (see `tool-identity.md` for schema).
2. Recompute the policy bundle hash (the catalog hash is a separate field in the TRACE Claim: `tool_catalog.hash`).
3. Submit the change through the normal approval workflow.
4. Restart the enclave. The restart re-measures the catalog, producing a new `tool_catalog.hash` in subsequent TRACE Claims.

The new server is not reachable until the enclave restarts with the updated catalog. There is no runtime path to add a server without measurement.

### Emergency Access (Break-Glass)

If an unauthorized server must be accessed urgently without an enclave restart, the gateway supports a break-glass mode. Break-glass adds the server to a temporary exception list for the current enclave session.

Break-glass use is visible in the TRACE Claim:

```json
"catalog_exceptions": [
  {
    "server_identity": "spiffe://corp.example/emergency/server",
    "reason": "P0 incident -- customer data export required",
    "authorized_by": "ops-lead@example.com",
    "timestamp": "2026-06-01T03:17:00Z"
  }
]
```

TRACE Claims with a non-empty `catalog_exceptions` list are flagged for auditor review. Break-glass use appears in all TRACE Claims for the duration of that enclave session.
