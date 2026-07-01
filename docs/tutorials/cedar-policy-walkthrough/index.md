# Cedar Policy Walkthrough

Write and test Cedar policies that control which tools a cMCP-governed agent can call.

## What you'll learn

- How Cedar policy syntax maps to cMCP entity types (principal, action, resource)
- How to write a minimal allow-all policy and a production-grade restrictive policy
- How to test policies with the `cedar` CLI before deploying
- The most common mistakes and how to avoid them

## Prerequisites

```
pip install cmcp-runtime
cargo install cedar-policy-cli   # Cedar CLI for local policy evaluation
```

______________________________________________________________________

## Understand the entity model

cMCP evaluates every tool call against Cedar policies using three entities:

| Entity role | cMCP type                   | Example value                         |
| ----------- | --------------------------- | ------------------------------------- |
| `principal` | `cMCP::Principal`           | session that initiated the call       |
| `action`    | `cMCP::Action::"call_tool"` | fixed: all tool calls use this action |
| `resource`  | `cMCP::Resource`            | the tool being called                 |

The principal carries `session_id` and `workflow_id`. The resource carries `tool_name` and `server_domain`. Cedar also receives a `context` record with `session_max_sensitivity` and `workflow_id`.

A tool call is denied unless at least one `permit` rule matches and no `forbid` rule matches. Cedar evaluates `forbid` before `permit`, so a `forbid` always wins.

______________________________________________________________________

## Write a minimal allow-all policy

This policy is appropriate for local development. It permits every tool call unconditionally.

Create `policies/allow-all.cedar`:

```
permit (
  principal,
  action == cMCP::Action::"call_tool",
  resource
);
```

Add a `policies/manifest.json` so cMCP can compute the bundle hash:

```
{
  "version": "0.1.0",
  "authored_at": "2026-06-01T00:00:00Z",
  "author_identity": "developer@example.com",
  "commit_sha": "local-dev"
}
```

Add a minimal `policies/schema.cedarschema` (one line, no whitespace):

```
{"cMCP":{"entityTypes":{"Principal":{"memberOfTypes":[],"shape":{"type":"Record","attributes":{"session_id":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}},"Resource":{"memberOfTypes":[],"shape":{"type":"Record","attributes":{"tool_name":{"type":"String","required":true}}}}},"actions":{"call_tool":{"appliesTo":{"principalTypes":["cMCP::Principal"],"resourceTypes":["cMCP::Resource"],"context":{"type":"Record","attributes":{"session_max_sensitivity":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}}}}}}
```

Start the runtime with dev mode:

```
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
```

______________________________________________________________________

## Write a production policy

Production policies should be explicit about what is permitted and deny everything else. This policy allows a specific workflow to call a named set of tools, blocks calls when PII is in session, and denies all other calls by default.

Create `policies/production.cedar`:

```
// Permit the customer-onboarding workflow to call approved tools only
permit (
  principal,
  action == cMCP::Action::"call_tool",
  resource
)
when {
  context.workflow_id == "customer_onboarding" &&
  resource.tool_name in ["crm.get_customer", "kyc.verify_identity", "salesforce.contacts"]
};

// Block salesforce.contacts when the session has reached PII sensitivity
forbid (
  principal,
  action == cMCP::Action::"call_tool",
  resource
)
when {
  context.session_max_sensitivity == "pii" &&
  resource.tool_name == "salesforce.contacts"
};

// Explicit default-deny: Cedar is default-deny already, but this makes it
// auditable: the bundle hash changes if this rule is removed
forbid (
  principal,
  action == cMCP::Action::"call_tool",
  resource
);
```

The explicit `forbid` at the bottom ensures that removing all `permit` rules does not silently open access: the default deny is now tamper-evident (changing it changes the bundle hash).

______________________________________________________________________

## Test a policy with the cedar CLI

Before loading a policy bundle into the runtime, test it locally with the `cedar` CLI. Install it with `cargo install cedar-policy-cli`. This lets you verify decisions without starting the gateway.

```
cedar authorize \
  --policies policies/production.cedar \
  --schema policies/schema.cedarschema \
  --principal 'cMCP::Principal::"s1"' \
  --action 'cMCP::Action::"call_tool"' \
  --resource 'cMCP::Resource::"crm.get_customer"' \
  --context '{"session_max_sensitivity":"public","workflow_id":"customer_onboarding"}'
```

Expected output: `ALLOW`

Test the forbid rule:

```
cedar authorize \
  --policies policies/production.cedar \
  --schema policies/schema.cedarschema \
  --principal 'cMCP::Principal::"s1"' \
  --action 'cMCP::Action::"call_tool"' \
  --resource 'cMCP::Resource::"salesforce.contacts"' \
  --context '{"session_max_sensitivity":"pii","workflow_id":"customer_onboarding"}'
```

Expected output: `DENY`

______________________________________________________________________

## Common mistakes

**Missing `when` condition on a permit rule.** A `permit` without a `when` block allows all matching calls unconditionally. Always scope permits to at least a `workflow_id` or tool name list:

```
// Wrong: permits every tool call from every principal
permit (principal, action == cMCP::Action::"call_tool", resource);

// Right: scoped to a workflow and tool list
permit (principal, action == cMCP::Action::"call_tool", resource)
when {
  context.workflow_id == "my_workflow" &&
  resource.tool_name in ["tool_a", "tool_b"]
};
```

**Overly permissive resource match.** If the `resource` clause is just `resource` (wildcard), the rule applies to every tool. In a production policy, always bind the resource to a specific tool name or a named list.

**Forgetting that `forbid` always wins.** If you have both a `permit` and a `forbid` that match the same call, the call is denied. Order in the policy file does not matter; Cedar semantics are: any `forbid` match overrides all `permit` matches.

**Changing the schema without recomputing the bundle hash.** The bundle hash covers the schema file. Any change to `schema.cedarschema` changes the hash and invalidates `CMCP_POLICY_HASH`. After every schema or policy file change, recompute the bundle hash and update the env var before restarting the runtime.

______________________________________________________________________

## Summary

You wrote a minimal dev policy and a production policy with workflow scoping, a PII-triggered forbid, and an explicit default-deny. You tested both with the `cedar` CLI before loading them into the runtime. Any change to the policy bundle changes the `policy_bundle.hash` field in TRACE Claims, making the active policy tamper-evident.

Related tutorials: [Verify a TRACE claim](https://cmcp.agentrust-io.com/docs/tutorials/verifying-a-trace-claim/index.md): confirm the policy hash in a produced claim matches what you deployed. [Multi-tenant deployment](https://cmcp.agentrust-io.com/docs/tutorials/multi-tenant-config/index.md): run per-tenant policy bundles with separate hashes.
