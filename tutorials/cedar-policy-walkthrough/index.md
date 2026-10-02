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

| Entity role | cMCP type  | Example value                                               |
| ----------- | ---------- | ----------------------------------------------------------- |
| `principal` | `Agent`    | `Agent::"anonymous"` by default, or the supplied `agent_id` |
| `action`    | `Action`   | `Action::"ReadFile"` for `read_file`                        |
| `resource`  | `Resource` | `Resource::"salesforce.contacts"` for that tool             |

The runtime supplies entity identifiers, with no principal or resource attributes. Match a tool using its resource UID, not `resource.tool_name`. Session and workflow values belong to the `context` record, including `session_max_sensitivity` and `workflow_id`.

Actions are derived from the tool name by splitting on underscores, capitalizing each part, and joining them: `read_file` becomes `ReadFile`, and `crm.get_customer` becomes `Crm.getCustomer`. They are not a fixed `call_tool` action. The examples below use an action wildcard and constrain resources instead.

A tool call is denied unless at least one `permit` rule matches and no `forbid` rule matches. Cedar evaluates `forbid` before `permit`, so a `forbid` always wins.

______________________________________________________________________

## Write a minimal allow-all policy

This policy is appropriate for local development. It permits every tool call unconditionally.

Create `policies/allow-all.cedar`:

```
permit (
  principal,
  action,
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

Add `policies/schema.cedarschema` for the three tools used below. The empty namespace matches the runtime; add action declarations for any additional tools you use. This schema describes these tutorial requests, not every context field the gateway may supply.

```
{"":{"entityTypes":{"Agent":{"memberOfTypes":[],"shape":{"type":"Record","attributes":{}}},"Resource":{"memberOfTypes":[],"shape":{"type":"Record","attributes":{}}}},"actions":{"Crm.getCustomer":{"appliesTo":{"principalTypes":["Agent"],"resourceTypes":["Resource"],"context":{"type":"Record","attributes":{"session_max_sensitivity":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}}},"Kyc.verifyIdentity":{"appliesTo":{"principalTypes":["Agent"],"resourceTypes":["Resource"],"context":{"type":"Record","attributes":{"session_max_sensitivity":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}}},"Salesforce.contacts":{"appliesTo":{"principalTypes":["Agent"],"resourceTypes":["Resource"],"context":{"type":"Record","attributes":{"session_max_sensitivity":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}}}}}}
```

Start the runtime with dev mode:

```
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
```

______________________________________________________________________

## Write a production policy

Production policies should be explicit about what is permitted and deny everything else. This policy allows a specific workflow to call a named set of tools, blocks `salesforce.contacts` when PII is in session, and denies all other calls by default.

Replace `policies/allow-all.cedar` with `policies/production.cedar`. Do not leave the development allow-all policy in the bundle: all `.cedar` files are evaluated together, and its broad permit would allow calls outside this workflow and tool list. Use enforcing mode to block denied calls; advisory mode logs them and forwards them.

Write `policies/production.cedar`:

```
// Permit the customer-onboarding workflow to call approved tools only
permit (
  principal,
  action,
  resource
)
when {
  context.workflow_id == "customer_onboarding" &&
  resource in [Resource::"crm.get_customer", Resource::"kyc.verify_identity", Resource::"salesforce.contacts"]
};

// Block salesforce.contacts when the session has reached PII sensitivity
forbid (
  principal,
  action,
  resource
)
when {
  context.session_max_sensitivity == "pii" &&
  resource == Resource::"salesforce.contacts"
};
```

Cedar implicitly denies calls when no permit matches. Do not add an unconditional `forbid` as a default-deny rule: it overrides every permit, including approved calls. Removing all permits also denies everything. Any change to the policy bytes changes the bundle hash.

______________________________________________________________________

## Test a policy with the cedar CLI

Before loading a policy bundle into the runtime, test it locally with the `cedar` CLI. Install it with `cargo install cedar-policy-cli`. This lets you verify decisions without starting the gateway.

```
cedar authorize \
  --policies policies/production.cedar \
  --schema policies/schema.cedarschema \
  --principal 'Agent::"anonymous"' \
  --action 'Action::"Crm.getCustomer"' \
  --resource 'Resource::"crm.get_customer"' \
  --context '{"session_max_sensitivity":"public","workflow_id":"customer_onboarding"}'
```

Expected decision: `Allow`. These entity UIDs and context values match the runtime request.

Test the forbid rule:

```
cedar authorize \
  --policies policies/production.cedar \
  --schema policies/schema.cedarschema \
  --principal 'Agent::"anonymous"' \
  --action 'Action::"Salesforce.contacts"' \
  --resource 'Resource::"salesforce.contacts"' \
  --context '{"session_max_sensitivity":"pii","workflow_id":"customer_onboarding"}'
```

Expected decision: `Deny`.

______________________________________________________________________

## Common mistakes

**Missing `when` condition on a permit rule.** A `permit` without a `when` block allows all matching calls unconditionally. Always scope permits to at least a `workflow_id` or tool name list:

```
// Wrong: permits every tool call from every principal
permit (principal, action, resource);
```

Use this scoped alternative instead; do not combine it with the broad permit above:

```
// Scoped to a workflow and tool list
permit (principal, action, resource)
when {
  context.workflow_id == "my_workflow" &&
  resource in [Resource::"tool_a", Resource::"tool_b"]
};
```

**Overly permissive resource match.** If the `resource` clause is just `resource` (wildcard), the rule applies to every tool. In a production policy, always bind the resource to a specific tool name or a named list.

**Forgetting that `forbid` always wins.** If you have both a `permit` and a `forbid` that match the same call, the call is denied. Order in the policy file does not matter; Cedar semantics are: any `forbid` match overrides all `permit` matches.

**Changing the schema without recomputing the bundle hash.** The bundle hash covers the schema file. Any change to `schema.cedarschema` changes the hash and invalidates `CMCP_POLICY_HASH`. After every schema or policy file change, recompute the bundle hash and update the env var before restarting the runtime.

______________________________________________________________________

## Summary

You wrote a minimal dev policy and a production policy with workflow scoping, a PII-triggered forbid, and Cedar’s implicit default-deny. You tested both with the `cedar` CLI before loading them into the runtime. Any change to the policy bundle changes the `policy_bundle.hash` field in TRACE Claims, making the active policy tamper-evident.

Related tutorials: [Verify a TRACE claim](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/index.md): confirm the policy hash in a produced claim matches what you deployed. [Multi-tenant deployment](https://cmcp.agentrust-io.com/tutorials/multi-tenant-config/index.md): run per-tenant policy bundles with separate hashes.
