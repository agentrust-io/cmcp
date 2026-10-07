# Cedar Policy Walkthrough

This page is for whoever decides what an AI agent is allowed to do through cMCP. You write the rules in Cedar, a small open-source language for access rules, and by the end you have a permissive rule set for local testing, a stricter one for production, and a way to test both before the gateway uses them.

## What you'll learn

- How Cedar policy syntax maps to cMCP entity types (principal, action, resource)
- How to write a minimal allow-all policy and a production-grade restrictive policy
- How to test policies with the `cedar` CLI before deploying
- The most common mistakes and how to avoid them

## Prerequisites

```bash
pip install cmcp-runtime
cargo install cedar-policy-cli   # Cedar CLI for local policy evaluation
```

---

## Understand the entity model

Every Cedar rule talks about three things: who is asking (the principal), what they want to do (the action) and what they want to do it to (the resource). cMCP fills these in for each tool call like this:

| Entity role | cMCP type | Example value |
|---|---|---|
| `principal` | `Agent` | `Agent::"anonymous"` by default, or the supplied `agent_id` |
| `action` | `Action` | `Action::"ReadFile"` for `read_file` |
| `resource` | `Resource` | `Resource::"salesforce.contacts"` for that tool |

The basic rule: a tool call is refused unless at least one `permit` rule matches it and no `forbid` rule does. A matching `forbid` always wins.

??? info "Technical detail: how the runtime builds the Cedar request"
    The runtime supplies entity identifiers only, with no principal or resource attributes. Match a tool using its resource UID, not `resource.tool_name`. Session and workflow values belong to the `context` record, including `session_max_sensitivity` and `workflow_id`.

    Actions are derived from the tool name by splitting on underscores, capitalizing each part, and joining them: `read_file` becomes `ReadFile`, and `crm.get_customer` becomes `Crm.getCustomer`. They are not a fixed `call_tool` action. The examples below use an action wildcard and constrain resources instead.

    Cedar evaluates `forbid` before `permit`, which is why a `forbid` always wins.

---

## Write a minimal allow-all policy

This policy is only for trying things on your own machine. It allows every tool call.

Create `policies/allow-all.cedar`:

```cedar
permit (
  principal,
  action,
  resource
);
```

Add a `policies/manifest.json` so cMCP can compute the bundle hash, a fingerprint of all your policy files that goes into every signed record:

```json
{
  "version": "0.1.0",
  "authored_at": "2026-06-01T00:00:00Z",
  "author_identity": "developer@example.com",
  "commit_sha": "local-dev"
}
```

Add `policies/schema.cedarschema`, which tells Cedar what the three tools used below look like. Add an action entry for any other tool you use. This schema covers only the requests in this tutorial, not every field the gateway may supply, and its empty namespace matches what the runtime expects.

```json
{"":{"entityTypes":{"Agent":{"memberOfTypes":[],"shape":{"type":"Record","attributes":{}}},"Resource":{"memberOfTypes":[],"shape":{"type":"Record","attributes":{}}}},"actions":{"Crm.getCustomer":{"appliesTo":{"principalTypes":["Agent"],"resourceTypes":["Resource"],"context":{"type":"Record","attributes":{"session_max_sensitivity":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}}},"Kyc.verifyIdentity":{"appliesTo":{"principalTypes":["Agent"],"resourceTypes":["Resource"],"context":{"type":"Record","attributes":{"session_max_sensitivity":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}}},"Salesforce.contacts":{"appliesTo":{"principalTypes":["Agent"],"resourceTypes":["Resource"],"context":{"type":"Record","attributes":{"session_max_sensitivity":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}}}}}}
```

Start the runtime with dev mode:

```bash
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
```

---

## Write a production policy

A production policy should list exactly what is allowed and refuse everything else. This one lets one named workflow call a short list of tools, blocks `salesforce.contacts` once personal data (PII) has entered the session, and refuses every other call.

Replace `policies/allow-all.cedar` with `policies/production.cedar`. Do not leave the allow-all file in the folder: cMCP reads every `.cedar` file together, and its broad permit would let through calls outside this workflow and tool list. Run in enforcing mode to actually block refused calls; advisory mode only logs them and lets them through.

Write `policies/production.cedar`:

```cedar
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

Cedar already refuses any call that no `permit` matches, so you do not need a catch-all refusal. Do not add an unconditional `forbid` for that purpose: it would override every `permit` and block approved calls too. Removing all permits also refuses everything. Any change to a policy file, even one byte, changes the bundle hash.

---

## Test a policy with the cedar CLI

You can check what your rules decide without starting the gateway, using the `cedar` command-line tool. Install it with `cargo install cedar-policy-cli`.

```bash
cedar authorize \
  --policies policies/production.cedar \
  --schema policies/schema.cedarschema \
  --principal 'Agent::"anonymous"' \
  --action 'Action::"Crm.getCustomer"' \
  --resource 'Resource::"crm.get_customer"' \
  --context '{"session_max_sensitivity":"public","workflow_id":"customer_onboarding"}'
```

Expected decision: `Allow`. The names and values in this command match what the runtime sends for the same call.

Test the forbid rule:

```bash
cedar authorize \
  --policies policies/production.cedar \
  --schema policies/schema.cedarschema \
  --principal 'Agent::"anonymous"' \
  --action 'Action::"Salesforce.contacts"' \
  --resource 'Resource::"salesforce.contacts"' \
  --context '{"session_max_sensitivity":"pii","workflow_id":"customer_onboarding"}'
```

Expected decision: `Deny`.

---

## Common mistakes

**Missing `when` condition on a permit rule.** A `permit` without a `when` block allows every call it matches, with no further check. Always limit a permit to at least a `workflow_id` or a list of tool names:

```cedar
// Wrong: permits every tool call from every principal
permit (principal, action, resource);

```

Use this scoped alternative instead; do not combine it with the broad permit above:

```cedar
// Scoped to a workflow and tool list
permit (principal, action, resource)
when {
  context.workflow_id == "my_workflow" &&
  resource in [Resource::"tool_a", Resource::"tool_b"]
};
```

**Resource match that is too broad.** If the `resource` part of a rule is just `resource`, the rule applies to every tool. In production, always name a specific tool or a list of tools.

**Forgetting that `forbid` always wins.** If a `permit` and a `forbid` both match the same call, the call is refused. The order of rules in the file makes no difference.

**Changing the schema without recomputing the bundle hash.** The bundle hash includes the schema file, so any change to `schema.cedarschema` changes the hash, and a pinned `CMCP_POLICY_HASH` no longer matches. After every schema or policy change, recompute the bundle hash and update that variable before restarting the runtime.

---

## Summary

You wrote an allow-all policy for testing and a production policy that is limited to one workflow, blocks a tool once personal data is present, and refuses everything else by default. You tested both with the `cedar` tool before the gateway used them. Because any change to the policy files changes the `policy_bundle.hash` field in the signed TRACE claim (cMCP's per-session record), anyone checking the claim can tell exactly which policy was running.

Related tutorials: [Verify a TRACE claim](./verifying-a-trace-claim.md) shows how to confirm the policy hash in a claim matches what you deployed, and [Multi-tenant deployment](./multi-tenant-config.md) covers separate policies, each with its own hash, for different customers.
