# Starter Cedar policies

These templates use the request mapping in
[`CedarBackend.build_request`](../../src/cmcp_runtime/policy/cedar.py) and the
context supplied by the [MCP proxy](../../src/cmcp_runtime/mcp/proxy.py).
The principal is `Agent::"<agent_id>"`, the resource is
`Resource::"<catalog tool name>"`, and the action is derived from the tool name
(for example, `read_file` becomes `Action::"ReadFile"`). These templates leave
the principal and action unconstrained and select tools by resource ID.

| Template | Effect | Example allow | Example deny |
| --- | --- | --- | --- |
| `tool-allowlist.cedar` | Permits only example tools `a` and `b` | Resource `a` | Resource `c` |
| `sensitive-egress-guard.cedar` | Forbids uncovered calls for `pii`, `hipaa_phi`, or `mnpi` sessions, and all calls with compliance domain `external` | Public session, internal domain | External domain, even for a public session |
| `per-call-amount-cap.cedar` | Forbids integer `arguments.amount` above 1000 | Amount 1000 | Amount 1001 |

## Compose a bundle

Replace `a` and `b` with your approved catalog tool names. Copy that allowlist
and whichever guards you need into your policy bundle directory, alongside its
`manifest.json` and `schema.cedarschema`. Configure `policy_bundle_path` to point
there and recompute any configured bundle hash after editing. See
[bundle loading](../../src/cmcp_runtime/policy/bundle.py) for the required files
and hash/signature checks. This directory contains policy snippets, not a
complete deployable bundle.

Cedar denies by default: a call needs a matching `permit` and no matching
`forbid`. The guards contain only `forbid` rules, so each guard alone denies
every call. Compose them with an explicit permit such as the allowlist. Adding
another broad permit can widen the allowlist; a matching forbid still wins.
The tests load the actual files and evaluate each guard with the allowlist.

## Context and limits

- `session_max_sensitivity` is the running session maximum, including the current
  call's effective sensitivity. The example guard names only `pii`, `hipaa_phi`,
  and `mnpi`; extend it for other built-in or deployment-specific labels.
- The proxy derives `baa_covered` from the catalog entry's `requires_baa` flag
  (`not requires_baa`). This boolean is policy input, not proof that a legal BAA
  exists. Review catalog metadata and governance before relying on it.
- `compliance_domain` is the catalog entry's label; an unknown tool defaults to
  `external`. The guard uses this field, not `destination_class` (which the proxy
  currently sets to `external` for every call).
- The amount cap assumes an integer amount in an agreed unit, such as cents.
  Validate the tool's input schema and choose the cap and units for your use case.
  The proxy's `_cedar_safe` converts floats to strings and removes null values;
  numeric comparison here does not validate strings, floats, booleans, negative
  values, currencies, or missing amounts. A missing amount does not trigger the
  cap. Do not rely on Cedar evaluation errors to reject mistyped amounts when
  another policy permits the call.
- There is no call counter or running spend total in the Cedar context. The
  amount template provides neither rate limiting nor cumulative spend control.
- Use enforcing mode to block denied calls. Advisory and silent modes let them
  through; they are not enforcement substitutes.

## Run the tests

From the repository root, after installing `.[dev]`:

```bash
pytest tests/unit/test_policy_templates.py -q
```
