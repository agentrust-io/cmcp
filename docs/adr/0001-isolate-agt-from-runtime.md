# ADR 0001: Isolate AGT from the cMCP runtime

- Status: Accepted
- Date: 2026-08-27

## Context

cMCP imported AGT v4 runtime classes for call gating, response inspection,
catalog scanning, and an unused kernel marker. AGT v5 has dependency constraints
that conflict with cMCP's current cryptography and TRACE requirements. More
importantly, a confidential gateway's enforcement availability should not depend
on an optional governance toolkit.

## Decision

cMCP owns its runtime enforcement boundary: catalog allowlisting and drift
classification, call budgets, dangerous-argument checks, response scanning,
sensitivity classification, and readiness. The installable runtime has no AGT or
`agent_os` dependency.

AGT remains an isolated CI and release tool. Those jobs create a dedicated
virtual environment, generate governance evidence, and run strict verification.
Legacy `agent_os_version` policy-manifest metadata remains readable so signed and
hashed bundles do not break, but it is explicitly ignored by runtime enforcement.

## Alternatives considered

- Upgrade the runtime to AGT v5: rejected because its ACS lifecycle differs from
  the narrow v4 surface cMCP used and its dependency constraints conflict.
- Pin AGT v4 indefinitely: rejected because this leaves a security control tied
  to a deprecated dependency line.
- Make AGT optional with weaker fallbacks: rejected because installed-package
  variation would change security behavior.

## Consequences

- Runtime installs and imports are independent of AGT and can move to current
  cryptography releases.
- Security behavior is deterministic across installations and covered directly
  by cMCP tests.
- cMCP now owns maintenance of the extracted enforcement patterns and contracts.
- AGT upgrades can be evaluated in CI without constraining production packages.

## Follow-up

- Keep a subprocess import test that rejects any `agent_os` runtime import.
- Keep AGT verification isolated in both CI and release workflows.
- Review the versioned detection patterns as part of security releases.
