# Session Sensitivity Policy

Closes #36.

## Overview

The gateway tracks per-session sensitivity state and uses it to enforce policy on later tool calls (P1.5 session-context bleed). Once a session context is contaminated with sensitive data, all subsequent tool calls in that session are evaluated against the elevated sensitivity level.

## Section 1 — Session Sensitivity State Machine

States (ordered by sensitivity level):

```
public -> pii -> confidential -> hipaa_phi | mnpi | trade_secret (highest)
```

Transitions are one-way: state only increases. There is no automatic downgrade.

**Transition trigger:** a tool call response is received that is classified at a higher sensitivity level than the current session state.

**Classification source:** Cedar policy annotating the tool ("this tool returns PII"), or the gateway's response inspection (DLP pattern matching on response content).

## Section 2 — Egress Policy Based on Session Sensitivity

Cedar policy blocking outbound calls to public endpoints when session sensitivity is `confidential` or higher:

```cedar
forbid(principal, action == Action::"call_tool", resource)
when {
  context.session_sensitivity in ["confidential", "hipaa_phi", "mnpi", "trade_secret"] &&
  resource.destination_class == "public_external"
};
```

Cedar policy for MNPI: after a call that touches MNPI data, no calls to communication tools (Slack, email, social):

```cedar
forbid(principal, action == Action::"call_tool", resource)
when {
  context.session_sensitivity == "mnpi" &&
  resource.tool_category == "communication"
};
```

## Section 3 — Session Reset Protocol

**Endpoint:** `POST /session/reset` (authenticated, requires operator credential).

**Effect:** clears sensitivity state, generates a new `session_id`, creates a new audit chain entry:

```json
{
  "type": "session_reset",
  "reason": "string",
  "authorized_by": "string",
  "previous_session_id": "string",
  "new_session_id": "string"
}
```

The reset is logged. An auditor can see that a sensitivity boundary was explicitly cleared and who authorized it.

**Use case:** a user finishes a finance task (MNPI context) and switches to an HR task (PII context). The operator or system calls `session_reset` to start a clean context.

## Section 4 — TRACE Claim Extension

Add to the TRACE Claim:

```json
"session_max_sensitivity": "string",
"session_reset_count": 0
```

`session_reset_count` records how many times the session was reset during the TRACE Claim period.
