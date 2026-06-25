# Experiment: Session-Level vs. Per-Call Policy — The Compliance Gap

**Claim:** Monotonic session sensitivity state for LLM data governance (cMCP Claim 2)

**What this experiment proves:**

Individual call authorization is necessary but insufficient for cross-system compliance boundary enforcement. This experiment constructs a realistic 5-call agent session that demonstrates the gap between per-call policy (evaluates each call in isolation) and session-level policy (evaluates each call with accumulated sensitivity context from prior calls).

**Scenario:**

A clinical decision-support agent retrieves a patient record (PHI), then makes several downstream calls. Each downstream call is individually authorized — the agent has permission to call each of those tools. But after the PHI retrieval, the session context is contaminated: any external call the agent makes could carry PHI from its context window. Per-call policy cannot detect this; session-level policy blocks it.

**Call trace:**

| Call | Tool | Compliance domain | Response sensitivity |
|------|------|-------------------|---------------------|
| 1 | `ehr.get_patient` | hipaa_phi | PHI (MRN, diagnosis) |
| 2 | `slack.post_message` | external, no BAA | clean payload |
| 3 | `analytics.run_query` | internal | clean payload |
| 4 | `ehr.get_patient` | hipaa_phi | PHI (same patient) |
| 5 | `external_webhook.post` | external, no BAA | clean payload |

**The gap:**

Calls 2, 3, and 5 have clean payloads. A per-call policy evaluating only the outbound arguments sees nothing wrong. But the session has handled PHI in calls 1 and 4. The agent's context window contains that PHI. An external call that follows a PHI call may carry PHI regardless of what the explicit payload looks like.

Session policy blocks calls 2, 3, and 5 because `session_max_sensitivity == "hipaa_phi"` and those destinations are external or not covered by a BAA.

## Running

```bash
# From repo root
pip install -e .
python experiments/claim2-session-vs-call-policy/run.py
```

## Expected output

```
Session trace: 5 calls, PHI contamination at calls 1 and 4
------------------------------------------------------------------------
 #  Tool                     Domain       Payload tags       Per-call   Session  Gap
------------------------------------------------------------------------
 1  ehr.get_patient          hipaa_phi    hipaa_phi, pii     ALLOW      ALLOW    -
 2  slack.post_message       external     (clean)            ALLOW      DENY     MISSED
 3  analytics.run_query      internal     confidential       ALLOW      ALLOW    -
 4  ehr.get_patient          hipaa_phi    hipaa_phi, pii     ALLOW      ALLOW    -
 5  external_webhook.post    external     (clean)            ALLOW      DENY     MISSED

Summary
-------
True cross-boundary violations (PHI session + external non-BAA call): 2
Per-call policy caught:    0 / 2  (0%)
Session policy caught:     2 / 2  (100%)
Violations MISSED by per-call: 2  (calls [2, 5])

session_max_sensitivity after call 5: 'hipaa_phi'
```

Call 3 (analytics.run_query, internal) is correctly permitted -- internal destinations
are a different compliance boundary. The true violations are calls 2 and 5: external
destinations without BAA coverage after PHI has entered the session.
