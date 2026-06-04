# RQ6 Interview Guide: Phase 2 Demand Validation

**Research Question:** Are SaaS vendors receiving enterprise questionnaires about MCP server behavior they cannot answer with SOC 2?

**Goal:** Determine whether Phase 2 (provider-side server attestation) has pull from SaaS vendors facing enterprise compliance pressure, or whether it should follow Phase 1 GA.

---

## Screening Criteria

Prospect must meet at least 2 of the following before scheduling an interview:

- Has deployed or is deploying MCP endpoints for enterprise customers
- Has enterprise customers with active compliance programs (SOC 2 Type II requirement, ISO 27001, or regulatory oversight)
- Has had at least one enterprise deal go through security review in the past 6 months

---

## Interview Questions

1. "Walk me through the last security questionnaire or due diligence review your largest enterprise customer put you through. What were they asking about your MCP server specifically?"

2. "Has any enterprise customer asked you to prove — not just describe — what your MCP server does with their data during a tool call? What artifact did you give them?"

3. "When an enterprise customer asks 'what happens to our data when it flows through your MCP endpoint', what do you currently tell them? Is that answer sufficient for their compliance team?"

4. "Have you ever had a deal stall or a renewal become more complex because a customer wanted stronger evidence of MCP server behavior than your SOC 2 provides?"

5. "If your enterprise customers started asking you for per-call proof of what your MCP server did with their data, how would you currently produce that?"

---

## Go/No-Go Criteria for Phase 2 Timeline

**GO:** 3 or more SaaS vendor interviews where the answer to question 4 is "yes, this has happened."

**NO-GO:** Fewer than 3 such interviews after 15 or more vendor conversations. Revisit Phase 2 timeline and confirm it follows Phase 1 GA.

**WATCH:** If Phase 1 design partners start asking about their own upstream MCP vendors (the vendors providing the servers the design partner's agents call), this is the pull signal for Phase 2 regardless of vendor interview results.

---

*Closes #19*
