# Design Partner Engagement Template

---

## Target Profile

- Enterprise AI platform team or CISO organization with agents in production or blocked from production by compliance
- Regulated industry preferred (financial services, healthcare, legal) or SaaS vendor whose enterprise customers push compliance requirements downstream
- Has a working MCP deployment or active MCP adoption plan
- Has a named compliance or security blocker

---

## Initial Conversation Guide

### Qualifying Questions

All three must be answered affirmatively before proceeding to engagement terms.

1. "Do you have agents that call MCP tools with access to sensitive or regulated data?"
2. "Have you received, or do you expect to receive, a compliance, legal, or audit requirement around how those agents handle data?"
3. "If a regulator or customer asked you to prove that specific policies were enforced on a specific date's agent traffic, could you do that today?"

---

## Engagement Terms

Define the following in the letter of intent before the sprint begins.

**Scope**
- Which use case
- Which MCP tools
- Which data categories

**Proof requirement**
- What format does the enterprise want the TRACE Claim in?
- Who will verify it — internal compliance team or external auditor?

**Policy expression**
- What do their Cedar policies need to express? Examples: tool allowlist, field redaction, cross-system compliance boundary

**Integration path**
- What changes to their current agent deployment does the gateway require?

**Timeline**
- 30-day sprint milestone: what does "it works" look like?

**Success criteria**
- Defined jointly before the sprint starts

---

## Phase 1 vs Phase 2 Buyer Questions

**Phase 1 — enterprise deploying agents:**
"Which MCP servers do your agents call? Which are first-party (you own the server) and which are third-party (a SaaS vendor)?"

**Phase 2 — SaaS vendor running MCP servers:**
"Do your enterprise customers ask you to prove what your MCP server does with their data? Have you had a renewal stall on this question?"

**Note:** Some design partners will be both — they deploy agents (Phase 1) and run MCP servers for their own customers (Phase 2). Identify this early and scope the engagement accordingly.

---

*Closes #14*
