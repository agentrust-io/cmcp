# Research Guide: RQ1 — MCP-Specific Tool-Call Payload Leakage

**Research question:** Are MCP practitioners experiencing tool-call payload leakage specifically at the tool call layer, distinct from the broader AI pipeline problem?

**Why this matters:** The evidence for P1 (data exposure through tool calls) comes from AI pipeline interviews, not from anyone describing MCP tool calls specifically. If the pain is at the pipeline level and MCP is just one more surface, cMCP's framing may be wrong. If the pain is specifically at the tool call layer, cMCP is correctly scoped.

**Move-to-confirmed criteria:** 3+ ICP-fit personas describe this pain in the context of MCP tool calls specifically — not just "AI data leakage" in general.

---

## Interview Guide Additions (add to existing interview script)

These questions follow any discussion of the prospect's current MCP deployment or tool call infrastructure.

### Observability and logging questions
1. "Walk me through your current observability setup for tool calls specifically. When your agent calls an MCP tool, what gets logged? Where does that log go? Who has access to it?"

2. "Does your APM or observability tooling — Datadog, Splunk, OpenTelemetry, whatever you use — capture the payload content of tool calls, or just the metadata (tool name, latency, status code)?"

3. "Have you had to configure payload logging for debugging? If so, how did you make sure sensitive data in those payloads didn't end up in your observability backend?"

### Incident and gap questions
4. "Has there been any situation where sensitive data from a tool call showed up somewhere it should not have — in a log, in a monitoring dashboard, in a vendor's telemetry system?"

5. "When an agent calls a third-party MCP server — a SaaS vendor's endpoint — what happens to the data in that tool call from the vendor's perspective? Do you know whether the vendor logs request payloads? Have you asked?"

6. "If you had to prove that a specific tool call from last Tuesday did not expose PII beyond your intended recipients, could you do that today? What evidence would you use?"

### MCP-specific tool call questions
7. "When you think about your MCP server catalog — the tools your agents can call — are there any tools where you worry about what happens to the data in the tool call arguments? Which ones, and why?"

8. "Have you implemented any payload scrubbing or redaction before tool calls? If so, where does that scrubbing run — in the agent framework, in a middleware layer, or somewhere else?"

---

## Community Survey Design

Distribute in MCP practitioner communities (Discord, Slack groups, developer forums).

**Survey title:** "How are you handling sensitive data in MCP tool calls?"

**Questions (keep to 5 to maximize completion):**

1. "When your agent calls an MCP tool with sensitive data in the arguments (PII, financial data, credentials), where does that data go after the call?" [Multi-select: to the tool only, to our observability/APM backend, to the tool vendor's telemetry, to third-party dependencies we don't fully know, I don't know]

2. "Have you had any situation where tool call payload data showed up somewhere unexpected?" [Yes (with text box for description), No, Not sure]

3. "Do you have any controls in place specifically for tool call payloads (as opposed to general AI pipeline controls)?" [Yes — what kind?, No — relying on general pipeline controls, No — this is a gap we know about, This is not a concern for our use case]

4. "Which of these describes your current situation best?" [We have MCP in production with sensitive data, We have MCP in development/pilot with sensitive data, We have MCP in production but not with sensitive data yet, We're evaluating MCP]

5. "What is your primary concern about tool call data handling?" [Open text]

**Target:** 50+ responses. **Confirmation threshold:** >30% of respondents in option 1 of Q1 select "to our observability/APM backend" or "to the tool vendor's telemetry."

---

## Confirmation vs Disconfirmation Criteria

**Confirmed (add to opportunity tree):** 3+ interviews where the respondent names a specific MCP tool call incident or a specific gap they know exists and have not closed. Survey shows >30% report unexpected data destinations for tool call payloads.

**Disconfirmed (deprioritize P1-specific features):** Interviews consistently describe the problem at the AI pipeline level ("prompts going to OpenAI") without naming tool calls specifically. Survey shows <10% have had unexpected data destinations at the tool call layer.

**Partially confirmed (sharpen scope):** Interviewees name the concern but have not had an incident. This suggests P1 is a real risk but not yet a live fire — the right framing is prevention rather than response.

---

## Output

**If confirmed:** P1 shapes (P1.1 over-sharing, P1.2 chatty responses, P1.3 cross-system boundary) move from "inferred" to "confirmed" on the opportunity tree. Update SPEC.md evidence section. Prioritize egress DLP and call graph tracking in Phase 1 engineering scope.

**If disconfirmed:** These Phase 1 features are still worth building (they address real OWASP MCP10 threats) but should not lead the customer narrative. Lead with P3 (provable governance) and P2 (unsanctioned tool use) which have stronger direct evidence.
