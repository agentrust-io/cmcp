# Research Guide: RQ4 — What Escalates the Proof Gap to Blocking?

**Research question:** What specific event causes an enterprise to move from "SOC 2 is fine" to "I need proof from the time of processing"? Is it a regulatory examination, a customer contractual demand, a post-incident audit, or something else?

**Why this matters:** The qualifying trigger determines the entire sales motion. If the trigger is a regulatory exam, the entry point is the compliance function. If it is a customer contractual demand, it is the vendor security review team. If it is post-incident, urgency is highest but the window is narrow.

---

## Screening Criteria for Interview Candidates

Prospect must meet at least one:
- Operates under regulatory oversight in AI (EU AI Act, DORA, HIPAA, GDPR, NYDFS, SEC AI governance guidance)
- Has received an external audit or security questionnaire for an AI system in the past 12 months
- Has AI agents in production or blocked from production by a compliance requirement
- Is a CISO, CCO, VP Engineering, or AI platform lead with direct accountability for AI governance

---

## Interview Guide (5–7 questions)

### Opening context question
"Walk me through the last time someone outside your organization — a regulator, a customer, an auditor — asked you to prove something about how your AI handled their data. Not describe it, but prove it."

*Listen for:* whether this has happened at all. If it has not happened yet, skip to the escalation scenario question.

### Escalation event questions
1. "What specifically triggered that request? Was it a scheduled regulatory examination, a customer renewal conversation, an incident, or something else?"

2. "When they said they needed proof rather than a written description, what did they actually ask for? What artifact or evidence were they expecting?"

3. "What did you give them? How did they respond to what you gave them?"

4. "Did it block anything — a deal, a deployment, a certification — or was it ultimately resolved without consequence?"

### Escalation scenario question (for prospects who have not experienced this yet)
"Which scenario do you think is most likely to force this issue for you: (a) a regulatory examination, (b) an enterprise customer renewal where the customer's security team pushes back, (c) an internal audit discovering a gap, or (d) an incident where you need to reconstruct what the agent did?"

*Follow-up:* "Is any of those already on your horizon in the next 6–12 months?"

### Urgency calibration question
"If the escalation event you described — or the one you anticipate — happened tomorrow, what would prevent you from answering it today? Is it a technical gap (you do not have the logs), a trust gap (you have logs but an auditor would not trust them), or a coverage gap (you have some evidence but not for AI-specific actions)?"

### Stakes question
"What is the business consequence if you cannot answer that question — a deal lost, a fine, a delayed deployment, a reputational hit? Can you put a rough number on the cost of being in that position?"

---

## Trigger Taxonomy

Use this taxonomy to code interview responses:

| Trigger | Definition | Urgency level | Sales motion |
|---------|-----------|--------------|-------------|
| Regulatory examination | A regulator (EU AI Act supervisor, DORA examiner, OCC, FCA, etc.) formally requests evidence during an exam cycle | High — has a deadline | Compliance function is the entry point |
| Customer contractual demand | An enterprise customer includes a proof requirement in a contract, renewal, or security questionnaire | Medium-high — deal-blocking | Vendor security review team is the entry point |
| Post-incident audit | An AI incident (data breach, model error, regulatory finding) triggers a retrospective demand for proof | Very high — time-pressured | CISO and legal are the entry points |
| Proactive internal audit | The enterprise's own internal audit function identifies the gap before an external party does | Medium — self-imposed | CISO or CCO is the entry point |
| Competitive displacement | A competitor claims provable governance and the enterprise needs to match the claim | Low-medium | Product/business teams are the entry point |

---

## Output and Decision Criteria

**Target:** 5–7 CISO-level interviews.

**Go signal:** 3+ interviews where the escalation trigger is identified as real and currently anticipated within 12 months. The qualifying question ("what business are you giving up today...") surfaces a specific, named situation.

**No-go signal:** Fewer than 2 interviews where the trigger is concrete and near-term. The proof gap is theoretical to this set of prospects — revisit the target segment.

**Finding to embed in sales motion:** The most common trigger type (regulatory / contractual / post-incident) determines the primary entry point and the opening conversation frame. If most triggers are contractual, lead with "your enterprise customers are about to start asking you for this." If most are regulatory, lead with the regulatory examination scenario.
