# Regulated Buyer Playbook

The entry point for production-bound regulated buyers is the proof gap, not the software layer.

---

## Section 1: Segment Identification (First 5 Minutes)

Ask: "Where are your AI agents in the deployment lifecycle — pilot, staging, or production?"

- If the answer is "production-blocked by compliance": this is a regulated buyer. Go to Section 2.
- If the answer is "still in pilot": this may be an early-stage buyer. Go to Section 3.

---

## Section 2: Regulated Buyer Entry Point Script

Do NOT lead with software gateway capabilities. Do NOT compare to Kong, Cloudflare, or other API gateways. Start here:

> "Let me ask you a specific question. When your compliance team or an auditor asks 'prove that your AI agents handled customer data according to your policy on a specific date' — what do you give them today?"

### Common Responses and How to Continue

**"We give them our audit logs and our SOC 2"**
> "SOC 2 describes your intended configuration, not what ran on that date. If an auditor asks whether the log could have been rewritten, what do you say?"

This opens the proof gap. Continue from there.

**"We're not at that stage yet"**
> "Which compliance milestone would require you to have that answer? EU AI Act, DORA, your next enterprise renewal?"

Identify the trigger event before moving forward.

**"We haven't had that question yet"**
> "Which of your customers is most likely to ask it first — the one in financial services, the one in healthcare?"

Personalize the threat. The question is not whether it will come, but who will ask it first.

### Qualification Signal

The conversation moves from "this is theoretical" to "here's the specific situation we're worried about." That shift is the qualification signal. Do not proceed to architecture until you hear a specific blocker.

---

## Section 3: Early-Stage Buyer Transition Signal

Early-stage buyers are in pilot and not yet blocked by compliance.

- Lead with software governance — lower friction, immediate value
- Plant the seed: "When you move to production and compliance gets involved, the question they'll ask is X. We can answer that with hardware attestation."
- Watch for the transition event: a compliance review, a customer security questionnaire, a regulatory deadline. That is the signal to switch to the regulated buyer conversation in Section 2.

---

## Section 4: Objection Handling

**Objection:** "We already have a software gateway deployed."

> "Good — that handles policy enforcement. The question is whether your auditors can verify that the policy you describe in documents is the policy that actually ran on your traffic on a specific date. Let me ask: the next time an auditor asks that question, what evidence do you hand them?"

Redirect to the proof gap.

**Objection:** "This sounds like we'd have to rip out our existing gateway."

> "No. Hardware attestation sits alongside your existing enforcement layer. It adds cryptographic proof to decisions your gateway is already making. You're not replacing the gateway — you're making its claims verifiable."

---

*Closes #15*
