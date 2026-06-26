# Claim 2, Experiment 1: False Positive Rate of the Monotonic Sensitivity Model

**Claim:** Monotonic Session Sensitivity State for LLM Data Governance  
**Paper:** `agentrust-io/papers/session-sensitivity.md`

---

## What this measures

The monotonic session sensitivity model blocks ALL external non-BAA calls once `session_max_sensitivity` reaches `hipaa_phi`. This conservatism has a cost: calls where the agent would not actually have exposed PHI get blocked alongside calls where it would have.

This experiment quantifies that cost across five representative BFSI/healthcare workflow patterns using labeled ground-truth traces.

**False positive (FP):** Session policy blocks an external non-BAA call where `phi_in_agent_context` is `false` — the agent demonstrably would not have transmitted PHI in this call.

**False positive rate (FPR) = FP / (FP + TP_blocked)**

---

## Running

```bash
pip install -e .
python experiments/claim2-false-positive-rate/run.py
```

No hardware TEE required.

---

## Expected output

```
Claim 2 | False positive rate of the monotonic sensitivity model
========================================================================

Persona                          Blocked   TP   FP    FPR
---------------------------------------------------------
Clinical Decision Support              2    2    0     0%
Billing Agent                          4    0    4   100%
Compliance Reporter                    3    2    1    33%
Mixed Workflow                         3    1    2    67%
Batch Notification Processor           4    0    4   100%
---------------------------------------------------------
Overall                               16    5   11    69%
```

---

## The five personas

| Persona | PHI pattern | Expected FPR |
|---------|------------|--------------|
| Clinical Decision Support | PHI flows throughout all downstream calls | 0% |
| Billing Agent | PHI accessed once for patient identity; billing workflow is PHI-free | 100% |
| Compliance Reporter | Aggregate PHI stats in some reports; notification email has none | 33% |
| Mixed Workflow | Agent alternates between scheduling (no PHI) and clinical tasks | 67% |
| Batch Processor | PHI accessed once for patient list; each reminder is PHI-free | 100% |

---

## Interpretation

- **2 of 5 workflow patterns** produce 100% FPR. Every blocked call is a false positive. PHI is accessed once for identity/batch retrieval, then the workflow pivots entirely to non-PHI tasks. The monotonic model cannot distinguish this from workflows where PHI flows throughout.

- **Clinical Decision Support** shows the model working as intended: 0% FPR. PHI is referenced in every downstream external call, so all blocks are justified.

- **Overall FPR: 69%.** 11 of 16 blocked external calls across all five personas are false positives.

---

## Design implications

**Why FP is acceptable (compliance cost):** A false negative (allowing a PHI-contaminated call) would be a compliance violation. A false positive (blocking a PHI-free call) has an operational cost but no compliance cost. The model correctly prioritizes false negative elimination.

**How operators can reduce FPR today:**
1. Partition PHI-retrieval and downstream workflows into separate sessions with explicit operator-credentialed resets between phases.
2. Configure Cedar policies with per-tool BAA coverage for downstream tools that are provably PHI-free.

**What Phase 2 agent-cooperative tagging would achieve:**
If the agent SDK reports which prior call IDs are present in its context window when issuing a new call, the gateway can replace temporal adjacency approximation with call-ID-level provenance. FPR drops to 0% for all five personas. This is the primary empirical motivation for Phase 2.

---

## Ground truth labeling

`phi_in_agent_context` in `fixtures/trace_corpus.json` is set by the experimenter, not computed by the gateway. It represents whether the agent's reasoning for a specific call references PHI from prior responses. This is the label the gateway *cannot* observe — which is exactly why the monotonic model exists.

A value of `false` means: if this call had been allowed, the agent would not have transmitted PHI content. The PHI exists in the session context window (it was retrieved in an earlier call), but the agent's decision and arguments for this specific call are independent of that PHI content.
