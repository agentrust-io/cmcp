# Claim 5: Temporal Adjacency as a Formally Bounded Provenance Approximation

**Claim:** Temporal Adjacency as a Formally Bounded Approximation of Data Provenance for AI Agent Compliance  
**Paper:** `agentrust-io/papers/temporal-adjacency.md`

---

## What this measures

At the MCP transport boundary, a gateway cannot observe whether an LLM agent included a specific tool response in its context window for the next call. The temporal adjacency model records an edge from call A to call B whenever B's sequence number is greater than A's and A contributed to session sensitivity. This is conservative: it may record edges where the agent did not actually use A's data (false positives), but it never misses an edge where the agent did (no false negatives).

| Property | What it proves |
|---|---|
| P1 — Sequential recording | Calls recorded with monotonic sequence numbers |
| P2 — Cross-boundary detection | Transitions from high-sensitivity domains recorded in graph |
| P3 — Provenance disclaimer | `edges_represent` field explicitly qualifies adjacency vs. provenance |
| P4 — No false negatives | Any PHI-relevant subsequent call has seq > PHI call seq; edge implicit |
| P5 — Concurrent calls | Simultaneous calls both adjacent to prior PHI call |
| P6 — Denied calls in graph | Agent's request is evidence of awareness, regardless of response delivery |

---

## Running

```bash
pip install -e .
python experiments/claim5-temporal-adjacency/run.py
```

---

## Relationship to Claim 2 FPR

The Claim 2 false positive rate experiment (`experiments/claim2-false-positive-rate/`) measures the operational cost of the monotonic model — what fraction of blocked external calls are unnecessary. That experiment and this one are two sides of the same coin: this experiment proves no false negatives; the FPR experiment measures the false positive rate empirically.

---

## High-sensitivity domains (implementation note)

The `SessionCallLog` records cross-boundary events when a call follows a call in a high-sensitivity compliance domain. The current set is `{"phi", "pii", "pci", "restricted"}`. The catalog compliance_domain field should map tool destinations to these labels for cross-boundary detection to trigger. The session sensitivity model uses a separate `SENSITIVITY_ORDER` dict with `hipaa_phi`, `mnpi`, etc. These two taxonomies are intentionally separate: the call graph tracks destination-class transitions, while session state tracks data-class sensitivity.
