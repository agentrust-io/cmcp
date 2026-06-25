# cMCP Experiments

Reproducible experiments backing technical claims in the cMCP papers.

Each experiment imports directly from `cmcp_runtime`. Run from the repo root after `pip install -e .`.

## Experiments

| Dir | Claim | What it measures |
|-----|-------|-----------------|
| [claim1-policy-hash-binding](claim1-policy-hash-binding/) | Claim 1 — TEE-measured policy enforcement | Policy bundle hash is deterministic, tamper-detectable, and bound in the TRACE Claim signature |
| [claim2-session-vs-call-policy](claim2-session-vs-call-policy/) | Claim 2 — Session sensitivity state | Gap between per-call policy and session-level policy across a synthetic PHI-contaminated trace |
| [claim2-false-positive-rate](claim2-false-positive-rate/) | Claim 2 — Session sensitivity state | False positive rate of the monotonic model across 5 workflow personas; overall FPR 69% |

## Running

```bash
pip install -e .

# Experiment 1 (no hardware TEE required)
python experiments/claim1-policy-hash-binding/run.py

# Experiment 2 (no hardware TEE required)
python experiments/claim2-session-vs-call-policy/run.py

# Experiment 3 (no hardware TEE required)
python experiments/claim2-false-positive-rate/run.py
```

Both experiments run in software-only mode. No hardware TEE is required. TRACE Claims produced in software-only mode are labeled `attestation_assurance: none` and must not be used for compliance purposes.
