# cMCP Experiments

Reproducible experiments backing technical claims in the cMCP papers.

Each experiment imports directly from `cmcp_runtime`. Run from the repo root after `pip install -e .`.

## Experiments

| Dir | Claim | What it measures |
|-----|-------|-----------------|
| [claim1-policy-hash-binding](claim1-policy-hash-binding/) | Claim 1 — TEE-measured policy enforcement | Policy bundle hash is deterministic, tamper-detectable, and bound in the TRACE Claim signature |
| [claim2-session-vs-call-policy](claim2-session-vs-call-policy/) | Claim 2 — Session sensitivity state | Gap between per-call policy and session-level policy across a synthetic PHI-contaminated trace |
| [claim2-false-positive-rate](claim2-false-positive-rate/) | Claim 2 — Session sensitivity state | False positive rate of the monotonic model across 5 workflow personas; overall FPR 69% |
| [claim3-rug-pull-detection](claim3-rug-pull-detection/) | Claim 3 — Tool catalog drift detection | Definition hash changes on single-sentence description tamper (48% bit difference); CatalogHashMismatch raised fail-closed |
| [claim4-trace-claim-nonce](claim4-trace-claim-nonce/) | Claim 4 — TRACE Claim nonce binding | Nonce binds claim to specific session and TEE instance; session_id tamper breaks signature; entry removal breaks export hash |

## Running

```bash
pip install -e .
python experiments/claim1-policy-hash-binding/run.py
python experiments/claim2-session-vs-call-policy/run.py
python experiments/claim2-false-positive-rate/run.py
python experiments/claim3-rug-pull-detection/run.py
python experiments/claim4-trace-claim-nonce/run.py
```

All experiments run in software-only mode. No hardware TEE is required. TRACE Claims produced in software-only mode are labeled `attestation_assurance: none` and must not be used for compliance purposes.
