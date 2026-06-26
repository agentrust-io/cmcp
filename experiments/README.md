# cMCP Experiments

Reproducible experiments backing technical claims in the cMCP papers.

Each experiment imports directly from `cmcp_runtime`. Run from the repo root after `pip install -e .`.

## Experiments

| Dir | Claim | Key result |
|-----|-------|-----------|
| [claim1-policy-hash-binding](claim1-policy-hash-binding/) | Claim 1 — TEE-measured policy enforcement | Deterministic hash, 51% avalanche on 1-char change, PolicyHashMismatch, TRACE sig invalidated |
| [claim2-session-vs-call-policy](claim2-session-vs-call-policy/) | Claim 2 — Session sensitivity state | Session policy catches 2/2 PHI cross-boundary violations; per-call catches 0/2 |
| [claim2-false-positive-rate](claim2-false-positive-rate/) | Claim 2 — Session sensitivity state (cost) | Overall FPR 69%; Billing/Batch 100%; Clinical Decision Support 0% |
| [claim3-rug-pull-detection](claim3-rug-pull-detection/) | Claim 3 — Tool catalog drift detection | 48% bit change on one-sentence description tamper; CatalogHashMismatch fail-closed |
| [claim4-trace-claim-nonce](claim4-trace-claim-nonce/) | Claim 4 — TRACE Claim nonce binding | 6 properties: nonce determinism, session/instance binding, replay prevention, sig tamper, selective disclosure |
| [claim5-temporal-adjacency](claim5-temporal-adjacency/) | Claim 5 — Temporal adjacency provenance | Zero false negatives by construction; provenance disclaimer in every summary; denied calls in graph |
| [claim6-cross-org-attestation](claim6-cross-org-attestation/) | Claim 6 — Cross-org attestation chains | Dual-TEE protocol: independent keys, session linkage, independent verify, binary swap detection |
| [claim-hw-attestation](claim-hw-attestation/) | Hardware attestation (real TEE) | Requires a confidential VM; SKIPs without one. Real report + nonce binding + end-to-end claim verification |

## Running

```bash
pip install -e .
python experiments/claim1-policy-hash-binding/run.py
python experiments/claim2-session-vs-call-policy/run.py
python experiments/claim2-false-positive-rate/run.py
python experiments/claim3-rug-pull-detection/run.py
python experiments/claim4-trace-claim-nonce/run.py
python experiments/claim5-temporal-adjacency/run.py
python experiments/claim6-cross-org-attestation/run.py

# Requires a confidential VM; SKIPs cleanly (exit 0) on hosts without a TEE.
python experiments/claim-hw-attestation/run.py
```

The `claim1`–`claim6` experiments run in software-only mode. No hardware TEE is required. TRACE Claims produced in software-only mode carry `attestation_assurance: none` and must not be used for compliance purposes. The `claim-hw-attestation` experiment is the exception: it exercises a real hardware report and verification, and only produces results on a confidential VM (see [claim-hw-attestation/README.md](claim-hw-attestation/README.md)).

## CI tests

| File | Claims | Tests |
|------|--------|-------|
| `tests/unit/test_claim1_hash_binding.py` | Claim 1 | 6 |
| `tests/unit/test_claim2_session_gap.py` | Claim 2 | 6 |
| `tests/unit/test_claim3_rug_pull_detection.py` | Claim 3 | 6 |
| `tests/unit/test_claim4_trace_claim_nonce.py` | Claim 4 | 6 |
| `tests/unit/test_claim5_temporal_adjacency.py` | Claim 5 | 9 |
| `tests/unit/test_claim6_cross_org_attestation.py` | Claim 6 | 9 |
