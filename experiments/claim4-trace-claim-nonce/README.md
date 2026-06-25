# Claim 4: TRACE Claim Session-Bound Nonce and Selective Disclosure Resistance

**Claim:** Operator-Trust-Free Governance Proof Artifact with Session-Bound Attestation Nonce  
**Paper:** `agentrust-io/papers/trace-claim.md`

---

## What this measures

The TRACE Claim nonce construction `SHA-256(tee_public_key_bytes || session_id_bytes)` binds each attestation report to a specific session and TEE instance. This experiment verifies:

| Property | Claim |
|---|---|
| P1 — Nonce determinism | Same key + session → same nonce |
| P2 — Session binding | Different session_id → different nonce |
| P3 — Instance binding | Different TEE key → different nonce for the same session |
| P4 — Replay prevention | Claim from session A fails nonce check for session B |
| P5 — Signature tamper-evident | Replacing session_id in a signed claim breaks Ed25519 signature |
| P6 — Selective disclosure resistance | Removing one audit entry changes bundle_hash; export signature fails |

---

## Running

```bash
pip install -e .
python experiments/claim4-trace-claim-nonce/run.py
```

---

## Note on P4

In software-only mode, the nonce binding is demonstrated as a mathematical check: the nonce embedded in the claim (computed at claim-generation time for session A) is shown to differ from the verifier's expected nonce for session B. In hardware TEE mode, the nonce is hardware-signed inside the TEE and cannot be forged by the operator. The mathematical check becomes a hardware-enforced check.

P5 (signature tamper-evidence) is fully enforced in software and does not require hardware.
