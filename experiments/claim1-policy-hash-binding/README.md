# Experiment: Policy Bundle Hash Binding

**Claim:** Hardware-attested policy enforcement at the AI agent tool boundary (cMCP Claim 1)

**What this experiment proves:**

1. The policy bundle hash is fully determined by the bundle content — same content, same hash, every time.
2. Any change to any byte in any policy file produces a completely different hash (avalanche property).
3. `load_policy_bundle` raises `PolicyHashMismatch` when the hash of the bundle on disk does not match the expected hash, preventing a substituted bundle from being used.
4. The bundle hash appears in the TRACE Claim's `trace.policy.bundle_hash` field and is covered by the claim's Ed25519 signature. Tampering with the hash breaks signature verification.

**What this means for governance:**

A rogue administrator who modifies the Cedar policy bundle after it was approved cannot silently substitute the new bundle — the computed hash will not match the approved hash, and the gateway will refuse to start. The approved hash recorded in the TRACE Claim can be compared against the policy bundle in version control by any verifier at any time, without trusting the operator.

**Fixtures:**

- `fixtures/bundle-v1/` — original approved policy (permits `ehr.get_patient`)
- `fixtures/bundle-v2/` — identical except one character changed in a comment (`A` → `a` in `allow_ehr_tools.cedar` line 1)

## Running

```bash
# From repo root
pip install -e .
python experiments/claim1-policy-hash-binding/run.py
```

## Expected output

```
=== Experiment: Policy Bundle Hash Binding ===

[1] Hash determinism
    bundle-v1 hash: sha256:...
    bundle-v1 hash (reload): sha256:...
    Deterministic: YES

[2] Avalanche effect (one character change in comment)
    bundle-v1: sha256:<H1>
    bundle-v2: sha256:<H2>
    Bits changed: ~128/256 (expected ~50% for SHA-256)
    Hashes identical: NO  <-- tamper detected

[3] Tamper detection: load bundle-v2 with expected_hash = bundle-v1 hash
    PolicyHashMismatch raised: YES  <-- gateway would not start

[4] TRACE Claim signature covers bundle_hash
    Original claim signature:     VALID
    Claim with tampered hash:     INVALID  <-- verifier rejects

All 4 properties confirmed.
```
