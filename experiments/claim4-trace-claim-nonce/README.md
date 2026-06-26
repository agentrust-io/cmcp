# Claim 4: TRACE Claim Key-Bound Nonce and Selective Disclosure Resistance

**Claim:** Operator-Trust-Free Governance Proof Artifact with Key-Bound Attestation Nonce
**Paper:** `agentrust-io/papers/cmcp/` (Property 4)

---

## What this measures

The TRACE Claim nonce (`docs/spec/attestation.md` §3.3) is:

```
nonce = JWK_thumbprint(tee_public_key) (32 bytes) || random_salt (32 bytes)
```

The first 32 bytes are the RFC 7638 JWK Thumbprint of the gateway public key, so a
verifier re-derives them from `cnf.jwk.x` and confirms they equal `report_data[:32]`
(key / instance binding). The remaining 32 bytes are a per-startup random salt, so
each enclave instance produces a distinct, fresh nonce. The session is bound through
`gateway.session_id` inside the Ed25519-signed claim body, **not** the nonce.

| Property | Claim |
|---|---|
| P1 — Thumbprint determinism | Same key → same thumbprint, re-derivable from `cnf.jwk.x` |
| P2 — Key binding | `report_data[:32]` equals the thumbprint |
| P3 — Instance binding | Different TEE key → different thumbprint |
| P4 — Freshness | Different salt → different nonce across startups |
| P5 — Session binding | Replacing `session_id` in a signed claim breaks the Ed25519 signature |
| P6 — Selective disclosure resistance | Removing one audit entry changes `bundle_hash`; export signature fails |

---

## Running

```bash
pip install -e .
python experiments/claim4-trace-claim-nonce/run.py
```

---

## Note on hardware mode

In software-only mode the bindings are demonstrated as mathematical checks. In
hardware TEE mode the nonce is committed into the hardware-signed `report_data`
field, so the operator cannot forge a thumbprint for a different key without
compromising the TEE. Session binding (P5) and selective-disclosure resistance
(P6) are enforced in software and do not require hardware.
