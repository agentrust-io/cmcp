# Claim 6: Cross-Organizational Attestation Chains for B2B AI Tool Access

**Claim:** Cross-Organizational Attestation Chains for B2B AI Tool Access  
**Paper:** `agentrust-io/papers/cross-org-attestation.md`  
**Status:** Phase 2 concept. Phase 2 server TEE not yet deployed. This experiment is a software simulation of the dual-attestation protocol.

---

## What this measures

In B2B AI tool access, enterprise (party A) uses a Phase 1 cMCP gateway and SaaS vendor (party B) uses a Phase 2 cMCP server. Each operates an independent TEE with a separate keypair. A third-party verifier can confirm both sides independently, without trusting either operator's infrastructure.

| Property | What it proves |
|---|---|
| P1 — Independent keys | Gateway and server have different TEE keypairs |
| P2 — Session linkage | Both claims carry the same session_id |
| P3 — Phase 1 nonce | SHA-256(gateway_key ∥ session_id) binds Phase 1 to session |
| P4 — Phase 2 nonce | SHA-256(server_key ∥ session_id) binds Phase 2 to session |
| P5 — Independent verify | Each claim verifiable against its own public key |
| P6 — Tamper independence | Phase 1 tamper invalidates only Phase 1; Phase 2 unaffected |
| P7 — Binary swap detection | Different server binary → different measurement → verifier rejects |

---

## Running

```bash
pip install -e .
python experiments/claim6-cross-org-attestation/run.py
```

---

## Cross-org verification protocol

```
Verifier checklist for a paired Phase 1 + Phase 2 TRACE Claim:
1. Verify Phase 1 Ed25519 signature against embedded gateway public key
2. Compute expected Phase 1 nonce = SHA-256(gateway_key || session_id)
3. Confirm Phase 1 attestation report contains the expected nonce (hardware check in production)
4. Verify Phase 2 Ed25519 signature against embedded server public key
5. Compute expected Phase 2 nonce = SHA-256(server_key || session_id)
6. Confirm Phase 2 attestation report contains the expected nonce (hardware check in production)
7. Confirm Phase 1 session_id == Phase 2 session_id (linkage)
8. Confirm Phase 2 server_binary_measurement == pre-approved measurement
9. Confirm Phase 2 tool_catalog_hash == independently-reviewed catalog hash
```

Steps 3 and 6 require hardware in production. In software simulation (this experiment), they are demonstrated as mathematical checks.

---

## What Phase 2 attests (per server TEE)

- **Server binary measurement**: SHA-256 of the tool server binary, measured into the TEE PCR before any code runs. A binary update changes the measurement; verifiers holding the prior approved measurement detect it.
- **Tool catalog hash**: SHA-256 of the server's approved tool definitions. Prevents server-side rug-pulls independent of Phase 1 catalog drift detection.
- **Egress policy hash**: SHA-256 of the server's egress policy. Prevents the server from calling unapproved upstream APIs with enterprise data.
