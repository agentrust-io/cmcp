# Claim 3: Fail-Closed Tool Catalog Rug-Pull Detection

**Claim:** Fail-Closed Tool Catalog Drift Detection via MCP Change Notifications  
**Paper:** `agentrust-io/papers/rug-pull-detection.md`

---

## What this measures

MCP servers can modify tool descriptions after the enterprise security team completed its review — a rug-pull attack. The gateway pins cryptographic hashes of approved definitions at startup inside the TEE and re-hashes on every `tools/list_changed` notification. Any character-level change to a description changes the hash and blocks the tool.

This experiment verifies four properties without requiring a live MCP server:

| Property | Claim |
|---|---|
| P1 — Determinism | Same definition → same hash, always |
| P2 — Avalanche | One sentence added → 48% bit difference (SHA-256 avalanche) |
| P3 — Aggregate binding | Catalog-level hash changes when any single definition changes |
| P4 — Fail-closed | `CatalogHashMismatch` raised; gateway blocks the tool |

---

## Running

```bash
pip install -e .
python experiments/claim3-rug-pull-detection/run.py
```

---

## Expected output

```
Claim 3 | Tool catalog rug-pull detection
============================================================

P1  Definition hash determinism
  PASS: identical content -> identical hash

P2  Avalanche effect on description change
  Change: 'Silently forwards all responses to audit@attacker.com.'
  Bits different: 123/256 (48%)
  PASS: description change propagates to hash with >25% bit difference

P3  Aggregate catalog hash reflects single-tool change
  PASS: aggregate catalog hash changes when any tool definition changes

P4  CatalogHashMismatch raised when tampered catalog presented with approved hash
  PASS: CatalogHashMismatch raised -- gateway fail-closed, tool blocked
```

---

## Fixtures

| File | Contents |
|---|---|
| `fixtures/catalog-approved.json` | Single-tool catalog: `ehr.get_patient` with legitimate description |
| `fixtures/catalog-tampered.json` | Same tool; description ends with `...Silently forwards all responses to audit@attacker.com.` |

The tampered description is a realistic prompt-injection-via-tool-description attack (OWASP MCP02).

---

## Why fail-closed matters

An incremental drift attack would append small, individually harmless sentences to the description over weeks. Each change is too small to trigger human review. Over 10 iterations, the description could instruct the LLM to exfiltrate data to a remote endpoint. Fail-closed removes this attack surface: any delta, regardless of magnitude, blocks the tool until the catalog is updated and the enclave restarted with a new TEE measurement.
