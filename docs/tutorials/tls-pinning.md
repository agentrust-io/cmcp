# TLS Pinning

Configure certificate pinning for upstream tool servers so the audit chain records whether a call was made to a server whose certificate was verified at connection time.

## What you'll learn

- What `PLACEHOLDER_FINGERPRINT` means and why it must be replaced before production
- How to extract the real SHA-256 fingerprint from an upstream server's certificate
- How to set `tls_fingerprint` in `catalog.json`
- What `evidence_class` values `"tls-pinned"` and `"hash-only"` mean in audit entries
- What TLS pinning does and does not prove

## Prerequisites

```bash
pip install cmcp-runtime
openssl  # standard on Linux/macOS; available via Git Bash on Windows
```

---

## Understand the placeholder fingerprint

The quickstart `catalog.json` uses this fingerprint value:

```json
"tls_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
```

This is a sentinel, not a real certificate pin. When the runtime encounters this placeholder it logs a one-time warning and falls back to standard CA verification — the connection proceeds but peer identity is verified by CA trust only, not pinned to the catalog. The audit chain records `evidence_class: "hash-only"` for every call to that server.

Replace it with the real SHA-256 fingerprint of your upstream server's certificate before setting `enforcement_mode: enforcing`.

---

## Get the server certificate fingerprint

Use `openssl s_client` to retrieve the certificate and extract its fingerprint:

```bash
openssl s_client -connect your-tool-server.example.com:443 \
  -servername your-tool-server.example.com \
  </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

The output looks like:

```
SHA256 Fingerprint=AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78
```

Convert it to the format cMCP expects. Remove the colons and base64-encode the raw bytes:

```bash
openssl s_client -connect your-tool-server.example.com:443 \
  -servername your-tool-server.example.com \
  </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 \
  | sed 's/SHA256 Fingerprint=//' \
  | tr -d ':' \
  | xxd -r -p \
  | base64
```

The result is a 44-character base64 string. Prefix it with `SHA256:` in `catalog.json`.

---

## Set the fingerprint in catalog.json

Update the `server` block for the tool entry:

```json
{
  "tool_name": "your-company.tool-name",
  "server": {
    "display_name": "Your Tool Server",
    "url": "https://your-tool-server.example.com/mcp",
    "tls_fingerprint": "SHA256:q7AcXxYZ8nQmKpLsWdHuFrNbTgVjCeOaIyMkUvPwEx4=",
    "transport": "http-sse",
    "rotation_mode": "key-pinned"
  },
  ...
}
```

The runtime verifies this fingerprint on every outbound connection to the tool server. If the server's certificate has changed (including rotation), the connection is refused and the call is blocked before it reaches Cedar policy evaluation.

After updating `catalog.json`, recompute the catalog hash and set `CMCP_CATALOG_HASH`.

The runtime computes the hash over the canonical JSON of the catalog entries sorted by `tool_name` — not over the raw file bytes. The snippet below replicates that computation exactly:

```bash
python3 -c "
import json, hashlib
with open('catalog.json') as f:
    entries = json.load(f)
sorted_entries = sorted(entries, key=lambda e: e['tool_name'])
canonical = json.dumps(sorted_entries, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
print('sha256:' + hashlib.sha256(canonical.encode()).hexdigest())
"
```

Set the result as the env var before restarting the runtime:

```bash
export CMCP_CATALOG_HASH="sha256:<hex from above>"
cmcp start --config cmcp-config.yaml
```

---

## Read the evidence class in the audit chain

Every audit entry includes an `evidence_class` field. The value reflects what the runtime verified about the server connection at the time of the call:

| `evidence_class` value | Meaning |
|---|---|
| `"tls-pinned"` | The upstream server's certificate fingerprint was verified against `catalog.json` at connection time. The call was made to the pinned server. |
| `"hash-only"` | The tool call and response were hashed and chained, but the server certificate was not pinned. Either `PLACEHOLDER_FINGERPRINT` was used or the connection succeeded without fingerprint verification. |

In your audit entries:

```json
{
  "entry_type": "tool_call",
  "tool_name": "your-company.tool-name",
  "evidence_class": "tls-pinned",
  "policy_decision": "allow",
  ...
}
```

`evidence_class: "tls-pinned"` appears in the TRACE Claim's audit chain and is visible to verifiers who export the audit bundle.

---

## Understand what TLS pinning proves and does not prove

TLS pinning verifies that the runtime connected to the specific server whose certificate you approved at catalog-build time. This closes several attack vectors: DNS spoofing, certificate misissuance, and BGP hijacking that redirects tool calls to a server with a different certificate.

What pinning does not prove: it does not prove non-repudiation of individual responses. The server is verified at connection time; individual response payloads are hashed and chained in the audit log (via `response_payload_hash`), but the hash alone does not prove the server signed that specific response. For response-level non-repudiation you need the upstream server to sign its responses, which is outside the scope of cMCP's current catalog format.

If the upstream server rotates its certificate, you must update `catalog.json`, recompute the catalog hash, and restart the runtime. With `rotation_mode: "key-pinned"`, the runtime will refuse connections to the server after rotation until the catalog is updated.

---

## Summary

You replaced the development sentinel fingerprint with a real SHA-256 certificate pin, updated the catalog hash, and confirmed that audit entries record `evidence_class: "tls-pinned"` for verified connections. TLS pinning prevents server substitution attacks but does not extend to individual response non-repudiation.

Related tutorials: [Cedar policy walkthrough](./cedar-policy-walkthrough.md) — the catalog is also covered by the attestation measurement. [Verify a TRACE claim](./verifying-a-trace-claim.md) — the catalog hash in the TRACE claim must match the catalog you pinned.
