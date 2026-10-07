# TLS Pinning

This page is for operators who want to be sure cMCP is talking to the real tool server and not an impostor. Every HTTPS server presents a certificate; pinning means writing down the fingerprint of the exact certificate you expect, so cMCP refuses to connect if it sees a different one. Once set up, the log records for every call whether the server was checked this way.

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

This is a stand-in, not a real certificate fingerprint. When cMCP sees it, it logs one warning and falls back to the normal HTTPS check: the connection goes ahead if any trusted certificate authority vouches for the server, without comparing it to the catalog. The log records `evidence_class: "hash-only"` for every call to that server.

Replace it with the real SHA-256 fingerprint of your tool server's certificate before setting `enforcement_mode: enforcing`.

---

## Get the server certificate fingerprint

Use `openssl s_client` to fetch the certificate and print its fingerprint:

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

Convert it to the format cMCP expects: remove the colons and base64-encode the raw bytes:

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

cMCP checks this fingerprint every time it connects to the tool server. If the certificate has changed for any reason, including a routine renewal, the connection is refused and the call is blocked before your policy rules even run.

After updating `catalog.json`, recompute the catalog hash (the fingerprint of the whole catalog) and set `CMCP_CATALOG_HASH`.

cMCP computes that hash over a normalised form of the catalog entries, sorted by `tool_name`, and not over the file's raw bytes. The snippet below does the same computation:

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

Set the result as the environment variable before restarting cMCP:

```bash
export CMCP_CATALOG_HASH="sha256:<hex from above>"
cmcp start --config cmcp-config.yaml
```

---

## Read the evidence class in the audit chain

Every log entry has an `evidence_class` field saying what cMCP checked about the server connection for that call:

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

`evidence_class: "tls-pinned"` is part of the log covered by the signed TRACE claim, so anyone who exports the log can see it.

---

## Understand what TLS pinning proves and does not prove

Pinning shows that cMCP connected to the exact server whose certificate you approved when you built the catalog. That stops attacks that send tool calls to a different server: faked DNS answers, wrongly issued certificates, and internet routing hijacks (BGP).

What pinning does not prove: that the server really sent a particular response, in a way the server could not later deny. The server is checked when the connection opens. Each response is fingerprinted and logged (`response_payload_hash`), but a fingerprint alone does not show the server signed that response. For that, the tool server would have to sign its own responses, which cMCP's current catalog format does not cover.

If the tool server changes its certificate, you must update `catalog.json`, recompute the catalog hash and restart cMCP. With `rotation_mode: "key-pinned"`, cMCP refuses to connect to the server after the change until the catalog is updated.

---

## Summary

You replaced the stand-in fingerprint with the real certificate fingerprint, updated the catalog hash, and confirmed that log entries record `evidence_class: "tls-pinned"` for checked connections. Pinning stops someone swapping in a different server; it does not prove who sent each individual response.

Related tutorials: the [Cedar policy walkthrough](./cedar-policy-walkthrough.md) (the catalog is also covered by the hardware measurement), and [Verify a TRACE claim](./verifying-a-trace-claim.md), where the catalog hash in the TRACE claim must match the catalog you pinned.
