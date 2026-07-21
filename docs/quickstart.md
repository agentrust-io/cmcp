---
description: cMCP quickstart. From zero to your first signed TRACE Claim in under 30 minutes using CMCP_DEV_MODE=1, no hardware TEE required. Install, write a Cedar policy and tool catalog, run the gateway, and verify the claim.
---

# Quickstart - cMCP Runtime

From zero to first TRACE Claim in under 30 minutes. Uses `CMCP_DEV_MODE=1` so no hardware TEE is required.

---

## What you'll build

You'll run a cMCP Runtime that intercepts tool calls from a demo agent, enforces a Cedar policy bundle, and produces a signed TRACE Claim at the end of the session. The demo scenario uses a mock `salesforce.contacts` tool. The TRACE Claim records which tools were called, what data classes they touched, and that the policy bundle hash matches what was measured at startup.

---

## Prerequisites

- Ubuntu 24.04 (or any Linux distro with Python 3.11+)
- Python 3.11 or newer
- pip

Verify:

```bash
python3 --version   # Python 3.11.x or higher
pip --version
```

---

## Install

```bash
pip install cmcp-runtime
```

This installs:
- `cmcp` - the gateway CLI
- `cmcp_verify` - the Python library for verifying TRACE Claims (no separate CLI install needed)

---

## Configuration

Create a working directory for the demo:

```bash
mkdir cmcp-quickstart && cd cmcp-quickstart
mkdir policies
```

Write `cmcp-config.yaml`:

```yaml
attestation:
  provider: auto
  enforcement_mode: advisory
policy_bundle_path: ./policies/
catalog_path: ./catalog.json
listen_addr: "127.0.0.1:8443"
```

- `provider: auto` detects hardware TEE if present; falls back to software-only when `CMCP_DEV_MODE=1`
- `enforcement_mode: advisory` logs policy denies but does not hard-block calls (safe for first run; switch to `enforcing` in production)
- `policy_bundle_path` is the directory containing `.cedar` policy files and `manifest.json`
- `catalog_path` is the JSON file listing approved tools

---

## Cedar policy

Write `policies/manifest.json`:

```json
{
  "version": "0.1.0",
  "authored_at": "2026-06-05T00:00:00Z",
  "author_identity": "developer@example.com",
  "commit_sha": "quickstart-demo"
}
```

Write `policies/demo.cedar`:

```cedar
// Rule 1: permit tool calls from the demo-agent workflow
permit (
  principal,
  action == cMCP::Action::"call_tool",
  resource
) when {
  context.workflow_id == "demo-agent"
};

// Rule 2: deny salesforce.contacts when the session contains PII
forbid (
  principal,
  action == cMCP::Action::"call_tool",
  resource == cMCP::Resource::"salesforce.contacts"
) when {
  context.session_max_sensitivity == "pii"
};

// Rule 3: permit everything else
permit (
  principal,
  action == cMCP::Action::"call_tool",
  resource
);
```

Rule 1 scopes the demo agent to its workflow. Rule 2 blocks `salesforce.contacts` once PII has entered the session, preventing a data class elevation path. Rule 3 is the default allow. Cedar evaluates `forbid` before `permit`, so rule 2 takes precedence when both match.

Write `policies/schema.cedarschema` (one line):

```
{"cMCP":{"entityTypes":{"Principal":{"memberOfTypes":[],"shape":{"type":"Record","attributes":{"session_id":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}},"Resource":{"memberOfTypes":[],"shape":{"type":"Record","attributes":{"tool_name":{"type":"String","required":true}}}}},"actions":{"call_tool":{"appliesTo":{"principalTypes":["cMCP::Principal"],"resourceTypes":["cMCP::Resource"],"context":{"type":"Record","attributes":{"session_max_sensitivity":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}}}}}}
```

---

## Catalog

Write `catalog.json`. The `definition_hash` is the SHA-256 of the canonical JSON of `approved_definition` (sorted keys, no whitespace, ASCII-safe). For the entry below it is precomputed.

```json
[
  {
    "tool_name": "salesforce.contacts",
    "server": {
      "display_name": "Salesforce Contacts MCP Server (mock)",
      "url": "http://localhost:9001/mcp",
      "tls_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "transport": "http-sse",
      "rotation_mode": "key-pinned"
    },
    "approved_definition": {
      "description": "Query Salesforce contacts by account name or contact ID.",
      "input_schema": {
        "type": "object",
        "required": ["query"],
        "properties": {
          "query": {"type": "string", "description": "Account name or contact ID"},
          "max_records": {"type": "integer", "default": 50}
        }
      },
      "output_schema": {
        "type": "object",
        "properties": {
          "contacts": {"type": "array"},
          "total_count": {"type": "integer"}
        }
      }
    },
    "definition_hash": "sha256:b42ecf14612f23456b5b0794864a00288d4038ac444cedb87fc214cefee89e35",
    "compliance_domain": "pii",
    "requires_baa": false,
    "sensitivity_level": "pii",
    "added_at": "2026-06-05T00:00:00Z",
    "approved_by": "developer@example.com"
  }
]
```

The `definition_hash` is computed from the exact bytes of `approved_definition` in canonical form:

```bash
python3 -c "
import json, hashlib
d = {
  'description': 'Query Salesforce contacts by account name or contact ID.',
  'input_schema': {
    'type': 'object',
    'required': ['query'],
    'properties': {
      'query': {'type': 'string', 'description': 'Account name or contact ID'},
      'max_records': {'type': 'integer', 'default': 50}
    }
  },
  'output_schema': {
    'type': 'object',
    'properties': {
      'contacts': {'type': 'array'},
      'total_count': {'type': 'integer'}
    }
  }
}
s = json.dumps(d, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
print('sha256:' + hashlib.sha256(s.encode()).hexdigest())
"
```

If you change any field in `approved_definition`, rerun the command and update `definition_hash`. The runtime rejects catalog entries where the hash does not match.

---

## Start the runtime

```bash
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
```

In dev mode the runtime uses a software-only TEE provider (no hardware required). The startup log ends with the listen address:

```
cMCP Runtime starting: TEE: software-only, listen: 127.0.0.1:8443
INFO:     Uvicorn running on http://127.0.0.1:8443 (Press CTRL+C to quit)
```

**Note**: Tokenless development mode is local-only. Non-loopback access requires setting a `CMCP_BEARER_TOKEN`. This protects developers from accidentally exposing an unauthenticated gateway to LAN, container, or cloud networks.

The gateway is now listening and blocks the terminal, so open a second terminal for the next steps. The policy-bundle and tool-catalog hashes are recorded inside the TRACE Claim you retrieve below (`trace.policy.bundle_hash` and `gateway.catalog.hash`), so there is no need to copy them from the log.

---

## Make a tool call

In a second terminal:

```bash
curl -X POST http://localhost:8443/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "salesforce.contacts",
      "arguments": {"query": "Acme Corp", "max_records": 10},
      "_cmcp": {
        "session_id": "demo-session-001",
        "workflow_id": "demo-agent"
      }
    }
  }'
```

The runtime intercepts the call, evaluates the Cedar policy (rule 1 matches because `workflow_id == "demo-agent"`), records an audit entry, and forwards to the upstream mock server.

---

## Get the TRACE Claim

The TRACE Claim is finalized and signed when the session is **closed**. Closing takes the session's internal id (a UUID) — not the `_cmcp.session_id` label (`demo-session-001`) you sent with the call. Read that id from the audit export, then close the session:

```bash
# 1. Look up the session's internal id
SESSION_UUID=$(curl -s "http://localhost:8443/audit/export?session_id=demo-session-001" \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['entries'][0]['session_id'])")

# 2. Close the session; this returns the signed TRACE Claim
curl -s -X POST "http://localhost:8443/sessions/$SESSION_UUID/close" \
  | python3 -m json.tool > claim.json
```

The closed session's claim stays available at `GET /sessions/$SESSION_UUID/trace-claim`.

The response is a signed `GatewayClaim`. It looks like:

```json
{
  "cmcp_version": "1.0",
  "trace": {
    "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
    "iat": 1749081600,
    "subject": "spiffe://cmcp.gateway/tee/<gateway-id>",
    "runtime": {
      "platform": "tpm2",
      "measurement": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      "firmware_version": "software-only-dev-mode"
    },
    "policy": {
      "bundle_hash": "sha256:<bundle_hash>",
      "enforcement_mode": "advisory",
      "version": "0.1.0"
    },
    "data_class": "pii",
    "tool_transcript": {
      "hash": "sha256:<audit_chain_tip>",
      "call_count": 1
    },
    "cnf": {
      "jwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "<base64url_public_key>",
        "kid": "cmcp-<key_prefix>"
      }
    }
  },
  "gateway": {
    "session_id": "demo-session-001",
    "audit_chain": {
      "root": "sha256:<chain_root>",
      "tip": "sha256:<chain_tip>",
      "length": 1
    },
    "call_summary": {
      "tool_calls_total": 1,
      "tool_calls_allowed": 1,
      "tool_calls_denied": 0,
      "tool_calls_faulted": 0,
      "tools_invoked": ["salesforce.contacts"],
      "session_max_sensitivity": "pii",
      "call_graph_summary": {
        "compliance_domains_touched": ["pii"],
        "cross_boundary_events": []
      }
    },
    "catalog": {
      "hash": "sha256:<catalog_hash>",
      "drift_detected": false
    },
    "attestation_generated_at": "2026-06-05T00:00:00Z",
    "attestation_validity_seconds": 86400,
    "attestation_stale": false
  },
  "signature": "<base64url_ed25519_sig>"
}
```

---

## Verify

Verify the claim with the bundled `cmcp verify` command — no code required. It checks the Ed25519 signature, schema, attestation freshness, and audit-chain consistency without trusting the runtime operator:

```bash
cmcp verify claim.json
```

Expected output in dev mode:

```
[cmcp verify] schema                PASS
[cmcp verify] signature             PASS
[cmcp verify] policy_bundle.hash    PASS  (not pinned - pass --policy-hash to pin)
[cmcp verify] tool_catalog.hash     PASS  (not pinned - pass --catalog-hash to pin)
[cmcp verify] attestation_freshness PASS
[cmcp verify] audit_chain           PASS
[cmcp verify] hardware_attestation  FAIL  software-only mode - not hardware-backed
[cmcp verify] RESULT: FAIL (partially_verified)
```

`partially_verified` is expected in dev mode: every cryptographic field verifies, but there is no hardware attestation to bind them to. To pin the policy and catalog hashes, read them from the claim (`trace.policy.bundle_hash`, `gateway.catalog.hash`) and pass them explicitly:

```bash
cmcp verify claim.json \
  --policy-hash "$(python3 -c "import json; print(json.load(open('claim.json'))['trace']['policy']['bundle_hash'])")" \
  --catalog-hash "$(python3 -c "import json; print(json.load(open('claim.json'))['gateway']['catalog']['hash'])")"
```

On a real TEE host the `hardware_attestation` check passes and the overall result becomes `verified`.

The `cmcp_verify` Python library is also available for programmatic checks (`from cmcp_verify import verify_trace_claim, ApprovedHashes`).

---

## What's in the TRACE Claim

| Field | What it proves |
|---|---|
| `trace.runtime.platform` | Which TEE hardware produced the attestation report (`tpm2`, `amd-sev-snp`, etc.) |
| `trace.runtime.measurement` | PCR/measurement recorded by hardware at enclave boot - all zeros in dev mode |
| `trace.policy.bundle_hash` | SHA-256 of the Cedar policy bundle loaded at startup - changing any policy file changes this hash |
| `trace.policy.enforcement_mode` | Whether policy denies are hard (`enforcing`) or logged-only (`advisory`) |
| `trace.data_class` | Highest sensitivity level touched in the session (`pii` in this demo) |
| `trace.tool_transcript.hash` | SHA-256 of the audit chain tip - binds the call log to this Trust Record |
| `trace.tool_transcript.call_count` | Number of tool calls in the session |
| `trace.cnf.jwk` | Ed25519 public key used to sign this claim - bound to the TEE signing key |
| `gateway.audit_chain.root` / `.tip` | Hash-chained audit log root and tip - verifiable without replaying individual entries |
| `gateway.call_summary` | Per-session statistics: total, allowed, denied, faulted calls and tools invoked |
| `gateway.catalog.drift_detected` | `true` if any tool definition changed after catalog load - signals a rug-pull attempt |
| `signature` | Ed25519 signature over canonical JSON of the entire claim body (excluding `signature`) |

---

## Next steps

- **Full financial-services scenario**: see `examples/bfsi-demo/` for a multi-tool scenario with MNPI and PHI policies, cross-boundary events, and a KYC workflow.
- **Spec reference**: see `docs/SPEC.md` for the full product specification and `docs/spec/` for individual component specs.
- **Switch to enforcing mode**: set `enforcement_mode: enforcing` in `cmcp-config.yaml`. Policy denies will return HTTP 403 and the call will not be forwarded.
- **Hardware TEE**: remove `CMCP_DEV_MODE=1` on an Azure DCasv5 (SEV-SNP) or DCedsv5 (TDX) VM. The `trace.runtime.measurement` will reflect real hardware values and verification status becomes `verified`.
