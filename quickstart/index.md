# Quickstart - cMCP Runtime

From zero to first TRACE Claim in under 30 minutes. Uses `CMCP_DEV_MODE=1` so no hardware TEE is required.

______________________________________________________________________

## What you'll build

You'll run a cMCP Runtime that intercepts tool calls from a demo agent and enforces a Cedar policy bundle. You'll see the runtime do two things:

1. **Block** a call to a sensitive tool (`salesforce.contacts`). The gateway returns HTTP 403 and the call never reaches any upstream.
1. **Allow** a call to a non-sensitive tool (`echo`) and forward it to a small mock upstream.

At the end you close the session and get a signed TRACE Claim that records both calls, which policy decided each one, and the policy bundle hash measured at startup. You verify the claim without trusting the operator.

______________________________________________________________________

## Prerequisites

- Ubuntu 24.04 (or any Linux distro with Python 3.11+); macOS also works
- Python 3.11 or newer
- pip

Verify:

```
python3 --version   # Python 3.11.x or higher
pip --version
```

______________________________________________________________________

## Install

```
pip install cmcp-runtime
```

This installs:

- `cmcp` - the gateway CLI
- `cmcp_verify` - the Python library for verifying TRACE Claims (no separate CLI install needed)

______________________________________________________________________

## Configuration

Create a working directory for the demo:

```
mkdir cmcp-quickstart && cd cmcp-quickstart
mkdir policies
```

Write `cmcp-config.yaml`:

```
attestation:
  provider: auto
  enforcement_mode: enforcing
policy_bundle_path: ./policies/
catalog_path: ./catalog.json
audit_db_path: ./audit.db
```

- `provider: auto` detects a hardware TEE if present; falls back to software-only when `CMCP_DEV_MODE=1`
- `enforcement_mode: enforcing` means a policy deny returns HTTP 403 and the call is not forwarded. Use `advisory` instead if you want denies logged but not blocked while you tune a new policy.
- `policy_bundle_path` is the directory containing `.cedar` policy files and `manifest.json`
- `catalog_path` is the JSON file listing approved tools

______________________________________________________________________

## Cedar policy

Write `policies/manifest.json`:

```
{
  "version": "0.1.0",
  "authored_at": "2026-06-05T00:00:00Z",
  "author_identity": "developer@example.com",
  "commit_sha": "quickstart-demo"
}
```

Write `policies/demo.cedar`:

```
// Rule 1: permit calls from the demo-agent workflow.
permit (
  principal,
  action,
  resource
) when {
  context.workflow_id == "demo-agent"
};

// Rule 2: block the sensitive tool by resource name. forbid overrides permit,
// so this call is denied at the gateway and never reaches any upstream.
forbid (
  principal,
  action,
  resource == Resource::"salesforce.contacts"
);
```

The gateway builds the Cedar `resource` from the tool name, so `resource == Resource::"salesforce.contacts"` matches a call to that tool. Cedar evaluates `forbid` before `permit`, so rule 2 wins when both match. Rule 1 scopes everything else to the `demo-agent` workflow.

Write `policies/schema.cedarschema` (one line):

```
{"cMCP":{"entityTypes":{"Principal":{"memberOfTypes":[],"shape":{"type":"Record","attributes":{"session_id":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}},"Resource":{"memberOfTypes":[],"shape":{"type":"Record","attributes":{"tool_name":{"type":"String","required":true}}}}},"actions":{"call_tool":{"appliesTo":{"principalTypes":["cMCP::Principal"],"resourceTypes":["cMCP::Resource"],"context":{"type":"Record","attributes":{"session_max_sensitivity":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}}}}}}
```

______________________________________________________________________

## Catalog

Write `catalog.json`. It lists two tools: `salesforce.contacts` (sensitive, the policy blocks it) and `echo` (non-sensitive, the policy allows it). Both point at the mock upstream you start below.

The `definition_hash` is the SHA-256 of the canonical JSON of `approved_definition` (sorted keys, no whitespace, ASCII-safe). The values below are precomputed to match.

```
[
  {
    "tool_name": "salesforce.contacts",
    "server": {
      "display_name": "Salesforce Contacts MCP Server (mock)",
      "url": "http://localhost:9001/mcp",
      "tls_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "transport": "http-sse"
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
  },
  {
    "tool_name": "echo",
    "server": {
      "display_name": "Echo MCP Server (mock)",
      "url": "http://localhost:9001/mcp",
      "tls_fingerprint": "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
      "transport": "http-sse"
    },
    "approved_definition": {
      "description": "Returns its input unchanged. For testing only.",
      "input_schema": {"type": "object", "properties": {"message": {"type": "string"}}},
      "output_schema": {"type": "object", "properties": {"message": {"type": "string"}}}
    },
    "definition_hash": "sha256:130436578985268754fd1925a01a7a12e2f94bcfd439f4f43050f816f866e8d6",
    "compliance_domain": "public",
    "requires_baa": false,
    "sensitivity_level": "public",
    "added_at": "2026-06-05T00:00:00Z",
    "approved_by": "developer@example.com"
  }
]
```

The `tls_fingerprint` values above are placeholders (they only need to match the `SHA256:<base64>` format for the demo). If you change any field in an `approved_definition`, recompute its `definition_hash`; the runtime rejects catalog entries where the hash does not match:

```
python3 -c "
import json, hashlib
d = {
  'description': 'Returns its input unchanged. For testing only.',
  'input_schema': {'type': 'object', 'properties': {'message': {'type': 'string'}}},
  'output_schema': {'type': 'object', 'properties': {'message': {'type': 'string'}}}
}
s = json.dumps(d, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
print('sha256:' + hashlib.sha256(s.encode()).hexdigest())
"
```

______________________________________________________________________

## Confirm your setup

Before starting the gateway, check that the config, policy bundle, and catalog all parse:

```
cmcp validate-config --config cmcp-config.yaml
```

If this reports an error, fix it now. It is easier to read here than mixed into the startup logs.

______________________________________________________________________

## Start the runtime

```
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml
```

In dev mode the runtime uses a software-only TEE provider (no hardware required). You will see a few informational warnings before it starts listening. These are expected in dev mode and do not mean anything is broken:

```
No hardware TEE detected. Running in development mode: attestation is not hardware-backed. ...
SPIFFE SVID not available (SPIRE agent socket not found ...) - gateway will use self-signed TLS for mTLS
CMCP_NRAS_API_KEY is not set -- skipping NRAS post-attestation appraisal. ...
cMCP Runtime starting: TEE: software-only, listen: 0.0.0.0:8443
INFO:     Uvicorn running on http://0.0.0.0:8443 (Press CTRL+C to quit)
```

The gateway now holds this terminal open. Leave it running and open a **second terminal** for the next steps. In that second terminal, `cd` back into `cmcp-quickstart` (and re-activate your Python environment if you use one) so the commands run from the right place.

______________________________________________________________________

## Make a blocked call

In the second terminal, call the sensitive tool. The policy forbids it, so the gateway denies it before contacting any upstream:

```
curl -i -X POST http://localhost:8443/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "salesforce.contacts",
      "arguments": {"query": "Acme Corp", "max_records": 10},
      "_cmcp": {"session_id": "demo-session-001", "workflow_id": "demo-agent"}
    }
  }'
```

You get back `HTTP/1.1 403 Forbidden` and a JSON-RPC error:

```
{"jsonrpc": "2.0", "error": {"code": -32000, "message": "Request denied by policy", "data": {"error_code": "POLICY_DENY", "call_id": "..."}}, "id": 1}
```

This is the point of the gateway: the sensitive call was stopped at the policy boundary. No upstream needed to be running for this to work.

______________________________________________________________________

## Make an allowed call

Now the `echo` tool, which the policy permits. For an allowed call the gateway forwards to the upstream, so start a small mock upstream first.

If you cloned the repo, run the bundled one:

```
python3 scripts/mock_upstream.py --port 9001
```

If you only installed the package, write a compact mock into a file and run it:

```
cat > mock_upstream.py <<'PY'
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        msg = json.loads(self.rfile.read(n) or b"{}")
        body = json.dumps({"jsonrpc": "2.0", "id": msg.get("id"),
                           "result": {"content": [{"type": "text", "text": "mock response"}]}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

print("mock upstream listening on :9001", flush=True)
HTTPServer(("0.0.0.0", 9001), H).serve_forever()
PY
python3 mock_upstream.py
```

The mock holds its terminal open too, so run it in a **third terminal** (or background it). Then, back in the second terminal, make the allowed call:

```
curl -i -X POST http://localhost:8443/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "echo",
      "arguments": {"message": "hello"},
      "_cmcp": {"session_id": "demo-session-001", "workflow_id": "demo-agent"}
    }
  }'
```

You get `HTTP/1.1 200 OK` and the mock's response. The policy permitted the call (rule 1 matched on `workflow_id`), the gateway recorded an audit entry, and forwarded to the upstream.

______________________________________________________________________

## Get the TRACE Claim

The TRACE Claim is finalized and signed when the session is **closed**. Closing takes the session's internal id (a UUID), not the `_cmcp.session_id` label (`demo-session-001`) you sent with the call. Read that id from the audit export, then close the session:

```
# 1. Look up the session's internal id
SESSION_UUID=$(curl -s "http://localhost:8443/audit/export?session_id=demo-session-001" \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['entries'][0]['session_id'])")

# 2. Close the session; this returns the signed TRACE Claim
curl -s -X POST "http://localhost:8443/sessions/$SESSION_UUID/close" \
  | python3 -m json.tool > claim.json
```

The closed session's claim stays available at `GET /sessions/$SESSION_UUID/trace-claim`.

The `gateway.call_summary` in `claim.json` records both calls:

```
"call_summary": {
  "tool_calls_total": 2,
  "tool_calls_allowed": 1,
  "tool_calls_denied": 1,
  "tools_invoked": ["echo", "salesforce.contacts"]
}
```

______________________________________________________________________

## Verify

Verify the claim with the bundled `cmcp verify` command - no code required. It checks the Ed25519 signature, schema, attestation freshness, and audit-chain consistency without trusting the runtime operator:

```
cmcp verify claim.json
```

Expected output in dev mode:

```
[cmcp verify] schema                   PASS
[cmcp verify] signature                PASS
[cmcp verify] policy_bundle.hash       PASS  (not pinned - pass --policy-hash to pin)
[cmcp verify] tool_catalog.hash        PASS  (not pinned - pass --catalog-hash to pin)
[cmcp verify] attestation_freshness    PASS
[cmcp verify] audit_chain              PASS
[cmcp verify] hardware_attestation     FAIL  software-only mode - not hardware-backed
[cmcp verify] RESULT: FAIL (partially_verified)
```

`partially_verified` is expected in dev mode: every cryptographic field verifies, but there is no hardware attestation to bind them to. To pin the policy and catalog hashes, read them from the claim and pass them explicitly:

```
cmcp verify claim.json \
  --policy-hash "$(python3 -c "import json; print(json.load(open('claim.json'))['trace']['policy']['bundle_hash'])")" \
  --catalog-hash "$(python3 -c "import json; print(json.load(open('claim.json'))['gateway']['catalog']['hash'])")"
```

On a real TEE host the `hardware_attestation` check passes and the overall result becomes `verified`.

The `cmcp_verify` Python library is also available for programmatic checks (`from cmcp_verify import verify_trace_claim, ApprovedHashes`).

______________________________________________________________________

## What's in the TRACE Claim

| Field                               | What it proves                                                                                    |
| ----------------------------------- | ------------------------------------------------------------------------------------------------- |
| `trace.runtime.platform`            | Which TEE hardware produced the attestation report (`tpm2`, `amd-sev-snp`, etc.)                  |
| `trace.runtime.measurement`         | PCR/measurement recorded by hardware at enclave boot - all zeros in dev mode                      |
| `trace.policy.bundle_hash`          | SHA-256 of the Cedar policy bundle loaded at startup - changing any policy file changes this hash |
| `trace.policy.enforcement_mode`     | Whether policy denies are hard (`enforcing`) or logged-only (`advisory`)                          |
| `trace.data_class`                  | Highest sensitivity level touched in the session                                                  |
| `trace.tool_transcript.hash`        | SHA-256 of the audit chain tip - binds the call log to this Trust Record                          |
| `trace.tool_transcript.call_count`  | Number of tool calls in the session                                                               |
| `trace.cnf.jwk`                     | Ed25519 public key used to sign this claim - bound to the TEE signing key                         |
| `gateway.audit_chain.root` / `.tip` | Hash-chained audit log root and tip - verifiable without replaying individual entries             |
| `gateway.call_summary`              | Per-session statistics: total, allowed, denied, faulted calls and tools invoked                   |
| `gateway.catalog.drift_detected`    | `true` if any tool definition changed after catalog load - signals a rug-pull attempt             |
| `signature`                         | Ed25519 signature over canonical JSON of the entire claim body (excluding `signature`)            |

______________________________________________________________________

## Next steps

- **Full financial-services scenario**: see `examples/bfsi-demo/` for a multi-tool scenario with MNPI and PHI policies, cross-boundary events, and a KYC workflow.
- **Spec reference**: see `docs/SPEC.md` for the full product specification and `docs/spec/` for individual component specs.
- **Advisory mode**: set `enforcement_mode: advisory` in `cmcp-config.yaml`. Policy denies are logged and flagged in the claim (`would_have_denied`) but the call is still forwarded - useful while tuning a new policy.
- **Hardware TEE**: remove `CMCP_DEV_MODE=1` on an Azure DCasv5 (SEV-SNP) or DCedsv5 (TDX) VM. The `trace.runtime.measurement` will reflect real hardware values and verification status becomes `verified`.
