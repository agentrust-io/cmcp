# BFSI Demo : cMCP Gateway

Demonstrates a financial services governance scenario: an agent calls financial tools, the gateway enforces Cedar policies, and produces a TRACE Claim an auditor can verify.

## Scenario

An agent calls two tools:
1. `crm.query` : queries PII-tagged customer records
2. `kyc.verify` : runs KYC verification (confidential sensitivity)

Three Cedar policies enforce:
1. All approved catalog tools are allowed by default
2. After any MNPI data enters the session, `communication.send` is blocked
3. After PHI data enters the session, calls to non-BAA-covered services are blocked

## Run it

```bash
# Start in dev mode (no hardware TEE required)
CMCP_DEV_MODE=1 cmcp start --config examples/bfsi-demo/cmcp-config.yaml
```

After the gateway starts, call a tool using any MCP client pointing to `http://localhost:8443`.

## Verify the TRACE Claim

```python
from cmcp_verify import verify_trace_claim, ApprovedHashes
import json

claim = json.load(open("trace-claim.json"))
approved = ApprovedHashes(
    policy_bundle_hash="sha256:<hash from startup log>",
    tool_catalog_hash="sha256:<hash from startup log>",
)
result = verify_trace_claim(claim, approved)
print(f"Status: {result.status.value}")
print(f"Verified: {result.verified_fields}")
```

## Notes

- Replace `tls_fingerprint` values in `catalog.json` with real fingerprints from your mock servers
- The gateway verifies upstream server identity before forwarding any call
- In production, set `CMCP_POLICY_HASH` and `CMCP_CATALOG_HASH` to the expected hashes
