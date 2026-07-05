# Attestation Specification

**Document status:** Draft v0.1\
**Applies to:** cMCP Runtime, all TEE providers\
**Related issues:** #5, #6, #23, #33, #38

______________________________________________________________________

## Overview

The cMCP Runtime produces TRACE Claims: signed, hardware-attested proof artifacts that allow a verifier to confirm that a specific set of MCP tool calls was evaluated against a specific policy bundle inside a verified TEE, without trusting the operator. This document is the authoritative specification for how attestation evidence is collected, how the audit chain is constructed, how freshness is enforced, how keys are managed, and how tool catalog integrity is maintained.

______________________________________________________________________

## Section 1 - Provider Detection

### 1.1 Auto-Detection Algorithm

At runtime startup, the process probes for TEE providers in the following fixed order. The first provider whose conditions are satisfied is selected. Only one provider is active per runtime instance.

```
probe_order = ["tpm", "sev-snp", "tdx"]
```

The `opaque` (OPAQUE managed-runtime) provider is a recognized but not-yet-implemented placeholder. It is intentionally excluded from `probe_order`, so it is never auto-selected. Selecting it explicitly (`attestation.provider: opaque`) raises `ATTESTATION_PROVIDER_NOT_IMPLEMENTED` rather than reporting itself as "not detected".

The detection loop:

```
for provider in probe_order:
    if detect(provider):
        active_provider = provider
        break
else:
    if DEVELOPMENT_MODE:
        active_provider = "software-only"
    else:
        FATAL: no TEE provider found, refusing to start
```

Production deployments must not start if no hardware TEE is available. The `DEVELOPMENT_MODE` flag (environment variable `CMCP_DEV_MODE=1`) enables the software-only fallback exclusively for local development and CI pipelines.

### 1.2 Per-Provider Detection Conditions

#### TPM (Medium Assurance)

Detection conditions (any of):

- `/dev/tpm0` exists and is readable by the runtime process, OR
- `/dev/tpmrm0` exists and is readable by the runtime process (resource manager interface), OR
- A vTPM device is detected via the TSS2 ESAPI device enumeration call `Esys_GetCapability(TPMS_CAPABILITY_DATA)` returning at least one TPM device handle.

What goes in `attestation_report.measurement`:

```
measurement = SHA-256(PCR0 || PCR1 || PCR2 || PCR3 || PCR4 || PCR5 || PCR6 || PCR7)
```

Each PCR value is the raw 32-byte SHA-256 digest read from the TPM. Concatenation is in bank index order (0 through 7), no separators. The result is a 32-byte SHA-256 digest encoded as lowercase hex. The PCR bank used is SHA-256. If the platform only offers a SHA-1 bank, the runtime logs a warning and uses SHA-1 PCR values zero-extended to 32 bytes before hashing; this is noted in `attestation_report.measurement_note: "sha1-bank-fallback"`.

Quote generation: the gateway calls `TPM2_Quote` with `qualifying_data` set to the first 32 bytes of the §3.3 nonce: the `JWK_thumbprint(tee_public_key)`: because TPM `qualifying_data` carries a single digest. A verifier re-derives the thumbprint from `cnf.jwk.x` and checks it against the quote's `qualifying_data`. The quote and its signature are stored in `attestation_report.raw_evidence` (base64-encoded) for verifier use.

#### SEV-SNP (High Assurance)

Detection conditions (all of):

- `/dev/sev-guest` exists and is readable by the runtime process, AND
- The processor vendor string (CPUID leaf 0) equals `"AuthenticAMD"`.

What goes in `attestation_report.measurement`:

```
measurement = SNP_REPORT.measurement
```

`SNP_REPORT.measurement` is the 48-byte launch measurement field from the AMD SEV-SNP attestation report, encoded as lowercase hex (96 characters). It is obtained by calling `ioctl(fd, SNP_GET_REPORT, &req)` on `/dev/sev-guest` with the 64-byte `report_data` field set to the §3.3 nonce (`JWK_thumbprint(tee_public_key) || random_salt`, which fills the field exactly).

The full SNP report structure is stored in `attestation_report.raw_evidence` (base64-encoded) for verifier use.

#### TDX (High Assurance)

Detection conditions (all of):

- `/dev/tdx-guest` exists and is readable by the runtime process, AND
- The processor vendor string (CPUID leaf 0) equals `"GenuineIntel"`.

What goes in `attestation_report.measurement`:

```
measurement = {
  "mrtd": TDREPORT.TDINFO.MRTD,
  "rtmr0": TDREPORT.TDINFO.RTMR[0],
  "rtmr1": TDREPORT.TDINFO.RTMR[1],
  "rtmr2": TDREPORT.TDINFO.RTMR[2],
  "rtmr3": TDREPORT.TDINFO.RTMR[3]
}
```

Each value is a 48-byte SHA-384 digest encoded as lowercase hex (96 characters). `MRTD` is the measurement of the initial TD contents. `RTMR0`-`RTMR3` are the runtime measurement registers. The TD report is obtained via `ioctl(fd, TDX_CMD_GET_REPORT0, &req)` with the 64-byte `reportdata` set to the §3.3 nonce (`JWK_thumbprint(tee_public_key) || random_salt`, which fills the field exactly).

The full TD report and quote are stored in `attestation_report.raw_evidence` for verifier use.

#### OPAQUE (Highest Assurance)

> **Not yet implemented.** This subsection describes the intended design. The current `OpaqueProvider` is a placeholder: it is excluded from auto-detect and raises `ATTESTATION_PROVIDER_NOT_IMPLEMENTED` when selected explicitly. The conditions below are the planned detection behavior, not shipped behavior.

Detection conditions (planned):

- The environment variable `OPAQUE_RUNTIME_ENDPOINT` is set and non-empty.

What goes in `attestation_report.measurement`:

The OPAQUE Managed Runtime provides a dedicated attestation API. The runtime calls `GET $OPAQUE_RUNTIME_ENDPOINT/v1/attestation` with the §3.3 nonce (`JWK_thumbprint(tee_public_key) || random_salt`) as a query parameter. The response includes an OPAQUE-specific measurement blob and a signed attestation certificate chain rooted in OPAQUE's hardware root of trust. The measurement field is set to the `measurement` field from the OPAQUE attestation response (format defined by the OPAQUE Runtime SDK; currently a 32-byte SHA-256 encoded as lowercase hex). The full response is stored in `attestation_report.raw_evidence`.

### 1.3 Software-Only Development Fallback

When `CMCP_DEV_MODE=1` is set and no hardware TEE is detected:

```
{
  "attestation_report": {
    "provider": "software-only",
    "measurement": "DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION",
    "raw_evidence": null
  },
  "attestation_assurance": "none"
}
```

Rules:

- TRACE Claims with `attestation_assurance: "none"` must not be used for compliance purposes.
- The runtime logs a prominent warning at startup: `"WARNING: running in software-only mode. TRACE Claims have no hardware attestation and cannot be used for compliance."`.
- Signing still occurs (the ephemeral Ed25519 key is generated in normal process memory), but the signature only proves the claim was not tampered with after issuance -- it provides no hardware-backed assurance of the enclave's integrity.

______________________________________________________________________

## Section 2 - Audit Chain

### 2.1 Signing Key Generation

At enclave startup, before accepting any connections:

1. Generate an ephemeral Ed25519 keypair inside the TEE using a CSPRNG seeded from the hardware entropy source (TPM `TPM2_GetRandom`, SEV-SNP `RDRAND` + kernel `/dev/urandom` mix-in, TDX equivalent, or OPAQUE runtime entropy API).
1. The private key is held only in enclave memory (or equivalent protected region). It is never written to disk, never logged, never exported via any API.
1. The public key is encoded as a 32-byte Ed25519 public key in base64url (no padding). This value is placed in the `tee_public_key` field of every TRACE Claim issued by this runtime instance.
1. When the enclave exits (graceful shutdown or crash), the private key is zeroed from memory via a secure-erase routine before the memory region is released.

The attestation report's `report_data` (nonce) is bound to this key, ensuring the hardware-attested report and the signing key are cryptographically linked (see Section 3.3).

### 2.2 Audit Entry Format

Each MCP tool call interception produces one audit entry. The canonical format is:

```
{
  "entry_id": "<uuid-v4>",
  "timestamp_utc": "<ISO8601, e.g. 2025-09-15T14:23:01.452Z>",
  "call_id": "<uuid-v4, matches the MCP call correlation ID>",
  "tool_name": "<string, e.g. 'github_search_repos'>",
  "server_identity": "<string, SPIFFE ID or TLS fingerprint, e.g. 'spiffe://acme.example/mcp/github'>",
  "policy_decision": "<'allow' | 'deny' | 'redact'>",
  "policy_rule_matched": "<string, Cedar policy ID that matched, e.g. 'policy_id::allow_github_read'>",
  "payload_hash_sha256": "<lowercase hex, SHA-256 of canonical JSON of the tool call input>",
  "response_hash_sha256": "<lowercase hex, SHA-256 of canonical JSON of the tool response, or 'N/A' if denied before response>",
  "tool_drift_detected": false,
  "prev_entry_hash": "<lowercase hex, SHA-256 of previous entry, or 'GENESIS' for first entry>",
  "entry_hash": "<lowercase hex, SHA-256 of this entry minus the entry_hash field>"
}
```

Field notes:

- `policy_decision: "redact"` means the call was allowed but the response was partially redacted before forwarding to the agent. A separate audit entry is not created for the redacted fields; instead the `response_hash_sha256` is the hash of the post-redaction response.
- `tool_drift_detected: true` is set when the tool's live definition does not match the catalog's `approved_definition` (see Section 5.2). This field is omitted when false.
- Payload and response hashes use canonical JSON (RFC 8785) to ensure deterministic hashing regardless of key ordering or whitespace.

### 2.3 Hash Chaining Algorithm

```
canonical_entry = canonical_json(entry_without_entry_hash)
entry_hash = lowercase_hex(SHA-256(canonical_entry))
```

"Entry without entry_hash" means the entry object with the `entry_hash` key removed before serialization. The `prev_entry_hash` key is included in the canonical form.

For the first entry in a session:

```
prev_entry_hash = "GENESIS"
```

Chain invariants:

- `audit_chain_root` in the TRACE Claim = `entry_hash` of the first entry.
- `audit_chain_tip` in the TRACE Claim = `entry_hash` of the most recent entry at the time the TRACE Claim is generated.
- The chain is append-only. No entry may be modified or deleted after it is written.
- The chain lives entirely inside the enclave's memory (or encrypted persistent storage for long-running runtime instances). No external process can append to or modify the chain.

A verifier reconstructing the chain recomputes each `entry_hash` from the entry body and checks that each `prev_entry_hash` equals the `entry_hash` of the preceding entry, confirming append-only integrity across the full session.

### 2.4 Audit Log Export

Audit logs are exported as a signed bundle to prevent selective disclosure:

1. Verifier sends a signed API request to the runtime's export endpoint: `POST /v1/audit/export` with a body containing `{"session_id": "<uuid>", "verifier_nonce": "<base64url>"}`. The request must be signed with a verifier key whose public key is pre-configured in the runtime's policy bundle.
1. The runtime assembles the full ordered array of all audit entries for the session.
1. The runtime computes `bundle_hash = SHA-256(canonical_json(entries_array))`.
1. The runtime signs `bundle_hash || verifier_nonce` with the enclave's Ed25519 private key.
1. The response is:

```
{
  "session_id": "<uuid>",
  "entries": [],
  "bundle_hash": "<lowercase hex>",
  "verifier_nonce": "<base64url, echoed>",
  "signature": "<base64url, Ed25519 signature over SHA-256(bundle_hash_bytes || verifier_nonce_bytes)>"
}
```

The verifier:

1. Recomputes `bundle_hash` over the received `entries` array.
1. Verifies it matches the `bundle_hash` field.
1. Verifies the signature using the `tee_public_key` from the TRACE Claim.
1. Reconstructs the hash chain across all entries to confirm append-only integrity.

Partial exports are not supported. A verifier requesting a subset of entries receives a denial; they must request the full session log and filter locally.

______________________________________________________________________

## Section 3 - Attestation Freshness

### 3.1 Validity Window

The TRACE Claim includes:

```
{
  "attestation_generated_at": "2025-09-15T00:00:00Z",
  "attestation_validity_seconds": 86400
}
```

Default: `attestation_validity_seconds = 86400` (24 hours). Configurable via `cmcp-config.yaml`:

```
attestation:
  validity_seconds: 86400   # 24 hours, minimum 3600 (1 hour)
```

Verifier check:

```
now_utc - parse_iso8601(attestation_generated_at) < attestation_validity_seconds
```

If this check fails, the TRACE Claim is considered stale. Verifiers must reject stale claims for compliance purposes. They may log them for forensic review.

### 3.2 Refresh Procedure

Attestation refresh without service interruption:

1. While the enclave is running, call the TEE's attestation API again with a fresh timestamp and the same §3.3 nonce (`JWK_thumbprint(tee_public_key) || random_salt`).
1. Replace `attestation_report` in the runtime's in-memory state with the new report.
1. Update `attestation_generated_at` to the current UTC timestamp.
1. All subsequent TRACE Claims use the new `attestation_report` and new `attestation_generated_at`.
1. TRACE Claims already issued during the current session retain their original `attestation_generated_at`. They are valid for their own validity window and are not retroactively stale.
1. The signing key does not change during a refresh. The key is bound to the enclave instance, not the attestation report's timestamp.

Session duration constraint:

```
attestation:
  max_session_duration: 86400  # equals validity_seconds by default
```

Sessions cannot outlive the attestation. If a session reaches `max_session_duration`, the runtime closes it and requires the agent to reconnect. On reconnect, the agent receives a TRACE Claim with a fresh attestation.

### 3.3 Replay Prevention

The `attestation_report.report_data` field contains a 64-byte nonce that binds the hardware-generated report to the gateway's TEE key:

```
nonce = JWK_thumbprint(tee_public_key) (32 bytes) || random_salt (32 bytes)
```

- `JWK_thumbprint(tee_public_key)`: the RFC 7638 JWK Thumbprint of the Ed25519 public key: SHA-256 over the canonical JSON of the required OKP members in lexicographic order (`crv`, `kty`, `x`). This is re-derivable by any verifier from `cnf.jwk.x`.
- `random_salt`: 32 random bytes generated once per enclave startup, so two enclave instances produce distinct nonces even with the same key (e.g. blue-green deploy).
- The 64-byte value is passed as the `report_data` / `user_data` / `reportdata` / `qualifying_data` field when requesting the hardware attestation report. The field name varies by provider; the semantic is the same: a caller-supplied value included in the signed measurement.

Verifier check (key binding, CRYPTO-001):

```
expected_fingerprint = JWK_thumbprint(base64url_decode(cnf.jwk.x))
actual_nonce = base64url_decode(trace.runtime.nonce)
assert actual_nonce[:32] == expected_fingerprint
```

A TRACE Claim whose `cnf.jwk` public key was substituted after attestation fails this check, because the embedded `report_data` (hardware-signed) will not match the re-derived thumbprint. A claim produced by a different enclave instance carries a different key (and salt), so it fails too.

**Session binding** is carried separately, by `gateway.session_id` inside the Ed25519-signed claim body: not by the nonce. The hardware report is generated once per enclave instance at startup, before any session exists, so it cannot bind a specific `session_id`. Because the signature covers `session_id`, a claim cannot be presented under a different session without breaking verification. See §3.3.1.

#### 3.3.1 Session binding

The signed claim body includes `gateway.session_id`. Any change to it invalidates the Ed25519 signature, so a valid claim for session A cannot be replayed as session B. For the cross-organizational case (Phase 2), the gateway and server TEEs each produce a claim carrying the **same** `session_id`; the shared identifier links the two independently-signed, independently-key-bound claims.

______________________________________________________________________

## Section 4 - Key Management

### 4.1 Phase 1: Ephemeral Keys

In Phase 1, the runtime uses a single ephemeral Ed25519 keypair per enclave instance. Properties:

- Generated at enclave startup (see Section 2.1).
- Exists only in enclave memory. Never exported, never persisted.
- Destroyed (zeroed) when the enclave exits.
- No rotation policy needed: the key's lifetime equals the enclave's lifetime.

Verification of historical TRACE Claims: a verifier holds a TRACE Claim containing `tee_public_key`. They verify the claim's `signature` using that embedded public key. No external key registry is required. The embedded public key plus the hardware attestation report (which binds the key via the `report_data` nonce) together prove:

- The key was generated inside a specific TEE instance with a specific measurement.
- All TRACE Claims signed by that key were produced by that TEE instance.
- The operator never had access to the private key.

Because the public key is embedded in the claim and attested by the hardware report, there is no need for a separate key transparency log in Phase 1.

### 4.2 Phase 2: Persistent Keys (Future)

For use cases requiring long-lived keys (e.g., participation in a key transparency log, or runtime restarts without breaking verifier trust):

- At first startup, generate an Ed25519 keypair and seal the private key to the TEE's measurement using the TEE's sealing API (TPM `TPM2_Create` with a parent key bound to PCRs; SEV-SNP sealing via a policy-bound key; TDX sealing via TD-bound key derivation; OPAQUE sealing via OPAQUE's key management API).
- The sealed key blob is stored on disk. On restart, the enclave unseals the key. Unsealing succeeds only if the enclave's current measurement matches the measurement policy used when sealing.
- Rotation: updating the enclave's code or configuration changes its measurement. The old sealed key cannot be unsealed by the new measurement. The new enclave generates a fresh keypair and seals it to its own measurement. Old TRACE Claims remain verifiable via their embedded public key. New claims use the new key.
- A key rotation event should be logged in the operator's change management system.

### 4.3 Compromise Response

If an enclave instance is suspected to be compromised:

1. Shut down the enclave immediately. This destroys the in-memory private key (Phase 1) or leaves the sealed key on disk (Phase 2, sealed key should be deleted).
1. Invalidate all active sessions that were served by the compromised enclave.
1. TRACE Claims issued by the compromised enclave (identifiable by their `tee_public_key`) should be flagged in the incident log. They cannot be cryptographically revoked (the signature remains valid), but their provenance is suspect.
1. Verifiers should be notified of the compromised `tee_public_key` value so they can reject or quarantine claims bearing it.
1. Start a new enclave instance. The new instance generates a fresh keypair with a new measurement.
1. Conduct a post-incident review of all audit entries from the compromised enclave period using the signed bundle export mechanism (Section 2.4).

There is no online revocation mechanism for Phase 1 keys. Revocation is handled out-of-band via incident notification to verifiers.

______________________________________________________________________

## Section 5 - Tool Catalog Hash Pinning

### 5.1 Catalog Format

The tool catalog is a JSON document versioned in the repository alongside the runtime configuration. It defines the set of approved tools and their expected definitions.

Top-level structure:

```
{
  "catalog_version": "1",
  "updated_at": "2025-09-15T00:00:00Z",
  "entries": [
    {
      "tool_name": "github_search_repos",
      "server_identity": {
        "tls_fingerprint": "sha256//AbCdEf...",
        "spiffe_id": "spiffe://acme.example/mcp/github"
      },
      "approved_definition": {
        "description": "Search GitHub repositories by keyword.",
        "input_schema": {
          "type": "object",
          "properties": {
            "query": { "type": "string" },
            "max_results": { "type": "integer", "default": 10 }
          },
          "required": ["query"]
        },
        "output_schema": {
          "type": "array",
          "items": { "type": "object" }
        }
      },
      "definition_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```

`definition_hash` for each entry:

```
definition_hash = lowercase_hex(SHA-256(canonical_json(approved_definition)))
```

`canonical_json` uses RFC 8785 (sorted keys, no insignificant whitespace).

### 5.2 Catalog Hash Computation

The catalog hash that goes into `tool_catalog.hash` in the TRACE Claim:

```
sorted_entries = sort(entries, key=tool_name, order=lexicographic_ascending)
catalog_hash = lowercase_hex(SHA-256(canonical_json(sorted_entries)))
```

Only the `entries` array (sorted) is hashed, not the `catalog_version` or `updated_at` fields. This ensures the catalog hash is stable across metadata-only updates.

At enclave startup, the runtime:

1. Loads the catalog document from the configured path.
1. Computes `catalog_hash` as above.
1. Stores the hash in the enclave's immutable measurement context (or records it for inclusion in every TRACE Claim).
1. Builds an in-memory index: `{tool_name -> catalog_entry}` for O(1) lookup during call interception.

### 5.3 Delta Detection

When the runtime receives a `notifications/tools/list_changed` notification from an upstream MCP server:

```
procedure handle_tools_list_changed(server_identity):
    new_definitions = fetch tools/list from server_identity
    for each tool in new_definitions:
        catalog_entry = catalog_index.get(tool.name)
        if catalog_entry is None:
            // Unknown tool not in catalog
            action = DENY_UNKNOWN_TOOL
            emit_alert(tool.name, "tool_not_in_catalog")
            continue
        live_hash = SHA-256(canonical_json(tool.definition))
        if live_hash != catalog_entry.definition_hash:
            catalog_entry.status = DRIFTED
            emit_alert(tool.name, "tool_definition_drifted", {
                "expected_hash": catalog_entry.definition_hash,
                "live_hash": live_hash
            })
```

Drift handling modes (configurable per tool or globally):

**fail-closed (default):**

```
catalog:
  drift_mode: fail-closed
```

All calls to a drifted tool are denied. The policy decision is `deny` and `policy_rule_matched` is `"system::catalog_drift_failclosed"`. The audit entry includes `"tool_drift_detected": true`. The tool remains denied until the catalog is updated via the authorized procedure (Section 5.4) and the enclave is restarted.

**alert-only:**

```
catalog:
  drift_mode: alert
```

Calls to a drifted tool are allowed (subject to normal policy evaluation), but every audit entry for that tool includes `"tool_drift_detected": true`. An alert is emitted to the configured alerting channel. This mode is intended for observability during catalog rollout, not for production compliance use.

A tool that appears in `tools/list` from a server but is absent from the catalog is always denied regardless of `drift_mode`, because the catalog is the authoritative allowlist.

### 5.4 Catalog Update Procedure

The catalog does not support hot-reload in Phase 1. Updates require:

1. Edit the catalog document: add, modify, or remove `entries`.
1. Recompute `definition_hash` for any modified `approved_definition`.
1. Commit the updated catalog to version control. This creates an auditable record of who approved the change and when.
1. Compute the new `catalog_hash` locally and record it in the commit message or PR description for pre-deployment verification.
1. Deploy the new runtime configuration. This requires an enclave restart.
1. On restart, the new enclave measures the new catalog hash. Subsequent TRACE Claims will contain the new `tool_catalog.hash`.
1. Verify: after startup, call `GET /v1/status` which returns the active `catalog_hash`. Confirm it matches the expected value from step 4.

There is no partial catalog update. The entire catalog is replaced atomically at restart. This prevents a TOCTOU window between loading individual tool definitions.

______________________________________________________________________

## Appendix A - TRACE Claim Fields Reference

Full set of fields relevant to attestation:

```
{
  "trace_version": "1",
  "session_id": "<uuid-v4>",
  "timestamp_utc": "<ISO8601>",
  "tee_public_key": "<base64url Ed25519 public key>",
  "attestation_report": {
    "provider": "<'tpm' | 'sev-snp' | 'tdx' | 'opaque' | 'software-only'>",
    "measurement": "<provider-specific, see Section 1>",
    "report_data": "<base64url nonce = JWK_thumbprint(tee_public_key) || random_salt>",
    "raw_evidence": "<base64url, full hardware attestation report>"
  },
  "attestation_assurance": "<'medium' | 'high' | 'highest' | 'none'>",
  "attestation_generated_at": "<ISO8601>",
  "attestation_validity_seconds": 86400,
  "policy_bundle": {
    "hash": "<SHA-256 of policy bundle>",
    "enforcement_mode": "<'enforcing' | 'advisory' | 'silent'>",
    "policy_version": "<semver>"
  },
  "tool_catalog": {
    "hash": "<SHA-256 of sorted catalog entries>"
  },
  "call_summary": {
    "total": 42,
    "allowed": 39,
    "denied": 3,
    "tools_invoked": ["github_search_repos", "jira_create_issue"]
  },
  "audit_chain_root": "<entry_hash of first audit entry>",
  "audit_chain_tip": "<entry_hash of most recent audit entry>",
  "signature": "<base64url, Ed25519 signature over SHA-256(canonical_json(claim_without_signature))>"
}
```

`attestation_assurance` values by provider: `tpm` = `"medium"`, `sev-snp` = `"high"`, `tdx` = `"high"`, `opaque` = `"highest"`, `software-only` = `"none"`.

______________________________________________________________________

## Appendix B - Verifier Checklist

A relying party verifying a TRACE Claim must perform all of the following checks:

1. Parse and validate the JSON structure against the TRACE Claim schema.
1. Verify `signature`: compute `SHA-256(canonical_json(claim_without_signature))`, verify Ed25519 signature using `tee_public_key`.
1. Verify attestation freshness: `now - attestation_generated_at < attestation_validity_seconds`.
1. Verify key binding: `JWK_thumbprint(base64url_decode(cnf.jwk.x)) == base64url_decode(trace.runtime.nonce)[:32]`. Session linkage is checked separately via the signed `gateway.session_id` (§3.3.1).
1. Verify hardware report: validate `attestation_report.raw_evidence` using the provider's verification SDK (e.g., AMD SEV-SNP `snp-validate`, Intel TDX `tdx-attest`, TPM quote verification via TSS2). Confirm the report's `report_data` field matches the nonce from step 4.
1. Check `attestation_assurance` is acceptable for the use case (e.g., compliance use requires `"high"` or `"highest"`; reject `"none"`).
1. Verify `policy_bundle.hash` matches the policy bundle the verifier expects was in use.
1. Verify `tool_catalog.hash` matches the catalog version the verifier expects.
1. If auditing call detail: request the signed audit bundle (Section 2.4), verify its signature, reconstruct the hash chain, confirm `audit_chain_root` and `audit_chain_tip` match the TRACE Claim.

Failure of any check means the TRACE Claim must not be accepted for compliance purposes.
