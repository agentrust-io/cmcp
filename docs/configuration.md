# Configuration Reference

`cmcp-config.yaml` controls the gateway's attestation provider, policy enforcement behavior, network settings, and file paths. Environment variables override specific fields and control secrets that must not appear in config files.

## Full example

```yaml
# cmcp-config.yaml - annotated full example

attestation:
  # TEE provider. auto detects in order: tpm -> sev-snp -> tdx.
  # opaque requires explicit opt-in via OPAQUE_ATTESTATION_URL env var.
  # Use software-only only with CMCP_DEV_MODE=1.
  provider: auto

  # enforcing: policy denies block the tool call and return HTTP 403.
  # advisory: policy denies are logged but the call is forwarded.
  # silent: like advisory but without operational log lines. The hash-chained
  #   audit log still records every would-have-denied decision -- silent
  #   quiets logs, never the evidence.
  enforcement_mode: enforcing

  # How long (in seconds) an attestation report is considered fresh.
  # Default is 24 hours. When validity expires, the default behavior is
  # fail_closed: active sessions are terminated until re-attestation.
  validity_seconds: 86400

  # fail_closed (default): terminate sessions when attestation expires.
  # warn_only: allow sessions to continue; marks TRACE Claims as stale.
  staleness_policy: fail_closed

  # Optional. If set, the runtime verifies the TEE measurement matches
  # this value at startup and refuses to start if it does not.
  # Format: provider-specific (e.g., hex PCR values for TPM,
  # AMD measurement register hex for SEV-SNP).
  # expected_measurement: "sha256:..."

agent_manifest:
  # Optional signed Agent Manifest binding (#302). When set, the runtime
  # verifies the manifest issuer signature, checks that the authenticated
  # agent subject matches manifest.agent_id, and requires the manifest's
  # policy/catalog hashes to match the loaded runtime hashes before sessions
  # can be created.
  path: ./agent-manifest.json
  trust_anchor_path: ./manifest-public-key.json
  authenticated_subject: spiffe://factory.example/agent/material-movement/dev

# Path to the directory containing .cedar policy files and manifest.json.
# Must not contain '..' components. Relative paths are resolved from the
# working directory at startup.
policy_bundle_path: policy/

# Path to the JSON tool catalog file.
# Must not contain '..' components.
catalog_path: catalog.json

# Address and port the runtime listens on.
listen_addr: "0.0.0.0:8443"

# Maximum size of a tool response payload in bytes. Responses larger than
# this are rejected before entering the response inspector (FM-5 size check).
# Default is 2MB (2097152 bytes).
max_response_size_bytes: 2097152

# Interval in seconds between automatic policy bundle reloads.
# 0 (default) disables automatic reload. Changing the policy bundle
# without restarting the runtime invalidates the attestation measurement.
# This field exists for advisory/silent deployments only; do not use in
# enforcing mode without a full enclave restart.
policy_reload_interval_seconds: 0
```

## Field reference

### attestation

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | `auto` | TEE provider. Valid values: `auto`, `tpm`, `sev-snp`, `tdx`, `opaque`, `software-only`. `auto` detects in order: tpm then sev-snp then tdx. `opaque` requires `OPAQUE_ATTESTATION_URL` to be set. `software-only` requires `CMCP_DEV_MODE=1`. |
| `enforcement_mode` | string | `enforcing` | Policy enforcement mode. Valid values: `enforcing`, `advisory`, `silent`. |
| `validity_seconds` | integer | `86400` | Attestation report validity period in seconds. Must be a positive integer. At expiry, behavior is controlled by `staleness_policy`. |
| `staleness_policy` | string | `fail_closed` | Action when attestation validity expires. Valid values: `fail_closed` (terminate sessions), `warn_only` (allow sessions, mark claims as stale). |
| `expected_measurement` | string | none | Optional. Expected TEE measurement value. If set, the runtime verifies the hardware measurement matches this string at startup and exits with a non-zero status if it does not. |

### agent_manifest

All fields are optional as a group. If `path` is set, `trust_anchor_path` must also be set. When the block is configured, cMCP fails closed on manifest signature failure, subject mismatch, policy hash drift, or catalog hash drift.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | none | Path to the signed Agent Manifest JSON document. Path traversal (`..` components) is rejected. |
| `trust_anchor_path` | string | none | Path to a JSON trust anchor containing the issuer Ed25519 public key, either as `{ "key_id": "...", "public_key_base64url": "..." }` or `{ "keys": [...] }`. |
| `authenticated_subject` | string | none | SPIFFE URI for the authenticated agent subject. This must equal `manifest.agent_id`. In production this should come from the agent SVID/mTLS identity; the config field is the current runtime input for that subject. |

### top-level fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `policy_bundle_path` | string | `policy/` | Path to the Cedar policy bundle directory. Must contain `.cedar` files and a `manifest.json`. Path traversal (`..` components) is rejected. |
| `catalog_path` | string | `catalog.json` | Path to the JSON tool catalog. Path traversal (`..` components) is rejected. |
| `listen_addr` | string | `0.0.0.0:8443` | Address and port the gateway binds to. |
| `max_response_size_bytes` | integer | `2097152` | Maximum tool response size in bytes (2MB). Must be a positive integer. Responses exceeding this limit are rejected before inspection. |
| `policy_reload_interval_seconds` | integer | `0` | Interval in seconds between automatic Cedar bundle reloads. `0` disables automatic reload. See note in the full example above. |

## Environment variables

Environment variables control secrets and mode flags that must not appear in config files. They are read once at process startup; they cannot be changed at runtime.

| Variable | Description | Overrides |
|----------|-------------|-----------|
| `CMCP_DEV_MODE=1` | Enables software-only attestation. No hardware TEE required. TRACE Claims will show `partially_verified` status. Required when `provider` is `software-only`. | `attestation.provider` (forces software-only) |
| `CMCP_BEARER_TOKEN` | Optional bearer token for runtime HTTP auth. If set, all requests to the runtime must include `Authorization: Bearer <token>`. If unset, no bearer auth is enforced. | none |
| `OPAQUE_ATTESTATION_URL` | Enables the Opaque Managed Runtime provider. Must be set to the Opaque attestation service URL. Required when `provider` is `opaque` or `auto` on Opaque infrastructure. | enables `opaque` provider detection |
| `CMCP_POLICY_HASH` | SHA-256 hash of the approved policy bundle. Required in non-dev mode and checked by startup before Agent Manifest binding. The gateway fails closed at startup if this is unset and `CMCP_DEV_MODE` is not `1`. Format: `sha256:<hex>`. | none (startup policy integrity check) |
| `CMCP_CATALOG_HASH` | SHA-256 hash of the approved `catalog.json`. Required in non-dev mode. The gateway fails closed at startup if this is unset and `CMCP_DEV_MODE` is not `1`. Format: `sha256:<hex>`. | none (additional startup check) |

## Enforcement modes

| Mode | Behavior | Use case |
|------|----------|----------|
| `enforcing` | Policy denies block the tool call. The runtime returns HTTP 403 and a structured error to the agent. The call is not forwarded to the upstream server. | Production. Default for new deployments. |
| `advisory` | Policy denies are logged in the audit chain but the call is forwarded. The TRACE Claim records the deny. No tool call is blocked. | Policy testing, migration from existing runtime. Safe for first run with an untuned policy. |
| `silent` | Policy is evaluated, the call is forwarded, and **the audit chain still records every would-have-denied decision** (as `advisory_deny`, visible in the TRACE Claim's call summary). The only difference from `advisory` is that no operational log lines are emitted. Silent quiets logs, never the evidence. | Measuring policy impact before rollout without operational log noise. The tamper-evident record remains complete, so post-hoc review stays possible. |

### Silent-mode audit contract

`enforcing` is the default and must be configured explicitly to use any other mode. In `silent` mode, `PolicyEvaluator` suppresses application-level log lines for denied tool calls but still returns `would_have_denied=True` in the `PolicyDecision`. The proxy writes an `advisory_deny` entry into the hash-chained audit log for every call that would have been denied. The audit chain records evidence even in silent mode. Only operational logs are quiet; the tamper-evident record remains complete and available for post-hoc review.

## Minimal working config

```yaml
attestation:
  provider: auto
  enforcement_mode: enforcing
policy_bundle_path: policy/
catalog_path: catalog.json
```

With `CMCP_DEV_MODE=1` for local development:

```yaml
attestation:
  provider: auto
  enforcement_mode: advisory
policy_bundle_path: ./policies/
catalog_path: ./catalog.json
```

## Production hardening checklist

- Set `attestation.enforcement_mode` to `enforcing`. Advisory mode provides no blocking protection against policy violations.
- Set `CMCP_CATALOG_HASH` to the SHA-256 of the approved `catalog.json`. The gateway fails closed at startup if this is unset in non-dev mode, but setting it explicitly pins the approved catalog hash and prevents silent substitution.
- Configure `agent_manifest.path`, `agent_manifest.trust_anchor_path`, and `agent_manifest.authenticated_subject` for agents with signed manifests. The runtime will refuse to start if the signed manifest does not bind the authenticated agent subject to the loaded policy bundle and catalog hashes.
- Set `attestation.expected_measurement` to the expected TEE measurement for your deployment. Without this, a different binary could be deployed and would still produce valid attestation reports.
- Use a real TEE provider (`tpm`, `sev-snp`, `tdx`, or `opaque`), not `software-only`. Software-only mode does not provide a hardware root of trust and leaves threat classes T1 through T4 open.
- Rotate the TEE signing key by performing a full enclave restart on a regular schedule. The signing key is hardware-sealed per enclave instance; rotation requires restart.
