# Agent Manifest / cMCP Catalog Authority Bridge (v1)

## Purpose and trust boundary

The Agent Manifest SDK verifies a Merkle root of its tool entries. cMCP independently hashes its complete approved catalog as canonical JSON. These are **different measurements**. Never substitute one for the other or insert custom fields into the Agent Manifest schema.

When both `agent_manifest.catalog_bridge_path` and `agent_manifest.catalog_bridge_trust_anchor_path` are configured, startup additionally requires a signed catalog authority receipt. Without those optional settings, upstream native Agent Manifest tool binding remains mandatory. The bridge is **not** hardware attestation. It is an operator-issued software signature binding the Agent Manifest, approved catalog, policy and tool Merkle root. The Agent Manifest signature and SDK validation remain mandatory. The bridge is not a substitute for those checks.

## Deployment sequence

1. Validate and freeze the approved cMCP catalog and policy bundle. Record the exact cMCP runtime catalog hash and policy bundle hash.
2. Translate the approved tools using upstream `cmcp_runtime.manifest_catalog.manifest_catalog_binding(catalog)`. This binds tool IDs, RFC 8785-canonicalized input schemas, and UTF-8 descriptions. **Do not** use the cMCP catalog hash as the Agent Manifest Merkle root.
3. Issue an Agent Manifest with exactly those tool entries and the calculated Merkle root. Sign it with the Agent Manifest issuer key using the supported Agent Manifest signing procedure; verify it independently with the installed SDK.
4. Using a **separate authorized bridge issuer key**, construct a receipt payload with the exact fields `version` (integer `1`), `manifest_id`, `manifest_digest`, `agent_id`, `policy_hash`, `runtime_catalog_hash`, `manifest_catalog_root`, `not_before`, `expires_at`, and `key_id`. All digest values use lowercase `sha256:` plus 64 hexadecimal digits; `key_id` is the SHA-256 hex fingerprint of the trusted 32-byte Ed25519 public key. The `manifest_digest` is SHA-256 of the signed Agent Manifest canonical signing preimage for JSON manifests, or of the COSE envelope bytes for COSE manifests, as read by cMCP.
5. Sign this payload with `sign_bridge(payload, issuer_private_key)` in a controlled issuance environment. This emits `{"payload": ..., "signature": "<base64url-no-padding>"}`. Do **not** store the private signing key on the gateway. Write the receipt as JSON and provision its public key in the same trust-anchor JSON format accepted by `load_agent_manifest_trust_anchor`.
6. Optionally add the bridge settings alongside existing `agent_manifest.path`, `agent_manifest.trust_anchor_path`, and `agent_manifest.authenticated_subject`:

```yaml
agent_manifest:
  path: /etc/cmcp/agent-manifest.json
  trust_anchor_path: /etc/cmcp/agent-manifest-issuer.json
  authenticated_subject: spiffe://example/agent/production
  catalog_bridge_path: /etc/cmcp/catalog-authority-receipt.json
  catalog_bridge_trust_anchor_path: /etc/cmcp/catalog-authority-issuer.json
  revocation_list_path: /etc/cmcp/manifest-revocations.jsonl
```

7. Restart in a staging environment and verify both acceptance of the exact approved configuration and fail-closed behavior when any measured artifact is modified. When a bridge is configured, treat missing or invalid receipts as deployment failures, not warnings.

## Rotation and recovery

Rotate the manifest, policy or catalog by generating a new manifest **and** a newly signed bridge receipt from the new frozen measurements. Deploy the corresponding trust anchors atomically with the receipts. To revoke a bridge signing key, remove its public key from the gateway trust-anchor file and restart; old receipts must then fail. Maintain the Agent Manifest revocation list separately: it does not revoke bridge keys. Keep prior signed artifacts in a restricted audit archive, not in the active configuration.

A receipt expires at `expires_at` and cannot be used before `not_before`. There is no remote revocation lookup or online freshness guarantee. Gateway startup checks the local clock, not an independently attested clock; operational controls must protect time synchronization and trusted configuration paths. The current bridge trust-anchor format and startup checks are software-based, not hardware-backed attestation.

## Limitations and assurance evidence

The deterministic mapping binds tool identity, description and input/output schemas. The full cMCP runtime catalog hash separately binds additional catalog metadata, including server configuration. The bridge is a correspondence claim between two *different* hash domains, not proof that a server actually runs the approved implementation. Existing runtime discovery and drift controls remain necessary.

Security validation includes receipt-signature tampering, signer substitution, stale receipts, malformed payloads, catalog changes, policy changes, and Agent Manifest substitutions. Before production use, run the full unit and integration suites and review signing-preimage/COSE compatibility against the installed SDK version. Never label a software-only deployment as TEE/TPM-attested.
