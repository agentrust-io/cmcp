# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/agentrust-io/cmcp/security/advisories/new). You will receive a confirmation within 2 business days and a triage decision within 5 business days.

## Response SLAs

| Severity | Definition | Fix Target |
|----------|------------|------------|
| Critical | Remote code execution, attestation bypass, signing key extraction, audit chain forgery | 30 days from confirmed report |
| High / Medium / Low | All other confirmed vulnerabilities | 90 days from confirmed report |

Timeline starts when the issue is confirmed as a valid vulnerability, not on initial receipt. We will communicate progress at least every 14 days during active remediation.

## Scope

The following components are in scope:

- **TEE attestation path**: measurement of policy bundle hash into hardware attestation report; attestation verification logic for TPM 2.0, AMD SEV-SNP, Intel TDX, and OPAQUE Managed Runtime providers
- **Signing key handling**: hardware-sealed key generation, storage, and use; any path by which a signing key could be extracted or used outside the enclave
- **Cedar policy enforcement**: correctness of allow/deny decisions; policy bundle loading and hash verification inside the enclave; enforcement mode handling
- **Audit chain**: integrity of TRACE claim output fields (`policy_bundle_hash`, `audit_chain_root`, `tee_public_key`); any path by which a valid audit entry could be forged or suppressed

## Out of Scope

The following are not eligible for a coordinated disclosure:

- Bugs in TEE firmware or hardware microcode (AMD, Intel, or cloud provider trust anchor issues): report those directly to the relevant vendor
- Vulnerabilities in the upstream Cedar policy language engine that are not specific to cMCP's integration: report those to the [Cedar project](https://github.com/cedar-policy/cedar)
- Theoretical weaknesses in TEE threat models that are already acknowledged in public literature
- Issues in third-party MCP tool implementations invoked through the gateway

If you are unsure whether an issue is in scope, report it anyway and we will triage.

## Credit

Reporters of confirmed, in-scope vulnerabilities will be acknowledged by name (or handle, if preferred) in the release notes of the fix. We will not publish details of the report without your consent. If you prefer to remain anonymous, say so in your advisory submission and we will honor that.
