# Container signature verification

The Docker release workflow pins cosign 3.0.6 for signing and verification. Use
that version to verify the image by its immutable digest:

```sh
cosign verify \
  --certificate-identity 'https://github.com/agentrust-io/cmcp/.github/workflows/docker.yml@refs/tags/v0.5.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/agentrust-io/cmcp-gateway@sha256:REPLACE_WITH_IMAGE_DIGEST
```

Replace the example tag and digest with the release being checked. The identity
must match the release workflow and tag; do not use a wildcard identity. The tag
workflow also runs this verification after signing.

PR CI runs `scripts/check_cosign_compatibility.sh` against a temporary loopback
registry using the same pinned CLI and its default bundle/OCI format. It verifies
a signed image and rejects a wrong public key and a different unsigned digest.
The fixture uses temporary keys and disables public transparency-log uploads;
those exceptions apply only to the test. It does not test GitHub OIDC, Fulcio,
Rekor or GHCR. The tag-only verification exercises the release identity and
transparency checks. Compatibility with older cosign versions or other verifiers
is not asserted.
