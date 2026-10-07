# Container signature verification

Each cMCP container image we release is digitally signed, so you can check that the
image you pulled is the one our release process built and that nobody changed it on the
way. This page is for anyone running the published gateway image. It gives the one
command that does the check.

The check uses cosign, an open-source tool for signing and verifying container images.
The release workflow pins cosign 3.0.6, so use that version. Check the image by its
digest (the `sha256:` fingerprint of the exact image contents), which cannot be moved to
point at a different image the way a tag can:

```sh
cosign verify \
  --certificate-identity 'https://github.com/agentrust-io/cmcp/.github/workflows/docker.yml@refs/tags/v0.5.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/agentrust-io/cmcp-gateway@sha256:REPLACE_WITH_IMAGE_DIGEST
```

Replace the example tag and digest with the release you are checking. The identity
must match the release workflow and tag exactly; do not use a wildcard identity, because
that would accept a signature from any workflow. The release workflow also runs this same
check right after it signs the image.

??? info "Technical detail: what our own tests cover"

    PR CI runs `scripts/check_cosign_compatibility.sh` against a temporary loopback
    registry using the same pinned CLI and its default bundle/OCI format. It verifies
    a signed image and rejects a wrong public key and a different unsigned digest.
    The fixture uses temporary keys and disables public transparency-log uploads;
    those exceptions apply only to the test. It does not test GitHub OIDC, Fulcio,
    Rekor or GHCR. The tag-only verification exercises the release identity and
    transparency checks. Compatibility with older cosign versions or other verifiers
    is not asserted.
