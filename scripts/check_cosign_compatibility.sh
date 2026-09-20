#!/usr/bin/env bash
# Exercise the release CLI's default bundle/OCI format without public uploads.
set -euo pipefail

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
export COSIGN_PASSWORD=''

cosign version --json > version.json
python3 - <<'PY'
import json
import os
with open('version.json') as stream:
    assert json.load(stream)['gitVersion'] == os.environ['COSIGN_VERSION']
PY

# No base-image pull, application secrets, OIDC token or public registry writes.
printf 'FROM scratch\nCOPY payload /payload\n' > Dockerfile
printf 'signed fixture\n' > payload
docker build --quiet -t localhost:5000/cosign-smoke:signed .
docker push localhost:5000/cosign-smoke:signed
signed=$(docker inspect --format '{{index .RepoDigests 0}}' localhost:5000/cosign-smoke:signed)
printf 'different unsigned fixture\n' > payload
docker build --quiet -t localhost:5000/cosign-smoke:unsigned .
docker push localhost:5000/cosign-smoke:unsigned
unsigned=$(docker inspect --format '{{index .RepoDigests 0}}' localhost:5000/cosign-smoke:unsigned)
test "$signed" != "$unsigned"

cosign generate-key-pair --output-key-prefix signer
cosign generate-key-pair --output-key-prefix stranger
# Only the isolated fixture omits public transparency services. Release signing
# and verification retain their normal keyless identity and transparency checks.
cosign sign --yes --key signer.key --tlog-upload=false --use-signing-config=false "$signed"
cosign verify --key signer.pub --insecure-ignore-tlog "$signed" > verified.json
python3 - "$signed" <<'PY'
import json
import sys
with open('verified.json') as stream:
    signatures = json.load(stream)
assert signatures
assert all(s['critical']['image']['docker-manifest-digest'] == sys.argv[1].split('@')[1]
           for s in signatures)
PY
if cosign verify --key stranger.pub --insecure-ignore-tlog "$signed"; then
  echo 'ERROR: verification accepted the wrong public key' >&2
  exit 1
fi
if cosign verify --key signer.pub --insecure-ignore-tlog "$unsigned"; then
  echo 'ERROR: verification accepted an unsigned image digest' >&2
  exit 1
fi
echo 'PASS: image signature and digest verified; wrong key and unsigned digest rejected'
