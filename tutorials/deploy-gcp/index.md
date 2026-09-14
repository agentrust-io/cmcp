# Deploy on GCP Confidential VMs

Run cMCP on Google Cloud infrastructure with Intel TDX so TRACE claims carry hardware-backed measurements.

## What you'll learn

- Which GCP machine types give you Intel TDX
- How to provision a Confidential VM with the gcloud CLI
- How to install and configure cMCP for TDX
- What to verify in the TRACE claim to confirm hardware attestation is live

## Prerequisites

- Google Cloud SDK installed and authenticated (`gcloud auth login`)
- A GCP project with Confidential Computing API enabled
- A GCP project with billing enabled and Confidential VM quota

Enable the required APIs:

```
gcloud services enable compute.googleapis.com \
  confidentialcomputing.googleapis.com
```

______________________________________________________________________

## Choose your hardware

GCP Confidential VMs offer two TEE types:

| TEE type         | GCP machine type                           | `provider` value | Notes                                  |
| ---------------- | ------------------------------------------ | ---------------- | -------------------------------------- |
| Intel TDX        | C3 (`c3-standard-*`, `c3-highmem-*`)       | `tdx`            | Supported in select zones              |
| AMD SEV-SNP      | N2D (`n2d-standard-*`)                     | `sev-snp`        | Wider zone availability                |
| AMD SEV (legacy) | N2D with `--confidential-compute-type=SEV` | `tpm` (vTPM)     | Use SEV-SNP or TDX for new deployments |

C3 with TDX is the recommended path for highest assurance on GCP. N2D with SEV-SNP is more widely available by zone.

Check which zones support C3 + TDX in your project:

```
gcloud compute zones list --filter="name~us-central1" --format="table(name,status)"
```

______________________________________________________________________

## Provision the VM

### Intel TDX (C3)

```
PROJECT_ID=$(gcloud config get-value project)
ZONE=us-central1-a

gcloud compute instances create cmcp-gateway \
  --project=$PROJECT_ID \
  --zone=$ZONE \
  --machine-type=c3-standard-4 \
  --confidential-compute-type=TDX \
  --on-host-maintenance=TERMINATE \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB \
  --shielded-secure-boot \
  --shielded-vtpm \
  --shielded-integrity-monitoring \
  --tags=cmcp-gateway
```

### AMD SEV-SNP (N2D)

```
gcloud compute instances create cmcp-gateway \
  --project=$PROJECT_ID \
  --zone=$ZONE \
  --machine-type=n2d-standard-4 \
  --confidential-compute-type=SEV_SNP \
  --on-host-maintenance=TERMINATE \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB \
  --shielded-secure-boot \
  --shielded-vtpm \
  --tags=cmcp-gateway
```

### Open the gateway port

```
gcloud compute firewall-rules create allow-cmcp \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:8443 \
  --target-tags=cmcp-gateway \
  --source-ranges=0.0.0.0/0
```

Get the external IP:

```
gcloud compute instances describe cmcp-gateway \
  --zone=$ZONE \
  --format="get(networkInterfaces[0].accessConfigs[0].natIP)"
```

______________________________________________________________________

## Install cMCP on the VM

```
VM_IP=$(gcloud compute instances describe cmcp-gateway \
  --zone=$ZONE \
  --format="get(networkInterfaces[0].accessConfigs[0].natIP)")

gcloud compute ssh azureuser@cmcp-gateway --zone=$ZONE

# On the VM:
sudo apt-get update -qq && sudo apt-get install -y python3-pip
pip install cmcp-runtime
cmcp --version
```

______________________________________________________________________

## Configure for TDX

Confirm the hardware is accessible. On a GCP TDX VM the TDX RTMR (Runtime Measurement Register) device is available:

```
ls /dev/tdx_guest 2>/dev/null && echo "TDX present" || echo "TDX not found"
```

If `tdx_guest` is absent, verify the instance was created with `--confidential-compute-type=TDX` and the zone supports TDX.

Create the working directory:

```
mkdir ~/cmcp-deploy && cd ~/cmcp-deploy
mkdir policies
```

`cmcp-config.yaml`:

```
attestation:
  provider: tdx
  enforcement_mode: enforcing
  validity_seconds: 86400
  staleness_policy: fail_closed

policy_bundle_path: ./policies/
catalog_path: ./catalog.json
listen_addr: "0.0.0.0:8443"
```

For SEV-SNP, change `provider: tdx` to `provider: sev-snp`.

Add a minimal policy bundle:

```
cat > policies/manifest.json <<'EOF'
{
  "version": "0.1.0",
  "authored_at": "2026-01-01T00:00:00Z",
  "author_identity": "ops@example.com",
  "commit_sha": "initial"
}
EOF

cat > policies/allow-all.cedar <<'EOF'
permit (principal, action, resource);
EOF

cat > policies/schema.cedarschema <<'EOF'
{"cMCP":{"entityTypes":{"Principal":{"memberOfTypes":[],"shape":{"type":"Record","attributes":{"session_id":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}},"Resource":{"memberOfTypes":[],"shape":{"type":"Record","attributes":{"tool_name":{"type":"String","required":true}}}}},"actions":{"call_tool":{"appliesTo":{"principalTypes":["cMCP::Principal"],"resourceTypes":["cMCP::Resource"],"context":{"type":"Record","attributes":{"session_max_sensitivity":{"type":"String","required":true},"workflow_id":{"type":"String","required":true}}}}}}}}
EOF

cat > catalog.json <<'EOF'
[]
EOF
```

______________________________________________________________________

## Start the gateway

```
export CMCP_BEARER_TOKEN="$(openssl rand -hex 32)"
echo "Bearer token: $CMCP_BEARER_TOKEN"  # save this

cmcp start --config cmcp-config.yaml
```

Expected startup log on a real TDX VM:

```
cMCP Runtime starting: TEE: tdx, listen: 0.0.0.0:8443
```

The TEE field reads `tdx`. If it reads `software-only`, the TDX device was not found: confirm the instance type and that `/dev/tdx_guest` exists.

______________________________________________________________________

## Verify hardware attestation

From your local machine:

```
VM_IP=<external IP from above>

# Retrieve a TRACE claim
curl -s -H "Authorization: Bearer $CMCP_BEARER_TOKEN" \
  http://$VM_IP:8443/session/test-session/claim \
  | python3 -m json.tool > claim.json

# Verify
python3 - <<'EOF'
import json
from cmcp_verify import verify_trace_claim, ApprovedHashes

with open("claim.json") as f:
    claim = json.load(f)

approved = ApprovedHashes(
    policy_bundle_hash="sha256:<bundle_hash from startup log>",
    tool_catalog_hash="sha256:<catalog_hash from startup log>",
)

result = verify_trace_claim(claim, approved)
print(f"Status:          {result.status.value}")
print(f"Platform:        {claim['trace']['runtime']['platform']}")
print(f"Measurement:     {claim['trace']['runtime']['measurement']}")
print(f"Verified fields: {result.verified_fields}")
EOF
```

Expected output on a real TDX VM:

```
Status:          verified
Platform:        intel-tdx
Measurement:     sha384:<non-zero hardware measurement>
Verified fields: ['schema', 'signature', 'policy_bundle.hash', 'tool_catalog.hash', 'attestation_freshness', 'audit_chain', 'hardware_attestation']
```

`hardware_attestation` in `verified_fields` confirms the measurement is hardware-backed.

______________________________________________________________________

## Pin the expected measurement

After confirming the measurement on a known-good deploy:

```
attestation:
  provider: tdx
  enforcement_mode: enforcing
  expected_measurement: "sha384:<measurement from claim>"
```

Any change to the cMCP binary or startup config produces a different measurement. The gateway exits at startup if the measurement does not match, rather than producing claims with an unknown value.

______________________________________________________________________

## Tear down

```
gcloud compute instances delete cmcp-gateway --zone=$ZONE --quiet
gcloud compute firewall-rules delete allow-cmcp --quiet
```

______________________________________________________________________

## Next steps

- [Azure deployment](https://cmcp.agentrust-io.com/tutorials/deploy-azure/index.md): AMD SEV-SNP and TDX on Azure DCasv5 / DCedsv5
- [TEE attestation](https://cmcp.agentrust-io.com/tutorials/tee-attestation/index.md): detailed explanation of what each provider proves
- [Verify a TRACE claim](https://cmcp.agentrust-io.com/tutorials/verifying-a-trace-claim/index.md): full verification protocol
- [Multi-tenant deployment](https://cmcp.agentrust-io.com/tutorials/multi-tenant-config/index.md): one gateway instance per tenant
