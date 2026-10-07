# Deploy on Azure Confidential VMs

This page is for operators who want to run cMCP on Microsoft Azure with hardware protection switched on. Azure Confidential VMs run on AMD SEV-SNP or Intel TDX processors, which keep the VM's memory sealed off from the cloud host and can produce a signed hardware report (an attestation) of the software that started. Following these steps, each signed session record cMCP produces (a TRACE claim) carries that hardware report instead of a software-only placeholder.

## What you'll learn

- Which Azure VM SKUs give you SEV-SNP vs TDX
- How to provision a Confidential VM with the Azure CLI
- How to install and configure cMCP for each hardware type
- What to verify in the TRACE claim to confirm hardware attestation is live

## Prerequisites

- Azure CLI installed and authenticated (`az login`)
- An Azure subscription with Confidential VM quota in your target region
- SSH key pair (`~/.ssh/id_rsa.pub` or equivalent)

---

## Choose your hardware

| TEE type | Azure VM series | `provider` value | Notes |
|---|---|---|---|
| AMD SEV-SNP | DCasv5, DCadsv5 | `sev-snp` | Most widely available |
| Intel TDX | DCesv6, DCedsv6 | `tdx` | Current-gen (v6); DCedsv5 is previous gen |
| vTPM (Trusted Launch) | Any Gen2 VM with Trusted Launch | `tpm` | All regions |

SEV-SNP (DCasv5) is the most widely available. Use TDX (DCesv6) where your compliance rules call for Intel. vTPM uses the VM's virtual security chip, which is a weaker guarantee than the other two.

Not every region offers every VM size. Check what your region offers before creating a resource group:

```bash
az vm list-skus --location eastus --size dc --output table
```

---

## Provision the VM

### SEV-SNP (DCasv5)

```bash
# Set your target region: verify DCasv5 is available first:
# az vm list-skus --location <region> --size Standard_DC2as_v5 --output table
LOCATION=eastus

az group create --name cmcp-rg --location $LOCATION

# Azure Confidential VMs require a CVM-specific OS image.
# Verify the latest available image with:
# az vm image list --publisher Canonical --offer 0001-com-ubuntu-confidential-vm-jammy --all --output table
az vm create \
  --resource-group cmcp-rg \
  --name cmcp-gateway \
  --image Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest \
  --size Standard_DC2as_v5 \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --enable-secure-boot true \
  --enable-vtpm true \
  --admin-username azureuser \
  --ssh-key-values ~/.ssh/id_rsa.pub \
  --public-ip-sku Standard
```

### TDX (DCesv6)

DCesv6 is the current Intel TDX series (5th Gen Intel). The older DCedsv5 also supports TDX but has been replaced.

```bash
# Verify DCesv6 availability in your region first:
# az vm list-skus --location <region> --size Standard_DC2es_v6 --output table
LOCATION=eastus

az group create --name cmcp-rg --location $LOCATION

az vm create \
  --resource-group cmcp-rg \
  --name cmcp-gateway-tdx \
  --image Canonical:0001-com-ubuntu-confidential-vm-jammy:22_04-lts-cvm:latest \
  --size Standard_DC2es_v6 \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --enable-secure-boot true \
  --enable-vtpm true \
  --admin-username azureuser \
  --ssh-key-values ~/.ssh/id_rsa.pub \
  --public-ip-sku Standard
```

### Open the gateway port

```bash
az network nsg rule create \
  --resource-group cmcp-rg \
  --nsg-name cmcp-gatewayNSG \
  --name allow-cmcp \
  --protocol Tcp \
  --priority 1010 \
  --destination-port-ranges 8443
```

Get the public IP:

```bash
az vm show \
  --resource-group cmcp-rg \
  --name cmcp-gateway \
  --show-details \
  --query publicIps -o tsv
```

---

## Install cMCP on the VM

Connect to the VM over SSH and run the setup script from the repository:

```bash
VM_IP=$(az vm show --resource-group cmcp-rg --name cmcp-gateway --show-details --query publicIps -o tsv)
ssh azureuser@$VM_IP

# On the VM:
sudo apt-get update -qq && sudo apt-get install -y python3-pip
pip install cmcp-runtime
cmcp --version
```

---

## Configure for SEV-SNP

Confirm the hardware device is present:

```bash
ls -la /dev/sev-guest
# Expected: crw------- 1 root root ...
```

Create a working directory and write the config:

```bash
mkdir ~/cmcp-deploy && cd ~/cmcp-deploy
mkdir policies
```

`cmcp-config.yaml`:

```yaml
attestation:
  provider: sev-snp
  enforcement_mode: enforcing
  validity_seconds: 86400
  staleness_policy: fail_closed

policy_bundle_path: ./policies/
catalog_path: ./catalog.json
listen_addr: "0.0.0.0:8443"
```

For TDX, change `provider: sev-snp` to `provider: tdx`.

Add a minimal set of policy rules (replace them with your real ones):

```bash
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
```

Add a minimal catalog (the list of tools the gateway may call):

```bash
cat > catalog.json <<'EOF'
[]
EOF
```

---

## Start the gateway

```bash
export CMCP_BEARER_TOKEN="$(openssl rand -hex 32)"
echo "Bearer token: $CMCP_BEARER_TOKEN"  # save this

cmcp start --config cmcp-config.yaml
```

Expected startup log on a real SEV-SNP VM:

```
cMCP Runtime starting: TEE: sev-snp, listen: 0.0.0.0:8443
```

The TEE field should read `sev-snp`. If it reads `software-only`, the gateway could not reach the SEV-SNP hardware: check the VM size and that `/dev/sev-guest` exists.

---

## Verify hardware attestation

From your own computer, fetch a TRACE claim from the gateway and check it:

```bash
# Start a session and retrieve its claim
curl -s -H "Authorization: Bearer $CMCP_BEARER_TOKEN" \
  http://$VM_IP:8443/session/test-session/claim \
  | python3 -m json.tool > claim.json

# Verify
python3 - <<'EOF'
import json
from cmcp_verify import verify_trace_claim, ApprovedHashes

with open("claim.json") as f:
    claim = json.load(f)

# Replace these hashes with values from the gateway startup log
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

Expected output on a real SEV-SNP VM:

```
Status:          verified
Platform:        amd-sev-snp
Measurement:     sha384:<non-zero hardware measurement>
Verified fields: ['schema', 'signature', 'policy_bundle.hash', 'tool_catalog.hash', 'attestation_freshness', 'audit_chain', 'hardware_attestation']
```

If `hardware_attestation` appears in `verified_fields`, the measurement (the fingerprint of the software that started) came from the hardware. On a DCedsv5 with TDX, `platform` reads `intel-tdx`.

---

## Pin the expected measurement

Once you have seen the measurement on a deployment you trust, write it into the config. The gateway will then refuse to start if the software is anything other than that exact version:

```yaml
attestation:
  provider: sev-snp
  enforcement_mode: enforcing
  expected_measurement: "sha384:<measurement from claim>"
```

If the cMCP software or its startup config changes, the measurement changes too, and the gateway stops at startup instead of signing claims with a value you did not expect.

---

## Tear down

```bash
az group delete --name cmcp-rg --yes --no-wait
```

---

## Next steps

- [GCP deployment](./deploy-gcp.md): Intel TDX on GCP C3 Confidential VMs
- [TEE attestation](./tee-attestation.md): detailed explanation of what each provider proves
- [Verify a TRACE claim](./verifying-a-trace-claim.md): full verification protocol
- [Multi-tenant deployment](./multi-tenant-config.md): one gateway instance per tenant
