#!/usr/bin/env bash
# deploy-azure.sh — provision an Azure Confidential VM and install cMCP
#
# Usage:
#   ./scripts/deploy-azure.sh [sev-snp|tdx]    (default: sev-snp)
#
# Prerequisites:
#   az login && az account set --subscription <id>
#   SSH public key at ~/.ssh/id_rsa.pub

set -euo pipefail

TEE_TYPE="${1:-sev-snp}"
RESOURCE_GROUP="cmcp-rg"
VM_NAME="cmcp-gateway"
ADMIN_USER="azureuser"
SSH_KEY="${HOME}/.ssh/id_rsa.pub"

case "$TEE_TYPE" in
  sev-snp)
    VM_SIZE="Standard_DC2as_v5"
    LOCATION="eastus"
    ;;
  tdx)
    VM_SIZE="Standard_DC2eds_v5"
    LOCATION="eastus2"
    ;;
  *)
    echo "Unknown TEE type: $TEE_TYPE. Use sev-snp or tdx." >&2
    exit 1
    ;;
esac

echo "==> Deploying cMCP on Azure ($TEE_TYPE) in $LOCATION"

# Resource group
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
echo "  Resource group: $RESOURCE_GROUP"

# Confidential VM
az vm create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --image "Canonical:ubuntu-24_04-lts:server:latest" \
  --size "$VM_SIZE" \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --enable-secure-boot true \
  --enable-vtpm true \
  --admin-username "$ADMIN_USER" \
  --ssh-key-values "$SSH_KEY" \
  --public-ip-sku Standard \
  --output none
echo "  VM created: $VM_NAME ($VM_SIZE)"

# Firewall rule for gateway port
NSG_NAME="${VM_NAME}NSG"
az network nsg rule create \
  --resource-group "$RESOURCE_GROUP" \
  --nsg-name "$NSG_NAME" \
  --name allow-cmcp \
  --protocol Tcp \
  --priority 1010 \
  --destination-port-ranges 8443 \
  --output none
echo "  NSG rule: allow TCP 8443"

# Get public IP
VM_IP=$(az vm show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --show-details \
  --query publicIps -o tsv)
echo "  Public IP: $VM_IP"

# Install cMCP on the VM via remote commands
echo "==> Installing cMCP on VM..."
ssh -o StrictHostKeyChecking=no "${ADMIN_USER}@${VM_IP}" bash <<'REMOTE'
set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y python3-pip
pip install --quiet cmcp-runtime
echo "cmcp-runtime $(cmcp --version 2>&1 | head -1) installed"
REMOTE

echo ""
echo "==> Done. Next steps:"
echo ""
echo "  1. SSH in:  ssh ${ADMIN_USER}@${VM_IP}"
echo "  2. Create cmcp-config.yaml (see docs/tutorials/deploy-azure.md)"
echo "  3. Start:   cmcp start --config cmcp-config.yaml"
echo ""
echo "  TEE type : $TEE_TYPE"
echo "  VM       : $VM_NAME ($VM_SIZE)"
echo "  IP       : $VM_IP"
