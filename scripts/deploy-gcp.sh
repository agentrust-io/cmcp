#!/usr/bin/env bash
# deploy-gcp.sh: provision a GCP Confidential VM and install cMCP
#
# Usage:
#   ./scripts/deploy-gcp.sh [tdx|sev-snp]    (default: tdx)
#
# Prerequisites:
#   gcloud auth login
#   gcloud services enable compute.googleapis.com confidentialcomputing.googleapis.com

set -euo pipefail

TEE_TYPE="${1:-tdx}"
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
ZONE="${GCP_ZONE:-us-central1-a}"
INSTANCE_NAME="cmcp-gateway"
IMAGE_FAMILY="ubuntu-2404-lts-amd64"
IMAGE_PROJECT="ubuntu-os-cloud"

if [[ -z "$PROJECT_ID" ]]; then
  echo "No GCP project set. Run: gcloud config set project <project-id>" >&2
  exit 1
fi

case "$TEE_TYPE" in
  tdx)
    MACHINE_TYPE="c3-standard-4"
    CC_TYPE="TDX"
    ;;
  sev-snp)
    MACHINE_TYPE="n2d-standard-4"
    CC_TYPE="SEV_SNP"
    ;;
  *)
    echo "Unknown TEE type: $TEE_TYPE. Use tdx or sev-snp." >&2
    exit 1
    ;;
esac

echo "==> Deploying cMCP on GCP ($TEE_TYPE) in $ZONE"
echo "    Project: $PROJECT_ID"

# Create VM
gcloud compute instances create "$INSTANCE_NAME" \
  --project="$PROJECT_ID" \
  --zone="$ZONE" \
  --machine-type="$MACHINE_TYPE" \
  --confidential-compute-type="$CC_TYPE" \
  --on-host-maintenance=TERMINATE \
  --image-family="$IMAGE_FAMILY" \
  --image-project="$IMAGE_PROJECT" \
  --boot-disk-size=20GB \
  --shielded-secure-boot \
  --shielded-vtpm \
  --shielded-integrity-monitoring \
  --tags=cmcp-gateway \
  --quiet
echo "  Instance created: $INSTANCE_NAME ($MACHINE_TYPE, $CC_TYPE)"

# Firewall rule
if ! gcloud compute firewall-rules describe allow-cmcp --project="$PROJECT_ID" &>/dev/null; then
  gcloud compute firewall-rules create allow-cmcp \
    --project="$PROJECT_ID" \
    --direction=INGRESS \
    --action=ALLOW \
    --rules=tcp:8443 \
    --target-tags=cmcp-gateway \
    --source-ranges=0.0.0.0/0 \
    --quiet
  echo "  Firewall rule: allow TCP 8443"
else
  echo "  Firewall rule allow-cmcp already exists, skipping"
fi

# Get external IP
VM_IP=$(gcloud compute instances describe "$INSTANCE_NAME" \
  --project="$PROJECT_ID" \
  --zone="$ZONE" \
  --format="get(networkInterfaces[0].accessConfigs[0].natIP)")
echo "  External IP: $VM_IP"

# Install cMCP on the VM
echo "==> Installing cMCP on VM..."
gcloud compute ssh "$INSTANCE_NAME" \
  --project="$PROJECT_ID" \
  --zone="$ZONE" \
  --command='sudo apt-get update -qq && sudo apt-get install -y python3-pip && pip install --quiet cmcp-runtime && echo "cmcp-runtime $(cmcp --version 2>&1 | head -1) installed"' \
  --quiet

echo ""
echo "==> Done. Next steps:"
echo ""
echo "  1. SSH in:  gcloud compute ssh $INSTANCE_NAME --zone=$ZONE"
echo "  2. Create cmcp-config.yaml (see docs/tutorials/deploy-gcp.md)"
echo "  3. Start:   cmcp start --config cmcp-config.yaml"
echo ""
echo "  TEE type : $TEE_TYPE ($CC_TYPE)"
echo "  Instance : $INSTANCE_NAME ($MACHINE_TYPE)"
echo "  IP       : $VM_IP"
