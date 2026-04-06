#!/usr/bin/env bash
# Azure OpenAI deployment setup for pwnkit
#
# Prereq: brew install azure-cli && az login
#
# This script:
#   1. Creates an Azure OpenAI resource (Cognitive Services account)
#   2. Deploys the configured model
#   3. Prints the endpoint + key + model name to copy into GitHub secrets
#
# Configurable via env vars:
#   AZURE_RG        — resource group name (default: pwnkit-rg)
#   AZURE_LOCATION  — region (default: eastus2)
#   AZURE_RESOURCE  — Azure OpenAI resource name (default: pwnkit-openai)
#   AZURE_MODEL     — model name (default: gpt-5)
#   AZURE_DEPLOYMENT— deployment name (default: gpt-5)
#   AZURE_CAPACITY  — TPM capacity in thousands (default: 100 = 100K TPM)

set -euo pipefail

RG="${AZURE_RG:-pwnkit-rg}"
LOCATION="${AZURE_LOCATION:-eastus2}"
RESOURCE="${AZURE_RESOURCE:-pwnkit-openai}"
MODEL="${AZURE_MODEL:-gpt-5}"
DEPLOYMENT="${AZURE_DEPLOYMENT:-gpt-5}"
CAPACITY="${AZURE_CAPACITY:-100}"

# ── Preflight ──
if ! command -v az >/dev/null 2>&1; then
  echo "ERROR: Azure CLI not installed. Run: brew install azure-cli"
  exit 1
fi

if ! az account show >/dev/null 2>&1; then
  echo "ERROR: Not logged into Azure. Run: az login"
  exit 1
fi

ACCOUNT=$(az account show --query name -o tsv)
SUBSCRIPTION=$(az account show --query id -o tsv)
echo ">> Using Azure account: $ACCOUNT"
echo ">> Subscription: $SUBSCRIPTION"
echo ""

# ── Resource Group ──
if az group show --name "$RG" >/dev/null 2>&1; then
  echo ">> Resource group '$RG' already exists"
else
  echo ">> Creating resource group '$RG' in $LOCATION..."
  az group create --name "$RG" --location "$LOCATION" -o none
fi

# ── Azure OpenAI Resource ──
if az cognitiveservices account show --name "$RESOURCE" --resource-group "$RG" >/dev/null 2>&1; then
  echo ">> OpenAI resource '$RESOURCE' already exists"
else
  echo ">> Creating Azure OpenAI resource '$RESOURCE'..."
  az cognitiveservices account create \
    --name "$RESOURCE" \
    --resource-group "$RG" \
    --kind OpenAI \
    --sku S0 \
    --location "$LOCATION" \
    --custom-domain "$RESOURCE" \
    --yes \
    -o none
fi

# ── Model Deployment ──
if az cognitiveservices account deployment show \
    --name "$RESOURCE" \
    --resource-group "$RG" \
    --deployment-name "$DEPLOYMENT" >/dev/null 2>&1; then
  echo ">> Deployment '$DEPLOYMENT' already exists"
else
  echo ">> Deploying model '$MODEL' as '$DEPLOYMENT' (capacity: ${CAPACITY}K TPM)..."
  echo ">> This may take a minute..."
  az cognitiveservices account deployment create \
    --name "$RESOURCE" \
    --resource-group "$RG" \
    --deployment-name "$DEPLOYMENT" \
    --model-name "$MODEL" \
    --model-format OpenAI \
    --sku-name Standard \
    --sku-capacity "$CAPACITY" \
    -o none || {
      echo ""
      echo "ERROR: Deployment failed. Common causes:"
      echo "  - Model '$MODEL' not available in $LOCATION"
      echo "  - Quota exceeded — request via portal"
      echo "  - Try a different region: AZURE_LOCATION=eastus $0"
      echo "  - Try a different model: AZURE_MODEL=gpt-4o $0"
      exit 1
    }
fi

# ── Get connection details ──
echo ""
echo "================================================================"
echo " Deployment ready! Copy these to your GitHub repository secrets:"
echo "================================================================"
echo ""

ENDPOINT=$(az cognitiveservices account show \
  --name "$RESOURCE" \
  --resource-group "$RG" \
  --query properties.endpoint -o tsv)

KEY=$(az cognitiveservices account keys list \
  --name "$RESOURCE" \
  --resource-group "$RG" \
  --query key1 -o tsv)

echo "AZURE_OPENAI_API_KEY=$KEY"
echo "AZURE_OPENAI_BASE_URL=${ENDPOINT}openai/v1"
echo "AZURE_OPENAI_MODEL=$DEPLOYMENT"
echo "AZURE_OPENAI_WIRE_API=responses"
echo ""
echo "================================================================"
echo " Set them in GitHub:"
echo "   gh secret set AZURE_OPENAI_API_KEY -b '$KEY'"
echo "   gh secret set AZURE_OPENAI_BASE_URL -b '${ENDPOINT}openai/v1'"
echo "   gh secret set AZURE_OPENAI_MODEL -b '$DEPLOYMENT'"
echo "   gh secret set AZURE_OPENAI_WIRE_API -b 'responses'"
echo "================================================================"
echo ""
echo " Or set them locally for testing:"
echo "   export AZURE_OPENAI_API_KEY='$KEY'"
echo "   export AZURE_OPENAI_BASE_URL='${ENDPOINT}openai/v1'"
echo "   export AZURE_OPENAI_MODEL='$DEPLOYMENT'"
echo "   export AZURE_OPENAI_WIRE_API='responses'"
echo ""
