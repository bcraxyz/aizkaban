#!/bin/bash

# ==============================================================================
# aizkaban — Cloud Run Deploy Script
#
# PREREQUISITES:
#   - gcloud CLI authenticated as a user with:
#       roles/owner or roles/editor on the deploy project
#       roles/resourcemanager.organizationAdmin (to bind org-level IAM in Step 4)
#   - Docker installed locally (preferred) or Cloud Build access on the deploy project
# ==============================================================================

set -e

echo ""
echo "╔══════════════════════════════════════╗"
echo "║      AIzkaban — Deploy Script        ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── Inputs ─────────────────────────────────────────────────────────────────────

read -r -p "Google Cloud Project ID (where Cloud Run will be deployed): " PROJECT_ID
[ -z "$PROJECT_ID" ] && echo "Error: Project ID required." && exit 1

read -r -p "Google Cloud Organization ID (org to scan): " ORG_ID
[ -z "$ORG_ID" ] && echo "Error: Organization ID required." && exit 1

read -r -p "Cloud Run region [us-central1]: " REGION
REGION="${REGION:-us-central1}"

SERVICE_NAME="aizkaban"
SA_NAME="aizkaban-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest"

echo ""
echo "  Project : $PROJECT_ID"
echo "  Org     : $ORG_ID"
echo "  Region  : $REGION"
echo "  Service : $SERVICE_NAME"
echo "  SA      : $SA_EMAIL"
echo "  Image   : $IMAGE"
echo ""
read -r -p "Proceed? [y/N]: " CONFIRM
[[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && echo "Aborted." && exit 0

# ── Step 1: Set active project ─────────────────────────────────────────────────
echo ""
echo "── Step 1: Setting active project ───────────────────────────────────────"
gcloud config set project "$PROJECT_ID"
echo "✅ Active project: $PROJECT_ID"

# ── Step 2: Enable required APIs ──────────────────────────────────────────────
echo ""
echo "── Step 2: Enabling required APIs ───────────────────────────────────────"
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  containerregistry.googleapis.com
echo "✅ APIs enabled."

# ── Step 3: Create Service Account ────────────────────────────────────────────
echo ""
echo "── Step 3: Creating Service Account ─────────────────────────────────────"
if gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" &>/dev/null; then
  echo "ℹ️  Service account already exists: $SA_EMAIL"
else
  gcloud iam service-accounts create "$SA_NAME" \
    --display-name="aizkaban Scanner" \
    --project="$PROJECT_ID"
  echo "✅ Service account created: $SA_EMAIL"
fi

# ── Step 4: Bind IAM roles at Organization level ──────────────────────────────
echo ""
echo "── Step 4: Binding IAM roles at Organization level ──────────────────────"
for ROLE in \
  "roles/cloudasset.viewer" \
  "roles/resourcemanager.organizationViewer"; do
  gcloud organizations add-iam-policy-binding "$ORG_ID" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="$ROLE" \
    --condition=None \
    --quiet > /dev/null
  echo "✅ Bound: $ROLE"
done

# ── Step 5: Build and push Docker image ───────────────────────────────────────
echo ""
echo "── Step 5: Building and pushing Docker image ────────────────────────────"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v docker &>/dev/null; then
  echo "   Using local Docker..."
  gcloud auth configure-docker --quiet 2>/dev/null
  docker build -t "$IMAGE" "$SCRIPT_DIR"
  docker push "$IMAGE"
else
  echo "   Docker not found, using Cloud Build..."
  gcloud builds submit "$SCRIPT_DIR" \
    --tag "$IMAGE" \
    --project "$PROJECT_ID"
fi
echo "✅ Image pushed: $IMAGE"

# ── Step 6: Deploy Cloud Run service ──────────────────────────────────────────
echo ""
echo "── Step 6: Deploying Cloud Run service ──────────────────────────────────"
gcloud run deploy "$SERVICE_NAME" \
  --image "$IMAGE" \
  --region "$REGION" \
  --project "$PROJECT_ID" \
  --service-account "$SA_EMAIL" \
  --set-env-vars "ORG_ID=${ORG_ID}" \
  --no-allow-unauthenticated \
  --min-instances 0 \
  --max-instances 1 \
  --memory 512Mi \
  --cpu 1 \
  --timeout 540 \
  --concurrency 1
echo "✅ Cloud Run service deployed."

SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
  --region "$REGION" \
  --project "$PROJECT_ID" \
  --format="value(status.url)")
echo "   URL: $SERVICE_URL"

# ── Step 7: Grant deployer identity Cloud Run Invoker (for initial scan) ──────
echo ""
echo "── Step 7: Granting invoker role to current identity ────────────────────"
CURRENT_IDENTITY=$(gcloud config get-value account)
gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
  --region "$REGION" \
  --project "$PROJECT_ID" \
  --member="user:${CURRENT_IDENTITY}" \
  --role="roles/run.invoker"
echo "✅ Invoker role granted to: $CURRENT_IDENTITY"

# ── Step 8: Trigger initial scan ──────────────────────────────────────────────
echo ""
echo "── Step 8: Triggering initial scan ──────────────────────────────────────"
echo "   (Scan runs in background — dashboard will populate within ~2 minutes)"
TOKEN=$(gcloud auth print-identity-token)
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "${SERVICE_URL}/refresh" \
  -H "Authorization: Bearer ${TOKEN}")

if [ "$HTTP_STATUS" = "200" ]; then
  echo "✅ Scan triggered successfully."
else
  echo "⚠️  Could not trigger scan automatically (HTTP $HTTP_STATUS)."
  echo "   Open the dashboard and click Refresh to run the first scan."
fi

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ AIzkaban deployed                                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf  "║  URL : %-54s║\n" "$SERVICE_URL"
printf  "║  Org : %-54s║\n" "$ORG_ID"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Next: Enable IAP on this Cloud Run service                  ║"
echo "║  https://cloud.google.com/iap/docs/enabling-cloud-run        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
