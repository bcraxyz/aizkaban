# aizkaban — Cloud Run

Persistent web dashboard deployed on Cloud Run. Scan results are held in memory and refreshed on demand via a Refresh button in the UI.

## Deploy

```bash
chmod +x deploy.sh
./deploy.sh
```

Prompts for Project ID, Organization ID, and region (default: `us-central1`).

### What deploy.sh does

1. Sets the active gcloud project
2. Enables required APIs (`run`, `cloudbuild`, `containerregistry`)
3. Creates a Service Account (`aizkaban-scanner@...`)
4. Binds three IAM roles at Organization level
5. Builds and pushes the Docker image via Cloud Build
6. Deploys the Cloud Run service (no public access, single instance)
7. Grants the deployer identity the Cloud Run Invoker role
8. Triggers an initial scan via `POST /refresh`

### Required permissions to run deploy.sh

Your gcloud identity needs:
- `roles/owner` or `roles/editor` on the deploy project
- `roles/resourcemanager.organizationAdmin` to bind org-level IAM roles in Step 4

## Post-deploy: Enable IAP

The service is deployed with `--no-allow-unauthenticated`. Enable IAP to control who can access the dashboard:

1. **Security → Identity-Aware Proxy** in the GCP Console
2. Enable IAP on the Cloud Run service
3. Grant `roles/iap.httpsResourceAccessor` to users who need access

Full guide: https://cloud.google.com/iap/docs/enabling-cloud-run

## Architecture

- Single Cloud Run service, 1 worker, max 1 instance
- In-memory SQLite — holds the current scan snapshot only
- Scan state is lost on container restart; click Refresh to repopulate (takes ~1–2 min)
- No external dependencies beyond the GCP APIs the SA is authorised to call

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard |
| `/refresh` | POST | Start scan (returns immediately, scan runs in background) |
| `/status` | GET | `{"running": bool, "error": str\|null}` — polled by the UI |
| `/health` | GET | Health check |
| `/favicon.svg` | GET | Favicon |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ORG_ID` | — | **Required.** GCP Organization ID to scan |
| `PORT` | `8080` | HTTP port |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
