# aizkaban — Shell

Standalone bash script. Runs a point-in-time scan and outputs a self-contained HTML report. No infrastructure required.

## Prerequisites

- `gcloud` CLI authenticated with org-level permissions (see root README)
- `jq` installed
- Cloud Asset API enabled on the active project:
  ```
  gcloud services enable cloudasset.googleapis.com
  ```

## Usage

```bash
chmod +x audit.sh

# Pass org ID via env var:
ORG_ID=123456789 ./audit.sh

# Or let the script prompt for it:
./audit.sh
```

Outputs a timestamped file in the current directory:

```
aizkaban-20260524-143022.html
```

Open in any browser. Use browser Print → Save as PDF to export.
