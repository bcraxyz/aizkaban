# aizkaban — Gemini API Key Auditor

Scans a Google Cloud organization for API keys that may unintentionally expose the Gemini API, based on the privilege escalation vector documented by [TruffleHog (Feb 2026)](https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules).

## The Risk

When the Gemini API is enabled on a GCP project, any existing unrestricted API key in that project silently gains access to Gemini endpoints — including keys originally created for Maps, Firebase, or other public-facing services. Keys deployed in client-side code under Google's prior guidance ("API keys are not secrets") can become live Gemini credentials with no warning and no notification.

## Findings

| Severity | Condition |
|---|---|
| 🔴 **Critical** | Unrestricted key + Gemini enabled — actively exploitable |
| 🟠 **High** | Unrestricted key + Gemini not enabled — one API enablement away from Critical |
| 🟢 **Low** | Key explicitly scoped to Gemini + Gemini enabled — intentional but visible |
| 🔵 **Info** | Gemini enabled, all keys properly restricted — clean |

Keys created before **March 2023** (pre-Gemini API availability) are flagged as **Pre-Gemini** — highest priority, most likely deployed in public-facing code under the old guidance.

## Tools

| Tool | Description |
|---|---|
| [`shell/`](shell/) | Standalone bash script, outputs a self-contained HTML report |
| [`cloudrun/`](cloudrun/) | Persistent Cloud Run dashboard with on-demand refresh |

Both tools share identical detection logic and produce identical findings.

## Required IAM Roles (Organization level)

| Role | Purpose |
|---|---|
| `roles/cloudasset.viewer` | Query Cloud Asset Inventory org-wide |
| `roles/resourcemanager.organizationViewer` | Enumerate and resolve project IDs |
| `roles/serviceusage.serviceUsageViewer` | Read enabled services per project |

## Remediation

For Critical and High findings:
1. Restrict the key to only the APIs it needs — **APIs & Services → Credentials → Edit key**
2. If the key is in client-side code or a public repository, **rotate it immediately**
3. Disable the Gemini API on projects where it is not intentionally in use

## References

- [TruffleHog: Google API Keys Weren't Secrets. But then Gemini Changed the Rules.](https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules)
- [The Hacker News coverage](https://thehackernews.com/2026/02/thousands-of-public-google-cloud-api.html)
- [Google API Key Best Practices](https://cloud.google.com/docs/authentication/api-keys-best-practices)
