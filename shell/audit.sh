#!/bin/bash

# ==============================================================================
# aizkaban — Gemini API Key Auditor
# Scans a GCP organization for API keys that may expose the Gemini API.
#
# PREREQUISITES:
#   1. gcloud CLI authenticated with sufficient permissions
#   2. jq installed
#   3. Cloud Asset API enabled on the active gcloud project:
#        gcloud services enable cloudasset.googleapis.com
#   4. The following IAM roles bound at Organization level:
#        roles/cloudasset.viewer
#        roles/resourcemanager.organizationViewer
#        roles/serviceusage.serviceUsageViewer
# ==============================================================================

set -euo pipefail

SCAN_TIME=$(date -u "+%Y-%m-%d %H:%M:%S UTC")
REPORT_FILE="aizkaban-$(date -u +%Y%m%d-%H%M%S).html"
PRE_GEMINI_CUTOFF="2023-03-01T00:00:00Z"

# ── Checks ─────────────────────────────────────────────────────────────────────

if ! command -v jq &>/dev/null; then
  echo "Error: jq is not installed." >&2
  exit 1
fi

echo "aizkaban — Gemini API Key Auditor"
echo "=================================="

CAI_CHECK=$(gcloud services list --enabled \
  --filter="config.name:cloudasset.googleapis.com" \
  --format="value(config.name)" 2>/dev/null)

if [ "$CAI_CHECK" != "cloudasset.googleapis.com" ]; then
  echo "Error: Cloud Asset API not enabled on active project." >&2
  echo "  Run: gcloud services enable cloudasset.googleapis.com" >&2
  exit 1
fi
echo "✅ Cloud Asset API enabled."

# ── Org ID ─────────────────────────────────────────────────────────────────────

ORG_ID="${ORG_ID:-}"
if [ -z "$ORG_ID" ]; then
  read -r -p "Enter GCP Organization ID: " ORG_ID
fi
if [ -z "$ORG_ID" ]; then
  echo "Error: Organization ID required." >&2
  exit 1
fi
echo "Organization: $ORG_ID"
echo ""

# ── Data collection ────────────────────────────────────────────────────────────

echo "Building project map..."
PROJECT_MAP=$(gcloud projects list --format="json(projectNumber,projectId)" 2>/dev/null)
[ -z "$PROJECT_MAP" ] && PROJECT_MAP="[]"

echo "Querying projects with Gemini API enabled..."
GEMINI_PROJECTS=$(gcloud asset search-all-resources \
  --scope="organizations/$ORG_ID" \
  --asset-types="serviceusage.googleapis.com/Service" \
  --query="state:ENABLED AND name:*generativelanguage.googleapis.com*" \
  --format="value(project)" 2>/dev/null | sed 's/projects\///' || true)

GEMINI_SET="[]"
if [ -n "$GEMINI_PROJECTS" ]; then
  GEMINI_SET=$(echo "$GEMINI_PROJECTS" | jq -R . | jq -s .)
fi

echo "Querying all API keys org-wide..."
KEYS_JSON=$(gcloud asset list \
  --organization="$ORG_ID" \
  --asset-types="apikeys.googleapis.com/Key" \
  --content-type=resource \
  --format="json" 2>/dev/null)
[ -z "$KEYS_JSON" ] && KEYS_JSON="[]"

echo "Analyzing..."

# ── Classify findings ──────────────────────────────────────────────────────────

FINDINGS=$(echo "$KEYS_JSON" | jq -r \
  --argjson pmap "$PROJECT_MAP" \
  --argjson gemini_set "$GEMINI_SET" \
  --arg cutoff "$PRE_GEMINI_CUTOFF" '
  ($pmap | map({(.projectNumber): .projectId}) | add // {}) as $dict |
  ($gemini_set | map({(.): true}) | add // {}) as $gset |
  [
    .[] |
    (.name | split("/")[4]) as $pnum |
    ($dict[$pnum] // $pnum) as $pid |
    ($gset[$pnum] // false) as $gemini_on |
    .resource.data as $d |
    ($d.restrictions.apiTargets // null) as $targets |
    (
      if $targets == null then "unrestricted"
      elif ($targets | map(.service) | any(. == "generativelanguage.googleapis.com")) then "gemini_scoped"
      else "restricted"
      end
    ) as $key_type |
    (
      if   $key_type == "unrestricted" and $gemini_on then "critical"
      elif $key_type == "unrestricted"                 then "high"
      elif $key_type == "gemini_scoped" and $gemini_on then "low"
      else null
      end
    ) as $severity |
    select($severity != null) |
    {
      severity:        $severity,
      project:         $pid,
      name:            ($d.displayName // "unnamed"),
      uid:             ($d.uid // ""),
      created:         ($d.createTime // ""),
      pre_gemini:      (($d.createTime // "") < $cutoff and ($d.createTime // "") != ""),
      app_restriction: (
        if $d.restrictions.browserKeyRestrictions then "Browser"
        elif $d.restrictions.serverKeyRestrictions then "Server/IP"
        elif $d.restrictions.androidKeyRestrictions then "Android"
        elif $d.restrictions.iosKeyRestrictions then "iOS"
        else "None"
        end
      )
    }
  ] |
  sort_by(
    if .severity == "critical" then 0
    elif .severity == "high" then 1
    elif .severity == "low"  then 2
    else 3 end
  )
')

# Clean Gemini-enabled projects (all keys restricted — info)
CLEAN_PROJECTS=$(echo "$KEYS_JSON" | jq -r \
  --argjson pmap "$PROJECT_MAP" \
  --argjson gemini_set "$GEMINI_SET" '
  ($pmap | map({(.projectNumber): .projectId}) | add // {}) as $dict |
  ($gemini_set | map({(.): true}) | add // {}) as $gset |
  [
    .[] |
    (.name | split("/")[4]) as $pnum |
    ($gset[$pnum] // false) as $gemini_on |
    .resource.data as $d |
    ($d.restrictions.apiTargets // null) as $targets |
    select($gemini_on and $targets != null) |
    select(($targets | map(.service) | any(. == "generativelanguage.googleapis.com")) | not) |
    ($dict[$pnum] // $pnum)
  ] | unique
')

# ── Summary counts ─────────────────────────────────────────────────────────────

TOTAL_PROJECTS=$(echo "$PROJECT_MAP" | jq 'length')
GEMINI_COUNT=$(echo "$GEMINI_SET" | jq 'length')
TOTAL_KEYS=$(echo "$KEYS_JSON" | jq 'length')
CRITICAL_COUNT=$(echo "$FINDINGS" | jq '[.[] | select(.severity=="critical")] | length')
HIGH_COUNT=$(echo "$FINDINGS"     | jq '[.[] | select(.severity=="high")]     | length')
LOW_COUNT=$(echo "$FINDINGS"      | jq '[.[] | select(.severity=="low")]      | length')
INFO_COUNT=$(echo "$CLEAN_PROJECTS" | jq 'length')

# ── Build HTML rows ────────────────────────────────────────────────────────────

make_rows() {
  local sev="$1"
  echo "$FINDINGS" | jq -r --arg sev "$sev" '
    .[] | select(.severity == $sev) |
    "<tr>" +
    "<td>" + .project + "</td>" +
    "<td>" + .name + "</td>" +
    "<td class=\"mono\">" + (.uid | if length > 16 then .[0:16] + "…" else . end) + "</td>" +
    "<td>" + (if .pre_gemini then "<span class=\"badge-pre\">Pre-Gemini</span>" else .created[0:10] end) + "</td>" +
    "<td>" + .app_restriction + "</td>" +
    "</tr>"
  '
}

make_table() {
  local rows="$1"
  if [ -z "$rows" ]; then
    echo '<p class="empty">No findings in this category.</p>'
    return
  fi
  cat <<TABLE
<div class="table-wrap"><table>
<thead><tr><th>Project</th><th>Key Name</th><th>UID</th><th>Created</th><th>App Restriction</th></tr></thead>
<tbody>
$rows
</tbody></table></div>
TABLE
}

CRITICAL_ROWS=$(make_rows "critical")
HIGH_ROWS=$(make_rows "high")
LOW_ROWS=$(make_rows "low")
INFO_ROWS=$(echo "$CLEAN_PROJECTS" | jq -r '.[] | "<tr><td>" + . + "</td></tr>"')

CRITICAL_TABLE=$(make_table "$CRITICAL_ROWS")
HIGH_TABLE=$(make_table "$HIGH_ROWS")
LOW_TABLE=$(make_table "$LOW_ROWS")
INFO_TABLE=$(make_table "$INFO_ROWS")

# ── Write HTML report ──────────────────────────────────────────────────────────

cat > "$REPORT_FILE" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>aizkaban — Audit Report</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&display=swap');
:root {
  --bg:          #f7f7f5;
  --surface:     #ffffff;
  --border:      #e4e4e0;
  --text:        #1a1a18;
  --muted:       #6b6b65;
  --critical:    #c0392b;
  --high:        #e67e22;
  --low:         #27ae60;
  --info:        #2980b9;
  --critical-bg: #fdf2f1;
  --high-bg:     #fef9f2;
  --low-bg:      #f2faf5;
  --info-bg:     #f2f8fd;
  --pre-color:   #8e44ad;
  --pre-bg:      #f8f2fc;
  --radius:      8px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg:          #111110;
    --surface:     #1c1c1a;
    --border:      #2e2e2b;
    --text:        #e8e8e4;
    --muted:       #888882;
    --critical-bg: #2a1614;
    --high-bg:     #2a1f10;
    --low-bg:      #122216;
    --info-bg:     #0f1e2a;
    --pre-bg:      #1e1226;
  }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: "DM Sans", ui-sans-serif, system-ui, sans-serif;
  background: var(--bg); color: var(--text);
  font-size: 14px; line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}
header {
  padding: 24px 40px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: baseline; gap: 16px; flex-wrap: wrap;
}
.logo { font-size: 20px; font-weight: 600; letter-spacing: -0.4px; }
.logo span { color: var(--muted); font-weight: 300; }
.scan-meta { font-size: 12px; color: var(--muted); margin-left: auto; }
main { max-width: 1100px; margin: 0 auto; padding: 28px 40px 60px; }
.stat-bar {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 12px; margin-bottom: 32px;
}
.stat {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 16px 18px;
}
.stat-value { font-size: 28px; font-weight: 600; line-height: 1; margin-bottom: 4px; }
.stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
.stat.critical .stat-value { color: var(--critical); }
.stat.high     .stat-value { color: var(--high); }
.stat.low      .stat-value { color: var(--low); }
.stat.info     .stat-value { color: var(--info); }
.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); margin-bottom: 16px; overflow: hidden;
}
.card-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 18px; border-bottom: 1px solid var(--border);
}
.card-header.critical { background: var(--critical-bg); }
.card-header.high     { background: var(--high-bg); }
.card-header.low      { background: var(--low-bg); }
.card-header.info     { background: var(--info-bg); }
.dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.dot.critical { background: var(--critical); }
.dot.high     { background: var(--high); }
.dot.low      { background: var(--low); }
.dot.info     { background: var(--info); }
.card-title { font-weight: 600; font-size: 13px; }
.card-desc  { font-size: 12px; color: var(--muted); }
.card-count {
  margin-left: auto; font-size: 12px; color: var(--muted);
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 20px; padding: 2px 10px;
}
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th {
  text-align: left; font-size: 11px; font-weight: 500;
  text-transform: uppercase; letter-spacing: .05em; color: var(--muted);
  padding: 9px 16px; border-bottom: 1px solid var(--border);
  cursor: pointer; user-select: none; white-space: nowrap;
}
th:hover { color: var(--text); }
th.asc::after  { content: " ↑"; }
th.desc::after { content: " ↓"; }
td { padding: 9px 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--bg); }
.mono { font-family: "JetBrains Mono", "Fira Code", monospace; font-size: 11px; color: var(--muted); }
.badge-pre {
  display: inline-block; font-size: 10px; font-weight: 500;
  background: var(--pre-bg); color: var(--pre-color);
  border: 1px solid var(--pre-color); border-radius: 4px; padding: 1px 6px;
}
.empty { padding: 18px; color: var(--muted); font-size: 13px; }
footer {
  text-align: center; padding: 20px; font-size: 11px;
  color: var(--muted); border-top: 1px solid var(--border);
}
@media print {
  body { background: #fff; color: #000; }
  header, main { padding-left: 20px; padding-right: 20px; }
  .card { break-inside: avoid; }
  tr:hover td { background: none; }
}
</style>
</head>
<body>
<header>
  <div class="logo">aizkaban <span>/ Gemini Key Auditor</span></div>
  <div class="scan-meta">Org: $ORG_ID &nbsp;·&nbsp; $SCAN_TIME</div>
</header>
<main>
  <div class="stat-bar">
    <div class="stat"><div class="stat-value">$TOTAL_PROJECTS</div><div class="stat-label">Projects</div></div>
    <div class="stat"><div class="stat-value">$GEMINI_COUNT</div><div class="stat-label">Gemini Enabled</div></div>
    <div class="stat"><div class="stat-value">$TOTAL_KEYS</div><div class="stat-label">API Keys</div></div>
    <div class="stat critical"><div class="stat-value">$CRITICAL_COUNT</div><div class="stat-label">Critical</div></div>
    <div class="stat high"><div class="stat-value">$HIGH_COUNT</div><div class="stat-label">High</div></div>
    <div class="stat low"><div class="stat-value">$LOW_COUNT</div><div class="stat-label">Low</div></div>
    <div class="stat info"><div class="stat-value">$INFO_COUNT</div><div class="stat-label">Clean</div></div>
  </div>

  <div class="card">
    <div class="card-header critical">
      <span class="dot critical"></span>
      <span class="card-title">Critical</span>
      <span class="card-desc">— Unrestricted key, Gemini enabled</span>
      <span class="card-count">$CRITICAL_COUNT keys</span>
    </div>
    $CRITICAL_TABLE
  </div>

  <div class="card">
    <div class="card-header high">
      <span class="dot high"></span>
      <span class="card-title">High</span>
      <span class="card-desc">— Unrestricted key, Gemini not enabled (latent)</span>
      <span class="card-count">$HIGH_COUNT keys</span>
    </div>
    $HIGH_TABLE
  </div>

  <div class="card">
    <div class="card-header low">
      <span class="dot low"></span>
      <span class="card-title">Low</span>
      <span class="card-desc">— Explicitly Gemini-scoped key, Gemini enabled</span>
      <span class="card-count">$LOW_COUNT keys</span>
    </div>
    $LOW_TABLE
  </div>

  <div class="card">
    <div class="card-header info">
      <span class="dot info"></span>
      <span class="card-title">Info</span>
      <span class="card-desc">— Gemini enabled, all keys properly restricted</span>
      <span class="card-count">$INFO_COUNT projects</span>
    </div>
    $INFO_TABLE
  </div>
</main>
<footer>aizkaban &nbsp;·&nbsp; Point-in-time audit &nbsp;·&nbsp; $SCAN_TIME</footer>
<script>
document.querySelectorAll('table').forEach(table => {
  table.querySelectorAll('th').forEach((th, col) => {
    let asc = true;
    th.addEventListener('click', () => {
      table.querySelectorAll('th').forEach(h => h.classList.remove('asc', 'desc'));
      const tbody = table.querySelector('tbody');
      const rows = Array.from(tbody.querySelectorAll('tr'));
      rows.sort((a, b) => {
        const av = a.cells[col]?.textContent.trim() ?? '';
        const bv = b.cells[col]?.textContent.trim() ?? '';
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      rows.forEach(r => tbody.appendChild(r));
      th.classList.add(asc ? 'asc' : 'desc');
      asc = !asc;
    });
  });
});
</script>
</body>
</html>
HTMLEOF

echo ""
echo "============================================================="
echo "✅ Audit complete: $REPORT_FILE"
echo "   Critical : $CRITICAL_COUNT"
echo "   High     : $HIGH_COUNT"
echo "   Low      : $LOW_COUNT"
echo "   Clean    : $INFO_COUNT projects"
echo "============================================================="
