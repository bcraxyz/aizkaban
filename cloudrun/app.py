import json
import logging
import os
import sqlite3
import subprocess
import threading
from datetime import datetime, timezone

from flask import Flask, Response, jsonify

# ── Config ─────────────────────────────────────────────────────────────────────

ORG_ID = os.environ.get("ORG_ID", "")
PRE_GEMINI_CUTOFF = "2023-03-01T00:00:00Z"
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

logging.basicConfig(level=getattr(logging, LOG_LEVEL), format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("aizkaban")

app = Flask(__name__)

# ── In-memory SQLite ───────────────────────────────────────────────────────────

_db_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def get_db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(":memory:", check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _init_db(_conn)
    return _conn


def _init_db(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS snapshot (
            id             INTEGER PRIMARY KEY CHECK (id = 1),
            scanned_at     TEXT NOT NULL,
            org_id         TEXT NOT NULL,
            total_projects          INTEGER DEFAULT 0,
            projects_with_findings  INTEGER DEFAULT 0,
            gemini_count            INTEGER DEFAULT 0,
            total_keys     INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count     INTEGER DEFAULT 0,
            low_count      INTEGER DEFAULT 0,
            info_count     INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            severity        TEXT NOT NULL,
            project         TEXT NOT NULL,
            key_name        TEXT NOT NULL,
            gemini_scoped   INTEGER DEFAULT 0,
            created         TEXT,
            expires         TEXT,
            pre_gemini      INTEGER DEFAULT 0,
            app_restriction TEXT,
            api_targets     TEXT
        );
    """)


def db_store(meta: dict, findings: list):
    with _db_lock:
        conn = get_db()
        conn.execute("DELETE FROM snapshot")
        conn.execute("DELETE FROM findings")
        conn.execute("""
            INSERT INTO snapshot
              (id, scanned_at, org_id, total_projects, projects_with_findings, gemini_count, total_keys,
               critical_count, high_count, low_count, info_count)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            meta["scanned_at"], meta["org_id"],
            meta["total_projects"], meta["projects_with_findings"], meta["gemini_count"], meta["total_keys"],
            meta["critical_count"], meta["high_count"], meta["low_count"], meta["info_count"],
        ))
        for f in findings:
            conn.execute("""
                INSERT INTO findings
                  (severity, project, key_name, gemini_scoped, created, expires,
                   pre_gemini, app_restriction, api_targets)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f["severity"], f["project"], f["name"],
                int(f["gemini_scoped"]), f["created"], f["expires"],
                int(f["pre_gemini"]), f["app_restriction"],
                json.dumps(f["api_targets"]),
            ))
        conn.commit()


def db_load() -> dict | None:
    with _db_lock:
        conn = get_db()
        row = conn.execute("SELECT * FROM snapshot WHERE id=1").fetchone()
        if not row:
            return None
        findings = []
        for r in conn.execute("""
            SELECT * FROM findings
            ORDER BY CASE severity
              WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'low' THEN 2 ELSE 3 END
        """).fetchall():
            d = dict(r)
            d["api_targets"] = json.loads(d["api_targets"] or "[]")
            findings.append(d)
        return {**dict(row), "findings": findings}


# ── Scan state ─────────────────────────────────────────────────────────────────

_scan_lock = threading.Lock()
_scan_state = {"running": False, "error": None}


def _set_scan_state(running: bool, error: str | None = None):
    with _scan_lock:
        _scan_state["running"] = running
        _scan_state["error"] = error


def get_scan_state() -> dict:
    with _scan_lock:
        return dict(_scan_state)


# ── Scanner ────────────────────────────────────────────────────────────────────

def run_gcloud(args: list[str]) -> str:
    result = subprocess.run(
        ["gcloud"] + args,
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        log.warning("gcloud stderr: %s", result.stderr[:300])
    return result.stdout.strip()


def classify_key(key_data: dict, gemini_set: set, pmap: dict) -> dict | None:
    d = key_data.get("resource", {}).get("data", {})
    if d.get("deleteTime"):
        return None
    name = key_data.get("name", "")
    parts = name.split("/")
    if len(parts) < 5:
        return None
    pnum = parts[4]
    gemini_on = pnum in gemini_set
    pid = pmap.get(pnum, pnum)
    restrictions = d.get("restrictions", {})
    api_targets = restrictions.get("apiTargets")

    if api_targets is None:
        key_type = "unrestricted"
    elif any(t.get("service") == "generativelanguage.googleapis.com" for t in api_targets):
        key_type = "gemini_scoped"
    else:
        key_type = "restricted"

    if key_type == "unrestricted" and gemini_on:
        severity = "critical"
    elif key_type == "unrestricted":
        severity = "high"
    elif gemini_on:
        severity = "low"
    else:
        severity = "info"

    created = d.get("createTime", "")
    pre_gemini = bool(created and created < PRE_GEMINI_CUTOFF)

    if restrictions.get("browserKeyRestrictions"):
        app_restriction = "Browser"
    elif restrictions.get("serverKeyRestrictions"):
        app_restriction = "Server/IP"
    elif restrictions.get("androidKeyRestrictions"):
        app_restriction = "Android"
    elif restrictions.get("iosKeyRestrictions"):
        app_restriction = "iOS"
    else:
        app_restriction = "None"

    return {
        "severity": severity,
        "project": pid,
        "project_num": pnum,
        "name": d.get("displayName") or "unnamed",
        "gemini_scoped": (key_type == "gemini_scoped" and gemini_on),
        "created": created,
        "expires": d.get("expireTime", ""),
        "pre_gemini": pre_gemini,
        "app_restriction": app_restriction,
        "api_targets": [t.get("service", "") for t in (api_targets or [])],
    }


def scan():
    log.info("Scan started for org %s", ORG_ID)
    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    raw_pmap = run_gcloud([
        "asset", "list",
        f"--organization={ORG_ID}",
        "--asset-types=cloudresourcemanager.googleapis.com/Project",
        "--content-type=resource",
        "--format=json",
    ])
    pmap_list = json.loads(raw_pmap) if raw_pmap else []
    # resource.data.projectNumber -> resource.data.projectId
    pmap = {}
    for p in pmap_list:
        d = p.get("resource", {}).get("data", {})
        project_id = d.get("projectId", "")
        raw_num = str(d.get("projectNumber", ""))
        project_number = raw_num.split("/")[-1]  # handles int, "123456", or "projects/123456"
        lifecycle = d.get("lifecycleState", "")
        if project_id and project_number and lifecycle == "ACTIVE":
            pmap[project_number] = project_id
    total_projects = len(pmap)

    gemini_raw = run_gcloud([
        "asset", "search-all-resources",
        f"--scope=organizations/{ORG_ID}",
        "--asset-types=serviceusage.googleapis.com/Service",
        "--query=state:ENABLED AND name:*generativelanguage.googleapis.com*",
        "--format=value(project)",
    ])
    gemini_set = set()
    if gemini_raw:
        for line in gemini_raw.splitlines():
            num = line.replace("projects/", "").strip()
            if num:
                gemini_set.add(num)
    gemini_count = len(gemini_set)

    keys_raw = run_gcloud([
        "asset", "list",
        f"--organization={ORG_ID}",
        "--asset-types=apikeys.googleapis.com/Key",
        "--content-type=resource",
        "--format=json",
    ])
    keys = json.loads(keys_raw) if keys_raw else []

    findings = []
    for key_data in keys:
        result = classify_key(key_data, gemini_set, pmap)
        if result:
            findings.append(result)

    sev_order = {"critical": 0, "high": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 4))

    total_keys     = len(findings)
    critical_count = sum(1 for f in findings if f["severity"] == "critical")
    high_count     = sum(1 for f in findings if f["severity"] == "high")
    low_count      = sum(1 for f in findings if f["severity"] == "low")
    info_count     = sum(1 for f in findings if f["severity"] == "info")

    projects_with_findings = len({f['project'] for f in findings if f['severity'] in ('critical','high','low')})

    meta = {
        "scanned_at": scanned_at,
        "org_id": ORG_ID,
        "total_projects": total_projects,
        "projects_with_findings": projects_with_findings,
        "gemini_count": gemini_count,
        "total_keys": total_keys,
        "critical_count": critical_count,
        "high_count": high_count,
        "low_count": low_count,
        "info_count": info_count,
    }
    db_store(meta, findings)
    log.info("Scan complete — critical=%d high=%d low=%d info=%d",
             critical_count, high_count, low_count, info_count)


def run_scan_background():
    _set_scan_state(running=True, error=None)
    try:
        scan()
        _set_scan_state(running=False)
    except Exception as e:
        log.exception("Scan failed")
        _set_scan_state(running=False, error=str(e))


# ── Assets ─────────────────────────────────────────────────────────────────────

FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="12" fill="#1a1a18"/>
  <path d="M32 10 C32 10 26 26 10 32 C26 38 32 54 32 54 C32 54 38 38 54 32 C38 26 32 10 32 10 Z" fill="white"/>
</svg>"""

GEMINI_ICON = (
    '<svg width="13" height="13" viewBox="0 0 24 24" '
    'style="vertical-align:-2px;margin-left:4px" title="Gemini-scoped">'
    '<path fill="#1a73e8" d="M12 2C12 2 9.5 9.5 2 12C9.5 14.5 12 22 12 22'
    'C12 22 14.5 14.5 22 12C14.5 9.5 12 2Z"/></svg>'
)

COLGROUP = (
    '<colgroup>'
    '<col class="col-project"><col class="col-name"><col class="col-created">'
    '<col class="col-expires"><col class="col-restriction"><col class="col-apis">'
    '</colgroup>'
)
THEAD = (
    '<thead><tr>'
    '<th>Project</th><th>Key Name</th><th>Created</th>'
    '<th>Expires</th><th>App Restriction</th><th>APIs</th>'
    '</tr></thead>'
)

# ── HTML rendering ─────────────────────────────────────────────────────────────

def created_cell(f: dict) -> str:
    if f.get("pre_gemini"):
        return '<span class="badge-pre">Pre-Gemini</span>'
    c = f.get("created", "")
    return c[:10] if c else "\u2014"


def findings_row(f: dict) -> str:
    expires = f.get("expires", "")
    expires_str = expires[:10] if expires else "\u2014"
    targets = f.get("api_targets", [])
    gemini_icon = GEMINI_ICON if f.get("gemini_scoped") else ""
    if targets:
        apis_cell = f'<span class="apis-badge">{len(targets)}</span>{gemini_icon}'
        apis_detail = "".join(f'<span class="api-pill">{t}</span>' for t in targets)
    else:
        apis_cell = '<span class="apis-unrestricted">All APIs</span>'
        apis_detail = "No API restrictions \u2014 key has access to all enabled APIs."
    return (
        f'<tr class="data-row" onclick="toggleApis(this)">'
        f'<td class="col-project">{f["project"]}</td>'
        f'<td class="col-name">{f["key_name"]}</td>'
        f'<td class="col-created">{created_cell(f)}</td>'
        f'<td class="col-expires">{expires_str}</td>'
        f'<td class="col-restriction">{f["app_restriction"]}</td>'
        f'<td class="col-apis">{apis_cell}</td>'
        f'</tr>'
        f'<tr class="apis-row" style="display:none">'
        f'<td colspan="6"><div class="apis-list">{apis_detail}</div></td>'
        f'</tr>'
    )


def build_table(rows: list[str]) -> str:
    if not rows:
        return '<p class="empty">No findings in this category.</p>'
    return f'<div class="table-wrap"><table>{COLGROUP}{THEAD}<tbody>{"".join(rows)}</tbody></table></div>'


def render_card(sev: str, title: str, desc: str, rows: list, count: int) -> str:
    table = build_table([findings_row(f) for f in rows])
    label = "key" if count == 1 else "keys"
    return (
        f'<div class="card">'
        f'<div class="card-header {sev}">'
        f'<span class="dot {sev}"></span>'
        f'<span class="card-title">{title}</span>'
        f'<span class="card-desc">\u2014 {desc}</span>'
        f'<span class="card-count">{count} {label}</span>'
        f'</div>{table}</div>'
    )


def render_dashboard(data: dict | None, scan_running: bool, scan_error: str | None) -> str:
    org_str = f"Org ID: {data['org_id']}" if data else f"Org ID: {ORG_ID}"
    footer_time = data["scanned_at"] if data else "\u2014"

    if data is None:
        body = (
            '<div class="no-data"><p>Scan in progress\u2026</p></div>'
            if scan_running else
            '<div class="no-data"><p>No scan data. Click <strong>Refresh</strong> to run the first scan.</p></div>'
        )
    else:
        findings = data["findings"]
        critical_rows = [f for f in findings if f["severity"] == "critical"]
        high_rows     = [f for f in findings if f["severity"] == "high"]
        low_rows      = [f for f in findings if f["severity"] == "low"]
        info_rows     = [f for f in findings if f["severity"] == "info"]
        stats = (
            f'<div class="stat-bar">'
            f'<div class="stat-group"><div class="stat-group-label">Projects</div>'
            f'<div class="stat-cells">'
            f'<div class="stat"><div class="stat-value">{data["total_projects"]}</div><div class="stat-label">Total</div></div>'
            f'<div class="stat critical"><div class="stat-value">{data["projects_with_findings"]}</div><div class="stat-label">Findings</div></div>'
            f'<div class="stat"><div class="stat-value">{data["gemini_count"]}</div><div class="stat-label">Gemini Enabled</div></div>'
            f'</div></div>'
            f'<div class="stat-group"><div class="stat-group-label">API Keys</div>'
            f'<div class="stat-cells">'
            f'<div class="stat"><div class="stat-value">{data["total_keys"]}</div><div class="stat-label">Total</div></div>'
            f'<div class="stat critical"><div class="stat-value">{data["critical_count"]}</div><div class="stat-label">Critical</div></div>'
            f'<div class="stat high"><div class="stat-value">{data["high_count"]}</div><div class="stat-label">High</div></div>'
            f'<div class="stat low"><div class="stat-value">{data["low_count"]}</div><div class="stat-label">Low</div></div>'
            f'<div class="stat info"><div class="stat-value">{data["info_count"]}</div><div class="stat-label">Info</div></div>'
            f'</div></div></div>'
        )
        body = (
            stats
            + render_card("critical", "Critical", "Unrestricted key, Gemini enabled",    critical_rows, len(critical_rows))
            + render_card("high",     "High",     "Unrestricted key, Gemini not enabled", high_rows,     len(high_rows))
            + render_card("low",      "Low",      "Restricted key, Gemini enabled",       low_rows,      len(low_rows))
            + render_card("info",     "Info",     "Restricted key, Gemini not enabled",   info_rows,     len(info_rows))
        )

    error_banner = f'<div class="error-banner">Scan error: {scan_error}</div>' if scan_error else ""

    polling_js = "startPolling();" if scan_running else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AIzkaban</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&display=swap');
:root{{--bg:#f7f7f5;--surface:#fff;--border:#e4e4e0;--text:#1a1a18;--muted:#6b6b65;--critical:#c0392b;--high:#e67e22;--low:#27ae60;--info:#2980b9;--critical-bg:#fdf2f1;--high-bg:#fef9f2;--low-bg:#f2faf5;--info-bg:#f2f8fd;--pre-color:#8e44ad;--pre-bg:#f8f2fc;--radius:8px}}
@media(prefers-color-scheme:dark){{:root{{--bg:#111110;--surface:#1c1c1a;--border:#2e2e2b;--text:#e8e8e4;--muted:#888882;--critical-bg:#2a1614;--high-bg:#2a1f10;--low-bg:#122216;--info-bg:#0f1e2a;--pre-bg:#1e1226}}}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"DM Sans",ui-sans-serif,system-ui,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}}
header{{padding:20px 40px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:16px;flex-wrap:wrap}}
.logo{{font-size:20px;font-weight:600;letter-spacing:-0.4px}}
.header-right{{margin-left:auto;display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
.org-id{{font-size:12px;color:var(--muted)}}
.spinner{{display:none;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--muted);border-radius:50%;animation:spin .7s linear infinite}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.btn{{font-size:12px;font-weight:500;background:var(--text);color:var(--bg);border:none;border-radius:6px;padding:7px 16px;cursor:pointer;transition:opacity .15s;font-family:inherit}}
.btn:hover{{opacity:.8}}.btn:disabled{{opacity:.4;cursor:not-allowed}}
main{{max-width:1200px;margin:0 auto;padding:28px 40px 60px}}
.no-data{{padding:60px 0;text-align:center;color:var(--muted)}}
.error-banner{{background:var(--critical-bg);color:var(--critical);border:1px solid var(--critical);border-radius:var(--radius);padding:10px 16px;margin-bottom:20px;font-size:13px}}
.stat-bar{{display:flex;gap:12px;margin-bottom:32px;flex-wrap:wrap}}
.stat-group{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);display:flex;overflow:hidden;flex:1;min-width:260px}}
.stat-group-label{{writing-mode:vertical-rl;font-size:10px;font-weight:500;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);padding:12px 8px;border-right:1px solid var(--border);background:var(--bg);display:flex;align-items:center;justify-content:center}}
.stat-cells{{display:flex;flex:1}}
.stat{{flex:1;padding:14px 16px;border-right:1px solid var(--border);min-width:0}}
.stat:last-child{{border-right:none}}
.stat-value{{font-size:26px;font-weight:600;line-height:1;margin-bottom:3px}}
.stat-label{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);white-space:nowrap}}
.stat.critical .stat-value{{color:var(--critical)}}.stat.high .stat-value{{color:var(--high)}}.stat.low .stat-value{{color:var(--low)}}.stat.info .stat-value{{color:var(--info)}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:16px;overflow:hidden}}
.card-header{{display:flex;align-items:center;gap:10px;padding:12px 18px;border-bottom:1px solid var(--border)}}
.card-header.critical{{background:var(--critical-bg)}}.card-header.high{{background:var(--high-bg)}}.card-header.low{{background:var(--low-bg)}}.card-header.info{{background:var(--info-bg)}}
.dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0}}
.dot.critical{{background:var(--critical)}}.dot.high{{background:var(--high)}}.dot.low{{background:var(--low)}}.dot.info{{background:var(--info)}}
.card-title{{font-weight:600;font-size:13px}}.card-desc{{font-size:12px;color:var(--muted)}}
.card-count{{margin-left:auto;font-size:12px;color:var(--muted);background:var(--bg);border:1px solid var(--border);border-radius:20px;padding:2px 10px}}
.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed}}
col.col-project{{width:24%}}col.col-name{{width:22%}}col.col-created{{width:11%}}col.col-expires{{width:11%}}col.col-restriction{{width:13%}}col.col-apis{{width:10%}}
th{{text-align:left;font-size:11px;font-weight:500;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:9px 16px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}}
th:hover{{color:var(--text)}}th.asc::after{{content:" \u2191"}}th.desc::after{{content:" \u2193"}}
td{{padding:9px 16px;border-bottom:1px solid var(--border);vertical-align:middle;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
tr.data-row{{cursor:pointer}}tr.data-row:hover td{{background:var(--bg)}}
tr.apis-row td{{padding:0;border-bottom:1px solid var(--border);white-space:normal}}
tr:last-child td{{border-bottom:none}}
.apis-list{{display:flex;flex-wrap:wrap;gap:6px;padding:10px 16px}}
.api-pill{{display:inline-block;font-size:11px;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:2px 8px;color:var(--muted)}}
.apis-badge{{display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:500;background:var(--bg);border:1px solid var(--border);border-radius:20px;padding:1px 8px}}
.apis-unrestricted{{font-size:12px;color:var(--muted)}}
.badge-pre{{display:inline-block;font-size:10px;font-weight:500;background:var(--pre-bg);color:var(--pre-color);border:1px solid var(--pre-color);border-radius:4px;padding:1px 6px}}
.empty{{padding:18px;color:var(--muted);font-size:13px}}
footer{{text-align:center;padding:20px;font-size:11px;color:var(--muted);border-top:1px solid var(--border)}}
@media print{{.btn,.spinner{{display:none!important}}.card{{break-inside:avoid}}tr.data-row:hover td{{background:none}}}}
</style>
</head>
<body>
<header>
  <div class="logo">AIzkaban</div>
  <div class="header-right">
    <span class="org-id" id="orgId">{org_str}</span>
    <div class="spinner" id="spinner"></div>
    <button class="btn" id="refreshBtn" onclick="startRefresh()">Refresh</button>
  </div>
</header>
<main>{error_banner}{body}</main>
<footer>AIzkaban &nbsp;\u00b7&nbsp; API Key Auditor &nbsp;\u00b7&nbsp; <time id="scanTime" data-utc="{footer_time}">{footer_time}</time></footer>
<script>
let polling=null;
function toggleApis(row){{const n=row.nextElementSibling;if(n&&n.classList.contains('apis-row'))n.style.display=n.style.display==='none'?'table-row':'none';}}
function startRefresh(){{fetch('/refresh',{{method:'POST'}}).then(r=>r.json()).then(d=>{{if(d.status==='started'||d.status==='already_running'){{setScanning(true);startPolling();}}}}).catch(()=>document.getElementById('orgId').textContent='Error \u2014 try again');}}
function startPolling(){{if(polling)return;polling=setInterval(()=>{{fetch('/status').then(r=>r.json()).then(d=>{{if(!d.running){{clearInterval(polling);polling=null;location.reload();}}}});}},3000);}}
function setScanning(on){{const btn=document.getElementById('refreshBtn');const sp=document.getElementById('spinner');btn.disabled=on;btn.textContent=on?'Scanning\u2026':'Refresh';sp.style.display=on?'block':'none';}}
document.querySelectorAll('table').forEach(table=>{{
  table.querySelectorAll('th').forEach((th,col)=>{{
    let asc=true;
    th.addEventListener('click',()=>{{
      table.querySelectorAll('th').forEach(h=>h.classList.remove('asc','desc'));
      const tbody=table.querySelector('tbody');
      const pairs=[];
      const rows=Array.from(tbody.querySelectorAll('tr'));
      for(let i=0;i<rows.length;i++){{if(rows[i].classList.contains('data-row'))pairs.push([rows[i],rows[i+1]]);}}
      pairs.sort((a,b)=>{{const av=a[0].cells[col]?.textContent.trim()??'';const bv=b[0].cells[col]?.textContent.trim()??'';return asc?av.localeCompare(bv):bv.localeCompare(av);}});
      pairs.forEach(([dr,ar])=>{{tbody.appendChild(dr);if(ar)tbody.appendChild(ar);}});
      th.classList.add(asc?'asc':'desc');asc=!asc;
    }});
  }});
}});
{polling_js}
const t=document.getElementById('scanTime');
if(t){{const d=new Date(t.dataset.utc);if(!isNaN(d))t.textContent=d.toLocaleString(undefined,{{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}});}}
</script>
</body>
</html>"""


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/favicon.svg")
def favicon():
    return Response(FAVICON_SVG, mimetype="image/svg+xml")


@app.route("/")
def index():
    data = db_load()
    state = get_scan_state()
    return render_dashboard(data, state["running"], state["error"])


@app.route("/refresh", methods=["POST"])
def refresh():
    state = get_scan_state()
    if state["running"]:
        return jsonify({"status": "already_running"})
    t = threading.Thread(target=run_scan_background, daemon=True)
    t.start()
    return jsonify({"status": "started"})


@app.route("/status")
def status():
    state = get_scan_state()
    return jsonify({"running": state["running"], "error": state["error"]})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ── Entrypoint ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not ORG_ID:
        raise SystemExit("ORG_ID environment variable is required")
    get_db()
    port = int(os.environ.get("PORT", 8080))
    log.info("aizkaban starting on port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False)
