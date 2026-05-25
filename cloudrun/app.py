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
            total_projects INTEGER DEFAULT 0,
            gemini_count   INTEGER DEFAULT 0,
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
            uid             TEXT NOT NULL,
            created         TEXT,
            pre_gemini      INTEGER DEFAULT 0,
            app_restriction TEXT
        );
        CREATE TABLE IF NOT EXISTS clean_projects (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL
        );
    """)


def db_store(meta: dict, findings: list, clean: list):
    with _db_lock:
        conn = get_db()
        conn.execute("DELETE FROM snapshot")
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM clean_projects")
        conn.execute("""
            INSERT INTO snapshot
              (id, scanned_at, org_id, total_projects, gemini_count, total_keys,
               critical_count, high_count, low_count, info_count)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            meta["scanned_at"], meta["org_id"],
            meta["total_projects"], meta["gemini_count"], meta["total_keys"],
            meta["critical_count"], meta["high_count"], meta["low_count"], meta["info_count"],
        ))
        for f in findings:
            conn.execute("""
                INSERT INTO findings
                  (severity, project, key_name, uid, created, pre_gemini, app_restriction)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                f["severity"], f["project"], f["name"], f["uid"],
                f["created"], int(f["pre_gemini"]), f["app_restriction"],
            ))
        for p in clean:
            conn.execute("INSERT INTO clean_projects (project) VALUES (?)", (p,))
        conn.commit()


def db_load() -> dict | None:
    with _db_lock:
        conn = get_db()
        row = conn.execute("SELECT * FROM snapshot WHERE id=1").fetchone()
        if not row:
            return None
        findings = [dict(r) for r in conn.execute("""
            SELECT * FROM findings
            ORDER BY CASE severity
              WHEN 'critical' THEN 0
              WHEN 'high'     THEN 1
              WHEN 'low'      THEN 2
              ELSE 3 END
        """).fetchall()]
        clean = [r["project"] for r in conn.execute(
            "SELECT project FROM clean_projects ORDER BY project"
        ).fetchall()]
        return {**dict(row), "findings": findings, "clean": clean}


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
    name = key_data.get("name", "")
    parts = name.split("/")
    if len(parts) < 5:
        return None
    pnum = parts[4]
    gemini_on = pnum in gemini_set
    pid = pmap.get(pnum, pnum)
    d = key_data.get("resource", {}).get("data", {})
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
    elif key_type == "gemini_scoped" and gemini_on:
        severity = "low"
    else:
        return None  # restricted + not gemini scoped → info (handled at project level)

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
        "uid": d.get("uid", ""),
        "created": created,
        "pre_gemini": pre_gemini,
        "app_restriction": app_restriction,
    }


def scan():
    log.info("Scan started for org %s", ORG_ID)
    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    raw_pmap = run_gcloud(["projects", "list", "--format=json(projectNumber,projectId)"])
    pmap_list = json.loads(raw_pmap) if raw_pmap else []
    pmap = {str(p.get("projectNumber", "")): p.get("projectId", "") for p in pmap_list}
    total_projects = len(pmap_list)

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
    total_keys = len(keys)

    findings = []
    # Track which gemini-enabled projects have at least one non-clean key
    dirty_gemini_projects = set()

    for key_data in keys:
        result = classify_key(key_data, gemini_set, pmap)
        if result:
            findings.append(result)
            if result["severity"] in ("critical", "low"):
                dirty_gemini_projects.add(result["project_num"])
        else:
            # Check if this is a restricted key in a gemini-enabled project
            parts = key_data.get("name", "").split("/")
            if len(parts) >= 5:
                pnum = parts[4]
                d = key_data.get("resource", {}).get("data", {})
                api_targets = d.get("restrictions", {}).get("apiTargets")
                if pnum in gemini_set and api_targets is not None:
                    # Restricted, not gemini-scoped → genuinely clean
                    pass  # collected below

    sev_order = {"critical": 0, "high": 1, "low": 2}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 3))

    # Clean projects: gemini on, no findings in that project
    finding_pnums = {f["project_num"] for f in findings if f["severity"] in ("critical", "low")}
    clean_projects = sorted(
        pmap.get(pnum, pnum)
        for pnum in gemini_set
        if pnum not in finding_pnums
    )

    critical_count = sum(1 for f in findings if f["severity"] == "critical")
    high_count     = sum(1 for f in findings if f["severity"] == "high")
    low_count      = sum(1 for f in findings if f["severity"] == "low")
    info_count     = len(clean_projects)

    meta = {
        "scanned_at": scanned_at,
        "org_id": ORG_ID,
        "total_projects": total_projects,
        "gemini_count": gemini_count,
        "total_keys": total_keys,
        "critical_count": critical_count,
        "high_count": high_count,
        "low_count": low_count,
        "info_count": info_count,
    }

    db_store(meta, findings, clean_projects)
    log.info("Scan complete — critical=%d high=%d low=%d clean=%d",
             critical_count, high_count, low_count, info_count)


def run_scan_background():
    _set_scan_state(running=True, error=None)
    try:
        scan()
        _set_scan_state(running=False)
    except Exception as e:
        log.exception("Scan failed")
        _set_scan_state(running=False, error=str(e))


# ── Favicon ────────────────────────────────────────────────────────────────────

FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="12" fill="#1a1a18"/>
  <text x="32" y="46" font-size="36" text-anchor="middle" font-family="serif">🔑</text>
</svg>"""

# ── Dashboard HTML ─────────────────────────────────────────────────────────────

def uid_short(uid: str) -> str:
    return uid[:16] + "…" if len(uid) > 16 else uid


def created_cell(f: dict) -> str:
    if f["pre_gemini"]:
        return '<span class="badge-pre">Pre-Gemini</span>'
    c = f.get("created", "")
    return c[:10] if c else "—"


def findings_row(f: dict) -> str:
    return (
        f"<tr>"
        f"<td>{f['project']}</td>"
        f"<td>{f['key_name']}</td>"
        f'<td class="mono">{uid_short(f["uid"])}</td>'
        f"<td>{created_cell(f)}</td>"
        f"<td>{f['app_restriction']}</td>"
        f"</tr>"
    )


def build_table(rows: list[str], cols: list[str]) -> str:
    if not rows:
        return '<p class="empty">No findings in this category.</p>'
    heads = "".join(f"<th>{c}</th>" for c in cols)
    body = "".join(rows)
    return (
        f'<div class="table-wrap"><table>'
        f"<thead><tr>{heads}</tr></thead>"
        f"<tbody>{body}</tbody>"
        f"</table></div>"
    )


def render_dashboard(data: dict | None, scan_running: bool, scan_error: str | None) -> str:
    if data is None:
        if scan_running:
            body = '<div class="no-data"><p>Scan in progress…</p></div>'
        else:
            body = '<div class="no-data"><p>No scan data. Click <strong>Refresh</strong> to run the first scan.</p></div>'
        org_str = f"Org: {ORG_ID}"
        footer_time = "—"
    else:
        org_str = f"Org: {data['org_id']}"
        footer_time = data['scanned_at']
        cols = ["Project", "Key Name", "UID", "Created", "App Restriction"]
        findings = data["findings"]

        def card(sev, title, desc, rows, count):
            table = build_table([findings_row(f) for f in rows], cols)
            label = "key" if count == 1 else "keys"
            return (
                f'<div class="card">'
                f'<div class="card-header {sev}">'
                f'<span class="dot {sev}"></span>'
                f'<span class="card-title">{title}</span>'
                f'<span class="card-desc">— {desc}</span>'
                f'<span class="card-count">{count} {label}</span>'
                f"</div>{table}</div>"
            )

        critical_rows = [f for f in findings if f["severity"] == "critical"]
        high_rows     = [f for f in findings if f["severity"] == "high"]
        low_rows      = [f for f in findings if f["severity"] == "low"]
        clean         = data.get("clean", [])

        clean_table = build_table(
            [f"<tr><td>{p}</td></tr>" for p in clean], ["Project"]
        )
        n_clean = len(clean)
        clean_label = "project" if n_clean == 1 else "projects"
        clean_card = (
            f'<div class="card">'
            f'<div class="card-header info">'
            f'<span class="dot info"></span>'
            f'<span class="card-title">Info</span>'
            f'<span class="card-desc">— Gemini enabled, all keys properly restricted</span>'
            f'<span class="card-count">{n_clean} {clean_label}</span>'
            f"</div>{clean_table}</div>"
        )

        stats = (
            f'<div class="stat-bar">'
            f'<div class="stat-group">'
            f'<div class="stat-group-label">Projects</div>'
            f'<div class="stat-cells">'
            f'<div class="stat"><div class="stat-value">{data["total_projects"]}</div><div class="stat-label">Total</div></div>'
            f'<div class="stat"><div class="stat-value">{data["gemini_count"]}</div><div class="stat-label">Gemini Enabled</div></div>'
            f'</div></div>'
            f'<div class="stat-group">'
            f'<div class="stat-group-label">API Keys</div>'
            f'<div class="stat-cells">'
            f'<div class="stat"><div class="stat-value">{data["total_keys"]}</div><div class="stat-label">Total</div></div>'
            f'<div class="stat critical"><div class="stat-value">{data["critical_count"]}</div><div class="stat-label">Critical</div></div>'
            f'<div class="stat high"><div class="stat-value">{data["high_count"]}</div><div class="stat-label">High</div></div>'
            f'<div class="stat low"><div class="stat-value">{data["low_count"]}</div><div class="stat-label">Low</div></div>'
            f'<div class="stat info"><div class="stat-value">{data["info_count"]}</div><div class="stat-label">Clean</div></div>'
            f'</div></div>'
            f'</div>'
        )
        body = (
            stats
            + card("critical", "Critical", "Unrestricted key, Gemini enabled", critical_rows, len(critical_rows))
            + card("high",     "High",     "Unrestricted key, Gemini not enabled (latent)", high_rows, len(high_rows))
            + card("low",      "Low",      "Explicitly Gemini-scoped key, Gemini enabled", low_rows, len(low_rows))
            + clean_card
        )

    error_banner = ""
    if scan_error:
        error_banner = f'<div class="error-banner">Scan error: {scan_error}</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>aizkaban</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&display=swap');
:root {{
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
}}
@media (prefers-color-scheme: dark) {{
  :root {{
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
  }}
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: "DM Sans", ui-sans-serif, system-ui, sans-serif;
  background: var(--bg); color: var(--text);
  font-size: 14px; line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}}
header {{
  padding: 20px 40px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
}}
.logo {{ font-size: 20px; font-weight: 600; letter-spacing: -0.4px; }}
.header-right {{ margin-left: auto; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
.scan-meta {{ font-size: 12px; color: var(--muted); }}
.spinner {{
  display: none; width: 14px; height: 14px;
  border: 2px solid var(--border); border-top-color: var(--muted);
  border-radius: 50%; animation: spin .7s linear infinite;
}}
@keyframes spin {{ to {{ transform: rotate(360deg); }} }}
.btn {{
  font-size: 12px; font-weight: 500;
  background: var(--text); color: var(--bg);
  border: none; border-radius: 6px;
  padding: 7px 16px; cursor: pointer;
  transition: opacity .15s; font-family: inherit;
}}
.btn:hover {{ opacity: .8; }}
.btn:disabled {{ opacity: .4; cursor: not-allowed; }}
main {{ max-width: 1100px; margin: 0 auto; padding: 28px 40px 60px; }}
.no-data {{ padding: 60px 0; text-align: center; color: var(--muted); }}
.error-banner {{
  background: var(--critical-bg); color: var(--critical);
  border: 1px solid var(--critical); border-radius: var(--radius);
  padding: 10px 16px; margin-bottom: 20px; font-size: 13px;
}}
.stat-bar {{
  display: flex; gap: 12px; margin-bottom: 32px; flex-wrap: wrap;
}}
.stat-group {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); display: flex; overflow: hidden; flex: 1; min-width: 280px;
}}
.stat-group-label {{
  writing-mode: vertical-rl; text-orientation: mixed;
  font-size: 10px; font-weight: 500; text-transform: uppercase;
  letter-spacing: .08em; color: var(--muted);
  padding: 12px 8px; border-right: 1px solid var(--border);
  background: var(--bg);
  display: flex; align-items: center; justify-content: center;
}}
.stat-cells {{ display: flex; flex: 1; }}
.stat {{
  flex: 1; padding: 14px 16px;
  border-right: 1px solid var(--border);
}}
.stat:last-child {{ border-right: none; }}
.stat-value {{ font-size: 28px; font-weight: 600; line-height: 1; margin-bottom: 4px; }}
.stat-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }}
.stat.critical .stat-value {{ color: var(--critical); }}
.stat.high     .stat-value {{ color: var(--high); }}
.stat.low      .stat-value {{ color: var(--low); }}
.stat.info     .stat-value {{ color: var(--info); }}
.card {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); margin-bottom: 16px; overflow: hidden;
}}
.card-header {{
  display: flex; align-items: center; gap: 10px;
  padding: 12px 18px; border-bottom: 1px solid var(--border);
}}
.card-header.critical {{ background: var(--critical-bg); }}
.card-header.high     {{ background: var(--high-bg); }}
.card-header.low      {{ background: var(--low-bg); }}
.card-header.info     {{ background: var(--info-bg); }}
.dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }}
.dot.critical {{ background: var(--critical); }}
.dot.high     {{ background: var(--high); }}
.dot.low      {{ background: var(--low); }}
.dot.info     {{ background: var(--info); }}
.card-title {{ font-weight: 600; font-size: 13px; }}
.card-desc  {{ font-size: 12px; color: var(--muted); }}
.card-count {{
  margin-left: auto; font-size: 12px; color: var(--muted);
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 20px; padding: 2px 10px;
}}
.table-wrap {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{
  text-align: left; font-size: 11px; font-weight: 500;
  text-transform: uppercase; letter-spacing: .05em; color: var(--muted);
  padding: 9px 16px; border-bottom: 1px solid var(--border);
  cursor: pointer; user-select: none; white-space: nowrap;
}}
th:hover {{ color: var(--text); }}
th.asc::after  {{ content: " ↑"; }}
th.desc::after {{ content: " ↓"; }}
td {{ padding: 9px 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
tr:last-child td {{ border-bottom: none; }}
tr:hover td {{ background: var(--bg); }}
.mono {{ font-family: "JetBrains Mono", "Fira Code", monospace; font-size: 11px; color: var(--muted); }}
.badge-pre {{
  display: inline-block; font-size: 10px; font-weight: 500;
  background: var(--pre-bg); color: var(--pre-color);
  border: 1px solid var(--pre-color); border-radius: 4px; padding: 1px 6px;
}}
.empty {{ padding: 18px; color: var(--muted); font-size: 13px; }}
footer {{
  text-align: center; padding: 20px; font-size: 11px;
  color: var(--muted); border-top: 1px solid var(--border);
}}
@media print {{
  .btn, .spinner {{ display: none !important; }}
  .card {{ break-inside: avoid; }}
  tr:hover td {{ background: none; }}
}}
</style>
</head>
<body>
<header>
  <div class="logo">aizkaban</div>
  <div class="header-right">
    <span class="scan-meta" id="meta">{org_str}</span>
    <div class="spinner" id="spinner"></div>
    <button class="btn" id="refreshBtn" onclick="startRefresh()">Refresh</button>
  </div>
</header>
<main>
{error_banner}{body}
</main>
<footer>aizkaban &nbsp;·&nbsp; API Key Auditor &nbsp;·&nbsp; {footer_time}</footer>
<script>
{"let polling = null;" if not scan_running else "document.addEventListener('DOMContentLoaded', () => startPolling());"}

function startRefresh() {{
  fetch('/refresh', {{method: 'POST'}})
    .then(r => r.json())
    .then(d => {{
      if (d.status === 'started' || d.status === 'already_running') {{
        setScanning(true);
        startPolling();
      }}
    }})
    .catch(() => document.getElementById('meta').textContent = 'Error — try again');
}}

function startPolling() {{
  if (polling) return;
  polling = setInterval(() => {{
    fetch('/status')
      .then(r => r.json())
      .then(d => {{
        if (!d.running) {{
          clearInterval(polling);
          polling = null;
          location.reload();
        }}
      }});
  }}, 3000);
}}

function setScanning(on) {{
  const btn = document.getElementById('refreshBtn');
  const sp  = document.getElementById('spinner');
  btn.disabled = on;
  btn.textContent = on ? 'Scanning…' : 'Refresh';
  sp.style.display = on ? 'block' : 'none';
}}

{"startPolling();" if scan_running else ""}
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
    get_db()  # initialise in-memory DB
    port = int(os.environ.get("PORT", 8080))
    log.info("aizkaban starting on port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False)
