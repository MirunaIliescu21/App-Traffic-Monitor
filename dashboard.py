#!/usr/bin/env python3
"""
Dashboard web pentru monitorul de trafic.

Ruleaza in PARALEL cu watcher.py, intr-un terminal separat:
  python3 dashboard.py

Deschide browser la: http://localhost:5000

Citeste traficul din baza de date si, in plus, scrie DOAR deciziile
utilizatorului despre destinatii noi ("E normal" / "Nu recunosc") in
tabela destination_status - nu modifica niciodata conexiunile colectate.
Compatibil cu watcher_v6.py (traffic_monitor.db).
"""

import sqlite3
import os
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from flask import Flask, jsonify, render_template_string, request

import companies
import destination_status as ds
import phishing_check
import phishing_store as pstore

DB_PATH = "traffic_monitor.db"
ALERTS_LOG_PATH = "alerts.log"
PORT = 5000
# Singurele adrese cu care se poate accesa dashboard-ul (vezi _request_is_trusted)
ALLOWED_HOSTS = {f"localhost:{PORT}", f"127.0.0.1:{PORT}"}

app = Flask(__name__)


# ---------- Citire date ----------

def get_db():
    if not os.path.exists(DB_PATH):
        return None
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    ds.init_tables(conn)  # no-op daca exista; dashboard-ul poate porni inaintea watcher-ului
    pstore.init_tables(conn)
    return conn


def read_recent_alerts(n=20) -> list[dict]:
    """Citeste ultimele N alerte din alerts.log."""
    if not os.path.exists(ALERTS_LOG_PATH):
        return []
    lines = []
    with open(ALERTS_LOG_PATH, encoding="utf-8") as f:
        lines = f.readlines()
    alerts = []
    for line in reversed(lines[-n:]):
        line = line.strip()
        if not line:
            continue
        alerts.append({"raw": line})
    return alerts


def read_recent_inbound(conn, n=20) -> list[dict]:
    """Ultimele N conexiuni primite (atacuri potentiale)."""
    cur = conn.execute("""
        SELECT timestamp, process_name, local_port, remote_ip, remote_port
        FROM inbound_events
        ORDER BY id DESC LIMIT ?
    """, (n,))
    return [dict(row) for row in cur.fetchall()]


def read_process_summary(conn) -> list[dict]:
    """
    Rezumat per proces: total conexiuni externe unice din ultimele 24h,
    sortate dupa activitate, ca sa vedem repede cine "vorbeste" cel mai mult.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    cur = conn.execute("""
        SELECT
            process_name,
            COUNT(*) as total,
            COUNT(DISTINCT remote_ip) as unique_ips,
            MAX(timestamp) as last_seen
        FROM connections
        WHERE timestamp > ?
          AND remote_ip NOT LIKE '192.168.%'
          AND remote_ip NOT LIKE '10.%'
          AND remote_ip NOT LIKE '127.%'
          AND remote_ip NOT LIKE '172.1%'
          AND remote_ip NOT LIKE '172.2%'
          AND remote_ip NOT LIKE '172.3%'
          AND remote_ip NOT LIKE '::1%'
          AND remote_ip NOT LIKE '::ffff:127%'
        GROUP BY process_name
        ORDER BY total DESC
        LIMIT 15
    """, (cutoff,))
    return [dict(row) for row in cur.fetchall()]


def read_recent_new_connections(conn, n=30) -> list[dict]:
    """Ultimele N combinatii (proces, IP) vazute pentru prima data."""
    cur = conn.execute("""
        SELECT process_name, remote_ip, remote_hostname, first_seen_at
        FROM notified_pairs
        ORDER BY first_seen_at DESC LIMIT ?
    """, (n,))
    return [dict(row) for row in cur.fetchall()]


def _with_display(row: dict) -> dict:
    """Adauga titlul si descrierea in limbaj simplu (companie in loc de cifre)."""
    title, description = companies.display(row["group_key"], row["group_type"])
    return {**row, "title": title, "description": description}


def _phishing_row(row: dict) -> dict:
    """Adauga adresa oficiala a brandului imitat (pentru mesajul din banda)."""
    brand = phishing_check.BRANDS.get(row.get("brand") or "")
    return {**row, "official": brand["domains"][0] if brand else None}


def read_phishing(conn) -> dict:
    return {
        "active": [_phishing_row(r) for r in pstore.active_alerts(conn)],
        "recent": [_phishing_row(r) for r in pstore.grouped_events(conn, 20)],
        "allowlist": pstore.list_allowlist(conn),
    }


# ---------- API endpoints ----------

@app.route("/api/status")
def api_status():
    conn = get_db()
    if conn is None:
        return jsonify({"error": "traffic_monitor.db negasit — porneste watcher.py mai intai"})

    process_summary = read_process_summary(conn)
    inbound = read_recent_inbound(conn)
    new_conns = read_recent_new_connections(conn)
    alerts = read_recent_alerts()

    pending = [_with_display(d) for d in ds.list_by_status(conn, ds.PENDING)]
    marked = [_with_display(d) for d in
              ds.list_by_status(conn, ds.NORMAL, 100) + ds.list_by_status(conn, ds.SUSPICIOUS, 100)]
    marked.sort(key=lambda d: d["decided_at"] or "", reverse=True)
    decision_log = ds.list_decision_log(conn, 30)
    phishing = read_phishing(conn)

    # numar total de conexiuni din ultimele 24h
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    cur = conn.execute("SELECT COUNT(*) FROM connections WHERE timestamp > ?", (cutoff,))
    total_24h = cur.fetchone()[0]

    conn.close()
    return jsonify({
        "total_connections_24h": total_24h,
        "process_summary": process_summary,
        "recent_inbound": inbound,
        "recent_new_connections": new_conns,
        "recent_alerts": alerts,
        "pending": pending,
        "marked": marked,
        "decision_log": decision_log,
        "phishing": phishing,
        "generated_at": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
    })


def _request_is_trusted() -> bool:
    """
    Dashboard-ul n-are autentificare (ruleaza doar pe 127.0.0.1), dar un site
    deschis in alt tab poate trimite cereri catre localhost. Ca nicio pagina
    straina sa nu poata apasa "E normal" in locul utilizatorului (si astfel sa
    amuteasca alertele), acceptam decizii doar daca:
      - Host e adresa dashboard-ului (blocheaza DNS rebinding),
      - Origin, daca exista, e tot dashboard-ul,
      - corpul e JSON (un site strain nu poate trimite JSON cross-origin fara
        preflight CORS, la care nu raspundem niciodata).
    """
    if request.headers.get("Host", "") not in ALLOWED_HOSTS:
        return False
    origin = request.headers.get("Origin")
    if origin is not None and origin not in {f"http://{h}" for h in ALLOWED_HOSTS}:
        return False
    return request.mimetype == "application/json"


@app.route("/api/decision", methods=["POST"])
def api_decision():
    """Aplica decizia utilizatorului: {process_name, group_key, status}."""
    if not _request_is_trusted():
        return jsonify({"error": "cerere refuzata"}), 403
    data = request.get_json(silent=True) or {}
    process_name = data.get("process_name")
    group_key = data.get("group_key")
    status = data.get("status")
    if not isinstance(process_name, str) or not isinstance(group_key, str) or status not in ds.VALID_STATUSES:
        return jsonify({"error": "date invalide"}), 400
    conn = get_db()
    if conn is None:
        return jsonify({"error": "baza de date lipseste"}), 503
    try:
        found = ds.set_status(conn, process_name, group_key, status)
    finally:
        conn.close()
    if not found:
        return jsonify({"error": "destinatia nu exista"}), 404
    return jsonify({"ok": True, "status": status})


PHISHING_ACTIONS = ("dismiss", "allow", "unallow")


@app.route("/api/phishing", methods=["POST"])
def api_phishing():
    """
    Decizia utilizatorului despre o alerta de phishing: {host, action}.
    Aceeasi protectie ca la /api/decision: un site de phishing nu trebuie sa-si poata
    amuti singur alerta trimitand o cerere catre dashboard-ul local.
    """
    if not _request_is_trusted():
        return jsonify({"error": "cerere refuzata"}), 403
    data = request.get_json(silent=True) or {}
    host = data.get("host")
    action = data.get("action")
    if (not isinstance(host, str) or not host or len(host) > 253
            or action not in PHISHING_ACTIONS):
        return jsonify({"error": "date invalide"}), 400
    host = host.lower()
    conn = get_db()
    if conn is None:
        return jsonify({"error": "baza de date lipseste"}), 503
    try:
        if action == "dismiss":
            ok = pstore.dismiss(conn, host) > 0
        elif action == "allow":
            ok = pstore.allow(conn, host)
        else:
            ok = pstore.unallow(conn, host)
    finally:
        conn.close()
    if not ok:
        return jsonify({"error": "domeniul nu exista"}), 404
    return jsonify({"ok": True})


# ---------- Interfata web ----------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Traffic Monitor</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: #58a6ff;
    --danger: #f85149;
    --warning: #d29922;
    --ok: #3fb950;
    --mono: 'Courier New', monospace;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    line-height: 1.5;
  }

  header {
    border-bottom: 1px solid var(--border);
    padding: 16px 24px;
    display: flex;
    align-items: center;
    gap: 12px;
    position: sticky;
    top: 0;
    background: var(--bg);
    z-index: 10;
  }

  .logo { font-size: 18px; font-weight: 700; color: var(--accent); letter-spacing: -0.5px; }
  .logo span { color: var(--muted); font-weight: 400; }

  .status-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--ok);
    box-shadow: 0 0 6px var(--ok);
    animation: pulse 2s infinite;
    margin-left: auto;
  }
  .status-dot.error { background: var(--danger); box-shadow: 0 0 6px var(--danger); }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  .updated-at { color: var(--muted); font-size: 12px; font-family: var(--mono); }

  main { padding: 20px 24px; display: grid; gap: 20px; max-width: 1400px; margin: 0 auto; }

  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 900px) { .grid-2 { grid-template-columns: 1fr; } }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }

  .card-header {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .card-title { font-weight: 600; font-size: 13px; color: var(--text); text-transform: uppercase; letter-spacing: 0.5px; }
  .card-count { margin-left: auto; font-family: var(--mono); font-size: 12px; color: var(--muted); }

  /* Stat cards */
  .stat-bar { display: flex; gap: 16px; flex-wrap: wrap; }

  .stat {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 20px;
    flex: 1;
    min-width: 140px;
  }

  .stat-value { font-size: 28px; font-weight: 700; font-family: var(--mono); color: var(--accent); }
  .stat-label { color: var(--muted); font-size: 12px; margin-top: 4px; }

  /* Tabele */
  table { width: 100%; border-collapse: collapse; }

  th {
    padding: 8px 16px;
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--border);
  }

  td {
    padding: 8px 16px;
    border-bottom: 1px solid #1c2128;
    font-size: 13px;
    font-family: var(--mono);
  }

  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(88, 166, 255, 0.04); }

  .proc-name { color: var(--accent); }
  .ip-addr { color: var(--text); }
  .muted { color: var(--muted); font-size: 11px; }
  .ts { color: var(--muted); font-size: 11px; }

  /* Badge de risc */
  .badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
  }
  .badge-danger { background: rgba(248, 81, 73, 0.15); color: var(--danger); border: 1px solid rgba(248,81,73,0.3); }
  .badge-warning { background: rgba(210, 153, 34, 0.15); color: var(--warning); border: 1px solid rgba(210,153,34,0.3); }

  /* Alerte */
  .alert-line {
    padding: 8px 16px;
    border-bottom: 1px solid #1c2128;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
  }
  .alert-line:last-child { border-bottom: none; }
  .alert-line.is-risk { color: var(--warning); }
  .alert-line.is-inbound { color: var(--danger); }

  /* Destinatii de verificat + butoane */
  .btn {
    font: inherit; font-size: 12px; font-weight: 600;
    padding: 5px 12px; border-radius: 6px; cursor: pointer;
    background: transparent; color: var(--text); border: 1px solid var(--border);
  }
  .btn:disabled { opacity: 0.5; cursor: wait; }
  .btn-ok { color: var(--ok); border-color: rgba(63,185,80,0.4); }
  .btn-ok:hover:not(:disabled) { background: rgba(63,185,80,0.12); }
  .btn-bad { color: var(--danger); border-color: rgba(248,81,73,0.4); }
  .btn-bad:hover:not(:disabled) { background: rgba(248,81,73,0.12); }
  .btn-ghost { color: var(--muted); }
  .btn-ghost:hover:not(:disabled) { background: rgba(139,148,158,0.12); }
  .badge-ok { background: rgba(63,185,80,0.15); color: var(--ok); border: 1px solid rgba(63,185,80,0.3); }

  .card-intro { padding: 12px 16px; color: var(--muted); font-size: 13px; border-bottom: 1px solid var(--border); }
  .pending-item {
    padding: 12px 16px; border-bottom: 1px solid #1c2128;
    display: flex; gap: 16px; align-items: center; flex-wrap: wrap;
  }
  .pending-item:last-child { border-bottom: none; }
  .pending-text { flex: 1; min-width: 240px; }
  .pending-title { font-size: 14px; }
  .pending-desc { color: var(--text); opacity: 0.75; font-size: 13px; margin-top: 2px; }
  .pending-sub { color: var(--muted); font-size: 12px; font-family: var(--mono); margin-top: 2px; word-break: break-all; }
  .pending-actions { display: flex; gap: 8px; }
  .card-attention { border-color: rgba(210,153,34,0.5); }

  /* Phishing */
  .banner-phishing {
    background: rgba(248,81,73,0.12);
    border: 1px solid var(--danger);
    border-radius: 8px;
    overflow: hidden;
  }
  .banner-phishing .banner-item { padding: 14px 16px; border-bottom: 1px solid rgba(248,81,73,0.3); }
  .banner-phishing .banner-item:last-child { border-bottom: none; }
  .banner-title { font-size: 15px; font-weight: 700; color: var(--danger); }
  .banner-text { margin-top: 4px; }
  .banner-sub { margin-top: 4px; color: var(--muted); font-size: 12px; font-family: var(--mono); word-break: break-all; }
  .banner-actions { margin-top: 10px; display: flex; gap: 8px; flex-wrap: wrap; }
  .stat-danger .stat-value { color: var(--danger); }

  .empty { padding: 20px 16px; color: var(--muted); font-style: italic; font-size: 13px; }

  /* Bara de progres pentru #conexiuni */
  .bar-wrap { display: flex; align-items: center; gap: 8px; }
  .bar { height: 4px; background: var(--border); border-radius: 2px; flex: 1; overflow: hidden; }
  .bar-fill { height: 100%; background: var(--accent); border-radius: 2px; transition: width 0.3s; }
  .bar-val { font-family: var(--mono); font-size: 11px; color: var(--muted); min-width: 40px; text-align: right; }
</style>
</head>
<body>

<header>
  <div class="logo">Traffic<span>Monitor</span></div>
  <div class="updated-at" id="updated-at">—</div>
  <div class="status-dot" id="status-dot"></div>
</header>

<main>

  <!-- Alerte de phishing active: banda ramane vizibila pana o inchizi -->
  <div id="phishing-banner"></div>

  <!-- Statistici rapide -->
  <div class="stat-bar" id="stat-bar">
    <div class="stat">
      <div class="stat-value" id="stat-total">—</div>
      <div class="stat-label">Conexiuni externe (24h)</div>
    </div>
    <div class="stat" id="stat-phishing-box">
      <div class="stat-value" id="stat-phishing">—</div>
      <div class="stat-label">Alerte phishing active</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="stat-pending">—</div>
      <div class="stat-label">De verificat</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="stat-processes">—</div>
      <div class="stat-label">Procese active</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="stat-inbound">—</div>
      <div class="stat-label">Conexiuni primite (inbound)</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="stat-alerts">—</div>
      <div class="stat-label">Alerte in jurnal</div>
    </div>
  </div>

  <!-- Site-uri suspecte deschise in browser -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">🎣 Site-uri suspecte deschise</div>
      <div class="card-count" id="phishing-count">—</div>
    </div>
    <div class="card-intro">
      Paginile deschise in Firefox al caror nume imita un brand cunoscut (OLX, banci, curieri).
      Se vad doar paginile deschise, nu si ferestrele private. Daca un site e de fapt real,
      apasa „Este site-ul real” si nu te mai anunt pentru el.
    </div>
    <div id="phishing-list"></div>
    <div id="phishing-allow"></div>
  </div>

  <!-- Destinatii de verificat: decizia utilizatorului -->
  <div class="card" id="pending-card">
    <div class="card-header">
      <div class="card-title">🟡 De verificat</div>
      <div class="card-count" id="pending-count">—</div>
    </div>
    <div class="card-intro">
      Programe pe care le stiam au contactat pentru prima data destinatii noi.
      Spune-mi daca le recunosti: „E normal” nu te mai deranjeaza pentru ele,
      „Nu recunosc” te anunta de fiecare data cand revin.
    </div>
    <div id="pending-list"></div>
  </div>

  <div class="grid-2">

    <!-- Deciziile tale -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Deciziile tale</div>
        <div class="card-count" id="marked-count">—</div>
      </div>
      <div id="marked-list"></div>
    </div>

    <!-- Istoric decizii -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Istoric decizii</div>
        <div class="card-count" id="log-count">—</div>
      </div>
      <div id="log-list"></div>
    </div>

  </div>

  <div class="grid-2">

    <!-- Procese active -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Procese active (24h)</div>
        <div class="card-count" id="proc-count">—</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Proces</th>
            <th>Conexiuni</th>
            <th>IP-uri distincte</th>
            <th>Ultima activitate</th>
          </tr>
        </thead>
        <tbody id="proc-table"></tbody>
      </table>
    </div>

    <!-- Alerte -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Jurnal alerte</div>
        <div class="card-count" id="alert-count">—</div>
      </div>
      <div id="alert-list"></div>
    </div>

  </div>

  <div class="grid-2">

    <!-- Conexiuni primite (inbound) -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">🔴 Conexiuni primite</div>
        <div class="card-count" id="inbound-count">—</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Sursa (atacator)</th>
            <th>Proces vizat</th>
            <th>Port local</th>
            <th>Cand</th>
          </tr>
        </thead>
        <tbody id="inbound-table"></tbody>
      </table>
    </div>

    <!-- Conexiuni noi vazute -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">Conexiuni noi observate</div>
        <div class="card-count" id="newconn-count">—</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Proces</th>
            <th>Destinatie</th>
            <th>Prima data vazut</th>
          </tr>
        </thead>
        <tbody id="newconn-table"></tbody>
      </table>
    </div>

  </div>

</main>

<script>
// Textele din retea (nume de host, procese) sunt controlate de terti: le
// escapam INAINTE sa ajunga in HTML, altfel un nume de host rau intentionat
// ar rula cod in pagina.
function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => (
    {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function fmt_dt(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString('ro-RO', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});
  } catch { return ts.substring(0,16); }
}

const STATUS_LABEL = {pending: 'de verificat', normal: 'normal', suspicious: 'suspect'};

function render_pending(list) {
  document.getElementById('pending-card').classList.toggle('card-attention', list.length > 0);
  document.getElementById('pending-count').textContent = list.length;
  document.getElementById('pending-list').innerHTML = list.length ? list.map(x => {
    const where = x.sample_hostname || x.sample_ip || '';
    const attrs = `data-proc="${esc(x.process_name)}" data-key="${esc(x.group_key)}"`;
    return `
      <div class="pending-item">
        <div class="pending-text">
          <div class="pending-title"><strong>${esc(x.process_name)}</strong> s-a conectat pentru prima data la <strong>${esc(x.title)}</strong></div>
          <div class="pending-desc">${esc(x.description)}</div>
          <div class="pending-sub">${esc(where)} · ${fmt_dt(x.first_seen)}</div>
        </div>
        <div class="pending-actions">
          <button class="btn btn-ok" data-action="normal" ${attrs}>✔ E normal</button>
          <button class="btn btn-bad" data-action="suspicious" ${attrs}>✖ Nu recunosc</button>
        </div>
      </div>`;
  }).join('') : '<div class="empty">Nimic de verificat — totul e la zi.</div>';
}

function render_marked(list) {
  document.getElementById('marked-count').textContent = list.length;
  document.getElementById('marked-list').innerHTML = list.length ? list.map(x => {
    const bad = x.status === 'suspicious';
    const attrs = `data-proc="${esc(x.process_name)}" data-key="${esc(x.group_key)}"`;
    return `
      <div class="pending-item">
        <div class="pending-text">
          <div class="pending-title"><strong>${esc(x.process_name)}</strong> → ${esc(x.title)}
            <span class="badge ${bad ? 'badge-danger' : 'badge-ok'}">${bad ? 'Nu recunosc' : 'Normal'}</span></div>
          <div class="pending-sub">decis ${fmt_dt(x.decided_at)}</div>
        </div>
        <div class="pending-actions">
          <button class="btn btn-ghost" data-action="pending" ${attrs}>Anuleaza decizia</button>
        </div>
      </div>`;
  }).join('') : '<div class="empty">Nicio decizie inca.</div>';
}

function render_log(list) {
  document.getElementById('log-count').textContent = list.length;
  document.getElementById('log-list').innerHTML = list.length ? list.map(x => `
    <div class="alert-line">${fmt_dt(x.timestamp)} · ${esc(x.process_name)} → ${esc(x.group_key)}:
      ${esc(STATUS_LABEL[x.old_status] || x.old_status)} → <strong>${esc(STATUS_LABEL[x.new_status] || x.new_status)}</strong></div>
  `).join('') : '<div class="empty">Nicio decizie in istoric.</div>';
}

function render_phishing(p) {
  const active = p.active;
  document.getElementById('stat-phishing').textContent = active.length;
  document.getElementById('stat-phishing-box').classList.toggle('stat-danger', active.length > 0);

  const btn = (host, action, label, cls) =>
    `<button class="btn ${cls}" data-phish-action="${action}" data-phish-host="${esc(host)}">${label}</button>`;

  document.getElementById('phishing-banner').innerHTML = active.length ? `
    <div class="banner-phishing">${active.slice(0, 3).map(a => `
      <div class="banner-item">
        <div class="banner-title">⚠️ ${a.brand ? 'Site care seamana cu ' + esc(a.brand) : 'Site suspect'}: ${esc(a.host)}</div>
        <div class="banner-text">${a.official ? 'Adresa oficiala ' + esc(a.brand) + ' este <strong>' + esc(a.official) + '</strong>. ' : ''}Nu introduce parole sau date de card pe acest site. Daca ai facut-o deja: blocheaza cardul si schimba parola acum.</div>
        <div class="banner-sub">${esc(a.reasons)} · ${fmt_dt(a.timestamp)}</div>
        <div class="banner-actions">
          ${btn(a.host, 'dismiss', 'Am inteles', 'btn-ghost')}
          ${btn(a.host, 'allow', 'Este site-ul real', 'btn-ok')}
        </div>
      </div>`).join('')}
      ${active.length > 3 ? `<div class="banner-item banner-sub">si inca ${active.length - 3} alerte, mai jos</div>` : ''}
    </div>` : '';

  document.getElementById('phishing-count').textContent = p.recent.length;
  document.getElementById('phishing-list').innerHTML = p.recent.length ? p.recent.map(x => `
    <div class="pending-item">
      <div class="pending-text">
        <div class="pending-title"><strong>${esc(x.host)}</strong>
          <span class="badge ${x.alerted ? 'badge-danger' : 'badge-warning'}">${esc(x.score)}/100</span>
          ${x.brand ? '<span class="muted">seamana cu ' + esc(x.brand) + '</span>' : ''}</div>
        <div class="pending-desc">${esc(x.reasons)}</div>
        <div class="pending-sub">${x.visits > 1 ? '×' + esc(x.visits) + ' deschideri · prima ' + fmt_dt(x.first_seen) + ' · ultima ' + fmt_dt(x.last_seen) : fmt_dt(x.last_seen)} · prin ${esc(x.kind)}</div>
      </div>
      <div class="pending-actions">${x.alerted ? btn(x.host, 'allow', 'Este site-ul real', 'btn-ok') : ''}</div>
    </div>`).join('') : '<div class="empty">Niciun site suspect deschis — bine!</div>';

  document.getElementById('phishing-allow').innerHTML = p.allowlist.length ? `
    <div class="card-intro" style="border-top:1px solid var(--border);border-bottom:none">Marcate ca reale:</div>` +
    p.allowlist.map(x => `
    <div class="pending-item">
      <div class="pending-text"><div class="pending-title">${esc(x.host)}</div>
        <div class="pending-sub">din ${fmt_dt(x.added_at)}</div></div>
      <div class="pending-actions">${btn(x.host, 'unallow', 'Anuleaza', 'btn-ghost')}</div>
    </div>`).join('') : '';
}

document.addEventListener('click', async (ev) => {
  const pbtn = ev.target.closest('button[data-phish-action]');
  if (!pbtn) return;
  const host = pbtn.dataset.phishHost, action = pbtn.dataset.phishAction;
  if (action === 'allow' && !confirm('Sigur este site-ul real? Nu vei mai primi alerte pentru ' + host + '.')) return;
  pbtn.disabled = true;
  try {
    const res = await fetch('/api/phishing', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({host, action}),
    });
    if (!res.ok) alert('Nu am putut salva decizia (' + res.status + ').');
  } catch (e) {
    alert('Nu am putut salva decizia: ' + e.message);
  }
  await refresh();
});

document.addEventListener('click', async (ev) => {
  const btn = ev.target.closest('button[data-action]');
  if (!btn) return;
  btn.disabled = true;
  try {
    const res = await fetch('/api/decision', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        process_name: btn.dataset.proc,
        group_key: btn.dataset.key,
        status: btn.dataset.action,
      }),
    });
    if (!res.ok) alert('Nu am putut salva decizia (' + res.status + ').');
  } catch (e) {
    alert('Nu am putut salva decizia: ' + e.message);
  }
  await refresh();
});

function fmt_ts(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString('ro-RO', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  } catch { return ts.substring(11,19); }
}

function max_conn(processes) {
  return Math.max(...processes.map(p => p.total), 1);
}

async function refresh() {
  try {
    const res = await fetch('/api/status');
    const d = await res.json();

    if (d.error) {
      document.getElementById('status-dot').className = 'status-dot error';
      document.getElementById('updated-at').textContent = d.error;
      return;
    }

    document.getElementById('status-dot').className = 'status-dot';
    document.getElementById('updated-at').textContent = 'actualizat la ' + d.generated_at;

    // Statistici
    document.getElementById('stat-total').textContent = d.total_connections_24h.toLocaleString();
    document.getElementById('stat-pending').textContent = d.pending.length;
    document.getElementById('stat-processes').textContent = d.process_summary.length;
    render_phishing(d.phishing);
    render_pending(d.pending);
    render_marked(d.marked);
    render_log(d.decision_log);
    document.getElementById('stat-inbound').textContent = d.recent_inbound.length;
    document.getElementById('stat-alerts').textContent = d.recent_alerts.length;

    // Procese
    const maxConn = max_conn(d.process_summary);
    document.getElementById('proc-count').textContent = d.process_summary.length + ' procese';
    document.getElementById('proc-table').innerHTML = d.process_summary.map(p => `
      <tr>
        <td class="proc-name">${esc(p.process_name)}</td>
        <td>
          <div class="bar-wrap">
            <div class="bar"><div class="bar-fill" style="width:${Math.round(p.total/maxConn*100)}%"></div></div>
            <div class="bar-val">${p.total}</div>
          </div>
        </td>
        <td class="muted">${p.unique_ips}</td>
        <td class="ts">${fmt_dt(p.last_seen)}</td>
      </tr>
    `).join('') || '<tr><td colspan="4" class="empty">Nicio activitate inregistrata inca.</td></tr>';

    // Alerte
    document.getElementById('alert-count').textContent = d.recent_alerts.length + ' alerte';
    document.getElementById('alert-list').innerHTML = d.recent_alerts.length
      ? d.recent_alerts.map(a => {
          const cls = (a.raw.includes('[INBOUND]') || a.raw.includes('[NU-RECUNOSC]') || a.raw.includes('[PHISHING')) ? 'is-inbound'
                    : a.raw.includes('[RISC')     ? 'is-risk'
                    : '';
          return `<div class="alert-line ${cls}">${esc(a.raw)}</div>`;
        }).join('')
      : '<div class="empty">Nicio alerta inregistrata — bine!</div>';

    // Inbound
    document.getElementById('inbound-count').textContent = d.recent_inbound.length;
    document.getElementById('inbound-table').innerHTML = d.recent_inbound.map(c => `
      <tr>
        <td><span class="badge badge-danger">${esc(c.remote_ip)}</span></td>
        <td class="proc-name">${esc(c.process_name || '—')}</td>
        <td class="muted">${c.local_port}</td>
        <td class="ts">${fmt_dt(c.timestamp)}</td>
      </tr>
    `).join('') || '<tr><td colspan="4" class="empty">Nicio conexiune primita.</td></tr>';

    // Conexiuni noi
    document.getElementById('newconn-count').textContent = d.recent_new_connections.length;
    document.getElementById('newconn-table').innerHTML = d.recent_new_connections.map(c => {
      const display = (c.remote_hostname && c.remote_hostname !== c.remote_ip)
        ? `<span style="color:var(--text)">${esc(c.remote_hostname)}</span><br><span class="muted">${esc(c.remote_ip)}</span>`
        : `<span class="ip-addr">${esc(c.remote_ip)}</span>`;
      return `
        <tr>
          <td class="proc-name">${esc(c.process_name)}</td>
          <td>${display}</td>
          <td class="ts">${fmt_dt(c.first_seen_at)}</td>
        </tr>`;
    }).join('') || '<tr><td colspan="3" class="empty">Nicio conexiune noua inca.</td></tr>';

  } catch (e) {
    document.getElementById('status-dot').className = 'status-dot error';
    document.getElementById('updated-at').textContent = 'Eroare la conectare: ' + e.message;
  }
}

// Actualizare automata la fiecare 5 secunde
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


if __name__ == "__main__":
    print("[*] Dashboard pornit la http://localhost:5000")
    print("[*] Ruleaza in paralel cu watcher_v6.py — scrie doar deciziile tale (E normal / Nu recunosc)")
    print("[*] Actualizare automata la fiecare 5 secunde")
    print("[*] Ctrl+C pentru oprire\n")
    app.run(host="127.0.0.1", port=PORT, debug=False)
