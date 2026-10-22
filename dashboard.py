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
        return jsonify({"error": "traffic_monitor.db negasit \u2014 porneste watcher.py mai intai"})

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

  /* ===== Navigare, pagini, stare generala, casete ===== */
  [hidden] { display: none !important; }
  header { flex-wrap: wrap; }
  nav { display: flex; gap: 4px; flex-wrap: wrap; margin-left: 16px; }
  nav a {
    color: var(--muted); text-decoration: none; font-size: 14px; font-weight: 600;
    padding: 6px 12px; border-radius: 6px; border: 1px solid transparent;
  }
  nav a:hover { color: var(--text); background: rgba(139,148,158,0.12); }
  nav a.active { color: var(--text); background: var(--surface); border-color: var(--border); }
  .nav-badge { display: inline-block; min-width: 18px; padding: 0 6px; margin-left: 4px; border-radius: 9px;
    font-size: 11px; font-weight: 700; text-align: center; color: #0d1117; }
  .nav-danger { background: var(--danger); }
  .nav-warn { background: var(--warning); }

  .page { display: grid; gap: 20px; }
  .page-title { font-size: 22px; font-weight: 700; }

  .hero { display: flex; gap: 20px; align-items: center; padding: 24px 28px; border-radius: 10px;
    border: 1px solid var(--border); background: var(--surface); }
  .hero-icon { width: 64px; height: 64px; flex: none; border-radius: 50%; display: flex; align-items: center; justify-content: center;
    font-size: 38px; font-weight: 700; line-height: 1; border: 3px solid currentColor; }
  .hero-ok .hero-icon { color: var(--ok); }
  .hero-warn .hero-icon { color: var(--warning); }
  .hero-danger .hero-icon { color: var(--danger); }
  .hero-title { font-size: 26px; font-weight: 700; }
  .hero-text { margin-top: 4px; font-size: 15px; color: var(--muted); }
  .hero-ok { border-color: rgba(63,185,80,0.5); background: rgba(63,185,80,0.08); }
  .hero-ok .hero-title { color: var(--ok); }
  .hero-warn { border-color: rgba(210,153,34,0.6); background: rgba(210,153,34,0.08); }
  .hero-warn .hero-title { color: var(--warning); }
  .hero-danger { border-color: var(--danger); background: rgba(248,81,73,0.12); }
  .hero-danger .hero-title { color: var(--danger); }

  .tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
  @media (max-width: 900px) { .tiles { grid-template-columns: repeat(2, 1fr); } }
  .tile { display: block; text-decoration: none; color: var(--text); background: var(--surface);
    border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; }
  .tile:hover { border-color: var(--accent); background: rgba(88,166,255,0.06); }
  .tile-value { font-size: 36px; font-weight: 700; font-family: var(--mono); color: var(--accent); }
  .tile-label { font-size: 15px; font-weight: 600; margin-top: 2px; }
  .tile-hint { color: var(--muted); font-size: 12px; margin-top: 4px; }
  .tile-danger { border-color: var(--danger); }
  .tile-danger .tile-value { color: var(--danger); }
  .tile-warn { border-color: rgba(210,153,34,0.6); }
  .tile-warn .tile-value { color: var(--warning); }
  .banner-more { display: block; text-decoration: none; color: var(--danger); font-weight: 600; }
  #phishing-banner:empty, #home-phishing:empty { display: none; }
</style>
</head>
<body>

<header>
  <div class="logo">Traffic<span>Monitor</span></div>
  <nav id="nav">
    <a href="#/" data-route="home">Prezentare generala</a>
    <a href="#/phishing" data-route="phishing">Phishing <span class="nav-badge nav-danger" id="nav-phishing" hidden></span></a>
    <a href="#/de-verificat" data-route="pending">De verificat <span class="nav-badge nav-warn" id="nav-pending" hidden></span></a>
    <a href="#/programe" data-route="programs">Programe</a>
    <a href="#/jurnal" data-route="log">Jurnal alerte</a>
    <a href="#/conexiuni-primite" data-route="inbound">Conexiuni primite <span class="nav-badge nav-danger" id="nav-inbound" hidden></span></a>
  </nav>
  <div class="updated-at" id="updated-at">\u2014</div>
  <div class="status-dot" id="status-dot"></div>
</header>

<main>

  <!-- ===== Prezentare generala: "Sunt in pericol acum?" ===== -->
  <section class="page" data-page="home">
    <div class="hero hero-ok" id="hero">
      <div class="hero-icon" id="hero-icon">\u2026</div>
      <div>
        <div class="hero-title" id="hero-title">Se incarca...</div>
        <div class="hero-text" id="hero-text"></div>
      </div>
    </div>

    <div id="home-phishing"></div>

    <div class="tiles">
      <a class="tile" href="#/phishing" id="tile-phishing">
        <div class="tile-value" id="tile-phishing-value">\u2014</div>
        <div class="tile-label">Alerte de phishing</div>
        <div class="tile-hint" id="tile-phishing-hint"></div>
      </a>
      <a class="tile" href="#/de-verificat" id="tile-pending">
        <div class="tile-value" id="tile-pending-value">\u2014</div>
        <div class="tile-label">De verificat</div>
        <div class="tile-hint">destinatii noi pe care sa le confirmi</div>
      </a>
      <a class="tile" href="#/jurnal" id="tile-log">
        <div class="tile-value" id="tile-log-value">\u2014</div>
        <div class="tile-label">Jurnal alerte</div>
        <div class="tile-hint">ultimele alerte primite</div>
      </a>
      <a class="tile" href="#/programe" id="tile-programs">
        <div class="tile-value" id="tile-programs-value">\u2014</div>
        <div class="tile-label">Programe active</div>
        <div class="tile-hint">programe care folosesc internetul</div>
      </a>
    </div>
  </section>

  <!-- ===== Phishing ===== -->
  <section class="page" data-page="phishing" hidden>
    <div class="page-title">Phishing</div>
    <div id="phishing-banner"></div>
    <div class="card">
      <div class="card-header">
        <div class="card-title">Site-uri suspecte deschise</div>
        <div class="card-count" id="phishing-count">\u2014</div>
      </div>
      <div class="card-intro">
        Paginile deschise in Firefox al caror nume imita un brand cunoscut (OLX, banci, curieri).
        Se vad doar paginile deschise, nu si ferestrele private. Daca un site e de fapt real,
        apasa \u201eEste site-ul real\u201d si nu te mai anunt pentru el.
      </div>
      <div id="phishing-list"></div>
      <div id="phishing-allow"></div>
    </div>
  </section>

  <!-- ===== De verificat ===== -->
  <section class="page" data-page="pending" hidden>
    <div class="page-title">De verificat</div>
    <div class="card" id="pending-card">
      <div class="card-header">
        <div class="card-title">Destinatii noi</div>
        <div class="card-count" id="pending-count">\u2014</div>
      </div>
      <div class="card-intro">
        Programe pe care le stiam au contactat pentru prima data destinatii noi.
        Spune-mi daca le recunosti: \u201eE normal\u201d nu te mai deranjeaza pentru ele,
        \u201eNu recunosc\u201d te anunta de fiecare data cand revin.
      </div>
      <div id="pending-list"></div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <div class="card-title">Deciziile tale</div>
          <div class="card-count" id="marked-count">\u2014</div>
        </div>
        <div id="marked-list"></div>
      </div>
      <div class="card">
        <div class="card-header">
          <div class="card-title">Istoric decizii</div>
          <div class="card-count" id="log-count">\u2014</div>
        </div>
        <div id="log-list"></div>
      </div>
    </div>
  </section>

  <!-- ===== Programe ===== -->
  <section class="page" data-page="programs" hidden>
    <div class="page-title">Programe care folosesc internetul</div>
    <div class="card"><div class="card-intro" style="border-bottom:none">
      Conexiuni externe in ultimele 24 de ore: <strong id="total-24h">\u2014</strong>
    </div></div>
    <div class="grid-2">
      <div class="card">
        <div class="card-header">
          <div class="card-title">Programe active (24h)</div>
          <div class="card-count" id="proc-count">\u2014</div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Program</th>
              <th>Conexiuni</th>
              <th>Adrese diferite</th>
              <th>Ultima activitate</th>
            </tr>
          </thead>
          <tbody id="proc-table"></tbody>
        </table>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">Conexiuni noi observate</div>
          <div class="card-count" id="newconn-count">\u2014</div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Program</th>
              <th>Destinatie</th>
              <th>Prima data vazut</th>
            </tr>
          </thead>
          <tbody id="newconn-table"></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- ===== Jurnal alerte ===== -->
  <section class="page" data-page="log" hidden>
    <div class="page-title">Jurnal alerte</div>
    <div class="card">
      <div class="card-header">
        <div class="card-title">Alerte recente</div>
        <div class="card-count" id="alert-count">\u2014</div>
      </div>
      <div id="alert-list"></div>
    </div>
  </section>

  <!-- ===== Conexiuni primite ===== -->
  <section class="page" data-page="inbound" hidden>
    <div class="page-title">Conexiuni primite din exterior</div>
    <div class="card">
      <div class="card-header">
        <div class="card-title">Cineva s-a conectat la calculatorul tau</div>
        <div class="card-count" id="inbound-count">\u2014</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Sursa</th>
            <th>Program vizat</th>
            <th>Port local</th>
            <th>Cand</th>
          </tr>
        </thead>
        <tbody id="inbound-table"></tbody>
      </table>
    </div>
  </section>

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
  if (!ts) return '\u2014';
  try {
    return new Date(ts).toLocaleString('ro-RO', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});
  } catch { return ts.substring(0,16); }
}

// ---------- Navigare intre pagini (fara reincarcare) ----------

const ROUTES = {
  '': 'home', '/': 'home', '/phishing': 'phishing', '/de-verificat': 'pending',
  '/programe': 'programs', '/jurnal': 'log', '/conexiuni-primite': 'inbound',
};

function route() {
  const page = ROUTES[location.hash.replace(/^#/, '')] || 'home';
  document.querySelectorAll('[data-page]').forEach(el => { el.hidden = el.dataset.page !== page; });
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('active', a.dataset.route === page));
  window.scrollTo(0, 0);
}
window.addEventListener('hashchange', route);
route();

// ---------- Prezentare generala ----------

function set_badge(id, n) {
  const el = document.getElementById(id);
  el.hidden = !(n > 0);
  el.textContent = n;
}

function set_tile(id, n, level) {
  document.getElementById(id + '-value').textContent = n;
  document.getElementById(id).classList.remove('tile-danger', 'tile-warn');
  if (level) document.getElementById(id).classList.add('tile-' + level);
}

function render_home(d) {
  const phishing = d.phishing.active.length;
  const pending = d.pending.length;

  let level, icon, title, text;
  if (phishing > 0) {
    level = 'danger'; icon = '!';
    title = 'Atentie: ' + phishing + (phishing === 1 ? ' alerta' : ' alerte') + ' de phishing';
    text = 'Ai deschis site-uri care imita un brand cunoscut. Nu introduce parole sau date de card pe ele.';
  } else if (pending > 0) {
    level = 'warn'; icon = '!';
    title = 'Ai ' + pending + (pending === 1 ? ' lucru' : ' lucruri') + ' de verificat';
    text = 'Programe cunoscute au contactat destinatii noi. Spune-mi daca le recunosti.';
  } else {
    level = 'ok'; icon = '\u2713';
    title = 'Totul in regula';
    text = 'Nicio alerta activa. Continui sa urmaresc in fundal.';
  }
  document.getElementById('hero').className = 'hero hero-' + level;
  document.getElementById('hero-icon').textContent = icon;
  document.getElementById('hero-title').textContent = title;
  document.getElementById('hero-text').textContent = text;

  set_tile('tile-phishing', phishing, phishing > 0 ? 'danger' : '');
  document.getElementById('tile-phishing-hint').textContent =
    d.phishing.recent.length + (d.phishing.recent.length === 1 ? ' site suspect in istoric' : ' site-uri suspecte in istoric');
  set_tile('tile-pending', pending, pending > 0 ? 'warn' : '');
  set_tile('tile-log', d.recent_alerts.length, '');
  set_tile('tile-programs', d.process_summary.length, '');

  set_badge('nav-phishing', phishing);
  set_badge('nav-pending', pending);
  set_badge('nav-inbound', d.recent_inbound.length);
}

// ---------- Phishing ----------

const STATUS_LABEL = {pending: 'de verificat', normal: 'normal', suspicious: 'suspect'};

function phish_btn(host, action, label, cls) {
  return `<button class="btn ${cls}" data-phish-action="${action}" data-phish-host="${esc(host)}">${label}</button>`;
}

function active_html(active, limit) {
  if (!active.length) return '';
  const shown = limit ? active.slice(0, limit) : active;
  const more = active.length - shown.length;
  return `<div class="banner-phishing">${shown.map(a => `
    <div class="banner-item">
      <div class="banner-title">${a.brand ? 'Site care seamana cu ' + esc(a.brand) : 'Site suspect'}: ${esc(a.host)}</div>
      <div class="banner-text">${a.official ? 'Adresa oficiala ' + esc(a.brand) + ' este <strong>' + esc(a.official) + '</strong>. ' : ''}Nu introduce parole sau date de card pe acest site. Daca ai facut-o deja: blocheaza cardul si schimba parola acum.</div>
      <div class="banner-sub">${esc(a.reasons)} \u00b7 ${fmt_dt(a.timestamp)}</div>
      <div class="banner-actions">
        ${phish_btn(a.host, 'dismiss', 'Am inteles', 'btn-ghost')}
        ${phish_btn(a.host, 'allow', 'Este site-ul real', 'btn-ok')}
      </div>
    </div>`).join('')}
    ${more > 0 ? `<a class="banner-item banner-more" href="#/phishing">Vezi toate cele ${active.length} alerte \u2192</a>` : ''}
  </div>`;
}

function render_phishing(p) {
  document.getElementById('phishing-banner').innerHTML = active_html(p.active, 0);
  document.getElementById('home-phishing').innerHTML = active_html(p.active, 3);

  document.getElementById('phishing-count').textContent = p.recent.length;
  document.getElementById('phishing-list').innerHTML = p.recent.length ? p.recent.map(x => `
    <div class="pending-item">
      <div class="pending-text">
        <div class="pending-title"><strong>${esc(x.host)}</strong>
          <span class="badge ${x.alerted ? 'badge-danger' : 'badge-warning'}">${esc(x.score)}/100</span>
          ${x.brand ? '<span class="muted">seamana cu ' + esc(x.brand) + '</span>' : ''}</div>
        <div class="pending-desc">${esc(x.reasons)}</div>
        <div class="pending-sub">${x.visits > 1 ? '\u00d7' + esc(x.visits) + ' deschideri \u00b7 prima ' + fmt_dt(x.first_seen) + ' \u00b7 ultima ' + fmt_dt(x.last_seen) : fmt_dt(x.last_seen)} \u00b7 prin ${esc(x.kind)}</div>
      </div>
      <div class="pending-actions">${x.alerted ? phish_btn(x.host, 'allow', 'Este site-ul real', 'btn-ok') : ''}</div>
    </div>`).join('') : '<div class="empty">Niciun site suspect deschis \u2014 bine!</div>';

  document.getElementById('phishing-allow').innerHTML = p.allowlist.length ? `
    <div class="card-intro" style="border-top:1px solid var(--border);border-bottom:none">Marcate ca reale:</div>` +
    p.allowlist.map(x => `
    <div class="pending-item">
      <div class="pending-text"><div class="pending-title">${esc(x.host)}</div>
        <div class="pending-sub">din ${fmt_dt(x.added_at)}</div></div>
      <div class="pending-actions">${phish_btn(x.host, 'unallow', 'Anuleaza', 'btn-ghost')}</div>
    </div>`).join('') : '';
}

// ---------- De verificat ----------

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
          <div class="pending-sub">${esc(where)} \u00b7 ${fmt_dt(x.first_seen)}</div>
        </div>
        <div class="pending-actions">
          <button class="btn btn-ok" data-action="normal" ${attrs}>E normal</button>
          <button class="btn btn-bad" data-action="suspicious" ${attrs}>Nu recunosc</button>
        </div>
      </div>`;
  }).join('') : '<div class="empty">Nimic de verificat \u2014 totul e la zi.</div>';
}

function render_marked(list) {
  document.getElementById('marked-count').textContent = list.length;
  document.getElementById('marked-list').innerHTML = list.length ? list.map(x => {
    const bad = x.status === 'suspicious';
    const attrs = `data-proc="${esc(x.process_name)}" data-key="${esc(x.group_key)}"`;
    return `
      <div class="pending-item">
        <div class="pending-text">
          <div class="pending-title"><strong>${esc(x.process_name)}</strong> \u2192 ${esc(x.title)}
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
    <div class="alert-line">${fmt_dt(x.timestamp)} \u00b7 ${esc(x.process_name)} \u2192 ${esc(x.group_key)}:
      ${esc(STATUS_LABEL[x.old_status] || x.old_status)} \u2192 <strong>${esc(STATUS_LABEL[x.new_status] || x.new_status)}</strong></div>
  `).join('') : '<div class="empty">Nicio decizie in istoric.</div>';
}

// ---------- Decizii (butoane) ----------

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

    render_home(d);
    document.getElementById('total-24h').textContent = d.total_connections_24h;
    render_phishing(d.phishing);
    render_pending(d.pending);
    render_marked(d.marked);
    render_log(d.decision_log);

    // Programe
    const maxConn = max_conn(d.process_summary);
    document.getElementById('proc-count').textContent = d.process_summary.length + ' programe';
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

    // Jurnal alerte
    document.getElementById('alert-count').textContent = d.recent_alerts.length + ' alerte';
    document.getElementById('alert-list').innerHTML = d.recent_alerts.length
      ? d.recent_alerts.map(a => {
          const cls = (a.raw.includes('[INBOUND]') || a.raw.includes('[NU-RECUNOSC]') || a.raw.includes('[PHISHING')) ? 'is-inbound'
                    : a.raw.includes('[RISC')     ? 'is-risk'
                    : '';
          return `<div class="alert-line ${cls}">${esc(a.raw)}</div>`;
        }).join('')
      : '<div class="empty">Nicio alerta inregistrata \u2014 bine!</div>';

    // Conexiuni primite
    document.getElementById('inbound-count').textContent = d.recent_inbound.length;
    document.getElementById('inbound-table').innerHTML = d.recent_inbound.map(c => `
      <tr>
        <td><span class="badge badge-danger">${esc(c.remote_ip)}</span></td>
        <td class="proc-name">${esc(c.process_name || '\u2014')}</td>
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
    print("[*] Ruleaza in paralel cu watcher_v6.py \u2014 scrie doar deciziile tale (E normal / Nu recunosc)")
    print("[*] Actualizare automata la fiecare 5 secunde")
    print("[*] Ctrl+C pentru oprire\n")
    app.run(host="127.0.0.1", port=PORT, debug=False)
