#!/usr/bin/env python3
"""
Avertizare de phishing: urmareste paginile deschise in Firefox si te anunta cand
un domeniu imita un brand cunoscut (vezi phishing_check.py).

Ruleaza ca proces separat de watcher_v6.py (conexiuni, beaconing) si foloseste
aceeasi baza de date. Citeste istoricul prin browser_history.py (pentru alt browser
se schimba doar sursa de vizite, restul ramane).

Confidentialitate: in baza se pastreaza DOAR domeniul paginilor suspecte (nu adresa
completa, care poate contine token-uri sau date personale) si NICIO pagina normala.
Nimic nu iese de pe calculator: verificarea e locala.

Reguli de alertare:
  - scor de la ALERT_SCORE in sus -> notificare critica + linie in alerts.log
  - fiecare intrare deliberata pe un site suspect se raporteaza: adresa tastata, bookmark,
    tab nou, link din alta aplicatie sau de pe alt site, reincarcare. O alerta de phishing
    nu se ignora: a doua vizita poate fi chiar momentul in care introduci datele.
  - se strang intr-una (in fereastra DEDUPE_SECONDS) doar duplicatele aceleiasi navigari:
    redirecturile (http -> https produce doua vizite in 1-2 secunde) si navigarea in
    interiorul aceluiasi site (un click pe "Continua" in pagina suspecta)
  - semnalele slabe (scor sub prag) se noteaza in baza, fara notificare
"""

import signal
import sqlite3
import time
from datetime import datetime, timezone

import browser_history as bh
import notifier
import phishing_check as pc
import phishing_store as store

DB_PATH = "traffic_monitor.db"
POLL_SECONDS = 2
DEDUPE_SECONDS = 60            # redirecturile si navigarea interna in aceasta fereastra sunt aceeasi navigare
DELIBERATE_KINDS = ("tastat", "bookmark", "reincarcare")   # intrari deliberate: alerteaza mereu
REDIRECT_KINDS = ("redirect", "incorporat")                # parte din aceeasi navigare
MAX_REMEMBERED_VISITS = 2000
LOOKBACK_SECONDS = 300         # la pornire, ne uitam si la ultimele 5 minute (repornirea nu pierde pagini)
RESCAN_SECONDS = 60            # cat de des cautam Firefox cand nu e instalat/gasit


def init_tables(conn: sqlite3.Connection) -> None:
    store.init_tables(conn)


def load_last_seen(conn: sqlite3.Connection) -> dict:
    """{domeniu: ultima data (epoch) cand a fost raportat}, ca o repornire sa nu re-alerteze pentru aceeasi vizita."""
    last_seen = {}
    for host, timestamp in conn.execute("SELECT host, MAX(timestamp) FROM phishing_events GROUP BY host"):
        try:
            last_seen[host] = datetime.fromisoformat(timestamp).timestamp()
        except ValueError:
            continue
    return last_seen


def is_duplicate(visit, last_seen, visit_hosts) -> bool:
    """
    True daca vizita face parte din aceeasi navigare ca ultima alerta pentru domeniu,
    deci nu merita o alerta noua. Intrarile deliberate (tastat, bookmark, reincarcare,
    link dintr-un loc nou) NU sunt niciodata duplicate, in afara de cazul in care e aceeasi
    vizita citita a doua oara (la repornirea serviciului).
    """
    last = last_seen.get(visit.host)
    if last is None:
        return False
    if visit.when <= last:
        return True
    if visit.when - last >= DEDUPE_SECONDS:
        return False
    if visit.kind in DELIBERATE_KINDS:
        return False
    if visit.kind in REDIRECT_KINDS:
        return True
    # link: navigare interna daca vizita de unde s-a venit era tot la acest domeniu
    return visit_hosts is not None and visit_hosts.get(visit.from_visit) == visit.host


def process_visit(conn, visit, last_seen, notify_fn=notifier.notify, log_fn=notifier.log_alert,
                  visit_hosts=None, allowlist=frozenset()):
    """
    Verifica o vizita. Intoarce verdictul daca s-a retinut ceva (suspect), altfel None.
    `last_seen` si `visit_hosts` (id vizita -> domeniu, pentru navigarea interna) se actualizeaza pe loc.
    Domeniile din `allowlist` (marcate "este site-ul real" de utilizator) sunt ignorate.
    """
    if store.is_allowed(visit.host, allowlist):
        return None
    verdict = pc.check_domain(visit.host)
    if verdict.score == 0:
        return None
    duplicate = is_duplicate(visit, last_seen, visit_hosts)
    if visit_hosts is not None:
        if len(visit_hosts) > MAX_REMEMBERED_VISITS:
            visit_hosts.clear()
        visit_hosts[visit.visit_id] = visit.host
    if duplicate:
        return None
    last_seen[visit.host] = visit.when

    alerted = verdict.alert
    conn.execute(
        "INSERT INTO phishing_events (timestamp, host, score, brand, reasons, kind, alerted) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (datetime.fromtimestamp(visit.when, timezone.utc).isoformat(), visit.host, verdict.score,
         verdict.brand, "; ".join(verdict.reasons), visit.kind, int(alerted)),
    )
    conn.commit()

    if alerted:
        title, text = pc.describe(visit.host, verdict)
        line = f"[PHISHING {verdict.score}/100] {visit.host} (deschis prin {visit.kind}): " + "; ".join(verdict.reasons)
        log_fn(line)
        print(line, flush=True)
        notify_fn(f"\u26a0\ufe0f {title}", text, "critical")
    else:
        print(f"[phishing sub prag] {visit.host}: {verdict.score}/100 - " + "; ".join(verdict.reasons), flush=True)
    return verdict


def poll_once(conn, watcher, last_seen, notify_fn=notifier.notify, log_fn=notifier.log_alert,
              visit_hosts=None) -> int:
    """O runda: ia vizitele noi si le verifica. Intoarce cate au fost retinute ca suspecte."""
    kept = 0
    visits = watcher.poll()
    if not visits:
        return 0
    allowlist = store.load_allowlist(conn)       # citita la fiecare runda: "este site-ul real" are efect imediat
    for visit in visits:
        if process_visit(conn, visit, last_seen, notify_fn, log_fn, visit_hosts, allowlist) is not None:
            kept += 1
    return kept


def _stop_on_sigterm(signum, frame):
    raise KeyboardInterrupt


def main():
    signal.signal(signal.SIGTERM, _stop_on_sigterm)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    init_tables(conn)
    last_seen = load_last_seen(conn)
    visit_hosts: dict = {}
    print(f"[*] Pornesc avertizarea de phishing (verific la fiecare {POLL_SECONDS}s)")
    print("[*] Ctrl+C (sau oprirea serviciului) pentru oprire\n", flush=True)

    watcher = None
    try:
        while watcher is None:
            databases = bh.find_databases()
            if databases:
                watcher = bh.HistoryWatcher(databases, lookback_seconds=LOOKBACK_SECONDS)
                print(f"[*] Urmaresc {len(databases)} profil(uri) Firefox", flush=True)
            else:
                print("[!] Nu am gasit niciun profil Firefox; mai caut peste un minut.", flush=True)
                time.sleep(RESCAN_SECONDS)
        while True:
            poll_once(conn, watcher, last_seen, visit_hosts=visit_hosts)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\n[*] Oprit.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
