#!/usr/bin/env python3
"""
Etapa 3 (v2): Monitor continuu pe fundal.

Model NOU, diferit de v1:
- NU mai cere aprobare (d/n) pentru fiecare conexiune - prea multe,
  Firefox singur generează zeci pe minut, e nepractic
- Rulează CONTINUU pe fundal, colectând tot traficul (ca collector.py)
- Notifică INFORMATIV, o singură dată, când vede o combinație
  (proces, IP) nouă - fără să blocheze, fără să ceară răspuns
- La fiecare ANALYSIS_INTERVAL_SECONDS, rulează analiza de risc
  (concentrare + beaconing + reputație, din baseline.py) pe datele
  proaspăt colectate și trimite o alertă ACTIVĂ doar dacă găsește
  ceva cu adevărat suspect (scor >= 50)

Rulare: sudo python3 watcher.py
Oprire: Ctrl+C
"""

import psutil
import sqlite3
import subprocess
import ipaddress
import hashlib
import socket
import os
import pwd
import time
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import companies
import destination_status as ds
import retention
from baseline_v5 import (
    is_private_ip, analyze_process, deduplicate_into_sessions,
    MIN_SAMPLES_FOR_BASELINE,
)

DB_PATH = "traffic_monitor.db"
ALERTS_LOG_PATH = "alerts.log"
POLL_INTERVAL_SECONDS = 1          # cât de des verificăm conexiunile active
                                     # (la 1s prindem și conexiuni scurte, gen curl -m 2;
                                     # la 3s+ le rataserăm, exact problema descoperită la collector.py)
ANALYSIS_INTERVAL_SECONDS = 120    # cât de des rulăm analiza de risc completă (2 minute)
RISK_ALERT_THRESHOLD = 50          # scor de la care trimitem alertă activă (nu doar informativă)
RETENTION_INTERVAL_SECONDS = 6 * 3600  # cât de des curățăm datele vechi (vezi retention.py)
WHITELIST_COOLDOWN_SECONDS = 300   # cât timp minim între două alerte de "comportament nou", per proces


# ---------- Notificări desktop, corect configurate pentru sudo ----------

def log_alert_to_file(message: str) -> None:
    """
    Scrie orice alertă (inbound sau risc ridicat) într-un fișier text
    permanent, INDIFERENT ce face desktop-ul cu popup-ul.

    De ce: notificările "critical" din GNOME rămân pe ecran până le
    închizi manual, dar unele versiuni nu le arhivează în istoricul de
    notificări după închidere - poți pierde complet urma alertei.
    Fișierul ăsta e o evidență permanentă, utilă și ca jurnal de audit.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(ALERTS_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message}\n")


def get_desktop_user_env() -> dict:
    """
    Când scriptul rulează cu sudo, procesul e root și NU are acces la
    sesiunea grafică a utilizatorului (DBUS_SESSION_BUS_ADDRESS, DISPLAY).
    Reconstruim aceste variabile pentru utilizatorul original (cel care
    a dat sudo), ca notify-send să știe către ce desktop să trimită popup-ul.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        return os.environ.copy()  # nu rulează cu sudo, mediul e deja corect

    try:
        uid = pwd.getpwnam(sudo_user).pw_uid
    except KeyError:
        return os.environ.copy()

    env = os.environ.copy()
    env["DISPLAY"] = env.get("DISPLAY", ":0")
    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{uid}/bus"
    return env


def send_desktop_notification(title: str, message: str, urgency: str = "normal") -> None:
    """Trimite un popup nativ Ubuntu, rulat ca utilizatorul desktop, nu ca root."""
    sudo_user = os.environ.get("SUDO_USER")
    env = get_desktop_user_env()

    try:
        if sudo_user:
            # rulăm notify-send explicit ca utilizatorul original, nu ca root
            subprocess.run(
                ["sudo", "-u", sudo_user, "notify-send",
                 f"--urgency={urgency}", "--icon=dialog-information", title, message],
                env=env, timeout=3, check=False,
            )
        else:
            subprocess.run(
                ["notify-send", f"--urgency={urgency}", title, message],
                env=env, timeout=3, check=False,
            )
    except (FileNotFoundError, subprocess.SubprocessError):
        pass  # nu blocăm scriptul dacă notificarea eșuează


# ---------- Colectare (identică ca logică cu collector.py) ----------

def init_db(conn: sqlite3.Connection) -> None:
    # WAL: dashboard-ul (alt proces) poate citi/scrie decizii cât timp watcher-ul
    # scrie conexiuni, fără "database is locked" la fiecare al doilea ciclu
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            pid INTEGER,
            process_name TEXT,
            binary_path TEXT,
            binary_hash TEXT,
            local_ip TEXT,
            local_port INTEGER,
            remote_ip TEXT,
            remote_port INTEGER,
            protocol TEXT,
            status TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_process_time ON connections (process_name, timestamp)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notified_pairs (
            process_name TEXT NOT NULL,
            remote_ip TEXT NOT NULL,
            remote_hostname TEXT,
            first_seen_at TEXT NOT NULL,
            PRIMARY KEY (process_name, remote_ip)
        )
    """)
    # Migrare pentru baze de date existente care nu au coloana remote_hostname
    try:
        conn.execute("ALTER TABLE notified_pairs ADD COLUMN remote_hostname TEXT")
    except Exception:
        pass  # coloana există deja, nu e nicio problemă
    # NOU: conexiuni PRIMITE (cineva se conectează la tine, nu invers)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS inbound_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            process_name TEXT,
            local_port INTEGER,
            remote_ip TEXT,
            remote_port INTEGER
        )
    """)
    # Starea alertelor de risc, persistată între reporniri — Fix Direcția A
    conn.execute("""
        CREATE TABLE IF NOT EXISTS risk_alert_state (
            process_name TEXT PRIMARY KEY,
            last_alerted_count INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    # NOU: destinații cunoscute per proces (domeniu sau subnet), pentru
    # regula de "comportament nou" - vezi get_group_key()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS known_destinations (
            process_name TEXT NOT NULL,
            group_key TEXT NOT NULL,
            group_type TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            times_seen INTEGER NOT NULL,
            PRIMARY KEY (process_name, group_key)
        )
    """)
    # NOU: cooldown persistat între reporniri - ultima dată când am trimis
    # o alertă de "comportament nou" pentru fiecare proces
    conn.execute("""
        CREATE TABLE IF NOT EXISTS whitelist_alert_state (
            process_name TEXT PRIMARY KEY,
            last_alerted_at TEXT NOT NULL
        )
    """)
    conn.commit()
    # NOU: starea destinațiilor noi (de verificat / normal / suspect) + istoric decizii
    ds.init_tables(conn)


# ---------- Persistare risk_alert_state ----------

def load_risk_alert_state(conn: sqlite3.Connection) -> dict:
    """Încarcă din SQLite starea alertelor de la rularea anterioară."""
    cur = conn.execute("SELECT process_name, last_alerted_count FROM risk_alert_state")
    state = {row[0]: row[1] for row in cur.fetchall()}
    if state:
        print(f"[*] Am încărcat starea alertelor pentru {len(state)} procese din rularea anterioară")
    return state


def save_risk_alert_state(conn: sqlite3.Connection, process_name: str, count: int) -> None:
    """Salvează în SQLite numărul de conexiuni la momentul ultimei alerte."""
    conn.execute("""
        INSERT INTO risk_alert_state (process_name, last_alerted_count, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(process_name) DO UPDATE SET
            last_alerted_count = excluded.last_alerted_count,
            updated_at = excluded.updated_at
    """, (process_name, count, datetime.now(timezone.utc).isoformat()))
    conn.commit()


# ---------- Persistare known_destinations + cooldown (regula de "comportament nou") ----------

def load_known_destinations(conn: sqlite3.Connection) -> tuple[set, set]:
    """
    Încarcă, din rulările anterioare, ce (proces, cheie) sunt deja
    cunoscute, plus setul de procese care au cel puțin o destinație
    cunoscută (folosit ca să nu alertăm la prima conexiune a unui proces
    complet nou - nu avem încă niciun "normal" de comparat).
    """
    # Cheile se țin la nivel de "entitate": 29 de blocuri Google cunoscute
    # pentru chrome înseamnă "chrome știe Google" - un bloc Google nou nu mai
    # e "comportament nou". Tabela known_destinations rămâne la nivel fin.
    cur = conn.execute("SELECT process_name, group_key, group_type FROM known_destinations")
    rows = cur.fetchall()
    known_keys = {(p, companies.entity_for(k, t)[0]) for p, k, t in rows}
    known_processes = {process_name for process_name, _, _ in rows}
    return known_keys, known_processes


def upsert_known_destination(conn: sqlite3.Connection, process_name: str, group_key: str,
                              group_type: str, timestamp: str) -> None:
    """Înregistrează/actualizează o destinație cunoscută - apelată la fiecare conexiune nouă (pereche)."""
    conn.execute("""
        INSERT INTO known_destinations (process_name, group_key, group_type, first_seen, last_seen, times_seen)
        VALUES (?, ?, ?, ?, ?, 1)
        ON CONFLICT (process_name, group_key) DO UPDATE SET
            last_seen = excluded.last_seen,
            times_seen = known_destinations.times_seen + 1
    """, (process_name, group_key, group_type, timestamp, timestamp))
    conn.commit()


def backfill_known_destinations_if_empty(conn: sqlite3.Connection, hostname_cache: dict) -> None:
    """
    La prima rulare după integrare, known_destinations e goală, deși
    `connections` poate avea luni de istoric deja. Fără backfill, orice
    proces ar părea "nou" o vreme, fără alerte utile. Populăm o dată din
    tot istoricul existent - exact logica validată în experiment.
    """
    existing = conn.execute("SELECT COUNT(*) FROM known_destinations").fetchone()[0]
    if existing > 0:
        print(f"[*] known_destinations are deja {existing} perechi (dintr-o rulare anterioară) - nu refac backfill-ul\n")
        return

    print("[*] known_destinations e goală - populez din istoricul existent (o singură dată)...")
    cur = conn.execute("""
        SELECT process_name, remote_ip, timestamp
        FROM connections
        ORDER BY timestamp
    """)
    agg: dict = {}
    for process_name, remote_ip, timestamp in cur.fetchall():
        if is_private_ip(remote_ip):
            continue
        group_key, group_type = get_group_key(remote_ip, hostname_cache)
        key = (process_name, group_key)
        if key not in agg:
            agg[key] = {"first": timestamp, "last": timestamp, "count": 1, "type": group_type}
        else:
            e = agg[key]
            e["last"] = timestamp
            e["count"] += 1

    for (process_name, group_key), e in agg.items():
        conn.execute("""
            INSERT INTO known_destinations (process_name, group_key, group_type, first_seen, last_seen, times_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (process_name, group_key) DO NOTHING
        """, (process_name, group_key, e["type"], e["first"], e["last"], e["count"]))
    conn.commit()
    print(f"[*] Backfill terminat: {len(agg)} perechi (proces, destinație) cunoscute\n")


def load_whitelist_alert_state(conn: sqlite3.Connection) -> dict:
    """Încarcă, per proces, ultima dată (datetime) când s-a trimis o alertă de 'comportament nou'."""
    cur = conn.execute("SELECT process_name, last_alerted_at FROM whitelist_alert_state")
    return {row[0]: datetime.fromisoformat(row[1]) for row in cur.fetchall()}


def save_whitelist_alert_state(conn: sqlite3.Connection, process_name: str, when: datetime) -> None:
    conn.execute("""
        INSERT INTO whitelist_alert_state (process_name, last_alerted_at)
        VALUES (?, ?)
        ON CONFLICT(process_name) DO UPDATE SET last_alerted_at = excluded.last_alerted_at
    """, (process_name, when.isoformat()))
    conn.commit()


def hash_binary(path: str) -> str | None:
    if not path:
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def get_process_info(pid: int, cache: dict) -> tuple[str, str, str]:
    if pid in cache:
        return cache[pid]
    try:
        proc = psutil.Process(pid)
        info = (proc.name(), proc.exe(), hash_binary(proc.exe()))
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        info = ("unknown", None, None)
    cache[pid] = info
    return info


def resolve_hostname(ip: str, cache: dict) -> str:
    """
    DNS invers: încearcă să afle numele de domeniu asociat unui IP
    (ex. "185.125.190.36" -> "azure.microsoft.com"). Util ca să
    recunoști imediat "a, asta e Digi Storage", nu doar un IP anonim.

    Nu toate IP-urile au un nume invers înregistrat - în acel caz,
    întoarcem IP-ul neschimbat, fără eroare.

    Cache în memorie, ca să nu facem o cerere DNS nouă la fiecare
    conexiune către același IP (ar fi lent și inutil).
    """
    if ip in cache:
        return cache[ip]
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        cache[ip] = hostname
    except (socket.herror, socket.gaierror, OSError):
        cache[ip] = ip  # fără nume găsit, rămânem cu IP-ul brut
    return cache[ip]


def extract_base_domain(hostname: str) -> str:
    """
    Extrage "domeniul de bază" dintr-un hostname complet.
    Ex: lb-140-82-112-21-iad.github.com -> github.com

    Euristică simplă: păstrăm ultimele 2 segmente separate prin punct.
    LIMITARE cunoscută: greșește pe domenii cu TLD compus din 2 părți
    (ex. "ceva.co.uk") - nu apare în datele noastre curente.
    """
    parts = hostname.rstrip(".").split(".")
    if len(parts) < 2:
        return hostname
    return ".".join(parts[-2:])


def get_group_key(ip: str, hostname_cache: dict) -> tuple[str, str]:
    """
    Calculează "cheia de grupare" a unei destinații, folosită de regula de
    "comportament nou" (vezi collect_and_notify). Trei metode, în ordine:

    1. Domeniu (din reverse DNS, via resolve_hostname - refolosim cache-ul
       deja existent, nicio cerere DNS în plus față de ce se face oricum)
    2. Subnet (/24 IPv4, /48 IPv6), dacă nu există reverse DNS - IP-uri
       vecine sunt adesea aceeași infrastructură (același furnizor cloud)
    3. IP-ul însuși, ca fallback ultim, dacă nici subnet-ul nu poate fi calculat

    Întoarce (cheie, tip) - tipul ajută la depanare/jurnal, ca să vezi prin
    ce metodă s-a făcut gruparea.
    """
    hostname = resolve_hostname(ip, hostname_cache)

    if hostname != ip:
        # resolve_hostname a găsit un nume real (nu a căzut pe fallback-ul "IP-ul însuși")
        return extract_base_domain(hostname), "domeniu"

    try:
        addr = ipaddress.ip_address(ip)

        # IPv4 mascat ca IPv6 (ex. ::ffff:34.78.67.165) - aceeași capcană
        # documentată deja la is_effectively_loopback() din acest fișier.
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped

        prefix = 24 if addr.version == 4 else 48
        network = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        return str(network), "subnet"
    except ValueError:
        return ip, "ip"  # fallback ultim, practic nu se întâmplă


def is_effectively_loopback(ip: str) -> bool:
    """
    Verifică dacă un IP e loopback (127.x.x.x, ::1), INCLUSIV varianta
    IPv6 "împachetată" (::ffff:127.0.0.1) - un format special, frecvent
    la conexiuni locale pe sisteme cu IPv6 activ, pe care Python NU îl
    recunoaște automat ca loopback din is_loopback simplu.
    """
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
        if addr.is_loopback:
            return True
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return addr.ipv4_mapped.is_loopback
        return False
    except ValueError:
        return False


def collect_and_notify(conn: sqlite3.Connection, process_cache: dict, notified_pairs: set,
                        notified_inbound: set, hostname_cache: dict,
                        known_destination_keys: set, known_processes: set,
                        last_whitelist_alert: dict,
                        decisions: dict | None = None,
                        notified_suspicious: set | None = None,
                        previous_open: set | None = None) -> int:
    """
    O trecere de colectare: salvează toate conexiunile active (ca collector.py),
    trimite notificare informativă pentru conexiuni IEȘITE noi, și ALERTĂ
    IMEDIATĂ pentru conexiuni PRIMITE (cineva se conectează la tine).

    Distincția ieșit/primit: mai întâi identificăm porturile locale aflate
    în stare LISTEN (adică "ascultăm" pe ele, suntem server). O conexiune
    ESTABLISHED al cărei port local se potrivește cu un port LISTEN e o
    conexiune PRIMITĂ - cineva din exterior a inițiat-o, nu tu.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    all_conns = list(psutil.net_connections(kind="inet"))

    if decisions is None:
        decisions = {}
    if notified_suspicious is None:
        notified_suspicious = set()
    # reîncărcăm deciziile din DB la fiecare ciclu: ce a apăsat utilizatorul
    # în dashboard ("E normal" / "Nu recunosc") se aplică în ~1 secundă
    decisions.clear()
    decisions.update(ds.load_decisions(conn))
    if len(notified_suspicious) > 5000:
        notified_suspicious.clear()

    # pasul 1: identificăm porturile pe care laptopul tău ASCULTĂ chiar acum
    listening_ports = {
        c.laddr.port for c in all_conns
        if c.status == "LISTEN" and c.laddr
    }

    rows = []
    current_open = set()  # conexiunile deschise ACUM (pentru ciclul următor)

    for conn_info in all_conns:
        if not conn_info.raddr or not conn_info.pid:
            continue

        remote_ip = conn_info.raddr.ip
        remote_port = conn_info.raddr.port
        local_port = conn_info.laddr.port if conn_info.laddr else None
        pid = conn_info.pid

        name, exe_path, binary_hash = get_process_info(pid, process_cache)
        protocol = "TCP" if conn_info.type == 1 else "UDP"

        # Scriem în bază DOAR conexiunile noi (care nu erau deschise la citirea
        # precedentă), nu fiecare conexiune deschisă la fiecare secundă: o
        # conexiune de 10 minute ar însemna 600 de rânduri (~275 MB/zi măsurat).
        # O conexiune = (proces, adresa+portul tău, adresa+portul destinației).
        # Beaconing-ul nu pierde nimic: un curl la 60s deschide de fiecare dată
        # o conexiune nouă, cu alt port local. previous_open=None (teste) scrie tot.
        conn_id = (
            pid,
            conn_info.laddr.ip if conn_info.laddr else None, local_port,
            remote_ip, remote_port, protocol,
        )
        current_open.add(conn_id)
        if previous_open is None or conn_id not in previous_open:
            rows.append((
                timestamp, pid, name, exe_path, binary_hash,
                conn_info.laddr.ip if conn_info.laddr else None,
                local_port, remote_ip, remote_port, protocol, conn_info.status,
            ))

        is_inbound = (
            conn_info.status == "ESTABLISHED"
            and local_port in listening_ports
            and not is_effectively_loopback(remote_ip)
        )

        if is_inbound:
            # NOU: conexiune PRIMITĂ - cineva s-a conectat la tine.
            # NU filtrăm IP-uri private aici (spre deosebire de traficul ieșit) -
            # un atacator pe aceeași rețea locală (ex. Kali în VirtualBox) are
            # tot un IP privat, dar tot vrem să te alerteze despre el.
            #
            # cheia include remote_port: fiecare CONEXIUNE NOUĂ (chiar de la
            # același IP, către același port local) are un remote_port diferit,
            # alocat aleator de sistemul de operare al atacatorului la fiecare
            # reconectare - fără remote_port în cheie, a doua reconectare de la
            # Kali nu mai declanșa alertă, deși era o încercare nouă, reală.
            inbound_key = (name, remote_ip, local_port, remote_port)
            if inbound_key in notified_inbound:
                continue
            notified_inbound.add(inbound_key)

            conn.execute(
                "INSERT INTO inbound_events (timestamp, process_name, local_port, remote_ip, remote_port) VALUES (?, ?, ?, ?, ?)",
                (timestamp, name, local_port, remote_ip, remote_port)
            )
            log_alert_to_file(
                f"[INBOUND] {remote_ip}:{remote_port} -> {name} (port local {local_port})"
            )
            send_desktop_notification(
                "🔴 Conexiune PRIMITĂ - cineva te-a contactat",
                f"{remote_ip} s-a conectat la {name} (portul tău {local_port})",
                urgency="critical",
            )
            print(f"[INBOUND!] {remote_ip}:{remote_port} -> {name} (port local {local_port})")
            continue  # nu mai trecem și prin logica de "ieșit" pentru aceeași conexiune

        # de aici: conexiuni IEȘITE către IP-uri publice
        if is_private_ip(remote_ip):
            continue

        group_key, group_type = get_group_key(remote_ip, hostname_cache)
        # decidem și ținem minte la nivel de companie (Google, Microsoft...) când
        # o știm; altfel la nivel de destinație exactă
        entity_key, entity_type = companies.entity_for(group_key, group_type)
        dest_key = (name, entity_key)
        status = decisions.get(dest_key)

        # --- destinație marcată "Nu recunosc": ORICE conexiune nouă alertează ---
        # Verificarea e înaintea lui `notified_pairs` și ignoră cooldown-ul:
        # o destinație pe care utilizatorul a declarat-o suspectă trebuie să
        # alerteze și când revine pe un IP deja văzut. Ca să nu alerteze la
        # fiecare secundă pentru ACEEAȘI conexiune încă deschisă, deduplicăm
        # pe (proces, IP, port remote, port local).
        if status == ds.SUSPICIOUS:
            conn_key = (name, remote_ip, remote_port, local_port)
            action = ds.decide_action(status, False, False, conn_key in notified_suspicious)
            if action == ds.ACTION_ALERT_SUSPICIOUS:
                notified_suspicious.add(conn_key)
                log_alert_to_file(
                    f"[NU-RECUNOSC] {name} contactează din nou {entity_key} ({remote_ip})"
                )
                send_desktop_notification(
                    f"🔴 {name} contactează o destinație marcată „Nu recunosc”",
                    f"{entity_key} ({remote_ip})",
                    urgency="critical",
                )
                print(f"[NU-RECUNOSC!] {name} -> {entity_key} ({remote_ip})")
            continue

        # notificare INFORMATIVĂ pentru conexiuni IEȘITE noi (logica veche)
        pair = (name, remote_ip)
        if pair in notified_pairs:
            continue

        notified_pairs.add(pair)
        hostname = resolve_hostname(remote_ip, hostname_cache)
        display_dest = hostname if hostname != remote_ip else remote_ip
        conn.execute(
            "INSERT OR IGNORE INTO notified_pairs (process_name, remote_ip, remote_hostname, first_seen_at) VALUES (?, ?, ?, ?)",
            (name, remote_ip, hostname, timestamp)
        )
        if status != ds.NORMAL:  # ce a confirmat utilizatorul ca normal nu mai deranjează
            send_desktop_notification(
                "Conexiune nouă observată",
                f"{name} -> {display_dest}",
                urgency="low",
            )
        print(f"[info] Conexiune nouă: {name} -> {display_dest} ({remote_ip})")

        # regula de "comportament nou" - proces deja cunoscut, destinație
        # (domeniu/subnet) niciodată văzută pentru el.
        is_new_destination = name in known_processes and dest_key not in known_destination_keys
        now_dt = datetime.now(timezone.utc)
        last_alert = last_whitelist_alert.get(name)
        cooldown_expired = (
            last_alert is None
            or (now_dt - last_alert).total_seconds() >= WHITELIST_COOLDOWN_SECONDS
        )
        action = ds.decide_action(status, is_new_destination, cooldown_expired, False)

        if action in (ds.ACTION_ALERT_NEW, ds.ACTION_PENDING_SILENT):
            # în ambele cazuri destinația intră în lista "de verificat" - chiar
            # dacă cooldown-ul a oprit notificarea, utilizatorul o vede în dashboard
            ds.record_pending(
                conn, name, entity_key, entity_type, timestamp,
                sample_ip=remote_ip,
                sample_hostname=hostname if hostname != remote_ip else None,
            )
            decisions[dest_key] = ds.PENDING

        if action == ds.ACTION_ALERT_NEW:
            title, _ = companies.display(entity_key, entity_type)
            log_alert_to_file(
                f"[COMPORTAMENT NOU] {name} -> destinație nouă: {entity_key} "
                f"({entity_type}; {group_key})"
            )
            send_desktop_notification(
                f"🟡 {name}: destinație nouă",
                f"Contactează pentru prima dată {title}. Deschide dashboard-ul ca să decizi.",
                urgency="normal",
            )
            print(f"[NOU-COMPORTAMENT] {name} -> {entity_key} ({entity_type}; {group_key})")
            last_whitelist_alert[name] = now_dt
            save_whitelist_alert_state(conn, name, now_dt)
        elif action == ds.ACTION_PENDING_SILENT:
            print(f"[NOU-COMPORTAMENT, fără notificare - cooldown] {name} -> {entity_key} ({entity_type}; {group_key})")

        known_destination_keys.add(dest_key)  # nivel entitate, ca în load_known_destinations
        known_processes.add(name)
        upsert_known_destination(conn, name, group_key, group_type, timestamp)

    if previous_open is not None:
        previous_open.clear()
        previous_open.update(current_open)

    if rows:
        conn.executemany("""
            INSERT INTO connections (
                timestamp, pid, process_name, binary_path, binary_hash,
                local_ip, local_port, remote_ip, remote_port, protocol, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
        conn.commit()

    return len(rows)


# ---------- Analiză periodică de risc (reutilizează baseline.py) ----------

def run_risk_analysis(conn: sqlite3.Connection, risk_alert_state: dict) -> None:
    """
    Rulează exact aceeași logică din baseline.py (concentrare, beaconing,
    reputație) pe datele acumulate până acum, și trimite o alertă ACTIVĂ
    (urgency=critical) doar pentru procesele cu scor >= RISK_ALERT_THRESHOLD.

    NOU: risc_alert_state ține minte, per proces, câte conexiuni (totale)
    avea la ULTIMA alertă trimisă. Dacă numărul nu s-a schimbat față de
    ultima dată (adică nu a apărut trafic nou), NU retrimitem popup -
    altfel un proces suspect declanșa aceeași alertă la infinit, la
    fiecare 2 minute, chiar dacă nu se întâmpla nimic nou (bug descoperit
    empiric: curl-ul de test oprit încă apărea "detectat" identic, de 3
    ori la rând, doar pentru că analiza re-evalua aceleași date vechi).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    cur = conn.execute("""
        SELECT process_name, timestamp, remote_ip, remote_port
        FROM connections
        WHERE timestamp > ?
        ORDER BY process_name, timestamp
    """, (cutoff,))
    by_process = defaultdict(list)
    for process_name, timestamp, remote_ip, remote_port in cur.fetchall():
        by_process[process_name].append({
            "timestamp": datetime.fromisoformat(timestamp),
            "remote_ip": remote_ip,
            "remote_port": remote_port,
        })

    all_destinations = defaultdict(set)
    for process_name, conns in by_process.items():
        for c in conns:
            all_destinations[c["remote_ip"]].add(process_name)

    print(f"\n[analiza] Rulez evaluarea de risc pe {len(by_process)} procese...")
    for process_name, conns in by_process.items():
        report = analyze_process(process_name, conns, all_destinations)
        if report["risk_score"] < RISK_ALERT_THRESHOLD:
            continue

        current_count = report["total_connections"]
        last_alerted_count = risk_alert_state.get(process_name)

        # afișăm TOATE motivele, nu doar primele 2
        reasons_text = "\n      ".join(report["reasons"])
        key_reasons = [r for r in report["reasons"] if "CONCENTRAT" in r or "BEACONING" in r or "Reputa" in r]
        summary = "; ".join(key_reasons) if key_reasons else reasons_text

        if last_alerted_count == current_count:
            # nimic nou față de ultima alertă - doar notă discretă în consolă, fără popup
            print(f"[risc neschimbat] {process_name}: tot la {report['risk_score']}/100, fără activitate nouă (nu retrimit popup)")
            continue

        print(f"[ALERTĂ] {process_name}: risc {report['risk_score']}/100")
        print(f"      {reasons_text}")
        log_alert_to_file(f"[RISC {report['risk_score']}/100] {process_name}: {summary}")
        send_desktop_notification(
            f"⚠️ Risc ridicat: {process_name}",
            f"Scor {report['risk_score']}/100 - {summary}",
            urgency="critical",
        )
        risk_alert_state[process_name] = current_count
        save_risk_alert_state(conn, process_name, current_count)

    print("[analiza] Terminat.\n")


# ---------- Bucla principală ----------

def main():
    print(f"[*] Pornesc monitorul continuu")
    print(f"[*] Polling conexiuni: {POLL_INTERVAL_SECONDS}s | Analiză risc: la fiecare {ANALYSIS_INTERVAL_SECONDS}s")
    print("[*] Ctrl+C pentru oprire\n")

    conn = sqlite3.connect(DB_PATH, timeout=10)
    init_db(conn)

    # încărcăm ce combinații am notificat deja (din rulări anterioare)
    cur = conn.execute("SELECT process_name, remote_ip FROM notified_pairs")
    notified_pairs = {(row[0], row[1]) for row in cur.fetchall()}
    print(f"[*] {len(notified_pairs)} combinații (proces, IP) deja notificate anterior\n")

    process_cache: dict = {}
    hostname_cache: dict = {}
    notified_inbound: set = set()
    risk_alert_state: dict = load_risk_alert_state(conn)

    # NOU: backfill din istoric (o singură dată, dacă tabela e goală), apoi
    # încărcăm ce e deja cunoscut + cooldown-ul de la rularea anterioară
    backfill_known_destinations_if_empty(conn, hostname_cache)
    known_destination_keys, known_processes = load_known_destinations(conn)
    last_whitelist_alert: dict = load_whitelist_alert_state(conn)
    migrated = ds.migrate_to_entities(conn, companies.entity_for)
    if migrated:
        print(f"[*] Am grupat {migrated} destinații din lista 'de verificat' pe companii\n")
    decisions: dict = ds.load_decisions(conn)
    notified_suspicious: set = set()
    previous_open: set = set()
    print(f"[*] {len(known_destination_keys)} destinații cunoscute pentru {len(known_processes)} procese\n")

    # curățare date vechi: la pornire, apoi la fiecare RETENTION_INTERVAL_SECONDS
    def run_retention():
        try:
            deleted = retention.purge_old_data(conn)
            if any(deleted.values()):
                print("[retenție] șterse: " + ", ".join(f"{t}={n}" for t, n in deleted.items()))
        except sqlite3.Error as e:
            print(f"[retenție] sărit (baza ocupată sau eroare): {e}")  # nu oprim monitorizarea

    retention.ensure_indexes(conn)
    run_retention()
    last_retention = time.time()

    last_analysis = time.time()

    try:
        while True:
            start = time.time()
            n = collect_and_notify(
                conn, process_cache, notified_pairs, notified_inbound, hostname_cache,
                known_destination_keys, known_processes, last_whitelist_alert,
                decisions, notified_suspicious, previous_open,
            )

            if len(process_cache) > 500:
                process_cache.clear()

            if time.time() - last_analysis >= ANALYSIS_INTERVAL_SECONDS:
                run_risk_analysis(conn, risk_alert_state)
                last_analysis = time.time()

            if time.time() - last_retention >= RETENTION_INTERVAL_SECONDS:
                run_retention()
                last_retention = time.time()

            elapsed = time.time() - start
            time.sleep(max(0, POLL_INTERVAL_SECONDS - elapsed))

    except KeyboardInterrupt:
        print("\n[*] Monitor oprit de utilizator.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
