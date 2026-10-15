#!/usr/bin/env python3
"""
Etapa 3 (v2): Monitor continuu pe fundal.

Model NOU, diferit de v1:
- NU mai cere aprobare (d/n) pentru fiecare conexiune - prea multe,
  Firefox singur genereaza zeci pe minut, e nepractic
- Ruleaza CONTINUU pe fundal, colectand tot traficul (ca collector.py)
- Notifica INFORMATIV, o singura data, cand vede o combinație
  (proces, IP) noua - fara sa blocheze, fara sa ceara raspuns
- La fiecare ANALYSIS_INTERVAL_SECONDS, ruleaza analiza de risc
  (concentrare + beaconing + reputație, din baseline.py) pe datele
  proaspat colectate și trimite o alerta ACTIVa doar daca gasește
  ceva cu adevarat suspect (scor >= 50)

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
POLL_INTERVAL_SECONDS = 1          # cat de des verificam conexiunile active
                                     # (la 1s prindem și conexiuni scurte, gen curl -m 2;
                                     # la 3s+ le rataseram, exact problema descoperita la collector.py)
ANALYSIS_INTERVAL_SECONDS = 120    # cat de des rulam analiza de risc completa (2 minute)
RISK_ALERT_THRESHOLD = 50          # scor de la care trimitem alerta activa (nu doar informativa)
RETENTION_INTERVAL_SECONDS = 6 * 3600  # cat de des curațam datele vechi (vezi retention.py)
WHITELIST_COOLDOWN_SECONDS = 300   # cat timp minim între doua alerte de "comportament nou", per proces


# ---------- Notificari desktop, corect configurate pentru sudo ----------

def log_alert_to_file(message: str) -> None:
    """
    Scrie orice alerta (inbound sau risc ridicat) într-un fișier text
    permanent, INDIFERENT ce face desktop-ul cu popup-ul.

    De ce: notificarile "critical" din GNOME raman pe ecran pana le
    închizi manual, dar unele versiuni nu le arhiveaza în istoricul de
    notificari dupa închidere - poți pierde complet urma alertei.
    Fișierul asta e o evidența permanenta, utila și ca jurnal de audit.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(ALERTS_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message}\n")


def get_desktop_user_env() -> dict:
    """
    Cand scriptul ruleaza cu sudo, procesul e root și NU are acces la
    sesiunea grafica a utilizatorului (DBUS_SESSION_BUS_ADDRESS, DISPLAY).
    Reconstruim aceste variabile pentru utilizatorul original (cel care
    a dat sudo), ca notify-send sa știe catre ce desktop sa trimita popup-ul.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        return os.environ.copy()  # nu ruleaza cu sudo, mediul e deja corect

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
            # rulam notify-send explicit ca utilizatorul original, nu ca root
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
        pass  # nu blocam scriptul daca notificarea eșueaza


# ---------- Colectare (identica ca logica cu collector.py) ----------

def init_db(conn: sqlite3.Connection) -> None:
    # WAL: dashboard-ul (alt proces) poate citi/scrie decizii cat timp watcher-ul
    # scrie conexiuni, fara "database is locked" la fiecare al doilea ciclu
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
        pass  # coloana exista deja, nu e nicio problema
    # NOU: conexiuni PRIMITE (cineva se conecteaza la tine, nu invers)
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
    # Starea alertelor de risc, persistata între reporniri — Fix Direcția A
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
    # NOU: cooldown persistat între reporniri - ultima data cand am trimis
    # o alerta de "comportament nou" pentru fiecare proces
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
    """Încarca din SQLite starea alertelor de la rularea anterioara."""
    cur = conn.execute("SELECT process_name, last_alerted_count FROM risk_alert_state")
    state = {row[0]: row[1] for row in cur.fetchall()}
    if state:
        print(f"[*] Am încarcat starea alertelor pentru {len(state)} procese din rularea anterioara")
    return state


def save_risk_alert_state(conn: sqlite3.Connection, process_name: str, count: int) -> None:
    """Salveaza în SQLite numarul de conexiuni la momentul ultimei alerte."""
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
    Încarca, din rularile anterioare, ce (proces, cheie) sunt deja
    cunoscute, plus setul de procese care au cel puțin o destinație
    cunoscuta (folosit ca sa nu alertam la prima conexiune a unui proces
    complet nou - nu avem înca niciun "normal" de comparat).
    """
    # Cheile se țin la nivel de "entitate": 29 de blocuri Google cunoscute
    # pentru chrome înseamna "chrome știe Google" - un bloc Google nou nu mai
    # e "comportament nou". Tabela known_destinations ramane la nivel fin.
    cur = conn.execute("SELECT process_name, group_key, group_type FROM known_destinations")
    rows = cur.fetchall()
    known_keys = {(p, companies.entity_for(k, t)[0]) for p, k, t in rows}
    known_processes = {process_name for process_name, _, _ in rows}
    return known_keys, known_processes


def upsert_known_destination(conn: sqlite3.Connection, process_name: str, group_key: str,
                              group_type: str, timestamp: str) -> None:
    """Înregistreaza/actualizeaza o destinație cunoscuta - apelata la fiecare conexiune noua (pereche)."""
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
    La prima rulare dupa integrare, known_destinations e goala, deși
    `connections` poate avea luni de istoric deja. Fara backfill, orice
    proces ar parea "nou" o vreme, fara alerte utile. Populam o data din
    tot istoricul existent - exact logica validata în experiment.
    """
    existing = conn.execute("SELECT COUNT(*) FROM known_destinations").fetchone()[0]
    if existing > 0:
        print(f"[*] known_destinations are deja {existing} perechi (dintr-o rulare anterioara) - nu refac backfill-ul\n")
        return

    print("[*] known_destinations e goala - populez din istoricul existent (o singura data)...")
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
    """Încarca, per proces, ultima data (datetime) cand s-a trimis o alerta de 'comportament nou'."""
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
    DNS invers: încearca sa afle numele de domeniu asociat unui IP
    (ex. "185.125.190.36" -> "azure.microsoft.com"). Util ca sa
    recunoști imediat "a, asta e Digi Storage", nu doar un IP anonim.

    Nu toate IP-urile au un nume invers înregistrat - în acel caz,
    întoarcem IP-ul neschimbat, fara eroare.

    Cache în memorie, ca sa nu facem o cerere DNS noua la fiecare
    conexiune catre același IP (ar fi lent și inutil).
    """
    if ip in cache:
        return cache[ip]
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        cache[ip] = hostname
    except (socket.herror, socket.gaierror, OSError):
        cache[ip] = ip  # fara nume gasit, ramanem cu IP-ul brut
    return cache[ip]


def extract_base_domain(hostname: str) -> str:
    """
    Extrage "domeniul de baza" dintr-un hostname complet.
    Ex: lb-140-82-112-21-iad.github.com -> github.com

    Euristica simpla: pastram ultimele 2 segmente separate prin punct.
    LIMITARE cunoscuta: greșește pe domenii cu TLD compus din 2 parți
    (ex. "ceva.co.uk") - nu apare în datele noastre curente.
    """
    parts = hostname.rstrip(".").split(".")
    if len(parts) < 2:
        return hostname
    return ".".join(parts[-2:])


def get_group_key(ip: str, hostname_cache: dict) -> tuple[str, str]:
    """
    Calculeaza "cheia de grupare" a unei destinații, folosita de regula de
    "comportament nou" (vezi collect_and_notify). Trei metode, în ordine:

    1. Domeniu (din reverse DNS, via resolve_hostname - refolosim cache-ul
       deja existent, nicio cerere DNS în plus fața de ce se face oricum)
    2. Subnet (/24 IPv4, /48 IPv6), daca nu exista reverse DNS - IP-uri
       vecine sunt adesea aceeași infrastructura (același furnizor cloud)
    3. IP-ul însuși, ca fallback ultim, daca nici subnet-ul nu poate fi calculat

    Întoarce (cheie, tip) - tipul ajuta la depanare/jurnal, ca sa vezi prin
    ce metoda s-a facut gruparea.
    """
    hostname = resolve_hostname(ip, hostname_cache)

    if hostname != ip:
        # resolve_hostname a gasit un nume real (nu a cazut pe fallback-ul "IP-ul însuși")
        return extract_base_domain(hostname), "domeniu"

    try:
        addr = ipaddress.ip_address(ip)

        # IPv4 mascat ca IPv6 (ex. ::ffff:34.78.67.165) - aceeași capcana
        # documentata deja la is_effectively_loopback() din acest fișier.
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped

        prefix = 24 if addr.version == 4 else 48
        network = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        return str(network), "subnet"
    except ValueError:
        return ip, "ip"  # fallback ultim, practic nu se întampla


def is_effectively_loopback(ip: str) -> bool:
    """
    Verifica daca un IP e loopback (127.x.x.x, ::1), INCLUSIV varianta
    IPv6 "împachetata" (::ffff:127.0.0.1) - un format special, frecvent
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
    O trecere de colectare: salveaza toate conexiunile active (ca collector.py),
    trimite notificare informativa pentru conexiuni IEȘITE noi, și ALERTa
    IMEDIATa pentru conexiuni PRIMITE (cineva se conecteaza la tine).

    Distincția ieșit/primit: mai întai identificam porturile locale aflate
    în stare LISTEN (adica "ascultam" pe ele, suntem server). O conexiune
    ESTABLISHED al carei port local se potrivește cu un port LISTEN e o
    conexiune PRIMITa - cineva din exterior a inițiat-o, nu tu.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    all_conns = list(psutil.net_connections(kind="inet"))

    if decisions is None:
        decisions = {}
    if notified_suspicious is None:
        notified_suspicious = set()
    # reîncarcam deciziile din DB la fiecare ciclu: ce a apasat utilizatorul
    # în dashboard ("E normal" / "Nu recunosc") se aplica în ~1 secunda
    decisions.clear()
    decisions.update(ds.load_decisions(conn))
    if len(notified_suspicious) > 5000:
        notified_suspicious.clear()

    # pasul 1: identificam porturile pe care laptopul tau ASCULTa chiar acum
    listening_ports = {
        c.laddr.port for c in all_conns
        if c.status == "LISTEN" and c.laddr
    }

    rows = []
    current_open = set()  # conexiunile deschise ACUM (pentru ciclul urmator)

    for conn_info in all_conns:
        if not conn_info.raddr or not conn_info.pid:
            continue

        remote_ip = conn_info.raddr.ip
        remote_port = conn_info.raddr.port
        local_port = conn_info.laddr.port if conn_info.laddr else None
        pid = conn_info.pid

        name, exe_path, binary_hash = get_process_info(pid, process_cache)
        protocol = "TCP" if conn_info.type == 1 else "UDP"

        # Scriem în baza DOAR conexiunile noi (care nu erau deschise la citirea
        # precedenta), nu fiecare conexiune deschisa la fiecare secunda: o
        # conexiune de 10 minute ar însemna 600 de randuri (~275 MB/zi masurat).
        # O conexiune = (proces, adresa+portul tau, adresa+portul destinației).
        # Beaconing-ul nu pierde nimic: un curl la 60s deschide de fiecare data
        # o conexiune noua, cu alt port local. previous_open=None (teste) scrie tot.
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
            # NOU: conexiune PRIMITa - cineva s-a conectat la tine.
            # NU filtram IP-uri private aici (spre deosebire de traficul ieșit) -
            # un atacator pe aceeași rețea locala (ex. Kali în VirtualBox) are
            # tot un IP privat, dar tot vrem sa te alerteze despre el.
            #
            # cheia include remote_port: fiecare CONEXIUNE NOUa (chiar de la
            # același IP, catre același port local) are un remote_port diferit,
            # alocat aleator de sistemul de operare al atacatorului la fiecare
            # reconectare - fara remote_port în cheie, a doua reconectare de la
            # Kali nu mai declanșa alerta, deși era o încercare noua, reala.
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
                "🔴 Conexiune PRIMITa - cineva te-a contactat",
                f"{remote_ip} s-a conectat la {name} (portul tau {local_port})",
                urgency="critical",
            )
            print(f"[INBOUND!] {remote_ip}:{remote_port} -> {name} (port local {local_port})")
            continue  # nu mai trecem și prin logica de "ieșit" pentru aceeași conexiune

        # de aici: conexiuni IEȘITE catre IP-uri publice
        if is_private_ip(remote_ip):
            continue

        group_key, group_type = get_group_key(remote_ip, hostname_cache)
        # decidem și ținem minte la nivel de companie (Google, Microsoft...) cand
        # o știm; altfel la nivel de destinație exacta
        entity_key, entity_type = companies.entity_for(group_key, group_type)
        dest_key = (name, entity_key)
        status = decisions.get(dest_key)

        # --- destinație marcata "Nu recunosc": ORICE conexiune noua alerteaza ---
        # Verificarea e înaintea lui `notified_pairs` și ignora cooldown-ul:
        # o destinație pe care utilizatorul a declarat-o suspecta trebuie sa
        # alerteze și cand revine pe un IP deja vazut. Ca sa nu alerteze la
        # fiecare secunda pentru ACEEAȘI conexiune înca deschisa, deduplicam
        # pe (proces, IP, port remote, port local).
        if status == ds.SUSPICIOUS:
            conn_key = (name, remote_ip, remote_port, local_port)
            action = ds.decide_action(status, False, False, conn_key in notified_suspicious)
            if action == ds.ACTION_ALERT_SUSPICIOUS:
                notified_suspicious.add(conn_key)
                log_alert_to_file(
                    f"[NU-RECUNOSC] {name} contacteaza din nou {entity_key} ({remote_ip})"
                )
                send_desktop_notification(
                    f"🔴 {name} contacteaza o destinație marcata „Nu recunosc”",
                    f"{entity_key} ({remote_ip})",
                    urgency="critical",
                )
                print(f"[NU-RECUNOSC!] {name} -> {entity_key} ({remote_ip})")
            continue

        # notificare INFORMATIVa pentru conexiuni IEȘITE noi (logica veche)
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
        if status != ds.NORMAL:  # ce a confirmat utilizatorul ca normal nu mai deranjeaza
            send_desktop_notification(
                "Conexiune noua observata",
                f"{name} -> {display_dest}",
                urgency="low",
            )
        print(f"[info] Conexiune noua: {name} -> {display_dest} ({remote_ip})")

        # regula de "comportament nou" - proces deja cunoscut, destinație
        # (domeniu/subnet) niciodata vazuta pentru el.
        is_new_destination = name in known_processes and dest_key not in known_destination_keys
        now_dt = datetime.now(timezone.utc)
        last_alert = last_whitelist_alert.get(name)
        cooldown_expired = (
            last_alert is None
            or (now_dt - last_alert).total_seconds() >= WHITELIST_COOLDOWN_SECONDS
        )
        action = ds.decide_action(status, is_new_destination, cooldown_expired, False)

        if action in (ds.ACTION_ALERT_NEW, ds.ACTION_PENDING_SILENT):
            # în ambele cazuri destinația intra în lista "de verificat" - chiar
            # daca cooldown-ul a oprit notificarea, utilizatorul o vede în dashboard
            ds.record_pending(
                conn, name, entity_key, entity_type, timestamp,
                sample_ip=remote_ip,
                sample_hostname=hostname if hostname != remote_ip else None,
            )
            decisions[dest_key] = ds.PENDING

        if action == ds.ACTION_ALERT_NEW:
            title, _ = companies.display(entity_key, entity_type)
            log_alert_to_file(
                f"[COMPORTAMENT NOU] {name} -> destinație noua: {entity_key} "
                f"({entity_type}; {group_key})"
            )
            send_desktop_notification(
                f"🟡 {name}: destinație noua",
                f"Contacteaza pentru prima data {title}. Deschide dashboard-ul ca sa decizi.",
                urgency="normal",
            )
            print(f"[NOU-COMPORTAMENT] {name} -> {entity_key} ({entity_type}; {group_key})")
            last_whitelist_alert[name] = now_dt
            save_whitelist_alert_state(conn, name, now_dt)
        elif action == ds.ACTION_PENDING_SILENT:
            print(f"[NOU-COMPORTAMENT, fara notificare - cooldown] {name} -> {entity_key} ({entity_type}; {group_key})")

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


# ---------- Analiza periodica de risc (reutilizeaza baseline.py) ----------

def run_risk_analysis(conn: sqlite3.Connection, risk_alert_state: dict) -> None:
    """
    Ruleaza exact aceeași logica din baseline.py (concentrare, beaconing,
    reputație) pe datele acumulate pana acum, și trimite o alerta ACTIVa
    (urgency=critical) doar pentru procesele cu scor >= RISK_ALERT_THRESHOLD.

    NOU: risc_alert_state ține minte, per proces, cate conexiuni (totale)
    avea la ULTIMA alerta trimisa. Daca numarul nu s-a schimbat fața de
    ultima data (adica nu a aparut trafic nou), NU retrimitem popup -
    altfel un proces suspect declanșa aceeași alerta la infinit, la
    fiecare 2 minute, chiar daca nu se întampla nimic nou (bug descoperit
    empiric: curl-ul de test oprit înca aparea "detectat" identic, de 3
    ori la rand, doar pentru ca analiza re-evalua aceleași date vechi).
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

        # afișam TOATE motivele, nu doar primele 2
        reasons_text = "\n      ".join(report["reasons"])
        key_reasons = [r for r in report["reasons"] if "CONCENTRAT" in r or "BEACONING" in r or "Reputa" in r]
        summary = "; ".join(key_reasons) if key_reasons else reasons_text

        if last_alerted_count == current_count:
            # nimic nou fața de ultima alerta - doar nota discreta în consola, fara popup
            print(f"[risc neschimbat] {process_name}: tot la {report['risk_score']}/100, fara activitate noua (nu retrimit popup)")
            continue

        print(f"[ALERTa] {process_name}: risc {report['risk_score']}/100")
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


# ---------- Bucla principala ----------

def main():
    print(f"[*] Pornesc monitorul continuu")
    print(f"[*] Polling conexiuni: {POLL_INTERVAL_SECONDS}s | Analiza risc: la fiecare {ANALYSIS_INTERVAL_SECONDS}s")
    print("[*] Ctrl+C pentru oprire\n")

    conn = sqlite3.connect(DB_PATH, timeout=10)
    init_db(conn)

    # încarcam ce combinații am notificat deja (din rulari anterioare)
    cur = conn.execute("SELECT process_name, remote_ip FROM notified_pairs")
    notified_pairs = {(row[0], row[1]) for row in cur.fetchall()}
    print(f"[*] {len(notified_pairs)} combinații (proces, IP) deja notificate anterior\n")

    process_cache: dict = {}
    hostname_cache: dict = {}
    notified_inbound: set = set()
    risk_alert_state: dict = load_risk_alert_state(conn)

    # NOU: backfill din istoric (o singura data, daca tabela e goala), apoi
    # încarcam ce e deja cunoscut + cooldown-ul de la rularea anterioara
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

    # curațare date vechi: la pornire, apoi la fiecare RETENTION_INTERVAL_SECONDS
    def run_retention():
        try:
            deleted = retention.purge_old_data(conn)
            if any(deleted.values()):
                print("[retenție] șterse: " + ", ".join(f"{t}={n}" for t, n in deleted.items()))
        except sqlite3.Error as e:
            print(f"[retenție] sarit (baza ocupata sau eroare): {e}")  # nu oprim monitorizarea

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
