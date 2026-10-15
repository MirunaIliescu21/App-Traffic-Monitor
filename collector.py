#!/usr/bin/env python3
"""
Etapa 1: Colector proces <-> conexiune de retea.

Ruleaza periodic, citește conexiunile active de pe sistem (TCP/UDP),
le asociaza cu procesul care le-a deschis (PID, nume, hash binar)
și le salveaza în SQLite pentru analiza ulterioara (baseline + detectie).

Rulare: sudo python3 collector.py
(are nevoie de sudo pentru a vedea toate conexiunile, nu doar ale userului curent)
"""

import psutil
import sqlite3
import hashlib
import time
from datetime import datetime, timezone

DB_PATH = "traffic_monitor.db"
# POLL_INTERVAL_SECONDS = 5
POLL_INTERVAL_SECONDS = 1



def init_db(db_path: str) -> sqlite3.Connection:
    """Creeaza schema daca nu exista deja."""
    conn = sqlite3.connect(db_path)
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
    # Index pentru interogari rapide pe proces + timp, utile la faza de baseline
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_process_time
        ON connections (process_name, timestamp)
    """)
    conn.commit()
    return conn


def hash_binary(path: str) -> str | None:
    """
    Calculeaza SHA256 al binarului executabilului.
    Util mai tarziu pentru a detecta daca binarul s-a schimbat
    (semn posibil de compromitere/backdoor) între rulari.
    """
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
    """
    Functia returneaza numele, path-ul și hash-ul unui proces si
    face cache simplu ca sa nu recalculam hash-ul de fiecare data (e costisitor).
    """
    if pid in cache:
        return cache[pid]

    try:
        proc = psutil.Process(pid)
        name = proc.name()
        exe_path = proc.exe()
        binary_hash = hash_binary(exe_path)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        name, exe_path, binary_hash = "unknown", None, None

    cache[pid] = (name, exe_path, binary_hash)
    return cache[pid]


def collect_once(conn: sqlite3.Connection, process_cache: dict) -> int:
    """O singura trecere de colectare. Întoarce numarul de conexiuni salvate."""
    timestamp = datetime.now(timezone.utc).isoformat()
    rows = []

    # kind="inet" prinde atat TCP cat și UDP, IPv4 și IPv6
    for conn_info in psutil.net_connections(kind="inet"):
        # Ne intereseaza doar conexiunile cu adresa la distanta (nu porturile locale în ascultare fara peer)
        if not conn_info.raddr:
            continue

        pid = conn_info.pid
        if pid is None:
            continue  # conexiune orfana / kernel, greu de atribuit unui proces

        name, exe_path, binary_hash = get_process_info(pid, process_cache)
        protocol = "TCP" if conn_info.type == 1 else "UDP"

        rows.append((
            timestamp,
            pid,
            name,
            exe_path,
            binary_hash,
            conn_info.laddr.ip if conn_info.laddr else None,
            conn_info.laddr.port if conn_info.laddr else None,
            conn_info.raddr.ip,
            conn_info.raddr.port,
            protocol,
            conn_info.status,
        ))

    if rows:
        conn.executemany("""
            INSERT INTO connections (
                timestamp, pid, process_name, binary_path, binary_hash,
                local_ip, local_port, remote_ip, remote_port, protocol, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
        conn.commit()

    return len(rows)


def main():
    print(f"[*] Pornesc colectorul, salvez în {DB_PATH}")
    print(f"[*] Interval de polling: {POLL_INTERVAL_SECONDS}s")
    print("[*] Ctrl+C pentru oprire\n")

    conn = init_db(DB_PATH)
    process_cache: dict = {}

    try:
        while True:
            start = time.time()
            n = collect_once(conn, process_cache)
            elapsed = time.time() - start
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {n} conexiuni salvate ({elapsed:.2f}s)")

            # golim cache-ul din cand în cand, ca sa prindem procese noi/schimbate
            if len(process_cache) > 500:
                process_cache.clear()

            time.sleep(max(0, POLL_INTERVAL_SECONDS - elapsed))
    except KeyboardInterrupt:
        print("\n[*] Oprit de utilizator.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
