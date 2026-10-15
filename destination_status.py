#!/usr/bin/env python3
"""
Starea destinațiilor: "de verificat" / "normal" / "suspect".

Modul comun, folosit atât de watcher_v6.py (scrie destinațiile noi, citește
deciziile), cât și de dashboard.py (afișează + butoanele "E normal" /
"Nu recunosc"). Nu depinde de psutil sau Flask - doar sqlite3 - ca să poată
fi testat izolat.

Trei stări (decizie de produs):
  pending    - destinație nouă pentru un proces cunoscut; utilizatorul nu a
               decis încă. Rămâne în listă, NU mai alertează, NU devine
               niciodată "normal" automat (liniștea nu înseamnă aprobare).
  normal     - utilizatorul a confirmat "E normal". Nu mai alertează.
  suspicious - utilizatorul a spus "Nu recunosc". Orice conexiune nouă către
               ea alertează, ignorând cooldown-ul.
"""

import sqlite3
from datetime import datetime, timezone

PENDING = "pending"
NORMAL = "normal"
SUSPICIOUS = "suspicious"
VALID_STATUSES = (PENDING, NORMAL, SUSPICIOUS)

# Acțiunile posibile pentru o conexiune ieșită către o destinație
ACTION_IGNORE = "ignore"
ACTION_ALERT_SUSPICIOUS = "alert_suspicious"
ACTION_ALERT_NEW = "alert_new"
ACTION_PENDING_SILENT = "pending_silent"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_tables(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS destination_status (
            process_name TEXT NOT NULL,
            group_key TEXT NOT NULL,
            group_type TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('pending', 'normal', 'suspicious')),
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            decided_at TEXT,
            sample_ip TEXT,
            sample_hostname TEXT,
            PRIMARY KEY (process_name, group_key)
        )
    """)
    # istoricul deciziilor - ca utilizatorul (și tu) să vedeți ce s-a decis și când
    conn.execute("""
        CREATE TABLE IF NOT EXISTS decision_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            process_name TEXT NOT NULL,
            group_key TEXT NOT NULL,
            old_status TEXT,
            new_status TEXT NOT NULL
        )
    """)
    conn.commit()


def decide_action(status: str | None, is_new_destination: bool,
                  cooldown_expired: bool, already_alerted_this_connection: bool) -> str:
    """
    Logica de decizie, ca funcție pură (ușor de testat, fără rețea sau DB).

    status: starea cunoscută a destinației (None dacă nu are rând încă).
    is_new_destination: procesul e cunoscut, dar nu a mai contactat grupul ăsta.
    cooldown_expired: a trecut destul timp de la ultima alertă "nouă" a procesului.
    already_alerted_this_connection: pentru "suspect" - conexiunea asta
        (aceeași, încă deschisă) a declanșat deja o alertă.
    """
    if status == SUSPICIOUS:
        return ACTION_IGNORE if already_alerted_this_connection else ACTION_ALERT_SUSPICIOUS
    if status == NORMAL:
        return ACTION_IGNORE
    if status == PENDING:
        return ACTION_IGNORE  # deja listată, deja alertată (sau tăcută) o dată
    if is_new_destination:
        return ACTION_ALERT_NEW if cooldown_expired else ACTION_PENDING_SILENT
    return ACTION_IGNORE


def record_pending(conn: sqlite3.Connection, process_name: str, group_key: str,
                   group_type: str, timestamp: str,
                   sample_ip: str | None = None, sample_hostname: str | None = None) -> bool:
    """Adaugă o destinație ca 'de verificat'. Întoarce True dacă e într-adevăr nouă."""
    cur = conn.execute("""
        INSERT OR IGNORE INTO destination_status
            (process_name, group_key, group_type, status, first_seen, last_seen,
             decided_at, sample_ip, sample_hostname)
        VALUES (?, ?, ?, 'pending', ?, ?, NULL, ?, ?)
    """, (process_name, group_key, group_type, timestamp, timestamp, sample_ip, sample_hostname))
    conn.commit()
    return cur.rowcount > 0


def set_status(conn: sqlite3.Connection, process_name: str, group_key: str,
               new_status: str, timestamp: str | None = None) -> bool:
    """
    Aplică decizia utilizatorului. Întoarce False dacă destinația nu există.
    Ridică ValueError pentru o stare invalidă (nu o ignorăm în tăcere).
    """
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Stare invalidă: {new_status!r}")
    ts = timestamp or _now()
    row = conn.execute(
        "SELECT status FROM destination_status WHERE process_name = ? AND group_key = ?",
        (process_name, group_key),
    ).fetchone()
    if row is None:
        return False
    old_status = row[0]
    if old_status == new_status:
        return True
    conn.execute("""
        UPDATE destination_status
        SET status = ?, decided_at = ?
        WHERE process_name = ? AND group_key = ?
    """, (new_status, None if new_status == PENDING else ts, process_name, group_key))
    conn.execute("""
        INSERT INTO decision_log (timestamp, process_name, group_key, old_status, new_status)
        VALUES (?, ?, ?, ?, ?)
    """, (ts, process_name, group_key, old_status, new_status))
    conn.commit()
    return True


def load_decisions(conn: sqlite3.Connection) -> dict:
    """
    {(proces, cheie): stare} pentru TOATE destinațiile cu rând. Watcher-ul
    reîncarcă asta la fiecare ciclu, ca decizia luată în dashboard să
    se aplice în câteva secunde, fără repornire.
    """
    cur = conn.execute("SELECT process_name, group_key, status FROM destination_status")
    return {(p, k): s for p, k, s in cur.fetchall()}


def list_by_status(conn: sqlite3.Connection, status: str, limit: int = 200) -> list[dict]:
    cur = conn.execute("""
        SELECT process_name, group_key, group_type, status, first_seen, last_seen,
               decided_at, sample_ip, sample_hostname
        FROM destination_status
        WHERE status = ?
        ORDER BY first_seen DESC
        LIMIT ?
    """, (status, limit))
    cols = ["process_name", "group_key", "group_type", "status", "first_seen",
            "last_seen", "decided_at", "sample_ip", "sample_hostname"]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def list_decision_log(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    cur = conn.execute("""
        SELECT timestamp, process_name, group_key, old_status, new_status
        FROM decision_log
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    cols = ["timestamp", "process_name", "group_key", "old_status", "new_status"]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


_STATUS_PRIORITY = {SUSPICIOUS: 2, NORMAL: 1, PENDING: 0}


def migrate_to_entities(conn: sqlite3.Connection, entity_fn) -> int:
    """
    Strânge rândurile existente pe "entitate" (de ex. 29 de blocuri de IP-uri
    Google devin un singur rând "Google"). entity_fn(group_key, group_type)
    întoarce (cheie, tip) - vezi companies.entity_for.

    La contopire câștigă decizia cea mai "prudentă": suspect > normal > de
    verificat. Dacă ai spus "E normal" pentru amazonaws.com, decizia acoperă
    acum tot "Amazon". Idempotentă: rândurile deja migrate nu se mai ating.
    Întoarce numărul de rânduri vechi înlocuite.
    """
    rows = conn.execute("""
        SELECT process_name, group_key, group_type, status, first_seen, last_seen,
               decided_at, sample_ip, sample_hostname
        FROM destination_status
        ORDER BY first_seen
    """).fetchall()

    merged = {}      # (proces, cheie_entitate) -> dict
    replaced = []    # (proces, cheie veche) de șters
    for process, key, gtype, status, first, last, decided, ip, host in rows:
        ekey, etype = entity_fn(key, gtype)
        if (ekey, etype) == (key, gtype):
            continue  # deja entitate (sau destinație fără companie cunoscută)
        replaced.append((process, key))
        cur = merged.get((process, ekey))
        if cur is None:
            merged[(process, ekey)] = {
                "type": etype, "status": status, "first": first, "last": last,
                "decided": decided, "ip": ip, "host": host,
            }
        else:
            cur["first"] = min(cur["first"], first)
            cur["last"] = max(cur["last"], last)
            if _STATUS_PRIORITY[status] > _STATUS_PRIORITY[cur["status"]]:
                cur["status"], cur["decided"] = status, decided
            elif status == cur["status"] and decided and (not cur["decided"] or decided > cur["decided"]):
                cur["decided"] = decided

    for process, key in replaced:
        conn.execute("DELETE FROM destination_status WHERE process_name = ? AND group_key = ?",
                     (process, key))
    for (process, ekey), m in merged.items():
        existing = conn.execute(
            "SELECT status, first_seen, last_seen, decided_at FROM destination_status "
            "WHERE process_name = ? AND group_key = ?", (process, ekey)).fetchone()
        if existing:  # entitatea exista deja (ex. rulare anterioară) - contopim și cu ea
            ex_status, ex_first, ex_last, ex_decided = existing
            if _STATUS_PRIORITY[ex_status] >= _STATUS_PRIORITY[m["status"]]:
                m["status"], m["decided"] = ex_status, ex_decided
            m["first"], m["last"] = min(m["first"], ex_first), max(m["last"], ex_last)
            conn.execute("DELETE FROM destination_status WHERE process_name = ? AND group_key = ?",
                         (process, ekey))
        conn.execute("""
            INSERT INTO destination_status
                (process_name, group_key, group_type, status, first_seen, last_seen,
                 decided_at, sample_ip, sample_hostname)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (process, ekey, m["type"], m["status"], m["first"], m["last"],
              m["decided"], m["ip"], m["host"]))
    conn.commit()
    return len(replaced)
