#!/usr/bin/env python3
"""
Retentia datelor: sterge din baza de date ce e prea vechi, ca fisierul sa
nu creasca la nesfarsit (in testele noastre: 3 MB -> 78 MB in cateva zile).

Ce se pastreaza, cat timp, si de ce:
  connections     14 zile  - istoricul brut, 1 rand/conexiune/secunda; analiza
                             de risc foloseste doar ultimele 24h, deci 14 zile
                             sunt suficiente pentru investigat ce s-a intamplat
  inbound_events  90 zile  - rare si valoroase (cineva s-a conectat LA tine)
  tot restul      pentru totdeauna - mici si sunt "memoria" aplicatiei:
                  known_destinations (ce e normal pentru fiecare program),
                  destination_status + decision_log (deciziile tale),
                  notified_pairs, risk_alert_state, whitelist_alert_state

IMPORTANT - ce NU face stergerea: nu micsoreaza fisierul. SQLite reutilizeaza
spatiul eliberat pentru date noi, deci baza nu mai creste, dar ramane la
dimensiunea atinsa. Ca sa recuperezi spatiul pe disc, opresti watcher-ul si
rulezi o data: python3 retention.py --vacuum

Rulare manuala (arata ce ar sterge, fara sa stearga):  python3 retention.py --dry-run
Rulare manuala (sterge):                                 python3 retention.py
"""

import sqlite3
import sys
from datetime import datetime, timedelta, timezone

DB_PATH = "traffic_monitor.db"

# tabel -> (zile pastrate, coloana cu data)
RETENTION_RULES = {
    "connections": (14, "timestamp"),
    "inbound_events": (90, "timestamp"),
}

BATCH_SIZE = 50_000  # stergem in loturi, ca sa nu blocam baza (watcher-ul scrie in ea)


def ensure_indexes(conn: sqlite3.Connection) -> None:
    """Fara index pe data, fiecare stergere ar parcurge tot tabelul."""
    conn.execute("CREATE INDEX IF NOT EXISTS idx_conn_time ON connections (timestamp)")
    conn.commit()


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def purge_old_data(conn: sqlite3.Connection, now: datetime | None = None,
                   rules: dict | None = None, dry_run: bool = False) -> dict:
    """
    Sterge randurile mai vechi decat regula fiecarui tabel.
    Intoarce {tabel: numar_randuri_sterse} (sau, la dry_run, cate AR fi sterse).
    """
    now = now or datetime.now(timezone.utc)
    rules = rules or RETENTION_RULES
    result = {}
    for table, (days, column) in rules.items():
        if not _table_exists(conn, table):
            continue
        cutoff = (now - timedelta(days=days)).isoformat()

        if dry_run:
            result[table] = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {column} < ?", (cutoff,)
            ).fetchone()[0]
            continue

        total = 0
        while True:
            cur = conn.execute(
                f"DELETE FROM {table} WHERE rowid IN "
                f"(SELECT rowid FROM {table} WHERE {column} < ? LIMIT ?)",
                (cutoff, BATCH_SIZE),
            )
            conn.commit()
            total += cur.rowcount
            if cur.rowcount < BATCH_SIZE:
                break
        result[table] = total
    return result


def vacuum(conn: sqlite3.Connection) -> None:
    """Recupereaza spatiul pe disc. Necesita watcher-ul si dashboard-ul OPRITE."""
    conn.execute("VACUUM")


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        ensure_indexes(conn)
        result = purge_old_data(conn, dry_run=dry_run)
        verb = "ar fi sterse" if dry_run else "sterse"
        for table, n in result.items():
            days = RETENTION_RULES[table][0]
            print(f"  {table}: {n} randuri {verb} (mai vechi de {days} zile)")
        if "--vacuum" in sys.argv and not dry_run:
            print("[*] Recuperez spatiul pe disc (VACUUM)...")
            vacuum(conn)
            print("[*] Gata.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
