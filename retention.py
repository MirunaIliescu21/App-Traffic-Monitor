#!/usr/bin/env python3
"""
Retenția datelor: șterge din baza de date ce e prea vechi, ca fișierul să
nu crească la nesfârșit (în testele noastre: 3 MB -> 78 MB în câteva zile).

Ce se păstrează, cât timp, și de ce:
  connections     14 zile  - istoricul brut, 1 rând/conexiune/secundă; analiza
                             de risc folosește doar ultimele 24h, deci 14 zile
                             sunt suficiente pentru investigat ce s-a întâmplat
  inbound_events  90 zile  - rare și valoroase (cineva s-a conectat LA tine)
  tot restul      pentru totdeauna - mici și sunt "memoria" aplicației:
                  known_destinations (ce e normal pentru fiecare program),
                  destination_status + decision_log (deciziile tale),
                  notified_pairs, risk_alert_state, whitelist_alert_state

IMPORTANT - ce NU face ștergerea: nu micșorează fișierul. SQLite reutilizează
spațiul eliberat pentru date noi, deci baza nu mai crește, dar rămâne la
dimensiunea atinsă. Ca să recuperezi spațiul pe disc, oprești watcher-ul și
rulezi o dată: python3 retention.py --vacuum

Rulare manuală (arată ce ar șterge, fără să șteargă):  python3 retention.py --dry-run
Rulare manuală (șterge):                                 python3 retention.py
"""

import sqlite3
import sys
from datetime import datetime, timedelta, timezone

DB_PATH = "traffic_monitor.db"

# tabel -> (zile păstrate, coloana cu data)
RETENTION_RULES = {
    "connections": (14, "timestamp"),
    "inbound_events": (90, "timestamp"),
}

BATCH_SIZE = 50_000  # ștergem în loturi, ca să nu blocăm baza (watcher-ul scrie în ea)


def ensure_indexes(conn: sqlite3.Connection) -> None:
    """Fără index pe dată, fiecare ștergere ar parcurge tot tabelul."""
    conn.execute("CREATE INDEX IF NOT EXISTS idx_conn_time ON connections (timestamp)")
    conn.commit()


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def purge_old_data(conn: sqlite3.Connection, now: datetime | None = None,
                   rules: dict | None = None, dry_run: bool = False) -> dict:
    """
    Șterge rândurile mai vechi decât regula fiecărui tabel.
    Întoarce {tabel: număr_rânduri_șterse} (sau, la dry_run, câte AR fi șterse).
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
    """Recuperează spațiul pe disc. Necesită watcher-ul și dashboard-ul OPRITE."""
    conn.execute("VACUUM")


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        ensure_indexes(conn)
        result = purge_old_data(conn, dry_run=dry_run)
        verb = "ar fi șterse" if dry_run else "șterse"
        for table, n in result.items():
            days = RETENTION_RULES[table][0]
            print(f"  {table}: {n} rânduri {verb} (mai vechi de {days} zile)")
        if "--vacuum" in sys.argv and not dry_run:
            print("[*] Recuperez spațiul pe disc (VACUUM)...")
            vacuum(conn)
            print("[*] Gata.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
