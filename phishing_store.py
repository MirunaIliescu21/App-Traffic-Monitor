"""
Datele despre alertele de phishing: ce s-a observat, ce a ascuns utilizatorul si
ce domenii a marcat ca "reale". Folosit de phishing_watcher.py (scrie) si de
dashboard.py (citeste si primeste deciziile utilizatorului).

Tabele:
  phishing_events     un rand per deschidere suspecta (doar numele domeniului, nu adresa completa)
  phishing_allowlist  domeniile pe care utilizatorul le-a marcat "este site-ul real"

"Am inteles" ascunde banda pentru acea alerta (dismissed=1); o vizita noua la acelasi
site creeaza o alerta noua, care apare iar. "Este site-ul real" opreste alertele pentru
domeniu, pana il anulezi.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

ACTIVE_HOURS = 24      # cat timp ramane in banda o alerta pe care utilizatorul n-a inchis-o


def init_tables(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS phishing_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            host TEXT NOT NULL,
            score INTEGER NOT NULL,
            brand TEXT,
            reasons TEXT,
            kind TEXT,
            alerted INTEGER NOT NULL DEFAULT 0,
            dismissed INTEGER NOT NULL DEFAULT 0
        )
    """)
    columns = [row[1] for row in conn.execute("PRAGMA table_info(phishing_events)")]
    if "dismissed" not in columns:           # baza creata de o versiune mai veche
        conn.execute("ALTER TABLE phishing_events ADD COLUMN dismissed INTEGER NOT NULL DEFAULT 0")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_phishing_time ON phishing_events (timestamp)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS phishing_allowlist (
            host TEXT PRIMARY KEY,
            added_at TEXT NOT NULL
        )
    """)
    conn.commit()


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.execute(sql, params)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------- citire ----------

def list_events(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    """Ultimele evenimente suspecte (si cele sub prag), cele mai noi primele."""
    return _rows(conn, "SELECT * FROM phishing_events ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,))


def grouped_events(conn: sqlite3.Connection, limit: int = 20, scan: int = 500) -> list[dict]:
    """
    Evenimentele grupate pe domeniu, cele mai recente primele: cate deschideri au fost, prima
    si ultima data. Restul campurilor (motive, cum s-a ajuns acolo) sunt de la ultima deschidere.
    Domeniile marcate "este site-ul real" nu apar (sunt in lista lor, cu "Anuleaza").
    Se uita doar la ultimele `scan` evenimente, ca lista sa ramana rapida.
    """
    allowlist = load_allowlist(conn)
    groups: dict[str, dict] = {}
    for row in list_events(conn, scan):                # cele mai noi primele
        if is_allowed(row["host"], allowlist):         # marcat "real": a iesit din lista, ca la "De verificat"
            continue
        group = groups.get(row["host"])
        if group is None:
            groups[row["host"]] = {**row, "visits": 1, "first_seen": row["timestamp"],
                                   "last_seen": row["timestamp"]}
        else:
            group["visits"] += 1
            group["first_seen"] = row["timestamp"]     # ne intoarcem in timp: ultima citita e cea mai veche
            group["alerted"] = max(group["alerted"], row["alerted"])
    return list(groups.values())[:limit]


def active_alerts(conn: sqlite3.Connection, now: datetime | None = None) -> list[dict]:
    """
    Alertele reale (scor de la prag) din ultimele ACTIVE_HOURS ore, pe care utilizatorul
    nu le-a inchis. Cate una per domeniu (cea mai recenta), cele mai noi primele.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = (now - timedelta(hours=ACTIVE_HOURS)).isoformat()
    rows = _rows(conn, "SELECT * FROM phishing_events WHERE alerted = 1 AND dismissed = 0 AND timestamp > ? "
                       "ORDER BY timestamp DESC, id DESC", (cutoff,))
    seen, result = set(), []
    for row in rows:
        if row["host"] not in seen:
            seen.add(row["host"])
            result.append(row)
    return result


def known_host(conn: sqlite3.Connection, host: str) -> bool:
    return conn.execute("SELECT 1 FROM phishing_events WHERE host = ? LIMIT 1", (host,)).fetchone() is not None


def list_allowlist(conn: sqlite3.Connection) -> list[dict]:
    return _rows(conn, "SELECT host, added_at FROM phishing_allowlist ORDER BY added_at DESC")


def load_allowlist(conn: sqlite3.Connection) -> frozenset:
    return frozenset(row[0] for row in conn.execute("SELECT host FROM phishing_allowlist"))


def is_allowed(host: str, allowlist) -> bool:
    """Domeniul sau un subdomeniu al unui domeniu marcat 'real'."""
    return any(host == a or host.endswith("." + a) for a in allowlist)


# ---------- deciziile utilizatorului ----------

def dismiss(conn: sqlite3.Connection, host: str) -> int:
    """"Am inteles": ascunde din banda alertele curente ale domeniului. Intoarce cate au fost ascunse."""
    cur = conn.execute("UPDATE phishing_events SET dismissed = 1 WHERE host = ? AND dismissed = 0", (host,))
    conn.commit()
    return cur.rowcount


def allow(conn: sqlite3.Connection, host: str) -> bool:
    """
    "Este site-ul real": domeniul nu mai alerteaza. Se accepta doar domenii pe care
    le-am semnalat noi (nu orice text primit), si alertele lui curente se inchid.
    """
    if not known_host(conn, host):
        return False
    conn.execute("INSERT OR REPLACE INTO phishing_allowlist (host, added_at) VALUES (?, ?)", (host, _now_iso()))
    conn.execute("UPDATE phishing_events SET dismissed = 1 WHERE host = ?", (host,))
    conn.commit()
    return True


def unallow(conn: sqlite3.Connection, host: str) -> bool:
    cur = conn.execute("DELETE FROM phishing_allowlist WHERE host = ?", (host,))
    conn.commit()
    return cur.rowcount > 0
