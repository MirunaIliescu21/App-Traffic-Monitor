#!/usr/bin/env python3
"""
Citeste paginile deschise de utilizator din istoricul browserului.

De ce: pentru avertizarea de phishing ne trebuie DOMENIUL pe care l-a deschis
omul (ex. olx-plata.ro), nu adresa IP a serverului. Istoricul Firefox il are,
cu ora exacta, si se poate citi fara drepturi de administrator.

Cum merge: Firefox tine istoricul intr-un fisier SQLite (places.sqlite) pe care
il blocheaza cat timp ruleaza. Citim o COPIE (fisierul + jurnalul -wal, unde
Firefox scrie vizitele noi inainte sa le mute in fisierul principal).

Fiecare browser/OS are alta cale; aici e doar adaptorul pentru Firefox. Restul
aplicatiei primeste obiecte `Visit` si nu stie de unde vin (istoric acum,
extensie de browser mai tarziu).

Limite: ferestrele private nu lasa nimic in istoric; se vad doar paginile
deschise (nu imaginile, reclamele sau apelurile de fundal ale paginii).

Folosire:
    python3 browser_history.py --list        profilurile gasite
    python3 browser_history.py --recent 10   ultimele 10 vizite
    python3 browser_history.py --watch       afiseaza vizitele noi, pe masura ce apar
"""

import argparse
import glob
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

# visit_type din Firefox -> cum a ajuns omul pe pagina
VISIT_KINDS = {
    1: "link",
    2: "tastat",
    3: "bookmark",
    4: "incorporat",
    5: "redirect",
    6: "redirect",
    7: "descarcare",
    8: "link",
    9: "reincarcare",
}


@dataclass(frozen=True)
class Visit:
    visit_id: int
    when: float          # secunde epoch UTC (fara fus orar, ca sa nu ne incurce ora locala)
    url: str
    host: str            # domeniul in litere mici, fara port
    kind: str            # tastat / link / redirect / bookmark / reincarcare / ...
    from_visit: int      # id-ul vizitei de unde s-a venit (0 = nicio sursa)
    title: str = ""
    browser: str = "firefox"


# ---------- gasirea profilurilor ----------

def _profile_patterns() -> list[str]:
    home = os.path.expanduser("~")
    patterns = [
        os.path.join(home, ".mozilla", "firefox", "*", "places.sqlite"),                       # Linux
        os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox", "*", "places.sqlite"),  # Ubuntu (snap)
        os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox", "*", "places.sqlite"),  # Flatpak
        os.path.join(home, "Library", "Application Support", "Firefox", "Profiles", "*", "places.sqlite"),  # macOS
    ]
    appdata = os.environ.get("APPDATA")
    if appdata:                                                                                  # Windows
        patterns.append(os.path.join(appdata, "Mozilla", "Firefox", "Profiles", "*", "places.sqlite"))
    return patterns


def find_databases() -> list[str]:
    """Caile catre toate fisierele places.sqlite gasite (unul per profil Firefox)."""
    found = []
    for pattern in _profile_patterns():
        found.extend(glob.glob(pattern))
    return sorted(set(found))


# ---------- citire ----------

def _host_of(url: str) -> str | None:
    """Domeniul unei pagini web (http/https), sau None pentru orice altceva (about:, file:, extensii)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https"):
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    return host or None


def _query(db_path: str, sql: str, params: tuple = ()) -> list[tuple] | None:
    """
    Ruleaza o interogare pe o COPIE a bazei (fisier + jurnal -wal). Intoarce None daca
    fisierul nu se poate citi acum (de ex. copiat exact cand Firefox il scria): se reincearca la urmatoarea citire.
    """
    tmp_dir = tempfile.mkdtemp(prefix="tm_history_")
    try:
        copy = os.path.join(tmp_dir, "places.sqlite")
        try:
            shutil.copyfile(db_path, copy)
            wal = db_path + "-wal"
            if os.path.exists(wal):
                shutil.copyfile(wal, copy + "-wal")
        except OSError:
            return None
        conn = None
        try:
            conn = sqlite3.connect(copy)
            return conn.execute(sql, params).fetchall()
        except sqlite3.Error:
            return None
        finally:
            if conn is not None:
                conn.close()
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


_VISITS_SQL = (
    "SELECT v.id, v.visit_date, p.url, v.visit_type, v.from_visit, COALESCE(p.title, '') "
    "FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id "
    "WHERE v.id > ? ORDER BY v.id ASC"
)


def latest_visit_id(db_path: str) -> int:
    """Id-ul ultimei vizite din istoric (0 daca e gol sau nu se poate citi)."""
    rows = _query(db_path, "SELECT COALESCE(MAX(id), 0) FROM moz_historyvisits")
    return int(rows[0][0]) if rows else 0


def latest_visit_id_before(db_path: str, cutoff_epoch: float) -> int:
    """Id-ul ultimei vizite mai vechi de `cutoff_epoch` (0 daca nu exista sau nu se poate citi)."""
    rows = _query(db_path, "SELECT COALESCE(MAX(id), 0) FROM moz_historyvisits WHERE visit_date < ?",
                  (int(cutoff_epoch * 1_000_000),))
    return int(rows[0][0]) if rows else 0


def read_visits(db_path: str, after_id: int = 0) -> tuple[list[Visit], int] | None:
    """
    (vizitele web cu id > after_id, cel mai mare id vazut) sau None daca baza nu s-a putut citi acum.
    Cel mai mare id include si vizitele care nu sunt pagini web (about:, file:), ca sa nu le recitim.
    """
    rows = _query(db_path, _VISITS_SQL, (after_id,))
    if rows is None:
        return None
    visits = []
    max_id = after_id
    for visit_id, visit_date, url, visit_type, from_visit, title in rows:
        max_id = max(max_id, int(visit_id))
        host = _host_of(url)
        if host is None:
            continue
        visits.append(Visit(
            visit_id=int(visit_id),
            when=(visit_date or 0) / 1_000_000,       # Firefox tine microsecunde
            url=url,
            host=host,
            kind=VISIT_KINDS.get(visit_type, "altul"),
            from_visit=int(from_visit or 0),
            title=title,
        ))
    return visits, max_id


def new_visits(db_path: str, after_id: int = 0, limit: int | None = None) -> list[Visit]:
    """Vizitele web cu id mai mare decat `after_id`, de la cea mai veche la cea mai noua."""
    result = read_visits(db_path, after_id)
    visits = result[0] if result else []
    return visits[-limit:] if limit else visits


def _signature(db_path: str) -> tuple:
    """(data modificarii, marime) pentru fisier si jurnal: se schimba cand Firefox scrie ceva nou."""
    parts = []
    for path in (db_path, db_path + "-wal"):
        try:
            st = os.stat(path)
            parts.append((st.st_mtime_ns, st.st_size))
        except OSError:
            parts.append(None)
    return tuple(parts)


class HistoryWatcher:
    """
    Urmareste istoricul si intoarce doar vizitele aparute de la ultima intrebare.

    - La pornire retine ce exista deja, dar nu mai vechi de `lookback_seconds` inainte de acum
      (ca o repornire a serviciului sa nu piarda paginile deschise chiar atunci).
    - Nu copiaza baza (zeci de MB) daca fisierul nu s-a schimbat de la ultima citire.
    """

    def __init__(self, databases: list[str] | None = None, lookback_seconds: float = 300,
                 now: float | None = None):
        self.databases = list(databases) if databases is not None else find_databases()
        cutoff = (time.time() if now is None else now) - lookback_seconds
        self._last_id = {path: latest_visit_id_before(path, cutoff) for path in self.databases}
        self._signature: dict[str, tuple] = {}

    def poll(self) -> list[Visit]:
        fresh: list[Visit] = []
        for path in self.databases:
            signature = _signature(path)          # luata INAINTE de citire: o scriere in timpul citirii se prinde data viitoare
            if signature == self._signature.get(path):
                continue
            result = read_visits(path, self._last_id[path])
            if result is None:
                continue                           # nu s-a putut citi acum; semnatura ramane veche, reincercam
            visits, max_id = result
            self._signature[path] = signature
            self._last_id[path] = max_id
            fresh.extend(visits)
        return sorted(fresh, key=lambda v: v.when)


# ---------- linia de comanda ----------

def _show(visit: Visit) -> str:
    when = datetime.fromtimestamp(visit.when).strftime("%Y-%m-%d %H:%M:%S")
    return f"{when} | {visit.kind:<11} | {visit.host} | {visit.url[:90]}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Citeste vizitele din istoricul Firefox")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="profilurile gasite")
    group.add_argument("--recent", type=int, metavar="N", help="ultimele N vizite")
    group.add_argument("--watch", action="store_true", help="afiseaza vizitele noi")
    args = parser.parse_args()

    databases = find_databases()
    if args.list:
        for path in databases:
            print(path)
        if not databases:
            print("Nu am gasit niciun profil Firefox.", file=sys.stderr)
        return 0 if databases else 1
    if not databases:
        print("Nu am gasit niciun profil Firefox.", file=sys.stderr)
        return 1

    if args.recent:
        every = [v for path in databases for v in new_visits(path)]
        for visit in sorted(every, key=lambda v: v.when)[-args.recent:]:
            print(_show(visit))
        return 0

    watcher = HistoryWatcher(databases, lookback_seconds=0)
    print("Urmaresc vizitele noi (Ctrl+C opreste). Deschide un site in Firefox...")
    try:
        while True:
            for visit in watcher.poll():
                print(_show(visit), flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
