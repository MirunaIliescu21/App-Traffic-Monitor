#!/usr/bin/env python3
"""
Baza ASN: pentru orice adresa IP publica, cui apartine.

Un ASN (Autonomous System Number) e numarul sub care o organizatie isi
anunta adresele pe internet. Fisierul public de la iptoasn.com spune, pentru
fiecare interval de adrese, ce ASN, ce tara si ce nume de organizatie.
Asta inlocuieste lista scrisa de mana din companies.py acolo unde ea nu stie.

Cum se foloseste:
    python3 asn.py --update          descarca fisierul si construieste asn.db
    python3 asn.py --build FISIER    construieste asn.db dintr-un fisier descarcat
    python3 asn.py --lookup 8.8.8.8  cui apartine o adresa
    python3 asn.py --check           arata ce ASN-uri am mapat pe companii

Fara asn.db, aplicatia merge ca inainte (lookup intoarce None peste tot).

Date: https://iptoasn.com (domeniu public, PDDL). Fiecare calculator isi
descarca singur fisierul, nu il redistribuim noi.

Limitare: un ASN spune cine ANUNTA adresa, nu cine foloseste serverul. Un
server inchiriat pe Amazon apare ca "Amazon".
"""

import argparse
import functools
import gzip
import os
import re
import socket
import sqlite3
import sys
import tempfile
import threading
import urllib.request
from datetime import datetime, timezone

ASN_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "asn.db")
SOURCE_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

_local = threading.local()   # o conexiune SQLite per fir (dashboard-ul foloseste fire)


# ---------- construire ----------

def _family_and_packed(ip: str):
    """(familie, octeti) pentru o adresa IPv4/IPv6, sau None daca nu e valida."""
    try:
        if ":" in ip:
            return 6, socket.inet_pton(socket.AF_INET6, ip)
        return 4, socket.inet_pton(socket.AF_INET, ip)
    except (OSError, ValueError):
        return None


def _open_text(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def build(source_path: str, db_path: str | None = None) -> tuple[int, int]:
    """
    Construieste baza de cautare dintr-un fisier ip2asn (TSV, optional .gz).
    Coloane: start, sfarsit, ASN, tara, nume. Liniile cu ASN 0 ("Not routed")
    si cele stricate se sar. Se scrie intr-un fisier temporar si se inlocuieste
    atomic, ca un serviciu care citeste baza in acel moment sa nu vada o baza pe jumatate.
    Intoarce (numar intervale, numar ASN-uri distincte).
    """
    db_path = db_path or ASN_DB_PATH
    directory = os.path.dirname(os.path.abspath(db_path))
    fd, tmp_path = tempfile.mkstemp(prefix="asn_build_", suffix=".db", dir=directory)
    os.close(fd)
    try:
        conn = sqlite3.connect(tmp_path)
        conn.execute("CREATE TABLE asn_ranges (family INTEGER NOT NULL, range_start BLOB NOT NULL, "
                     "range_end BLOB NOT NULL, asn INTEGER NOT NULL)")
        conn.execute("CREATE TABLE asn_names (asn INTEGER PRIMARY KEY, country TEXT, name TEXT)")
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")

        names: dict[int, tuple[str, str]] = {}
        batch = []
        n_ranges = 0
        with _open_text(source_path) as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5:
                    continue
                start, end, asn_text, country, name = parts[0], parts[1], parts[2], parts[3], parts[4]
                try:
                    asn = int(asn_text)
                except ValueError:
                    continue
                if asn == 0:
                    continue
                s = _family_and_packed(start)
                e = _family_and_packed(end)
                if s is None or e is None or s[0] != e[0]:
                    continue
                batch.append((s[0], s[1], e[1], asn))
                n_ranges += 1
                if asn not in names:
                    names[asn] = (country if country != "None" else "", name)
                if len(batch) >= 50_000:
                    conn.executemany("INSERT INTO asn_ranges VALUES (?, ?, ?, ?)", batch)
                    batch = []
        if batch:
            conn.executemany("INSERT INTO asn_ranges VALUES (?, ?, ?, ?)", batch)
        conn.executemany("INSERT INTO asn_names VALUES (?, ?, ?)",
                         [(asn, c, n) for asn, (c, n) in names.items()])
        conn.execute("CREATE INDEX idx_asn_start ON asn_ranges (family, range_start)")
        conn.execute("INSERT INTO meta VALUES ('built_at', ?)", (datetime.now(timezone.utc).isoformat(),))
        conn.execute("INSERT INTO meta VALUES ('source', ?)", (os.path.basename(source_path),))
        conn.commit()
        conn.close()
        os.replace(tmp_path, db_path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
    reset()
    return n_ranges, len(names)


def update(db_path: str | None = None) -> tuple[int, int]:
    """Descarca fisierul de la iptoasn.com si reconstruieste baza."""
    fd, tmp_path = tempfile.mkstemp(prefix="ip2asn_", suffix=".tsv.gz")
    os.close(fd)
    try:
        print(f"[*] Descarc {SOURCE_URL} ...")
        request = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "TrafficMonitor-asn-update"})
        with urllib.request.urlopen(request, timeout=60) as response, open(tmp_path, "wb") as out:
            while True:
                chunk = response.read(1 << 16)
                if not chunk:
                    break
                out.write(chunk)
        if os.path.getsize(tmp_path) < 1_000_000:
            raise RuntimeError("Fisierul descarcat e prea mic; nu pare fisierul ip2asn.")
        print("[*] Construiesc baza (cateva secunde)...")
        return build(tmp_path, db_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# ---------- cautare ----------

def available() -> bool:
    return os.path.exists(ASN_DB_PATH)


def reset() -> None:
    """Uita conexiunea si rezultatele retinute (dupa reconstruirea bazei, in teste)."""
    _lookup.cache_clear()
    _name.cache_clear()
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except sqlite3.Error:
            pass
    _local.conn = None
    _local.path = None


def _connection():
    conn = getattr(_local, "conn", None)
    if conn is not None and getattr(_local, "path", None) == ASN_DB_PATH:
        return conn
    if conn is not None:
        conn.close()
    conn = sqlite3.connect(f"file:{ASN_DB_PATH}?mode=ro", uri=True)
    _local.conn = conn
    _local.path = ASN_DB_PATH
    return conn


@functools.lru_cache(maxsize=8192)
def _lookup(ip: str):
    fp = _family_and_packed(ip)
    if fp is None:
        return None
    family, packed = fp
    try:
        row = _connection().execute(
            "SELECT range_end, asn FROM asn_ranges WHERE family = ? AND range_start <= ? "
            "ORDER BY range_start DESC LIMIT 1", (family, packed)).fetchone()
    except sqlite3.Error:
        return None
    if row is None or packed > row[0]:
        return None
    return row[1]


def lookup(ip: str) -> int | None:
    """Numarul ASN care anunta adresa, sau None (necunoscuta, neinrutata, baza lipsa)."""
    if not available():
        return None
    return _lookup(str(ip))


@functools.lru_cache(maxsize=2048)
def _name(asn: int):
    try:
        row = _connection().execute(
            "SELECT country, name FROM asn_names WHERE asn = ?", (asn,)).fetchone()
    except sqlite3.Error:
        return None
    return (row[0], row[1]) if row else None


def info(asn: int) -> tuple[str, str] | None:
    """(tara, nume organizatie) pentru un ASN, sau None."""
    if not available():
        return None
    return _name(int(asn))


_HANDLE = re.compile(r"^[A-Z0-9]+(?:-[A-Z0-9]+)*-(?:AS|ASN|AP|EU|NET|BLOCK)(?:-[A-Z0-9]+)*$")


def clean_name(name: str) -> str:
    """
    "GTELECOM-AS-AP Gtelecom Pty Ltd" -> "Gtelecom Pty Ltd". Numele din fisier
    incep adesea cu un cod tehnic (handle); il scoatem doar cand ce urmeaza
    e un nume cu cuvinte. Altfel il lasam asa cum e.
    """
    name = (name or "").strip()
    first, _, rest = name.partition(" ")
    if rest and _HANDLE.match(first):
        return rest.strip()
    return name


# ---------- linia de comanda ----------

def main() -> int:
    parser = argparse.ArgumentParser(description="Baza ASN pentru TrafficMonitor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--update", action="store_true", help="descarca de la iptoasn.com si construieste asn.db")
    group.add_argument("--build", metavar="FISIER", help="construieste asn.db dintr-un fisier ip2asn (.tsv sau .tsv.gz)")
    group.add_argument("--lookup", metavar="IP", help="cui apartine o adresa")
    group.add_argument("--check", action="store_true", help="ASN-urile mapate pe companii, cu numele din fisier")
    args = parser.parse_args()

    if args.update or args.build:
        n_ranges, n_asn = update() if args.update else build(args.build)
        print(f"[*] Gata: {n_ranges} intervale, {n_asn} organizatii -> {ASN_DB_PATH}")
        print("[*] Reporneste serviciul ca sa foloseasca baza noua: "
              "systemctl --user restart trafficmonitor-watcher trafficmonitor-dashboard")
        return 0

    if not available():
        print("asn.db lipseste. Ruleaza: python3 asn.py --update", file=sys.stderr)
        return 1

    if args.lookup:
        asn = lookup(args.lookup)
        if asn is None:
            print(f"{args.lookup}: necunoscuta sau neinrutata")
            return 0
        country, name = info(asn) or ("", "")
        print(f"{args.lookup}: AS{asn} | {country} | {name} | afisat ca: {clean_name(name)}")
        return 0

    import companies
    print("ASN | companie mapata | numele din fisier (verifica sa se potriveasca)")
    for asn, company in sorted(companies.ASN_COMPANIES.items(), key=lambda kv: (kv[1], kv[0])):
        country, name = info(asn) or ("-", "(lipseste din fisier)")
        print(f"AS{asn} | {company} | {name} ({country})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
