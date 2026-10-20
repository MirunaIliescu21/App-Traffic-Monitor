"""
Teste pentru browser_history.py (citirea istoricului Firefox).

Folosesc un places.sqlite sintetic, cu aceleasi tabele ca Firefox.
Rulare: pytest test_browser_history.py -v
"""

import os
import sqlite3

import pytest

import browser_history as bh


def make_places(path, rows, wal=False):
    """
    Creeaza un places.sqlite sintetic. rows: (visit_id, epoch_s, url, visit_type, from_visit, title).
    Intoarce conexiunea; cu wal=True ea trebuie tinuta deschisa, ca jurnalul sa ramana pe disc
    (exact situatia Firefox-ului care ruleaza).
    """
    conn = sqlite3.connect(path)
    if wal:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
    conn.execute("CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, "
                 "place_id INTEGER, visit_date INTEGER, visit_type INTEGER)")
    for visit_id, epoch, url, vtype, from_visit, title in rows:
        conn.execute("INSERT INTO moz_places (id, url, title) VALUES (?, ?, ?)", (visit_id, url, title))
        conn.execute("INSERT INTO moz_historyvisits (id, from_visit, place_id, visit_date, visit_type) "
                     "VALUES (?, ?, ?, ?, ?)", (visit_id, from_visit, visit_id, int(epoch * 1_000_000), vtype))
    conn.commit()
    return conn


ROWS = [
    (1, 1_000_000, "https://www.google.com/search?q=biziday", 1, 0, "biziday - Google"),
    (2, 1_000_005, "https://www.biziday.ro/", 5, 1, "Biziday"),
    (3, 1_000_100, "http://systemsunit.com/", 2, 0, ""),
    (4, 1_000_200, "about:preferences", 2, 0, "Settings"),
    (5, 1_000_300, "file:///home/x/doc.html", 2, 0, ""),
    (6, 1_000_400, "http://127.0.0.1:5000/", 2, 0, "Dashboard"),
]


@pytest.fixture
def places(tmp_path):
    path = str(tmp_path / "places.sqlite")
    conn = make_places(path, ROWS)
    conn.close()
    return path


class TestNewVisits:
    def test_reads_only_web_pages(self, places):
        hosts = [v.host for v in bh.new_visits(places)]
        assert hosts == ["www.google.com", "www.biziday.ro", "systemsunit.com", "127.0.0.1"]

    def test_about_and_file_pages_are_skipped(self, places):
        urls = [v.url for v in bh.new_visits(places)]
        assert not any(u.startswith(("about:", "file:")) for u in urls)

    def test_only_visits_after_given_id(self, places):
        visits = bh.new_visits(places, after_id=2)
        assert [v.visit_id for v in visits] == [3, 6]

    def test_kinds_are_translated(self, places):
        by_host = {v.host: v.kind for v in bh.new_visits(places)}
        assert by_host["systemsunit.com"] == "tastat"
        assert by_host["www.biziday.ro"] == "redirect"
        assert by_host["www.google.com"] == "link"

    def test_time_is_epoch_utc_seconds(self, places):
        first = bh.new_visits(places)[0]
        assert first.when == 1_000_000.0

    def test_from_visit_and_title_kept(self, places):
        biziday = [v for v in bh.new_visits(places) if v.host == "www.biziday.ro"][0]
        assert biziday.from_visit == 1
        assert biziday.title == "Biziday"

    def test_limit_keeps_most_recent(self, places):
        visits = bh.new_visits(places, limit=2)
        assert [v.visit_id for v in visits] == [3, 6]

    def test_host_is_lowercase_without_port(self, tmp_path):
        path = str(tmp_path / "p.sqlite")
        make_places(path, [(1, 5, "HTTPS://Olx-Plata.RO:8443/pay?x=1", 1, 0, "")]).close()
        assert bh.new_visits(path)[0].host == "olx-plata.ro"

    def test_unknown_visit_type_is_other(self, tmp_path):
        path = str(tmp_path / "p.sqlite")
        make_places(path, [(1, 5, "https://a.ro/", 99, 0, "")]).close()
        assert bh.new_visits(path)[0].kind == "altul"


class TestLatestVisitId:
    def test_latest_id(self, places):
        assert bh.latest_visit_id(places) == 6

    def test_empty_history_is_zero(self, tmp_path):
        path = str(tmp_path / "p.sqlite")
        make_places(path, []).close()
        assert bh.latest_visit_id(path) == 0


class TestRobustness:
    def test_missing_file_gives_empty_not_crash(self, tmp_path):
        missing = str(tmp_path / "nu_exista.sqlite")
        assert bh.new_visits(missing) == []
        assert bh.latest_visit_id(missing) == 0

    def test_corrupt_file_gives_empty_not_crash(self, tmp_path):
        bad = tmp_path / "places.sqlite"
        bad.write_bytes(b"asta nu e o baza sqlite" * 100)
        assert bh.new_visits(str(bad)) == []

    def test_database_without_expected_tables_gives_empty(self, tmp_path):
        path = str(tmp_path / "p.sqlite")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE altceva (x INTEGER)")
        conn.commit()
        conn.close()
        assert bh.new_visits(path) == []

    def test_original_file_is_not_modified(self, places):
        before = os.path.getsize(places), os.path.getmtime(places)
        bh.new_visits(places)
        assert (os.path.getsize(places), os.path.getmtime(places)) == before


class TestWriteAheadLog:
    def test_sees_visits_that_are_only_in_the_wal(self, tmp_path):
        """
        Cazul real: Firefox ruleaza si vizitele noi sunt (deocamdata) doar in
        jurnalul -wal, nu in fisierul principal. Trebuie sa le vedem.
        """
        path = str(tmp_path / "places.sqlite")
        conn = make_places(path, ROWS[:2], wal=True)   # conexiunea ramane deschisa
        try:
            assert os.path.exists(path + "-wal") and os.path.getsize(path + "-wal") > 0
            hosts = [v.host for v in bh.new_visits(path)]
            assert hosts == ["www.google.com", "www.biziday.ro"]
        finally:
            conn.close()


class TestFindDatabases:
    def test_finds_snap_and_classic_profiles(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("APPDATA", raising=False)
        snap = tmp_path / "snap/firefox/common/.mozilla/firefox/abc.default"
        classic = tmp_path / ".mozilla/firefox/xyz.default-release"
        for d in (snap, classic):
            d.mkdir(parents=True)
            (d / "places.sqlite").write_bytes(b"")
        found = bh.find_databases()
        assert len(found) == 2
        assert any("snap" in p for p in found)

    def test_finds_windows_profile_through_appdata(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path / "gol"))
        profile = tmp_path / "Roaming/Mozilla/Firefox/Profiles/q.default"
        profile.mkdir(parents=True)
        (profile / "places.sqlite").write_bytes(b"")
        monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
        assert len(bh.find_databases()) == 1

    def test_no_firefox_gives_empty_list(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("APPDATA", raising=False)
        assert bh.find_databases() == []


def add_visit(path, visit_id, epoch, url, vtype=1, from_visit=0, title=""):
    """Adauga o vizita intr-un places.sqlite existent si 'misca' data fisierului (ca Firefox cand scrie)."""
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO moz_places (id, url, title) VALUES (?, ?, ?)", (visit_id, url, title))
    conn.execute("INSERT INTO moz_historyvisits (id, from_visit, place_id, visit_date, visit_type) "
                 "VALUES (?, ?, ?, ?, ?)", (visit_id, from_visit, visit_id, int(epoch * 1_000_000), vtype))
    conn.commit()
    conn.close()
    stat = os.stat(path)
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))   # data modificarii creste sigur


class TestHistoryWatcher:
    def test_old_history_is_not_replayed_at_start(self, places):
        watcher = bh.HistoryWatcher([places], lookback_seconds=0, now=2_000_000)
        assert watcher.poll() == []

    def test_lookback_includes_recent_visits_at_start(self, places):
        """O repornire a serviciului nu trebuie sa piarda paginile deschise chiar atunci."""
        watcher = bh.HistoryWatcher([places], lookback_seconds=350, now=1_000_450)
        hosts = [v.host for v in watcher.poll()]
        assert hosts == ["systemsunit.com", "127.0.0.1"]       # cele din ultimele 350 s

    def test_new_visit_is_returned_once(self, places):
        watcher = bh.HistoryWatcher([places], lookback_seconds=0, now=2_000_000)
        add_visit(places, 7, 2_000_010, "https://olx-plata.ro/pay")
        first = watcher.poll()
        assert [v.host for v in first] == ["olx-plata.ro"]
        assert watcher.poll() == []

    def test_file_that_did_not_change_is_not_read_again(self, places, monkeypatch):
        watcher = bh.HistoryWatcher([places], lookback_seconds=0, now=2_000_000)
        calls = []
        real = bh.read_visits
        monkeypatch.setattr(bh, "read_visits", lambda *a, **k: calls.append(1) or real(*a, **k))
        watcher.poll()
        watcher.poll()
        watcher.poll()
        assert len(calls) == 1          # prima citire; apoi fisierul e neschimbat

    def test_failed_read_is_retried_not_lost(self, places, monkeypatch):
        watcher = bh.HistoryWatcher([places], lookback_seconds=0, now=2_000_000)
        add_visit(places, 7, 2_000_010, "https://olx-plata.ro/")
        real = bh.read_visits
        state = {"fail": True}

        def flaky(path, after_id=0):
            if state["fail"]:
                state["fail"] = False
                return None
            return real(path, after_id)

        monkeypatch.setattr(bh, "read_visits", flaky)
        assert watcher.poll() == []                              # citire esuata
        assert [v.host for v in watcher.poll()] == ["olx-plata.ro"]   # reincercata, nu pierduta

    def test_non_web_visits_do_not_get_reread_forever(self, places):
        watcher = bh.HistoryWatcher([places], lookback_seconds=0, now=2_000_000)
        add_visit(places, 7, 2_000_010, "about:preferences")
        assert watcher.poll() == []
        assert watcher._last_id[places] == 7

    def test_two_profiles_are_merged_in_time_order(self, tmp_path):
        a, b = str(tmp_path / "a.sqlite"), str(tmp_path / "b.sqlite")
        make_places(a, [(1, 10, "https://old-a.ro/", 1, 0, "")]).close()
        make_places(b, [(1, 10, "https://old-b.ro/", 1, 0, "")]).close()
        watcher = bh.HistoryWatcher([a, b], lookback_seconds=0, now=1_000)
        add_visit(a, 2, 2_000_020, "https://later.ro/")
        add_visit(b, 2, 2_000_010, "https://earlier.ro/")
        assert [v.host for v in watcher.poll()] == ["earlier.ro", "later.ro"]

    def test_missing_database_does_not_crash(self, tmp_path):
        watcher = bh.HistoryWatcher([str(tmp_path / "nu_exista.sqlite")], lookback_seconds=0, now=1)
        assert watcher.poll() == []
