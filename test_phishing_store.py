"""
Teste pentru phishing_store.py (alerte active, "Am inteles", "Este site-ul real").
Rulare: pytest test_phishing_store.py -v
"""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

import phishing_store as store

NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    store.init_tables(c)
    yield c
    c.close()


def add_event(conn, host, minutes_ago=5, score=80, alerted=1, dismissed=0, brand="OLX", kind="tastat"):
    when = (NOW - timedelta(minutes=minutes_ago)).isoformat()
    conn.execute("INSERT INTO phishing_events (timestamp, host, score, brand, reasons, kind, alerted, dismissed) "
                 "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (when, host, score, brand, "motiv", kind, alerted, dismissed))
    conn.commit()


class TestTables:
    def test_init_is_idempotent(self, conn):
        store.init_tables(conn)
        store.init_tables(conn)

    def test_old_table_without_dismissed_column_is_migrated(self):
        c = sqlite3.connect(":memory:")
        c.execute("CREATE TABLE phishing_events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, "
                  "host TEXT NOT NULL, score INTEGER NOT NULL, brand TEXT, reasons TEXT, kind TEXT, "
                  "alerted INTEGER NOT NULL DEFAULT 0)")
        c.execute("INSERT INTO phishing_events (timestamp, host, score, alerted) VALUES ('2026-10-20T10:00:00+00:00', 'a.ro', 80, 1)")
        c.commit()
        store.init_tables(c)
        assert c.execute("SELECT dismissed FROM phishing_events").fetchone()[0] == 0
        c.close()

    def test_works_with_row_factory_connections_too(self, conn):
        conn.row_factory = sqlite3.Row
        add_event(conn, "olx-plata.ro")
        assert store.list_events(conn)[0]["host"] == "olx-plata.ro"


class TestActiveAlerts:
    def test_recent_real_alert_is_active(self, conn):
        add_event(conn, "olx-plata.ro")
        assert [a["host"] for a in store.active_alerts(conn, NOW)] == ["olx-plata.ro"]

    def test_weak_signals_are_not_active_alerts(self, conn):
        add_event(conn, "185.12.4.9", score=40, alerted=0, brand=None)
        assert store.active_alerts(conn, NOW) == []

    def test_dismissed_alert_is_not_active(self, conn):
        add_event(conn, "olx-plata.ro", dismissed=1)
        assert store.active_alerts(conn, NOW) == []

    def test_alert_older_than_24h_is_not_active(self, conn):
        add_event(conn, "olx-plata.ro", minutes_ago=25 * 60)
        assert store.active_alerts(conn, NOW) == []

    def test_one_entry_per_host_newest_first(self, conn):
        add_event(conn, "olx-plata.ro", minutes_ago=30)
        add_event(conn, "bcr-securizat.top", minutes_ago=20, brand="BCR")
        add_event(conn, "olx-plata.ro", minutes_ago=10)
        hosts = [a["host"] for a in store.active_alerts(conn, NOW)]
        assert hosts == ["olx-plata.ro", "bcr-securizat.top"]

    def test_new_visit_after_dismiss_brings_the_alert_back(self, conn):
        add_event(conn, "olx-plata.ro", minutes_ago=30)
        store.dismiss(conn, "olx-plata.ro")
        assert store.active_alerts(conn, NOW) == []
        add_event(conn, "olx-plata.ro", minutes_ago=1)          # o vizita noua, nedismissata
        assert len(store.active_alerts(conn, NOW)) == 1


class TestDecisions:
    def test_dismiss_counts_and_hides(self, conn):
        add_event(conn, "olx-plata.ro")
        add_event(conn, "olx-plata.ro", minutes_ago=2)
        assert store.dismiss(conn, "olx-plata.ro") == 2
        assert store.dismiss(conn, "olx-plata.ro") == 0

    def test_dismiss_unknown_host_changes_nothing(self, conn):
        assert store.dismiss(conn, "nu-exista.ro") == 0

    def test_allow_adds_to_allowlist_and_closes_alerts(self, conn):
        add_event(conn, "olx-plata.ro")
        assert store.allow(conn, "olx-plata.ro") is True
        assert "olx-plata.ro" in store.load_allowlist(conn)
        assert store.active_alerts(conn, NOW) == []

    def test_allow_refuses_hosts_we_never_flagged(self, conn):
        """Un text arbitrar nu poate intra in lista de incredere, doar domenii semnalate de noi."""
        assert store.allow(conn, "banca-mea.ro") is False
        assert store.load_allowlist(conn) == frozenset()

    def test_unallow_removes(self, conn):
        add_event(conn, "olx-plata.ro")
        store.allow(conn, "olx-plata.ro")
        assert store.unallow(conn, "olx-plata.ro") is True
        assert store.load_allowlist(conn) == frozenset()
        assert store.unallow(conn, "olx-plata.ro") is False

    def test_is_allowed_matches_host_and_subdomains_only(self):
        allow = frozenset({"olx-plata.ro"})
        assert store.is_allowed("olx-plata.ro", allow)
        assert store.is_allowed("www.olx-plata.ro", allow)
        assert not store.is_allowed("evil-olx-plata.ro", allow)
        assert not store.is_allowed("olx-plata.ro.evil.com", allow)


class TestGroupedEvents:
    def test_visits_of_the_same_host_are_counted_once_in_the_list(self, conn):
        add_event(conn, "olx-plata.ro", minutes_ago=30)
        add_event(conn, "olx-plata.ro", minutes_ago=20)
        add_event(conn, "olx-plata.ro", minutes_ago=10)
        groups = store.grouped_events(conn)
        assert len(groups) == 1
        assert groups[0]["visits"] == 3

    def test_first_and_last_seen(self, conn):
        add_event(conn, "olx-plata.ro", minutes_ago=30)
        add_event(conn, "olx-plata.ro", minutes_ago=10)
        group = store.grouped_events(conn)[0]
        assert group["first_seen"] < group["last_seen"]
        assert group["last_seen"] == (NOW - timedelta(minutes=10)).isoformat()
        assert group["first_seen"] == (NOW - timedelta(minutes=30)).isoformat()

    def test_ordered_by_most_recent_visit(self, conn):
        add_event(conn, "a-olx.ro", minutes_ago=50)
        add_event(conn, "b-olx.ro", minutes_ago=40)
        add_event(conn, "a-olx.ro", minutes_ago=5)
        assert [g["host"] for g in store.grouped_events(conn)] == ["a-olx.ro", "b-olx.ro"]

    def test_details_come_from_the_latest_visit(self, conn):
        add_event(conn, "olx-plata.ro", minutes_ago=30, kind="link")
        add_event(conn, "olx-plata.ro", minutes_ago=5, kind="tastat")
        assert store.grouped_events(conn)[0]["kind"] == "tastat"

    def test_alerted_if_any_visit_alerted(self, conn):
        add_event(conn, "x.ro", minutes_ago=30, alerted=1)
        add_event(conn, "x.ro", minutes_ago=5, alerted=0)
        assert store.grouped_events(conn)[0]["alerted"] == 1

    def test_limit_applies_to_groups_not_events(self, conn):
        for i in range(5):
            for _ in range(3):
                add_event(conn, f"olx-{i}.ro", minutes_ago=100 - i)
        assert len(store.grouped_events(conn, limit=4)) == 4

    def test_empty(self, conn):
        assert store.grouped_events(conn) == []

    def test_domain_marked_real_leaves_the_list(self, conn):
        add_event(conn, "olx-plata.ro", minutes_ago=10)
        add_event(conn, "bcr-securizat.top", minutes_ago=5, brand="BCR")
        store.allow(conn, "olx-plata.ro")
        assert [g["host"] for g in store.grouped_events(conn)] == ["bcr-securizat.top"]

    def test_domain_comes_back_after_unallow(self, conn):
        add_event(conn, "olx-plata.ro", minutes_ago=10)
        store.allow(conn, "olx-plata.ro")
        store.unallow(conn, "olx-plata.ro")
        group = store.grouped_events(conn)[0]
        assert group["host"] == "olx-plata.ro" and group["visits"] == 1

    def test_subdomains_of_an_allowed_domain_leave_too(self, conn):
        add_event(conn, "olx-plata.ro", minutes_ago=10)
        add_event(conn, "www.olx-plata.ro", minutes_ago=5)
        store.allow(conn, "olx-plata.ro")
        assert store.grouped_events(conn) == []

    def test_history_is_kept_in_the_database(self, conn):
        add_event(conn, "olx-plata.ro", minutes_ago=10)
        store.allow(conn, "olx-plata.ro")
        assert conn.execute("SELECT COUNT(*) FROM phishing_events").fetchone()[0] == 1
