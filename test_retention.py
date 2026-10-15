"""Teste pentru curățarea datelor vechi. Rulare: python3 -m pytest test_retention.py -v"""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

import destination_status as ds
import retention
from watcher_v6 import init_db

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)


def ts(days_ago):
    return (NOW - timedelta(days=days_ago)).isoformat()


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    init_db(c)
    retention.ensure_indexes(c)
    yield c
    c.close()


def add_conn(c, days_ago, n=1):
    for _ in range(n):
        c.execute("INSERT INTO connections (timestamp, process_name, remote_ip) VALUES (?, 'chrome', '8.8.8.8')",
                  (ts(days_ago),))
    c.commit()


def count(c, table):
    return c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_old_connections_deleted_recent_kept(conn):
    add_conn(conn, 30, 5)
    add_conn(conn, 1, 3)
    out = retention.purge_old_data(conn, now=NOW)
    assert out["connections"] == 5
    assert count(conn, "connections") == 3


def test_boundary_just_inside_retention_is_kept(conn):
    add_conn(conn, 13.9)
    add_conn(conn, 14.1)
    retention.purge_old_data(conn, now=NOW)
    assert count(conn, "connections") == 1


def test_inbound_events_kept_longer_than_connections(conn):
    conn.execute("INSERT INTO inbound_events (timestamp, process_name, local_port, remote_ip, remote_port) "
                 "VALUES (?, 'nc', 4444, '192.168.56.102', 5000)", (ts(60),))
    conn.execute("INSERT INTO inbound_events (timestamp, process_name, local_port, remote_ip, remote_port) "
                 "VALUES (?, 'nc', 4444, '192.168.56.102', 5001)", (ts(120),))
    conn.commit()
    out = retention.purge_old_data(conn, now=NOW)
    assert out["inbound_events"] == 1
    assert count(conn, "inbound_events") == 1


def test_memory_tables_are_never_touched(conn):
    ds.record_pending(conn, "chrome", "x.com", "domeniu", ts(400))
    ds.set_status(conn, "chrome", "x.com", ds.NORMAL, timestamp=ts(400))
    conn.execute("INSERT INTO known_destinations VALUES ('chrome','x.com','domeniu',?,?,1)", (ts(400), ts(400)))
    conn.execute("INSERT INTO notified_pairs (process_name, remote_ip, first_seen_at) VALUES ('chrome','1.1.1.1',?)", (ts(400),))
    conn.commit()
    retention.purge_old_data(conn, now=NOW)
    assert count(conn, "destination_status") == 1
    assert count(conn, "decision_log") == 1
    assert count(conn, "known_destinations") == 1
    assert count(conn, "notified_pairs") == 1


def test_batching_deletes_everything(conn, monkeypatch):
    monkeypatch.setattr(retention, "BATCH_SIZE", 10)
    add_conn(conn, 30, 35)  # 3 loturi pline + unul parțial
    add_conn(conn, 1, 4)
    out = retention.purge_old_data(conn, now=NOW)
    assert out["connections"] == 35
    assert count(conn, "connections") == 4


def test_batching_exact_multiple_terminates(conn, monkeypatch):
    monkeypatch.setattr(retention, "BATCH_SIZE", 10)
    add_conn(conn, 30, 20)
    assert retention.purge_old_data(conn, now=NOW)["connections"] == 20


def test_dry_run_deletes_nothing(conn):
    add_conn(conn, 30, 5)
    out = retention.purge_old_data(conn, now=NOW, dry_run=True)
    assert out["connections"] == 5
    assert count(conn, "connections") == 5


def test_missing_table_is_skipped():
    c = sqlite3.connect(":memory:")
    assert retention.purge_old_data(c, now=NOW) == {}
    c.close()
