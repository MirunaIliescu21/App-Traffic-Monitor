"""
Teste pentru scrierea în bază doar a conexiunilor NOI, inclusiv dovada că
analiza de risc dă același rezultat pe date "doar conexiuni noi" ca pe datele
vechi, scrise la fiecare secundă.

Rulare: python3 -m pytest test_collection.py -v
"""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from baseline_v5 import analyze_process
from test_destination_status import Harness, fake_conn
from watcher_v6 import init_db


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    init_db(c)
    yield c
    c.close()


def rows(c):
    return c.execute("SELECT remote_ip, local_port FROM connections ORDER BY id").fetchall()


class TestOnlyNewConnectionsAreStored:
    def test_same_open_connection_is_stored_once(self, conn):
        h = Harness(conn, {})
        for _ in range(10):  # aceeași conexiune, văzută la 10 citiri la rând
            h.cycle([fake_conn("9.9.9.1", local_port=50000)])
        assert rows(conn) == [("9.9.9.1", 50000)]

    def test_reconnect_with_new_local_port_is_a_new_row(self, conn):
        h = Harness(conn, {})
        h.cycle([fake_conn("9.9.9.1", local_port=50000)])
        h.cycle([fake_conn("9.9.9.1", local_port=50001)])
        assert len(rows(conn)) == 2

    def test_connection_that_closes_and_reappears_is_stored_again(self, conn):
        h = Harness(conn, {})
        h.cycle([fake_conn("9.9.9.1", local_port=50000)])
        h.cycle([])                                            # s-a închis
        h.cycle([fake_conn("9.9.9.1", local_port=50000)])      # același port reutilizat mai târziu
        assert len(rows(conn)) == 2

    def test_two_parallel_connections_to_same_ip_are_both_stored(self, conn):
        h = Harness(conn, {})
        h.cycle([fake_conn("9.9.9.1", local_port=50000), fake_conn("9.9.9.1", local_port=50001)])
        assert len(rows(conn)) == 2

    def test_other_connections_keep_being_tracked_while_one_stays_open(self, conn):
        h = Harness(conn, {})
        h.cycle([fake_conn("9.9.9.1", local_port=50000)])
        h.cycle([fake_conn("9.9.9.1", local_port=50000), fake_conn("8.8.8.8", local_port=50002)])
        assert [r[0] for r in rows(conn)] == ["9.9.9.1", "8.8.8.8"]


class TestRiskAnalysisUnchanged:
    """Analiza trebuie să vadă același lucru, fie că primește fiecare citire, fie doar conexiunile noi."""

    START = datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc)

    def _beacon(self, polled: bool, n=45, interval=60, lasts_polls=3):
        conns = []
        for k in range(n):
            t0 = self.START + timedelta(seconds=k * interval)
            for p in range(lasts_polls if polled else 1):
                conns.append({"timestamp": t0 + timedelta(seconds=p),
                              "remote_ip": "93.184.216.34", "remote_port": 80})
        return conns

    def _score(self, conns):
        return analyze_process("curl", conns, {"93.184.216.34": {"curl"}})

    def test_beaconing_score_is_identical(self):
        old = self._score(self._beacon(polled=True))
        new = self._score(self._beacon(polled=False))
        assert old["risk_score"] == new["risk_score"]
        assert any("BEACONING" in r for r in new["reasons"])

    def test_concentration_signal_is_identical(self):
        old = self._score(self._beacon(polled=True))
        new = self._score(self._beacon(polled=False))
        assert any("CONCENTRAT" in r for r in old["reasons"]) == any("CONCENTRAT" in r for r in new["reasons"])
