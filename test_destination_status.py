"""
Teste pentru starea destinațiilor (de verificat / normal / suspect).

Rulare: python3 -m pytest test_destination_status.py -v
"""

import sqlite3
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

import companies
import destination_status as ds
import watcher_v6
from watcher_v6 import init_db, collect_and_notify


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    init_db(c)
    yield c
    c.close()


# ---------- logica pură ----------

class TestDecideAction:
    def test_new_destination_with_expired_cooldown_alerts(self):
        assert ds.decide_action(None, True, True, False) == ds.ACTION_ALERT_NEW

    def test_new_destination_during_cooldown_is_silent_pending(self):
        assert ds.decide_action(None, True, False, False) == ds.ACTION_PENDING_SILENT

    def test_known_destination_without_status_is_ignored(self):
        assert ds.decide_action(None, False, True, False) == ds.ACTION_IGNORE

    def test_pending_never_alerts_again(self):
        assert ds.decide_action(ds.PENDING, True, True, False) == ds.ACTION_IGNORE

    def test_normal_never_alerts(self):
        assert ds.decide_action(ds.NORMAL, True, True, False) == ds.ACTION_IGNORE

    def test_suspicious_alerts_even_during_cooldown(self):
        assert ds.decide_action(ds.SUSPICIOUS, False, False, False) == ds.ACTION_ALERT_SUSPICIOUS

    def test_suspicious_same_open_connection_alerts_only_once(self):
        assert ds.decide_action(ds.SUSPICIOUS, False, False, True) == ds.ACTION_IGNORE


# ---------- stocare ----------

class TestStorage:
    def test_record_pending_is_idempotent(self, conn):
        assert ds.record_pending(conn, "chrome", "x.com", "domeniu", "t1") is True
        assert ds.record_pending(conn, "chrome", "x.com", "domeniu", "t2") is False
        rows = ds.list_by_status(conn, ds.PENDING)
        assert len(rows) == 1 and rows[0]["first_seen"] == "t1"

    def test_set_status_updates_and_logs(self, conn):
        ds.record_pending(conn, "chrome", "x.com", "domeniu", "t1")
        assert ds.set_status(conn, "chrome", "x.com", ds.NORMAL) is True
        assert ds.list_by_status(conn, ds.PENDING) == []
        normal = ds.list_by_status(conn, ds.NORMAL)
        assert len(normal) == 1 and normal[0]["decided_at"] is not None
        log = ds.list_decision_log(conn)
        assert log[0]["old_status"] == ds.PENDING and log[0]["new_status"] == ds.NORMAL

    def test_set_status_unknown_destination_returns_false(self, conn):
        assert ds.set_status(conn, "chrome", "nu-exista.com", ds.NORMAL) is False

    def test_set_status_invalid_value_raises(self, conn):
        ds.record_pending(conn, "chrome", "x.com", "domeniu", "t1")
        with pytest.raises(ValueError):
            ds.set_status(conn, "chrome", "x.com", "whatever")

    def test_same_status_does_not_add_log_entry(self, conn):
        ds.record_pending(conn, "chrome", "x.com", "domeniu", "t1")
        ds.set_status(conn, "chrome", "x.com", ds.NORMAL)
        ds.set_status(conn, "chrome", "x.com", ds.NORMAL)
        assert len(ds.list_decision_log(conn)) == 1

    def test_user_can_change_mind(self, conn):
        ds.record_pending(conn, "chrome", "x.com", "domeniu", "t1")
        ds.set_status(conn, "chrome", "x.com", ds.NORMAL)
        ds.set_status(conn, "chrome", "x.com", ds.SUSPICIOUS)
        assert ds.load_decisions(conn)[("chrome", "x.com")] == ds.SUSPICIOUS
        assert len(ds.list_decision_log(conn)) == 2


# ---------- flux complet: collect_and_notify cu conexiuni simulate ----------

Addr = namedtuple("Addr", "ip port")
FakeConn = namedtuple("FakeConn", "raddr laddr pid status type")


def fake_conn(remote_ip, remote_port=443, local_port=50000, pid=1):
    return FakeConn(Addr(remote_ip, remote_port), Addr("192.168.1.5", local_port),
                    pid, "ESTABLISHED", 1)


class Harness:
    """Rulează cicluri de colectare cu conexiuni și 'DNS' false; adună notificările."""

    def __init__(self, conn, hostnames):
        self.conn = conn
        self.hostnames = hostnames  # ip -> hostname
        self.notifications = []
        self.process_cache, self.hostname_cache = {}, {}
        self.notified_pairs, self.notified_inbound = set(), set()
        self.known_keys, self.known_procs = set(), set()
        self.last_alert, self.decisions, self.notified_susp = {}, {}, set()
        self.previous_open = set()

    def seed_known(self, process, group_key, group_type="domeniu"):
        # ca în load_known_destinations: cheile cunoscute sunt la nivel de entitate
        self.known_keys.add((process, companies.entity_for(group_key, group_type)[0]))
        self.known_procs.add(process)

    def cycle(self, conns, name="chrome"):
        def fake_hostname(ip, cache):
            cache[ip] = self.hostnames.get(ip, ip)
            return cache[ip]

        with patch.object(watcher_v6.psutil, "net_connections", return_value=conns), \
             patch.object(watcher_v6, "get_process_info", return_value=(name, "/x", "h")), \
             patch.object(watcher_v6, "resolve_hostname", side_effect=fake_hostname), \
             patch.object(watcher_v6, "send_desktop_notification",
                          side_effect=lambda t, m, urgency="normal": self.notifications.append((t, urgency))), \
             patch.object(watcher_v6, "log_alert_to_file"):
            collect_and_notify(
                self.conn, self.process_cache, self.notified_pairs, self.notified_inbound,
                self.hostname_cache, self.known_keys, self.known_procs, self.last_alert,
                self.decisions, self.notified_susp, self.previous_open,
            )

    def alerts(self, urgency):
        return [n for n in self.notifications if n[1] == urgency]


HOSTS = {
    "8.8.8.1": "a.google.com",
    "8.8.8.2": "b.google.com",
    "9.9.9.1": "host.evil-example.net",
    "9.9.9.2": "other.evil-example.net",
}


class TestFullFlow:
    def test_new_destination_alerts_once_and_becomes_pending(self, conn):
        h = Harness(conn, HOSTS)
        h.seed_known("chrome", "google.com")
        h.cycle([fake_conn("9.9.9.1")])
        assert len(h.alerts("normal")) == 1
        pending = ds.list_by_status(conn, ds.PENDING)
        assert [p["group_key"] for p in pending] == ["evil-example.net"]
        assert pending[0]["sample_ip"] == "9.9.9.1"

    def test_pending_does_not_alert_again_and_is_not_auto_promoted(self, conn):
        h = Harness(conn, HOSTS)
        h.seed_known("chrome", "google.com")
        h.cycle([fake_conn("9.9.9.1")])
        h.last_alert.clear()  # simulăm cooldown expirat
        for _ in range(5):
            h.cycle([fake_conn("9.9.9.1"), fake_conn("9.9.9.2", local_port=50001)])
        assert len(h.alerts("normal")) == 1
        assert ds.load_decisions(conn)[("chrome", "evil-example.net")] == ds.PENDING

    def test_cooldown_suppressed_destination_still_listed_as_pending(self, conn):
        h = Harness(conn, HOSTS)
        h.seed_known("chrome", "google.com")
        h.cycle([fake_conn("9.9.9.1")])          # alertă + cooldown pornit
        h.cycle([fake_conn("8.8.8.1")])          # Google e deja cunoscut pentru chrome: nu apare nimic nou
        h.hostnames["7.7.7.1"] = "x.other-site.org"
        h.cycle([fake_conn("7.7.7.1")])          # nouă, dar în cooldown
        assert len(h.alerts("normal")) == 1
        keys = {p["group_key"] for p in ds.list_by_status(conn, ds.PENDING)}
        assert keys == {"evil-example.net", "other-site.org"}

    def test_normal_destination_is_silent(self, conn):
        h = Harness(conn, HOSTS)
        h.seed_known("chrome", "google.com")
        ds.record_pending(conn, "chrome", "evil-example.net", "domeniu", "t0")
        ds.set_status(conn, "chrome", "evil-example.net", ds.NORMAL)
        h.cycle([fake_conn("9.9.9.1")])
        assert h.notifications == []

    def test_suspicious_realerts_on_new_ip_ignoring_cooldown(self, conn):
        h = Harness(conn, HOSTS)
        h.seed_known("chrome", "google.com")
        ds.record_pending(conn, "chrome", "evil-example.net", "domeniu", "t0")
        ds.set_status(conn, "chrome", "evil-example.net", ds.SUSPICIOUS)
        h.last_alert["chrome"] = datetime.now(timezone.utc)  # cooldown ACTIV
        h.cycle([fake_conn("9.9.9.1")])
        h.cycle([fake_conn("9.9.9.2", local_port=50001)])
        assert len(h.alerts("critical")) == 2

    def test_suspicious_realerts_on_same_ip_new_connection(self, conn):
        h = Harness(conn, HOSTS)
        h.seed_known("chrome", "google.com")
        h.notified_pairs.add(("chrome", "9.9.9.1"))  # IP deja văzut, "pair" deja notificat
        ds.record_pending(conn, "chrome", "evil-example.net", "domeniu", "t0")
        ds.set_status(conn, "chrome", "evil-example.net", ds.SUSPICIOUS)
        h.cycle([fake_conn("9.9.9.1", local_port=50001)])
        h.cycle([fake_conn("9.9.9.1", local_port=50002)])  # reconectare = conexiune nouă
        assert len(h.alerts("critical")) == 2

    def test_suspicious_same_open_connection_does_not_spam(self, conn):
        h = Harness(conn, HOSTS)
        h.seed_known("chrome", "google.com")
        ds.record_pending(conn, "chrome", "evil-example.net", "domeniu", "t0")
        ds.set_status(conn, "chrome", "evil-example.net", ds.SUSPICIOUS)
        for _ in range(10):
            h.cycle([fake_conn("9.9.9.1")])  # aceeași conexiune, văzută la fiecare secundă
        assert len(h.alerts("critical")) == 1

    def test_decision_made_in_dashboard_applies_without_restart(self, conn):
        h = Harness(conn, HOSTS)
        h.seed_known("chrome", "google.com")
        h.cycle([fake_conn("9.9.9.1")])                      # devine pending
        ds.set_status(conn, "chrome", "evil-example.net", ds.SUSPICIOUS)  # click în dashboard
        h.cycle([fake_conn("9.9.9.2", local_port=50001)])    # următorul ciclu
        assert len(h.alerts("critical")) == 1

    def test_new_process_first_connection_is_not_pending(self, conn):
        h = Harness(conn, HOSTS)
        h.cycle([fake_conn("9.9.9.1")], name="program-nou")
        assert h.notifications == [("Conexiune nouă observată", "low")]
        assert ds.list_by_status(conn, ds.PENDING) == []


class TestCompanyGrouping:
    def test_many_blocks_of_one_company_make_one_pending_item(self, conn):
        h = Harness(conn, {"34.78.67.1": "x.1e100.net", "172.217.114.5": "y.1e100.net"})
        h.seed_known("chrome", "evil-example.net")  # chrome nu știe încă Google
        h.cycle([fake_conn("34.78.67.1"), fake_conn("172.217.114.5", local_port=50001)])
        pending = ds.list_by_status(conn, ds.PENDING)
        assert [p["group_key"] for p in pending] == ["Google"]
        assert pending[0]["group_type"] == "companie"

    def test_company_already_known_for_process_is_not_new_behavior(self, conn):
        # chrome vorbea deja cu Google (istoric) -> un bloc Google nou nu e "comportament nou"
        h = Harness(conn, {"2001:4860:4840::1": "a.1e100.net"})
        h.seed_known("chrome", "1e100.net")
        h.cycle([fake_conn("2001:4860:4840::1")])
        assert h.notifications == [("Conexiune nouă observată", "low")]
        assert ds.list_by_status(conn, ds.PENDING) == []

    def test_unknown_network_falls_back_to_exact_destination(self, conn):
        h = Harness(conn, {})  # fără reverse DNS, bloc nemapat
        h.seed_known("chrome", "evil-example.net")
        h.cycle([fake_conn("88.211.219.7")])
        pending = ds.list_by_status(conn, ds.PENDING)
        assert [(p["group_key"], p["group_type"]) for p in pending] == [("88.211.219.0/24", "subnet")]

    def test_normal_for_company_silences_all_its_blocks(self, conn):
        h = Harness(conn, {"34.78.67.1": "x.1e100.net"})
        h.seed_known("chrome", "evil-example.net")
        ds.record_pending(conn, "chrome", "Google", "companie", "t0")
        ds.set_status(conn, "chrome", "Google", ds.NORMAL)
        h.cycle([fake_conn("34.78.67.1")])
        assert h.alerts("normal") == []

    def test_suspicious_company_realerts_on_any_of_its_blocks(self, conn):
        h = Harness(conn, {"34.78.67.1": "x.1e100.net", "172.217.114.5": "y.1e100.net"})
        h.seed_known("chrome", "evil-example.net")
        ds.record_pending(conn, "chrome", "Google", "companie", "t0")
        ds.set_status(conn, "chrome", "Google", ds.SUSPICIOUS)
        h.cycle([fake_conn("34.78.67.1")])
        h.cycle([fake_conn("172.217.114.5", local_port=50001)])
        assert len(h.alerts("critical")) == 2


class TestMigrationToEntities:
    def _fill(self, conn):
        for key, typ, status in [
            ("2001:4860:4840::/48", "subnet", ds.PENDING),
            ("2001:4860:4841::/48", "subnet", ds.PENDING),
            ("1e100.net", "domeniu", ds.PENDING),
            ("88.211.219.0/24", "subnet", ds.PENDING),
        ]:
            ds.record_pending(conn, "chrome", key, typ, "2026-10-14T10:00:00+00:00")
            if status != ds.PENDING:
                ds.set_status(conn, "chrome", key, status)

    def test_blocks_of_same_company_merge_into_one_row(self, conn):
        self._fill(conn)
        replaced = ds.migrate_to_entities(conn, companies.entity_for)
        assert replaced == 3
        keys = {(r["group_key"], r["group_type"]) for r in ds.list_by_status(conn, ds.PENDING)}
        assert keys == {("Google", "companie"), ("88.211.219.0/24", "subnet")}

    def test_user_decision_survives_and_wins_over_pending(self, conn):
        self._fill(conn)
        ds.set_status(conn, "chrome", "1e100.net", ds.NORMAL)
        ds.migrate_to_entities(conn, companies.entity_for)
        assert ds.load_decisions(conn)[("chrome", "Google")] == ds.NORMAL

    def test_suspicious_beats_normal_when_merging(self, conn):
        self._fill(conn)
        ds.set_status(conn, "chrome", "1e100.net", ds.NORMAL)
        ds.set_status(conn, "chrome", "2001:4860:4840::/48", ds.SUSPICIOUS)
        ds.migrate_to_entities(conn, companies.entity_for)
        assert ds.load_decisions(conn)[("chrome", "Google")] == ds.SUSPICIOUS

    def test_migration_is_idempotent(self, conn):
        self._fill(conn)
        ds.migrate_to_entities(conn, companies.entity_for)
        assert ds.migrate_to_entities(conn, companies.entity_for) == 0
        assert len(ds.list_by_status(conn, ds.PENDING)) == 2

    def test_other_process_rows_stay_separate(self, conn):
        self._fill(conn)
        ds.record_pending(conn, "firefox", "1e100.net", "domeniu", "2026-10-14T10:00:00+00:00")
        ds.migrate_to_entities(conn, companies.entity_for)
        procs = {(r["process_name"], r["group_key"]) for r in ds.list_by_status(conn, ds.PENDING)}
        assert ("firefox", "Google") in procs and ("chrome", "Google") in procs
