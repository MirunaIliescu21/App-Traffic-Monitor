"""
Teste automate pentru watcher.py.

Rulare: pytest test_watcher.py -v
"""

import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

import watcher_v6
from watcher_v6 import is_effectively_loopback, init_db, run_risk_analysis


@pytest.fixture
def db_conn():
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    yield conn
    conn.close()


def insert_beacon_connections(conn, process_name, remote_ip, n=10, interval_seconds=60):
    """Inserează în tabela `connections` un tipar de beacon regulat, gata pentru run_risk_analysis."""
    rows = []
    t = datetime.now(timezone.utc) - timedelta(seconds=interval_seconds * n)
    for _ in range(n):
        rows.append((
            t.isoformat(), 1234, process_name, "/tmp/x", "hash",
            "192.168.1.50", 5000, remote_ip, 443, "TCP", "ESTABLISHED",
        ))
        t += timedelta(seconds=interval_seconds)
    conn.executemany("""
        INSERT INTO connections (timestamp, pid, process_name, binary_path, binary_hash,
            local_ip, local_port, remote_ip, remote_port, protocol, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)
    conn.commit()


class TestIsEffectivelyLoopback:
    def test_ipv4_loopback(self):
        assert is_effectively_loopback("127.0.0.1") is True

    def test_ipv6_loopback(self):
        assert is_effectively_loopback("::1") is True

    def test_ipv6_mapped_ipv4_loopback(self):
        """
        REGRESIE: acest format special (IPv6 ce încapsulează un IPv4
        loopback) a apărut real în log-urile watcher.py și NU era
        recunoscut de ipaddress.is_loopback simplu - a cauzat o alertă
        [INBOUND!] falsă pentru o conexiune internă (java pe localhost).
        """
        assert is_effectively_loopback("::ffff:127.0.0.1") is True

    def test_private_lan_ip_is_not_loopback(self):
        """IMPORTANT: IP-ul lui Kali (rețea privată, dar altă mașină) NU e loopback."""
        assert is_effectively_loopback("192.168.56.102") is False

    def test_public_ip_is_not_loopback(self):
        assert is_effectively_loopback("8.8.8.8") is False

    def test_invalid_ip_does_not_crash(self):
        assert is_effectively_loopback("not-an-ip") is False


class TestRunRiskAnalysisDeduplication:
    """
    Testează fix-ul cel mai recent: alertele de risc NU trebuie retrimise
    la fiecare ciclu de analiză dacă datele nu s-au schimbat (bug găsit
    empiric - curl oprit tot declanșa aceeași alertă de 3 ori la rând).
    """

    def test_first_alert_fires_notification(self, db_conn):
        insert_beacon_connections(db_conn, "curl", "93.184.216.34")
        risk_state = {}

        with patch.object(watcher_v6, "send_desktop_notification") as mock_notify:
            run_risk_analysis(db_conn, risk_state)
            assert mock_notify.call_count == 1

    def test_repeated_analysis_same_data_does_not_renotify(self, db_conn):
        """Nucleul regresiei: date NESCHIMBATE -> a doua/treia rulare nu mai trimit popup."""
        insert_beacon_connections(db_conn, "curl", "93.184.216.34")
        risk_state = {}

        with patch.object(watcher_v6, "send_desktop_notification") as mock_notify:
            run_risk_analysis(db_conn, risk_state)
            run_risk_analysis(db_conn, risk_state)
            run_risk_analysis(db_conn, risk_state)
            assert mock_notify.call_count == 1, (
                f"Ar trebui o singură notificare pentru date neschimbate, "
                f"dar au fost trimise {mock_notify.call_count}"
            )

    def test_new_activity_triggers_fresh_alert(self, db_conn):
        """Dacă apar conexiuni NOI (activitate proaspătă), trebuie să alerteze din nou."""
        insert_beacon_connections(db_conn, "curl", "93.184.216.34", n=10)
        risk_state = {}

        with patch.object(watcher_v6, "send_desktop_notification") as mock_notify:
            run_risk_analysis(db_conn, risk_state)
            assert mock_notify.call_count == 1

            # simulăm activitate nouă: mai multe conexiuni curl
            insert_beacon_connections(db_conn, "curl", "93.184.216.34", n=5)
            run_risk_analysis(db_conn, risk_state)
            assert mock_notify.call_count == 2, "Ar fi trebuit să alerteze din nou pentru activitate nouă"

    def test_state_persisted_and_loaded_prevents_alerts_on_restart(self, db_conn):
        """
        REGRESIE Fix 2: după o repornire, dacă starea e încărcată din SQLite,
        nu se mai trimit alerte pentru procese deja cunoscute ca suspecte.
        Simulăm o 'repornire' prin load_risk_alert_state -> dict nou -> analiză.
        """
        from watcher_v6 import load_risk_alert_state, save_risk_alert_state

        insert_beacon_connections(db_conn, "curl", "93.184.216.34")
        risk_state = {}

        # prima rulare: alertă trimisă, stare salvată în SQLite
        with patch.object(watcher_v6, "send_desktop_notification") as mock_notify:
            run_risk_analysis(db_conn, risk_state)
            assert mock_notify.call_count == 1

        # simulăm repornire: încărcăm starea din SQLite în loc de dict gol
        risk_state_after_restart = load_risk_alert_state(db_conn)
        assert "curl" in risk_state_after_restart  # starea a fost salvată

        # după repornire, cu aceleași date, NU ar trebui să mai trimitem alertă
        with patch.object(watcher_v6, "send_desktop_notification") as mock_notify:
            run_risk_analysis(db_conn, risk_state_after_restart)
            assert mock_notify.call_count == 0, (
                "După repornire cu stare persistată, nu ar trebui să re-alerteze"
            )

    def test_time_window_excludes_old_connections(self, db_conn):
        """
        REGRESIE Fix 1: conexiunile mai vechi de 24h nu mai sunt incluse
        în analiza de risc - verificăm că procesul 'vechi' nu mai apare.
        """
        from datetime import timedelta

        # inserăm conexiuni 'vechi' (acum 25h) - ar trebui excluse din analiză
        old_time = datetime.now(timezone.utc) - timedelta(hours=25)
        rows = []
        for i in range(10):
            t = old_time + timedelta(seconds=i * 60)
            rows.append((
                t.isoformat(), 999, "old_malware", "/tmp/x", "h",
                "192.168.1.50", 5000, "45.33.32.156", 443, "TCP", "ESTABLISHED",
            ))
        db_conn.executemany("""
            INSERT INTO connections (timestamp, pid, process_name, binary_path, binary_hash,
                local_ip, local_port, remote_ip, remote_port, protocol, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
        db_conn.commit()

        risk_state = {}
        with patch.object(watcher_v6, "send_desktop_notification") as mock_notify:
            run_risk_analysis(db_conn, risk_state)
            # conexiunile vechi nu ar trebui să declanșeze alertă
            assert mock_notify.call_count == 0, (
                "Conexiunile mai vechi de 24h nu ar trebui să declanșeze alerte"
            )

    def test_low_risk_process_never_notifies(self, db_conn):
        """Un proces cu trafic normal nu declanșează nicio alertă, la niciun ciclu."""
        # simulăm firefox: multe IP-uri diferite, interval neregulat
        rows = []
        t = datetime.now(timezone.utc) - timedelta(minutes=10)
        offsets = [0, 4, 7, 2, 9, 3, 6, 1, 8, 5]
        for i, off in enumerate(offsets):
            t += timedelta(seconds=off)
            rows.append((
                t.isoformat(), 1234, "firefox", "/tmp/x", "hash",
                "192.168.1.50", 5000, f"20.{i}.1.1", 443, "TCP", "ESTABLISHED",
            ))
        db_conn.executemany("""
            INSERT INTO connections (timestamp, pid, process_name, binary_path, binary_hash,
                local_ip, local_port, remote_ip, remote_port, protocol, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
        db_conn.commit()

        risk_state = {}
        with patch.object(watcher_v6, "send_desktop_notification") as mock_notify:
            run_risk_analysis(db_conn, risk_state)
            run_risk_analysis(db_conn, risk_state)
            assert mock_notify.call_count == 0
