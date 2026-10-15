"""
Teste automate pentru baseline.py.

De ce exista: in conversatia de dezvoltare, am descoperit si reparat empiric
mai multe bug-uri (fals pozitive la firefox/apt, IP-uri private, prag de
beaconing absolut vs relativ, IP-uri de test rezervate). Fara teste, riscam
sa reintroducem aceleasi erori la o modificare viitoare - exact ce s-a
intamplat o data cu trunchierea reasons[:2] din watcher.py.

Rulare: pytest test_baseline.py -v
"""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from baseline_v5 import is_private_ip, deduplicate_into_sessions, analyze_process


# ---------- Fixtures ----------

@pytest.fixture
def db_conn():
    """Baza de date SQLite in memorie, curata, pentru fiecare test."""
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


def make_connections(process_ip_pairs, start_time=None, interval_seconds=60):
    """
    Helper: construieste o lista de conexiuni la interval FIX, catre
    un IP (sau o lista de IP-uri, rotite round-robin).
    """
    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(hours=1)

    if isinstance(process_ip_pairs, str):
        process_ip_pairs = [process_ip_pairs]

    connections = []
    t = start_time
    for i in range(20):
        ip = process_ip_pairs[i % len(process_ip_pairs)]
        connections.append({"timestamp": t, "remote_ip": ip, "remote_port": 443})
        t += timedelta(seconds=interval_seconds)
    return connections


# ---------- is_private_ip ----------

class TestIsPrivateIp:
    def test_rfc1918_ranges_are_private(self):
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.5") is True
        assert is_private_ip("172.16.0.1") is True

    def test_loopback_is_private(self):
        assert is_private_ip("127.0.0.1") is True

    def test_public_ips_are_not_private(self):
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False

    def test_testnet_reserved_blocks_are_flagged_private(self):
        """
        Particularitate DOCUMENTATa a bibliotecii Python ipaddress:
        blocurile RFC 5737 (TEST-NET, rezervate documentatiei) sunt
        clasificate is_private=True, desi nu sunt IP-uri de retea locala.
        Acest test NU verifica un comportament corect, ci fixeaza
        comportamentul CUNOSCUT, ca sa nu alegem din nou aceste IP-uri
        pentru teste viitoare fara sa stim de capcana (ne-a pacalit de
        doua ori in timpul dezvoltarii).
        """
        assert is_private_ip("203.0.113.1") is True   # TEST-NET-3
        assert is_private_ip("198.51.100.1") is True  # TEST-NET-2


# ---------- deduplicate_into_sessions ----------

class TestDeduplicateIntoSessions:
    def test_merges_connections_within_gap(self):
        base = datetime.now(timezone.utc)
        connections = [
            {"timestamp": base, "remote_ip": "1.2.3.4", "remote_port": 80},
            {"timestamp": base + timedelta(seconds=1), "remote_ip": "1.2.3.4", "remote_port": 80},
            {"timestamp": base + timedelta(seconds=2), "remote_ip": "1.2.3.4", "remote_port": 80},
        ]
        sessions = deduplicate_into_sessions(connections)
        assert len(sessions) == 1  # toate in interval de 3s, sub SESSION_GAP_SECONDS -> o sesiune

    def test_keeps_separate_sessions_beyond_gap(self):
        base = datetime.now(timezone.utc)
        connections = [
            {"timestamp": base, "remote_ip": "1.2.3.4", "remote_port": 80},
            {"timestamp": base + timedelta(seconds=60), "remote_ip": "1.2.3.4", "remote_port": 80},
            {"timestamp": base + timedelta(seconds=120), "remote_ip": "1.2.3.4", "remote_port": 80},
        ]
        sessions = deduplicate_into_sessions(connections)
        assert len(sessions) == 3  # gap de 60s > SESSION_GAP_SECONDS -> sesiuni separate

    def test_empty_input_returns_empty(self):
        assert deduplicate_into_sessions([]) == []


# ---------- analyze_process: cazuri de baza ----------

class TestAnalyzeProcessCoreCases:
    def test_beacon_single_ip_regular_interval_is_high_risk(self, db_conn):
        """
        Cazul curl din testele reale: un singur IP, interval perfect
        regulat (~62s) -> trebuie detectat cu risc ridicat (concentrare
        + beaconing).
        """
        connections = make_connections("93.184.216.34", interval_seconds=62)
        all_destinations = {"93.184.216.34": {"curl"}}
        report = analyze_process("curl", connections, all_destinations)

        assert report["risk_score"] >= 80
        assert any("CONCENTRAT" in r for r in report["reasons"])
        assert any("BEACONING" in r for r in report["reasons"])

    def test_diverse_traffic_is_normal(self, db_conn):
        """
        Cazul firefox: multe IP-uri distincte, cu variatie NATURALa de timp
        (nu perfect regulata) -> normal, risc 0.

        Nota importanta descoperita la scrierea acestui test: daca traficul
        divers ar avea interval PERFECT regulat (ex. exact 5s intre fiecare),
        regula de beaconing tot s-ar declansa - si pe buna dreptate, e exact
        tiparul unui atacator cu IP-uri rotative (vezi test_rotating_ips...
        de mai jos). Diversitatea singura NU garanteaza "normal" - trebuie
        combinata cu variatie naturala de timp, nu interval matematic exact.
        """
        many_ips = [f"20.{i}.1.1" for i in range(10)]
        base = datetime.now(timezone.utc)
        offsets = [0, 4, 7, 2, 9, 3, 6, 1, 8, 5, 3, 7, 2, 9, 4, 6, 1, 8, 5, 2]
        connections = []
        t = base
        for i, off in enumerate(offsets):
            t += timedelta(seconds=off if i > 0 else 0)
            connections.append({
                "timestamp": t, "remote_ip": many_ips[i % len(many_ips)], "remote_port": 443
            })
        all_destinations = {ip: {"firefox"} for ip in many_ips}
        report = analyze_process("firefox", connections, all_destinations)

        assert report["risk_score"] == 0
        assert any("divers" in r.lower() for r in report["reasons"])

    def test_only_private_traffic_has_insufficient_data(self, db_conn):
        """Cazul NetworkManager: doar IP-uri locale -> nu se poate evalua risc extern."""
        connections = make_connections("192.168.1.1", interval_seconds=5)
        all_destinations = {"192.168.1.1": {"NetworkManager"}}
        report = analyze_process("NetworkManager", connections, all_destinations)

        assert report["risk_score"] == 0
        assert any("insuficiente" in r.lower() or "putine conexiuni externe" in r.lower()
                    for r in report["reasons"])

    def test_too_few_samples_is_not_evaluated(self, db_conn):
        """Cu sub 3 conexiuni, nu tragem nicio concluzie de risc."""
        connections = make_connections("8.8.8.8", interval_seconds=60)[:2]
        report = analyze_process("test_proc", connections, {})

        assert report["risk_score"] == 0
        assert "putine" in report["reasons"][0].lower()


# ---------- analyze_process: regresii pe bug-uri descoperite empiric ----------

class TestAnalyzeProcessRegressions:
    def test_frequent_irregular_traffic_does_not_trigger_beaconing(self, db_conn):
        """
        REGRESIE: cazul real VS Code (interval mediu ~3s, deviatie std ~4.93s).
        Inainte de fix (prag absolut de 5s), asta declansa fals-pozitiv de
        beaconing. Deviatia e aproape cat media insasi (variatie relativa
        ~164%) - complet neregulat, NU trebuie sa declanseze alerta.
        """
        base = datetime.now(timezone.utc)
        # construim manual intervale cu variatie mare, medie mica (~3s)
        offsets = [0, 3, 4, 9, 2, 11, 1, 8, 5, 0.5, 12, 2, 7, 1, 9, 3, 6, 10, 2, 4]
        connections = []
        t = base
        for i, off in enumerate(offsets):
            t += timedelta(seconds=off if i > 0 else 0)
            connections.append({
                "timestamp": t, "remote_ip": f"20.{i % 5}.1.1", "remote_port": 443
            })
        all_destinations = {f"20.{i}.1.1": {"code"} for i in range(5)}
        report = analyze_process("code", connections, all_destinations)

        assert not any("BEACONING" in r for r in report["reasons"]), (
            f"Fals pozitiv de beaconing pe trafic neregulat: {report['reasons']}"
        )

    def test_rotating_ips_with_regular_interval_still_caught(self, db_conn):
        """
        REGRESIE: un atacator care roteste 5 IP-uri (scapa de regula de
        concentrare, distinct_ips=5 > pragul de 3), DAR pastreaza interval
        regulat, tot trebuie prins - prin regula de regularitate, care nu
        depinde de cate IP-uri distincte sunt implicate.
        """
        ips = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "76.76.2.22"]
        connections = make_connections(ips, interval_seconds=45)
        all_destinations = {ip: {"rotating_c2"} for ip in ips}
        report = analyze_process("rotating_c2", connections, all_destinations)

        assert not any("CONCENTRAT" in r for r in report["reasons"])  # concentrarea NU se declanseaza
        assert any("BEACONING" in r for r in report["reasons"])       # dar regularitatea DA
        assert report["risk_score"] >= 50

    def test_full_reasons_are_available_not_truncated(self, db_conn):
        """
        REGRESIE: watcher.py trunchia motivele la primele 2 (mereu liniile
        generice), ascunzand motivul real. Verificam aici ca analyze_process
        insusi intoarce toate motivele relevante, complete - responsabilitatea
        de a nu le trunchia e a apelantului (watcher.py), dar testul asta
        confirma ca sursa de adevar contine informatia completa.
        """
        connections = make_connections("45.33.32.156", interval_seconds=60)
        all_destinations = {"45.33.32.156": {"malware_sim"}}
        report = analyze_process("malware_sim", connections, all_destinations)

        reasons_joined = " ".join(report["reasons"])
        assert "CONCENTRAT" in reasons_joined
        assert "BEACONING" in reasons_joined
        assert len(report["reasons"]) >= 2  # cel putin concentrare + beaconing, nu doar 1

    def test_large_time_gap_between_sessions_does_not_mask_beaconing(self, db_conn):
        """
        REGRESIE: descoperit empiric la testarea reala - un proces cu trafic
        perfect regulat (interval ~62s) intr-o sesiune RECENTa, dar cu o
        sesiune de test VECHE (la zile distanta) in acelasi istoric, nu mai
        era detectat ca beaconing deloc. Cauza: media/deviatia standard
        calculate pe TOT istoricul erau distruse de un singur gol enorm
        (zile) - un caz clasic de ne-robustete statistica la valori extreme.

        Fix: split_into_bursts() separa sesiunile la goluri > 10 minute,
        iar analiza de regularitate ruleaza doar pe cel mai mare burst.
        """
        old_burst_start = datetime.now(timezone.utc) - timedelta(days=35)
        recent_burst_start = datetime.now(timezone.utc) - timedelta(hours=1)

        connections = []
        # sesiune veche, mica (13 conexiuni) - de acum 35 de zile
        t = old_burst_start
        for _ in range(13):
            connections.append({"timestamp": t, "remote_ip": "93.184.216.34", "remote_port": 80})
            t += timedelta(seconds=62)
        # sesiune recenta, mare (44 conexiuni) - perfect regulata, acum
        t = recent_burst_start
        for _ in range(44):
            connections.append({"timestamp": t, "remote_ip": "93.184.216.34", "remote_port": 80})
            t += timedelta(seconds=62)

        all_destinations = {"93.184.216.34": {"curl"}}
        report = analyze_process("curl", connections, all_destinations)

        reasons_joined = " ".join(report["reasons"])
        assert "sesiuni separate" in reasons_joined.lower(), (
            f"Ar trebui sa raporteze ca a gasit sesiuni separate: {report['reasons']}"
        )
        assert "BEACONING" in reasons_joined, (
            f"Beaconing-ul din sesiunea recenta, perfect regulata, nu ar trebui "
            f"mascat de golul de 35 de zile: {report['reasons']}"
        )
        assert report["risk_score"] >= 50
