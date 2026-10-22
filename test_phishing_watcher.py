"""
Teste pentru phishing_watcher.py si notifier.py.
Rulare: pytest test_phishing_watcher.py -v
"""

import sqlite3
import subprocess

import pytest

import browser_history as bh
import notifier
import phishing_watcher as pw
from test_browser_history import add_visit, make_places


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    pw.init_tables(c)
    yield c
    c.close()


def visit(host, when=1_000_000.0, kind="link", url=None, vid=1, from_visit=0):
    return bh.Visit(visit_id=vid, when=when, url=url or f"https://{host}/pay?token=SECRET123", host=host,
                    kind=kind, from_visit=from_visit)


class Recorder:
    def __init__(self):
        self.notifications = []
        self.log_lines = []

    def notify(self, title, message, urgency="normal"):
        self.notifications.append((title, message, urgency))
        return True

    def log(self, line):
        self.log_lines.append(line)


@pytest.fixture
def rec():
    return Recorder()


def run(conn, v, last_seen, rec, visit_hosts=None):
    return pw.process_visit(conn, v, last_seen, rec.notify, rec.log, visit_hosts)


class TestProcessVisit:
    def test_normal_site_is_ignored_and_not_stored(self, conn, rec):
        assert run(conn, visit("biziday.ro"), {}, rec) is None
        assert conn.execute("SELECT COUNT(*) FROM phishing_events").fetchone()[0] == 0
        assert rec.notifications == [] and rec.log_lines == []

    def test_official_site_is_ignored(self, conn, rec):
        assert run(conn, visit("www.olx.ro"), {}, rec) is None
        assert rec.notifications == []

    def test_lookalike_alerts_with_critical_notification(self, conn, rec):
        verdict = run(conn, visit("olx-plata.ro"), {}, rec)
        assert verdict.alert
        assert len(rec.notifications) == 1
        title, message, urgency = rec.notifications[0]
        assert "OLX" in title and urgency == "critical"
        assert "olx.ro" in message and "card" in message

    def test_alert_is_written_to_the_journal(self, conn, rec):
        run(conn, visit("olx-plata.ro", kind="redirect"), {}, rec)
        assert len(rec.log_lines) == 1
        assert rec.log_lines[0].startswith("[PHISHING ") and "olx-plata.ro" in rec.log_lines[0]
        assert "redirect" in rec.log_lines[0]

    def test_event_is_stored_with_host_only_never_the_full_url(self, conn, rec):
        run(conn, visit("olx-plata.ro"), {}, rec)
        columns = [row[1] for row in conn.execute("PRAGMA table_info(phishing_events)")]
        assert "url" not in columns and "title" not in columns
        row = conn.execute("SELECT host, brand, alerted, kind FROM phishing_events").fetchone()
        assert row == ("olx-plata.ro", "OLX", 1, "link")
        dump = " ".join(str(c) for r in conn.execute("SELECT * FROM phishing_events") for c in r)
        assert "SECRET123" not in dump

    def test_weak_signal_is_stored_but_does_not_notify(self, conn, rec):
        verdict = run(conn, visit("185.12.4.9"), {}, rec)
        assert verdict is not None and not verdict.alert
        assert rec.notifications == [] and rec.log_lines == []
        row = conn.execute("SELECT host, alerted FROM phishing_events").fetchone()
        assert row == ("185.12.4.9", 0)

    def test_duplicate_visits_of_the_same_navigation_alert_once(self, conn, rec):
        """http -> https redirect: doua vizite la acelasi domeniu in cateva secunde = o singura alerta."""
        last_seen = {}
        run(conn, visit("olx-plata.ro", when=1_000_000), last_seen, rec)
        run(conn, visit("olx-plata.ro", when=1_000_002, kind="redirect"), last_seen, rec)
        assert len(rec.notifications) == 1
        assert conn.execute("SELECT COUNT(*) FROM phishing_events").fetchone()[0] == 1

    def test_later_visit_to_the_same_domain_alerts_again(self, conn, rec):
        """O alerta de phishing nu se ignora: a doua vizita poate fi momentul in care introduci datele."""
        last_seen = {}
        run(conn, visit("olx-plata.ro", when=1_000_000), last_seen, rec)
        run(conn, visit("olx-plata.ro", when=1_000_000 + pw.DEDUPE_SECONDS + 1), last_seen, rec)
        run(conn, visit("olx-plata.ro", when=1_000_000 + 600, kind="reincarcare"), last_seen, rec)
        assert len(rec.notifications) == 3

    def test_different_domains_do_not_share_the_dedupe_window(self, conn, rec):
        last_seen = {}
        run(conn, visit("olx-plata.ro"), last_seen, rec)
        run(conn, visit("bcr-securizat.top"), last_seen, rec)
        assert len(rec.notifications) == 2


class TestDeliberateVersusSameNavigation:
    """Intrarile deliberate alerteaza mereu; se strang doar redirecturile si navigarea interna."""

    @pytest.mark.parametrize("kind", ["tastat", "bookmark", "reincarcare", "link"])
    def test_deliberate_entry_seconds_later_alerts_again(self, conn, rec, kind):
        """Un tab nou deschis la cateva secunde dupa primul NU e un duplicat."""
        last_seen, hosts = {}, {}
        run(conn, visit("olx-plata.ro", when=1_000_000, vid=1), last_seen, rec, hosts)
        run(conn, visit("olx-plata.ro", when=1_000_005, kind=kind, vid=2), last_seen, rec, hosts)
        assert len(rec.notifications) == 2

    def test_redirect_within_the_window_is_the_same_navigation(self, conn, rec):
        last_seen, hosts = {}, {}
        run(conn, visit("olx-plata.ro", when=1_000_000, kind="tastat", vid=1), last_seen, rec, hosts)
        run(conn, visit("olx-plata.ro", when=1_000_001, kind="redirect", vid=2, from_visit=1), last_seen, rec, hosts)
        assert len(rec.notifications) == 1

    def test_redirect_after_the_window_alerts(self, conn, rec):
        last_seen, hosts = {}, {}
        run(conn, visit("olx-plata.ro", when=1_000_000, vid=1), last_seen, rec, hosts)
        run(conn, visit("olx-plata.ro", when=1_000_000 + pw.DEDUPE_SECONDS + 1, kind="redirect", vid=2), last_seen, rec, hosts)
        assert len(rec.notifications) == 2

    def test_click_inside_the_suspicious_site_is_not_a_new_alert(self, conn, rec):
        last_seen, hosts = {}, {}
        run(conn, visit("olx-plata.ro", when=1_000_000, kind="tastat", vid=1), last_seen, rec, hosts)
        run(conn, visit("olx-plata.ro", when=1_000_010, kind="link", vid=2, from_visit=1), last_seen, rec, hosts)
        assert len(rec.notifications) == 1

    def test_internal_navigation_chain_is_followed(self, conn, rec):
        """Pagina 3 vine din pagina 2, care vine din 1: toate la acelasi domeniu, o singura alerta."""
        last_seen, hosts = {}, {}
        run(conn, visit("olx-plata.ro", when=1_000_000, kind="tastat", vid=1), last_seen, rec, hosts)
        run(conn, visit("olx-plata.ro", when=1_000_010, kind="link", vid=2, from_visit=1), last_seen, rec, hosts)
        run(conn, visit("olx-plata.ro", when=1_000_020, kind="link", vid=3, from_visit=2), last_seen, rec, hosts)
        assert len(rec.notifications) == 1

    def test_link_coming_from_another_site_alerts(self, conn, rec):
        """Link de pe alt site (vizita sursa e la alt domeniu) = intrare noua."""
        last_seen, hosts = {}, {}
        run(conn, visit("olx-plata.ro", when=1_000_000, kind="tastat", vid=1), last_seen, rec, hosts)
        run(conn, visit("biziday.ro", when=1_000_005, kind="tastat", vid=2), last_seen, rec, hosts)
        run(conn, visit("olx-plata.ro", when=1_000_010, kind="link", vid=3, from_visit=2), last_seen, rec, hosts)
        assert len(rec.notifications) == 2

    def test_link_from_unknown_source_alerts(self, conn, rec):
        """Link din WhatsApp: nu avem vizita sursa (from_visit 0) -> alerteaza."""
        last_seen, hosts = {}, {}
        run(conn, visit("olx-plata.ro", when=1_000_000, vid=1, from_visit=0), last_seen, rec, hosts)
        run(conn, visit("olx-plata.ro", when=1_000_010, kind="link", vid=2, from_visit=0), last_seen, rec, hosts)
        assert len(rec.notifications) == 2

    def test_internal_navigation_after_the_window_reminds_again(self, conn, rec):
        last_seen, hosts = {}, {}
        run(conn, visit("olx-plata.ro", when=1_000_000, kind="tastat", vid=1), last_seen, rec, hosts)
        run(conn, visit("olx-plata.ro", when=1_000_000 + pw.DEDUPE_SECONDS + 5, kind="link", vid=2, from_visit=1),
            last_seen, rec, hosts)
        assert len(rec.notifications) == 2

    def test_same_visit_read_twice_is_never_a_new_alert(self, conn, rec):
        """Lookback-ul de la repornire reciteste vizite deja raportate."""
        last_seen = {}
        v = visit("olx-plata.ro", when=1_000_000, kind="tastat")
        run(conn, v, last_seen, rec)
        run(conn, v, last_seen, rec)
        assert len(rec.notifications) == 1

    def test_remembered_visits_stay_bounded(self, conn, rec):
        hosts = {i: "x.ro" for i in range(pw.MAX_REMEMBERED_VISITS + 5)}
        run(conn, visit("olx-plata.ro", vid=999_999), {}, rec, hosts)
        assert len(hosts) <= 2


class TestAllowlist:
    def test_allowed_domain_is_ignored_and_not_stored(self, conn, rec):
        verdict = pw.process_visit(conn, visit("olx-plata.ro"), {}, rec.notify, rec.log,
                                   allowlist=frozenset({"olx-plata.ro"}))
        assert verdict is None
        assert rec.notifications == []
        assert conn.execute("SELECT COUNT(*) FROM phishing_events").fetchone()[0] == 0

    def test_subdomain_of_an_allowed_domain_is_ignored(self, conn, rec):
        assert pw.process_visit(conn, visit("www.olx-plata.ro"), {}, rec.notify, rec.log,
                                allowlist=frozenset({"olx-plata.ro"})) is None

    def test_other_domains_still_alert(self, conn, rec):
        pw.process_visit(conn, visit("bcr-securizat.top"), {}, rec.notify, rec.log,
                         allowlist=frozenset({"olx-plata.ro"}))
        assert len(rec.notifications) == 1

    def test_allowing_in_the_dashboard_takes_effect_on_the_next_poll(self, tmp_path, conn, rec):
        """Fluxul real: alerta -> utilizatorul apasa 'Este site-ul real' -> vizita urmatoare e ignorata."""
        places = str(tmp_path / "places.sqlite")
        make_places(places, []).close()
        watcher = bh.HistoryWatcher([places], lookback_seconds=0, now=1_000)
        last_seen = {}
        add_visit(places, 1, 2_000_000, "https://olx-plata.ro/", vtype=2)
        assert pw.poll_once(conn, watcher, last_seen, rec.notify, rec.log) == 1

        from phishing_store import allow
        assert allow(conn, "olx-plata.ro") is True

        add_visit(places, 2, 2_000_100, "https://olx-plata.ro/", vtype=2)
        assert pw.poll_once(conn, watcher, last_seen, rec.notify, rec.log) == 0
        assert len(rec.notifications) == 1


class TestRestart:
    def test_last_seen_is_restored_from_the_database(self, conn, rec):
        run(conn, visit("olx-plata.ro", when=1_000_000), {}, rec)
        restored = pw.load_last_seen(conn)
        assert restored["olx-plata.ro"] == pytest.approx(1_000_000, abs=1)

    def test_no_second_alert_after_restart(self, conn, rec):
        """O repornire a serviciului nu trebuie sa re-alerteze pentru aceeasi pagina (lookback reciteste vizita)."""
        run(conn, visit("olx-plata.ro", when=1_000_000), {}, rec)
        restored = pw.load_last_seen(conn)
        run(conn, visit("olx-plata.ro", when=1_000_000), restored, rec)
        assert len(rec.notifications) == 1


class TestEndToEnd:
    def test_phishing_visit_in_firefox_history_triggers_alert(self, tmp_path, conn, rec):
        places = str(tmp_path / "places.sqlite")
        make_places(places, [(1, 10, "https://www.google.com/search?q=olx", 1, 0, "")]).close()
        watcher = bh.HistoryWatcher([places], lookback_seconds=0, now=1_000)
        last_seen = {}

        assert pw.poll_once(conn, watcher, last_seen, rec.notify, rec.log) == 0     # nimic nou

        add_visit(places, 2, 2_000_000, "https://biziday.ro/", vtype=1)
        add_visit(places, 3, 2_000_010, "https://olx-plata.ro/pay?x=1", vtype=1, from_visit=2)
        assert pw.poll_once(conn, watcher, last_seen, rec.notify, rec.log) == 1
        assert len(rec.notifications) == 1
        assert "olx-plata.ro" in rec.notifications[0][1]

        assert pw.poll_once(conn, watcher, last_seen, rec.notify, rec.log) == 0     # nu se repeta


class TestNotifier:
    def test_linux_uses_notify_send(self, monkeypatch):
        calls = []
        monkeypatch.setattr(notifier.sys, "platform", "linux")
        monkeypatch.setattr(notifier.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
        assert notifier.notify("Titlu", "Mesaj", "critical") is True
        assert calls == [["notify-send", "--urgency=critical", "Titlu", "Mesaj"]]

    def test_macos_uses_osascript_and_escapes_quotes(self, monkeypatch):
        calls = []
        monkeypatch.setattr(notifier.sys, "platform", "darwin")
        monkeypatch.setattr(notifier.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
        assert notifier.notify('Ti"tlu', 'Mesaj "citat"') is True
        assert calls[0][0] == "osascript"
        assert '\\"' in calls[0][2]

    def test_unsupported_platform_returns_false(self, monkeypatch):
        monkeypatch.setattr(notifier.sys, "platform", "win32")
        assert notifier.notify("t", "m") is False

    def test_missing_notify_send_does_not_crash(self, monkeypatch):
        monkeypatch.setattr(notifier.sys, "platform", "linux")

        def boom(*a, **k):
            raise FileNotFoundError

        monkeypatch.setattr(notifier.subprocess, "run", boom)
        assert notifier.notify("t", "m") is False

    def test_timeout_does_not_crash(self, monkeypatch):
        monkeypatch.setattr(notifier.sys, "platform", "linux")

        def slow(*a, **k):
            raise subprocess.TimeoutExpired("notify-send", 3)

        monkeypatch.setattr(notifier.subprocess, "run", slow)
        assert notifier.notify("t", "m") is False

    def test_log_alert_format(self, tmp_path, monkeypatch):
        path = tmp_path / "alerts.log"
        monkeypatch.setattr(notifier, "ALERTS_LOG_PATH", str(path))
        notifier.log_alert("[PHISHING 80/100] olx-plata.ro")
        line = path.read_text(encoding="utf-8").strip()
        assert line.startswith("[") and line.endswith("UTC] [PHISHING 80/100] olx-plata.ro")
