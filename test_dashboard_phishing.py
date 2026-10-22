"""
Teste pentru partea de phishing din dashboard: API, protectii, banda.
Rulare: pytest test_dashboard_phishing.py -v
"""

import re
import sqlite3
from datetime import datetime, timezone

import pytest

import dashboard
import phishing_store as store
from watcher_v6 import init_db

BASE = "http://localhost:5000"


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    monkeypatch.setattr(dashboard, "DB_PATH", str(db))
    monkeypatch.setattr(dashboard, "ALERTS_LOG_PATH", str(tmp_path / "alerts.log"))
    c = sqlite3.connect(db)
    init_db(c)
    store.init_tables(c)
    now = datetime.now(timezone.utc).isoformat()
    c.execute("INSERT INTO phishing_events (timestamp, host, score, brand, reasons, kind, alerted) "
              "VALUES (?, 'olx-plata.ro', 80, 'OLX', 'numele site-ului contine olx', 'tastat', 1)", (now,))
    c.execute("INSERT INTO phishing_events (timestamp, host, score, brand, reasons, kind, alerted) "
              "VALUES (?, '185.12.4.9', 40, NULL, 'adresa numerica', 'link', 0)", (now,))
    c.commit()
    c.close()
    return dashboard.app.test_client()


def act(client, host, action, **kw):
    kw.setdefault("base_url", BASE)
    return client.post("/api/phishing", json={"host": host, "action": action}, **kw)


def status(client):
    return client.get("/api/status", base_url=BASE).get_json()


class TestStatus:
    def test_status_has_active_recent_and_allowlist(self, client):
        p = status(client)["phishing"]
        assert [a["host"] for a in p["active"]] == ["olx-plata.ro"]
        assert p["active"][0]["official"] == "olx.ro"
        assert len(p["recent"]) == 2
        assert p["allowlist"] == []

    def test_repeated_visits_to_a_domain_are_grouped(self, client):
        c = sqlite3.connect(dashboard.DB_PATH)
        now = datetime.now(timezone.utc).isoformat()
        for _ in range(3):
            c.execute("INSERT INTO phishing_events (timestamp, host, score, brand, reasons, kind, alerted) "
                      "VALUES (?, 'olx-plata.ro', 80, 'OLX', 'motiv', 'tastat', 1)", (now,))
        c.commit(); c.close()
        recent = status(client)["phishing"]["recent"]
        olx = [r for r in recent if r["host"] == "olx-plata.ro"]
        assert len(olx) == 1 and olx[0]["visits"] == 4          # 1 din fixture + 3
        assert len(recent) == 2

    def test_dashboard_can_start_before_the_watcher_created_the_tables(self, tmp_path, monkeypatch):
        db = tmp_path / "fresh.db"
        monkeypatch.setattr(dashboard, "DB_PATH", str(db))
        monkeypatch.setattr(dashboard, "ALERTS_LOG_PATH", str(tmp_path / "alerts.log"))
        c = sqlite3.connect(db)
        init_db(c)
        c.close()
        p = dashboard.app.test_client().get("/api/status", base_url=BASE).get_json()["phishing"]
        assert p == {"active": [], "recent": [], "allowlist": []}


class TestDecisions:
    def test_dismiss_hides_the_banner(self, client):
        assert act(client, "olx-plata.ro", "dismiss").status_code == 200
        assert status(client)["phishing"]["active"] == []

    def test_allow_moves_host_to_allowlist(self, client):
        assert act(client, "olx-plata.ro", "allow").status_code == 200
        p = status(client)["phishing"]
        assert p["active"] == [] and [x["host"] for x in p["allowlist"]] == ["olx-plata.ro"]
        assert "olx-plata.ro" not in [r["host"] for r in p["recent"]]      # a iesit si din lista de site-uri suspecte

    def test_unallow(self, client):
        act(client, "olx-plata.ro", "allow")
        assert act(client, "olx-plata.ro", "unallow").status_code == 200
        assert status(client)["phishing"]["allowlist"] == []

    def test_unallow_brings_the_domain_back_into_the_list(self, client):
        act(client, "olx-plata.ro", "allow")
        act(client, "olx-plata.ro", "unallow")
        assert "olx-plata.ro" in [r["host"] for r in status(client)["phishing"]["recent"]]

    def test_host_is_case_insensitive(self, client):
        assert act(client, "OLX-Plata.RO", "dismiss").status_code == 200

    def test_unknown_host_is_404_and_allowlist_stays_empty(self, client):
        assert act(client, "banca-mea.ro", "allow").status_code == 404
        assert status(client)["phishing"]["allowlist"] == []

    @pytest.mark.parametrize("body", [
        {"action": "allow"}, {"host": "x.ro"}, {"host": "x.ro", "action": "hack"},
        {"host": 5, "action": "allow"}, {"host": "", "action": "allow"}, {"host": "a" * 300, "action": "allow"},
    ])
    def test_invalid_requests_are_400(self, client, body):
        assert client.post("/api/phishing", json=body, base_url=BASE).status_code == 400


class TestCrossSiteProtection:
    """Un site de phishing nu trebuie sa-si poata amuti singur alerta."""

    def test_foreign_origin_refused(self, client):
        r = act(client, "olx-plata.ro", "allow", headers={"Origin": "http://olx-plata.ro"})
        assert r.status_code == 403
        assert status(client)["phishing"]["allowlist"] == []

    def test_foreign_host_refused_dns_rebinding(self, client):
        r = act(client, "olx-plata.ro", "allow", base_url="http://olx-plata.ro:5000")
        assert r.status_code == 403
        assert len(status(client)["phishing"]["active"]) == 1

    def test_form_post_refused(self, client):
        r = client.post("/api/phishing", base_url=BASE, data={"host": "olx-plata.ro", "action": "allow"})
        assert r.status_code == 403
        assert len(status(client)["phishing"]["active"]) == 1

    def test_own_origin_accepted(self, client):
        assert act(client, "olx-plata.ro", "dismiss", headers={"Origin": BASE}).status_code == 200

    def test_get_not_allowed(self, client):
        assert client.get("/api/phishing", base_url=BASE).status_code == 405


class TestPage:
    def test_page_has_banner_card_and_tile(self, client):
        html = client.get("/", base_url=BASE).get_data(as_text=True)
        for needle in ("phishing-banner", "phishing-list", "stat-phishing", "render_phishing", "/api/phishing"):
            assert needle in html

    def test_phishing_lines_in_the_journal_are_highlighted(self):
        assert "[PHISHING" in dashboard.DASHBOARD_HTML

    def test_no_untrusted_phishing_field_is_interpolated_raw(self):
        """Domeniul si motivele vin din navigarea utilizatorului: trebuie sa treaca prin esc()."""
        html = dashboard.DASHBOARD_HTML
        for field in ("host", "brand", "reasons", "official", "kind", "score"):
            raw_uses = re.findall(r"\$\{[ax]\.%s\}" % field, html)
            assert raw_uses == [], f"{field} inserat fara esc(): {raw_uses}"
