"""
Teste pentru dashboard: endpoint-ul de decizii și protecțiile lui.

Rulare: python3 -m pytest test_dashboard.py -v
"""

import re
import sqlite3

import pytest

import dashboard
import destination_status as ds
from watcher_v6 import init_db

BASE = "http://localhost:5000"


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    monkeypatch.setattr(dashboard, "DB_PATH", str(db))
    monkeypatch.setattr(dashboard, "ALERTS_LOG_PATH", str(tmp_path / "alerts.log"))
    c = sqlite3.connect(db)
    init_db(c)
    ds.record_pending(c, "chrome", "evil-example.net", "domeniu", "2026-10-14T10:00:00+00:00",
                      sample_ip="9.9.9.1", sample_hostname="a.evil-example.net")
    c.close()
    return dashboard.app.test_client()


def post(client, body, **kw):
    kw.setdefault("base_url", BASE)
    return client.post("/api/decision", json=body, **kw)


def status_of(tmp_db_path_fixture, key="evil-example.net"):
    pass


def current_status():
    c = sqlite3.connect(dashboard.DB_PATH)
    try:
        return ds.load_decisions(c).get(("chrome", "evil-example.net"))
    finally:
        c.close()


class TestDecisionEndpoint:
    def test_normal_decision_is_saved(self, client):
        r = post(client, {"process_name": "chrome", "group_key": "evil-example.net", "status": "normal"})
        assert r.status_code == 200
        assert current_status() == ds.NORMAL

    def test_suspicious_decision_is_saved(self, client):
        post(client, {"process_name": "chrome", "group_key": "evil-example.net", "status": "suspicious"})
        assert current_status() == ds.SUSPICIOUS

    def test_user_can_undo_back_to_pending(self, client):
        post(client, {"process_name": "chrome", "group_key": "evil-example.net", "status": "normal"})
        post(client, {"process_name": "chrome", "group_key": "evil-example.net", "status": "pending"})
        assert current_status() == ds.PENDING

    def test_invalid_status_rejected(self, client):
        r = post(client, {"process_name": "chrome", "group_key": "evil-example.net", "status": "hack"})
        assert r.status_code == 400
        assert current_status() == ds.PENDING

    def test_missing_fields_rejected(self, client):
        assert post(client, {"status": "normal"}).status_code == 400

    def test_unknown_destination_404(self, client):
        r = post(client, {"process_name": "chrome", "group_key": "nu-exista.com", "status": "normal"})
        assert r.status_code == 404


class TestCrossSiteProtection:
    def test_foreign_origin_refused(self, client):
        r = post(client, {"process_name": "chrome", "group_key": "evil-example.net", "status": "normal"},
                 headers={"Origin": "http://site-rau.example"})
        assert r.status_code == 403 and current_status() == ds.PENDING

    def test_foreign_host_refused_dns_rebinding(self, client):
        r = post(client, {"process_name": "chrome", "group_key": "evil-example.net", "status": "normal"},
                 base_url="http://site-rau.example:5000")
        assert r.status_code == 403 and current_status() == ds.PENDING

    def test_non_json_form_post_refused(self, client):
        r = client.post("/api/decision", base_url=BASE,
                        data={"process_name": "chrome", "group_key": "evil-example.net", "status": "normal"})
        assert r.status_code == 403 and current_status() == ds.PENDING

    def test_own_origin_accepted(self, client):
        r = post(client, {"process_name": "chrome", "group_key": "evil-example.net", "status": "normal"},
                 headers={"Origin": BASE})
        assert r.status_code == 200

    def test_get_not_allowed(self, client):
        assert client.get("/api/decision", base_url=BASE).status_code == 405


class TestStatusApi:
    def test_status_lists_pending_marked_and_log(self, client):
        d = client.get("/api/status", base_url=BASE).get_json()
        assert [p["group_key"] for p in d["pending"]] == ["evil-example.net"]
        assert d["marked"] == []
        post(client, {"process_name": "chrome", "group_key": "evil-example.net", "status": "suspicious"})
        d = client.get("/api/status", base_url=BASE).get_json()
        assert d["pending"] == []
        assert d["marked"][0]["status"] == "suspicious"
        assert d["decision_log"][0]["new_status"] == "suspicious"

    def test_decisions_never_touch_connections_table(self, client):
        c = sqlite3.connect(dashboard.DB_PATH)
        c.execute("INSERT INTO connections (timestamp, process_name, remote_ip) VALUES ('t','chrome','9.9.9.1')")
        c.commit(); c.close()
        post(client, {"process_name": "chrome", "group_key": "evil-example.net", "status": "normal"})
        c = sqlite3.connect(dashboard.DB_PATH)
        assert c.execute("SELECT COUNT(*) FROM connections").fetchone()[0] == 1
        c.close()


class TestPageEscaping:
    def test_no_untrusted_field_is_interpolated_raw(self):
        """Orice câmp care vine din rețea/proces trebuie să treacă prin esc() în HTML."""
        html = dashboard.DASHBOARD_HTML
        for field in ("process_name", "remote_ip", "remote_hostname", "group_key",
                      "sample_hostname", "sample_ip", "raw"):
            raw_uses = re.findall(r"\$\{[a-z]\.%s(?: \|\| '—')?\}" % field, html)
            assert raw_uses == [], f"{field} inserat fără esc(): {raw_uses}"
