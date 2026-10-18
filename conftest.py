"""
Configurare comuna pentru toate testele.

Fara asta, testele care declanseaza alerte scriau in `alerts.log` REAL din
folderul proiectului (ALERTS_LOG_PATH e o cale relativa), asa ca fiecare rulare
de pytest umplea jurnalul din dashboard cu alerte false (5 linii "curl 80/100"
la aceeasi secunda). Aici redirectionam jurnalul intr-un folder temporar.
"""

import pytest

import asn
import watcher_v6


@pytest.fixture(autouse=True)
def isolate_alerts_log(tmp_path, monkeypatch):
    monkeypatch.setattr(watcher_v6, "ALERTS_LOG_PATH", str(tmp_path / "alerts.log"))


@pytest.fixture(autouse=True)
def isolate_asn(tmp_path, monkeypatch):
    """
    Pe calculatorul tau exista un asn.db real, care ar identifica retele pe care
    testele le vor "necunoscute". Fiecare test porneste cu o baza ASN inexistenta
    (sau cu una mica, construita de test).
    """
    monkeypatch.setattr(asn, "ASN_DB_PATH", str(tmp_path / "asn_test.db"))
    asn.reset()
    yield
    asn.reset()
