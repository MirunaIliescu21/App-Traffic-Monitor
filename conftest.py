"""
Configurare comuna pentru toate testele.

Fara asta, testele care declanseaza alerte scriau in `alerts.log` REAL din
folderul proiectului (ALERTS_LOG_PATH e o cale relativa), asa ca fiecare rulare
de pytest umplea jurnalul din dashboard cu alerte false (5 linii "curl 80/100"
la aceeasi secunda). Aici redirectionam jurnalul intr-un folder temporar.
"""

import pytest

import watcher_v6


@pytest.fixture(autouse=True)
def isolate_alerts_log(tmp_path, monkeypatch):
    monkeypatch.setattr(watcher_v6, "ALERTS_LOG_PATH", str(tmp_path / "alerts.log"))
