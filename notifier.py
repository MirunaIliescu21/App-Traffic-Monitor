"""
Notificari desktop si jurnalul de alerte, fara dependente de platforma.

Linux (testat): notify-send. macOS: osascript (netestat inca). Windows: de implementat -
pana atunci notify() intoarce False si alerta ramane in jurnalul alerts.log, care
se scrie oricum, ca alerta sa nu se piarda daca popup-ul nu apare.

Serviciul systemd de utilizator are deja sesiunea grafica (DBUS_SESSION_BUS_ADDRESS
e pusa in fisierul serviciului), deci notify-send merge direct, fara sudo.
"""

import subprocess
import sys
from datetime import datetime, timezone

ALERTS_LOG_PATH = "alerts.log"


def log_alert(message: str) -> None:
    """Adauga o linie in alerts.log, in acelasi format ca watcher-ul (apare in dashboard)."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(ALERTS_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message}\n")


def _applescript_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def notify(title: str, message: str, urgency: str = "normal") -> bool:
    """Trimite o notificare. Intoarce False daca platforma nu e suportata sau popup-ul nu a putut fi trimis."""
    platform = sys.platform
    if platform.startswith("linux"):
        command = ["notify-send", f"--urgency={urgency}", title, message]
    elif platform == "darwin":
        script = f"display notification {_applescript_string(message)} with title {_applescript_string(title)}"
        command = ["osascript", "-e", script]
    else:
        return False
    try:
        subprocess.run(command, timeout=3, check=False)
        return True
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return False
