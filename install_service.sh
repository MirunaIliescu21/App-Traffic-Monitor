#!/usr/bin/env bash
# Instaleaza TrafficMonitor ca servicii systemd de UTILIZATOR (Linux).
#   ./install_service.sh              instaleaza si porneste
#   ./install_service.sh --uninstall  opreste si sterge
# Ruleaza ca utilizatorul obisnuit, NU cu sudo: serviciile trebuie sa ruleze
# in sesiunea ta, ca notificarile desktop (notify-send) sa functioneze.
set -euo pipefail

UNIT_DIR="$HOME/.config/systemd/user"
SERVICES=(trafficmonitor-watcher trafficmonitor-dashboard trafficmonitor-phishing)

if [ "$(id -u)" -eq 0 ]; then
  echo "Nu rula cu sudo. Ruleaza ca utilizator obisnuit." >&2; exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
  for s in "${SERVICES[@]}"; do
    systemctl --user disable --now "$s.service" 2>/dev/null || true
    rm -f "$UNIT_DIR/$s.service"
  done
  systemctl --user daemon-reload
  echo "Servicii oprite si sterse. Datele (traffic_monitor.db, alerts.log) au ramas."
  exit 0
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-$(command -v python3)}"

"$PYTHON" -c "import psutil, flask" 2>/dev/null || {
  echo "Pythonul $PYTHON nu are psutil si flask. Instaleaza-le sau ruleaza cu PYTHON=/calea/catre/python ./install_service.sh" >&2
  exit 1
}

# un watcher pornit "de mana" intr-un terminal ar dubla colectarea; serviciul propriu se reinstaleaza fara probleme
if ! systemctl --user is-active --quiet trafficmonitor-watcher.service && pgrep -f "watcher_v6.py" >/dev/null; then
  echo "Un watcher ruleaza deja intr-un terminal. Opreste-l (Ctrl+C) si ruleaza din nou." >&2
  exit 1
fi

mkdir -p "$UNIT_DIR"

cat > "$UNIT_DIR/trafficmonitor-watcher.service" <<UNIT
[Unit]
Description=TrafficMonitor - colectare si alertare

[Service]
WorkingDirectory=$APP_DIR
ExecStart=$PYTHON -u $APP_DIR/watcher_v6.py
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%U/bus
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
UNIT

cat > "$UNIT_DIR/trafficmonitor-dashboard.service" <<UNIT
[Unit]
Description=TrafficMonitor - interfata web (http://localhost:5000)

[Service]
WorkingDirectory=$APP_DIR
ExecStart=$PYTHON -u $APP_DIR/dashboard.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
UNIT

cat > "$UNIT_DIR/trafficmonitor-phishing.service" <<UNIT
[Unit]
Description=TrafficMonitor - avertizare phishing (domenii care imita branduri)

[Service]
WorkingDirectory=$APP_DIR
ExecStart=$PYTHON -u $APP_DIR/phishing_watcher.py
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%U/bus
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
UNIT

systemctl --user daemon-reload
for s in "${SERVICES[@]}"; do
  systemctl --user enable "$s.service"
  systemctl --user restart "$s.service"
done

echo
echo "Instalat. Pornesc automat la fiecare login."
echo "  Stare:   systemctl --user status trafficmonitor-watcher trafficmonitor-dashboard trafficmonitor-phishing"
echo "  Loguri:  journalctl --user -u trafficmonitor-watcher -f   (sau ...-phishing)"
echo "  Dashboard: http://localhost:5000"
