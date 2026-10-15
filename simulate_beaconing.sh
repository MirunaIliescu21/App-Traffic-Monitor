#!/bin/bash
#
# Simulează un canal de beaconing C2: cereri HTTP repetate, la interval fix,
# către o singură destinație. Folosit pentru a testa detecția de
# CONCENTRARE + REGULARITATE din baseline_v5.py.
#
# NOU: durată configurabilă, se oprește singur - nu mai trebuie Ctrl+C manual.
#
# Rulare: ./simulate_beaconing.sh
# Oprire: automată, după DURATION_MINUTES (sau Ctrl+C oricând, manual)
#
# IMPORTANT: rulează acest script ÎN PARALEL cu watcher_v6.py, într-un
# terminal separat, ca traficul generat aici să fie și el înregistrat.

TARGET_IP="93.184.216.34"   # IP public de test (poți schimba cu altul real)
TARGET_PORT="80"
INTERVAL_SECONDS=60
TIMEOUT_SECONDS=2
DURATION_MINUTES=45          # se oprește singur după atâtea minute

end_time=$(( $(date +%s) + DURATION_MINUTES * 60 ))

echo "[*] Simulez beaconing catre http://${TARGET_IP}:${TARGET_PORT}/"
echo "[*] Interval: ${INTERVAL_SECONDS}s, timeout per cerere: ${TIMEOUT_SECONDS}s"
echo "[*] Durată: ${DURATION_MINUTES} minute (se oprește automat) - sau Ctrl+C oricând"
echo "[*] Estimat: ~$(( DURATION_MINUTES * 60 / INTERVAL_SECONDS )) cereri"
echo ""

count=0
while [ "$(date +%s)" -lt "$end_time" ]; do
    count=$((count + 1))
    timestamp=$(date '+%H:%M:%S')
    curl -s -m "${TIMEOUT_SECONDS}" "http://${TARGET_IP}:${TARGET_PORT}/" > /dev/null 2>&1
    echo "[${timestamp}] cerere #${count} trimisă"
    sleep "${INTERVAL_SECONDS}"
done

echo ""
echo "[*] Gata - ${count} cereri trimise în total, în ${DURATION_MINUTES} minute."
