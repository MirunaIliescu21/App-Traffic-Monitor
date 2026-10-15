#!/bin/bash
#
# Simuleaza un canal de beaconing C2: cereri HTTP repetate, la interval fix,
# catre o singura destinatie. Folosit pentru a testa detectia de
# CONCENTRARE + REGULARITATE din baseline_v5.py.
#
# NOU: durata configurabila, se opreste singur - nu mai trebuie Ctrl+C manual.
#
# Rulare: ./simulate_beaconing.sh
# Oprire: automata, dupa DURATION_MINUTES (sau Ctrl+C oricand, manual)
#
# IMPORTANT: ruleaza acest script IN PARALEL cu watcher_v6.py, intr-un
# terminal separat, ca traficul generat aici sa fie si el inregistrat.

TARGET_IP="93.184.216.34"   # IP public de test (poti schimba cu altul real)
TARGET_PORT="80"
INTERVAL_SECONDS=60
TIMEOUT_SECONDS=2
DURATION_MINUTES=45          # se opreste singur dupa atatea minute

end_time=$(( $(date +%s) + DURATION_MINUTES * 60 ))

echo "[*] Simulez beaconing catre http://${TARGET_IP}:${TARGET_PORT}/"
echo "[*] Interval: ${INTERVAL_SECONDS}s, timeout per cerere: ${TIMEOUT_SECONDS}s"
echo "[*] Durata: ${DURATION_MINUTES} minute (se opreste automat) - sau Ctrl+C oricand"
echo "[*] Estimat: ~$(( DURATION_MINUTES * 60 / INTERVAL_SECONDS )) cereri"
echo ""

count=0
while [ "$(date +%s)" -lt "$end_time" ]; do
    count=$((count + 1))
    timestamp=$(date '+%H:%M:%S')
    curl -s -m "${TIMEOUT_SECONDS}" "http://${TARGET_IP}:${TARGET_PORT}/" > /dev/null 2>&1
    echo "[${timestamp}] cerere #${count} trimisa"
    sleep "${INTERVAL_SECONDS}"
done

echo ""
echo "[*] Gata - ${count} cereri trimise in total, in ${DURATION_MINUTES} minute."
