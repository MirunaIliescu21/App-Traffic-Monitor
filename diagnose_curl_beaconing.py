#!/usr/bin/env python3
"""
Diagnostic: de ce beaconing-ul lui curl nu s-a mai declanșat, deși traficul
arată tot concentrat 100% pe un singur IP?

Recalculează exact ce face analyze_process() intern, dar afișează și
intervalele brute, ca să vedem dacă variația vine dintr-un gol izolat
(ca la testul din 17 august) sau dintr-un jitter distribuit uniform.

Rulare: python3 diagnose_curl_beaconing.py
"""

import sqlite3
import statistics
from datetime import datetime

from baseline_v5 import deduplicate_into_sessions, is_private_ip, BEACONING_CV_THRESHOLD

DB_PATH = "traffic_monitor.db"


def split_into_bursts(timestamps: list, max_gap_seconds: float = 600) -> list:
    """
    Împarte o listă de timestamp-uri în "burst-uri" separate, acolo unde
    golul dintre două consecutive depășește max_gap_seconds (implicit 10
    minute - mult peste jitter-ul așteptat de rețea, mult sub o pauză
    reală între sesiuni de test separate).

    Descoperire empirică: fără asta, un singur gol de 35 de zile (între
    testul din 17 august și cel de azi) distruge complet media/deviația
    standard calculate pe tot setul - un exemplu clasic de ne-robustețe
    a acestor statistici la valori extreme.
    """
    if not timestamps:
        return []
    bursts = [[timestamps[0]]]
    for t in timestamps[1:]:
        if (t - bursts[-1][-1]).total_seconds() > max_gap_seconds:
            bursts.append([])
        bursts[-1].append(t)
    return bursts


def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute("""
        SELECT timestamp, remote_ip, remote_port
        FROM connections
        WHERE process_name = 'curl'
        ORDER BY timestamp
    """)
    rows = cur.fetchall()
    conn.close()

    connections = [
        {"timestamp": datetime.fromisoformat(ts), "remote_ip": ip, "remote_port": port}
        for ts, ip, port in rows
    ]
    external = [c for c in connections if not is_private_ip(c["remote_ip"])]
    sessions = deduplicate_into_sessions(external)

    print(f"[*] {len(rows)} înregistrări brute -> {len(external)} externe -> {len(sessions)} sesiuni\n")

    timestamps = sorted(c["timestamp"] for c in sessions)

    bursts = split_into_bursts(timestamps, max_gap_seconds=600)
    print(f"[*] Date împărțite în {len(bursts)} burst-uri (gol > 10 min = sesiune de test separată):\n")
    for i, burst in enumerate(bursts):
        duration_min = (burst[-1] - burst[0]).total_seconds() / 60 if len(burst) > 1 else 0
        print(f"  Burst #{i+1}: {len(burst)} sesiuni, de la {burst[0]} la {burst[-1]} (~{duration_min:.0f} min)")

    largest_burst = max(bursts, key=len)
    print(f"\n[*] Analizăm burst-ul cel mai mare ({len(largest_burst)} sesiuni) izolat:\n")

    intervals = [(largest_burst[i+1] - largest_burst[i]).total_seconds() for i in range(len(largest_burst) - 1)]

    mean_interval = statistics.mean(intervals)
    stdev_interval = statistics.stdev(intervals)
    cv = stdev_interval / mean_interval if mean_interval > 0 else float("inf")

    print(f"[*] {len(intervals)} intervale în acest burst")
    print(f"[*] Medie: {mean_interval:.2f}s")
    print(f"[*] Deviație standard: {stdev_interval:.2f}s")
    print(f"[*] Coeficient de variație (CV): {cv:.3f} ({cv*100:.1f}%)")
    print(f"[*] Prag beaconing: CV < {BEACONING_CV_THRESHOLD} ({BEACONING_CV_THRESHOLD*100:.0f}%)")
    print(f"[*] Ar declanșa beaconing, izolat corect? {'DA' if cv < BEACONING_CV_THRESHOLD else 'NU'}")


if __name__ == "__main__":
    main()
