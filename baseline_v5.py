#!/usr/bin/env python3
"""
Etapa 2: Analiză baseline + detecție anomalii.

Citește din traffic_monitor.db (populat de collector.py sau de
generate_test_data.py) și pentru fiecare proces calculează:

1. Baseline de volum: cate conexiuni face procesul, în medie, pe oră
2. Set de destinații "obișnuite" (IP-uri văzute recurent)
3. Regularitatea intervalelor dintre conexiuni (semnal de beaconing)

Apoi scorează fiecare proces 0-100 (risc de anomalie) și explică DE CE.

Rulare: python3 baseline.py
"""

import sqlite3
import statistics
import ipaddress
from datetime import datetime
from collections import defaultdict

DB_PATH = "traffic_monitor.db"


def is_private_ip(ip: str) -> bool:
    """
    Verifică dacă un IP e privat/local (rețea de-acasă, router, etc.)
    Trafic către asemenea adrese NU poate fi exfiltrare externă,
    deci nu ar trebui să contribuie la scorul de risc.

    Exemple de IP-uri private: 192.168.x.x, 10.x.x.x, 172.16-31.x.x, 127.x.x.x (localhost)
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False  # dacă nu putem parsa IP-ul, tratăm ca extern (mai sigur)

# Praguri - le poți ajusta pe măsură ce vezi cum se comportă pe date reale
MIN_SAMPLES_FOR_BASELINE = 3       # sub atat, nu avem destule date ca să tragem concluzii
BEACONING_STDDEV_THRESHOLD = 5.0   # (păstrat ca prag absolut minim, vezi mai jos de ce mai e nevoie de el)
BEACONING_CV_THRESHOLD = 0.15      # coeficient de variație (stdev/medie) - sub 15% variație = regulat, suspect
                                     # NOU: prag RELATIV, nu doar absolut. Un beacon la 3s cu stdev 2s
                                     # variază enorm relativ (CV=0.67), dar un beacon la 60s cu stdev 5s
                                     # e foarte regulat relativ (CV=0.08) - pragul absolut singur nu
                                     # distinge cele două cazuri corect, cel relativ da.
CONCENTRATION_WEIGHT = 30          # puncte de risc pt. trafic concentrat pe puține destinații fixe
BEACONING_WEIGHT = 50              # puncte de risc pt. pattern de beaconing
VOLUME_ANOMALY_WEIGHT = 20         # puncte de risc pt. volum neobișnuit de mare

MAX_BURST_GAP_SECONDS = 600        # gol de peste 10 min = sesiune de activitate SEPARATĂ, nu continuare
                                     # DESCOPERIT EMPIRIC: media/deviația standard NU sunt robuste la
                                     # valori extreme - un singur gol mare (ex. o pauză de zile între
                                     # două sesiuni de trafic ale aceluiași proces) poate distruge complet
                                     # calculul de regularitate, mascand un pattern altfel aproape perfect
                                     # (caz real: 44 de sesiuni perfect regulate la ~62s, CV=0.2% izolat,
                                     # dar CV=781% dacă intră în calcul și un gol de 35 de zile din urmă)

# Praguri pentru regula de CONCENTRARE (înlocuiește vechea regulă de "unicitate")
MAX_DISTINCT_IPS_FOR_CONCENTRATION = 3   # dacă procesul vorbește cu MAI MULTE IP-uri distincte decat atat, îl considerăm "divers" (normal), nu concentrat
CONCENTRATION_RATIO_THRESHOLD = 0.7      # dacă un singur IP acoperă peste 70% din conexiunile externe, e concentrare suspectă

# Praguri pentru reputația externă (AbuseIPDB)

# Prag pentru deduplicare de sesiuni (vezi deduplicate_into_sessions mai jos)
SESSION_GAP_SECONDS = 3.0          # conexiuni către aceeași destinație la interval sub atat = aceeași "sesiune", nu evenimente separate


def deduplicate_into_sessions(connections: list) -> list:
    """
    Colectorul face polling periodic (ex. la 1s), deci o conexiune care
    trăiește 1-2 secunde poate fi "văzută" de 2+ ori consecutiv - o dată
    la fiecare interogare cat timp conexiunea era încă activă.

    Fără deduplicare, asta strică regularitatea beaconing-ului: în loc de
    un eveniment "conexiune făcută" la fiecare 60s, avem PERECHI de
    evenimente (0s, 60s, 61s, 120s, 121s...) - intervalele devin neregulate,
    deși comportamentul de fond E regulat.

    Grupăm conexiuni consecutive către ACEEAȘI destinație (ip+port), aflate
    la mai puțin de SESSION_GAP_SECONDS una de alta, într-o singură "sesiune"
    - păstrăm doar primul timestamp din fiecare grup.
    """
    if not connections:
        return []

    # sortăm după destinație, apoi timp, ca să grupăm corect sesiunile
    sorted_conns = sorted(connections, key=lambda c: (c["remote_ip"], c["remote_port"], c["timestamp"]))

    sessions = []
    current_key = None
    last_timestamp = None

    for c in sorted_conns:
        key = (c["remote_ip"], c["remote_port"])
        if key != current_key or (c["timestamp"] - last_timestamp).total_seconds() > SESSION_GAP_SECONDS:
            # început de sesiune nouă (destinație diferită SAU gap mare de timp)
            sessions.append(c)
            current_key = key
        last_timestamp = c["timestamp"]

    # reordonăm cronologic (am sortat după destinație mai sus, pentru grupare)
    sessions.sort(key=lambda c: c["timestamp"])
    return sessions


def split_into_bursts(timestamps: list, max_gap_seconds: float = MAX_BURST_GAP_SECONDS) -> list:
    """
    Împarte o listă ordonată de timestamp-uri în "burst-uri" separate,
    acolo unde golul dintre două timestamp-uri consecutive depășește
    max_gap_seconds. Complementul lui deduplicate_into_sessions: acolo
    uneam evenimente prea apropiate (polling dublu), aici separăm
    evenimente prea depărtate (sesiuni de activitate distincte).

    De ce contează: analiza de regularitate (beaconing) calculează media
    și deviația standard a intervalelor - ambele extrem de sensibile la
    o singură valoare extremă. Fără separare pe burst-uri, un gol mare
    între două sesiuni de activitate distincte (ex. procesul a tăcut
    zile întregi, apoi a reînceput) ar strica regularitatea calculată
    pe tot istoricul, deși fiecare sesiune în parte poate fi perfect
    regulată.
    """
    if not timestamps:
        return []
    bursts = [[timestamps[0]]]
    for t in timestamps[1:]:
        if (t - bursts[-1][-1]).total_seconds() > max_gap_seconds:
            bursts.append([])
        bursts[-1].append(t)
    return bursts


def load_connections(conn: sqlite3.Connection) -> dict:
    """Grupează toate conexiunile pe proces."""
    cur = conn.execute("""
        SELECT process_name, timestamp, remote_ip, remote_port
        FROM connections
        ORDER BY process_name, timestamp
    """)
    by_process = defaultdict(list)
    for process_name, timestamp, remote_ip, remote_port in cur.fetchall():
        by_process[process_name].append({
            "timestamp": datetime.fromisoformat(timestamp),
            "remote_ip": remote_ip,
            "remote_port": remote_port,
        })
    return by_process


def analyze_process(process_name: str, connections: list, all_destinations: dict) -> dict:
    """
    Analizează un singur proces și întoarce un raport cu scor de risc.
    all_destinations = dict {ip: set(procese care s-au conectat la acel ip)}
    folosit ca să știm dacă o destinație e "unică" pentru acest proces.
    """
    n = len(connections)
    report = {
        "process_name": process_name,
        "total_connections": n,
        "risk_score": 0,
        "reasons": [],
    }

    if n < MIN_SAMPLES_FOR_BASELINE:
        report["reasons"].append(f"Prea puține date ({n} conexiuni) - baseline nesigur")
        return report

    # NOU: deduplicăm conexiunile în sesiuni, ÎNAINTE de orice alt calcul.
    # Fără asta, polling-ul frecvent (1s) "vede" aceeași conexiune de mai
    # multe ori și strică regularitatea intervalelor.
    connections = deduplicate_into_sessions(connections)
    n_before_dedup = n
    n = len(connections)
    if n < n_before_dedup:
        report["reasons"].append(
            f"Deduplicare: {n_before_dedup} înregistrări brute -> {n} sesiuni reale de conexiune"
        )

    if n < MIN_SAMPLES_FOR_BASELINE:
        report["reasons"].append(f"Prea puține sesiuni reale ({n}) după deduplicare - baseline nesigur")
        return report

    # NOU: separăm conexiunile către IP-uri PRIVATE (rețea locală, router) de cele
    # către IP-uri PUBLICE (internet). Doar traficul extern contează pentru riscul
    # de exfiltrare - trafic către 192.168.x.x nu poate fi C2 extern.
    external_connections = [c for c in connections if not is_private_ip(c["remote_ip"])]
    n_external = len(external_connections)
    n_private = n - n_external

    if n_private > 0:
        report["reasons"].append(
            f"({n_private} conexiuni către rețeaua locală, excluse din calculul de risc)"
        )

    if n_external < MIN_SAMPLES_FOR_BASELINE:
        report["reasons"].append(
            f"Prea puține conexiuni externe ({n_external}) - risc extern nesigur de evaluat"
        )
        return report

    # --- 1. CONCENTRARE vs DIVERSITATE (înlocuiește vechea regulă de "unicitate") ---
    # Ideea: nu contează dacă un IP e "unic în tot sistemul" (aproape orice site
    # vizitat de firefox e "unic" - e normal, semn de diversitate/browsing uman).
    # Contează dacă ACEST proces vorbește cu FOARTE PUȚINE destinații fixe,
    # concentrat - asta seamănă cu un canal de C2, nu cu navigare normală.
    ip_counts = defaultdict(int)
    for c in external_connections:
        ip_counts[c["remote_ip"]] += 1

    distinct_ips = len(ip_counts)
    top_ip, top_ip_count = max(ip_counts.items(), key=lambda kv: kv[1])
    concentration_ratio = top_ip_count / n_external

    is_concentrated = (
        distinct_ips <= MAX_DISTINCT_IPS_FOR_CONCENTRATION
        and concentration_ratio >= CONCENTRATION_RATIO_THRESHOLD
    )

    if is_concentrated:
        # semnal suplimentar: dacă acel IP dominant nu e văzut la niciun alt proces,
        # crește suspiciunea (nu e o infrastructură comună/partajată, gen CDN)
        seen_by_others = len(all_destinations.get(top_ip, set())) > 1
        report["risk_score"] += CONCENTRATION_WEIGHT
        report["reasons"].append(
            f"Trafic CONCENTRAT: {concentration_ratio*100:.0f}% din conexiunile externe "
            f"merg către un singur IP ({top_ip}), din doar {distinct_ips} destinații distincte total"
            + ("" if seen_by_others else " - IP văzut DOAR la acest proces, la niciun altul")
        )

    else:
        report["reasons"].append(
            f"Trafic divers: {distinct_ips} destinații externe distincte - comportament tipic de navigare/utilizare normală"
        )

    # --- 2. Regularitatea intervalelor, CALCULATĂ DOAR PE TRAFIC EXTERN ---
    # (beaconing către routerul local e normal; beaconing către internet, nu)
    #
    # NOU: împărțim mai întai pe burst-uri (vezi split_into_bursts) și analizăm
    # doar cel mai mare - altfel un gol mare între două sesiuni de activitate
    # distincte (zile/săptămani) distruge complet media/deviația standard,
    # mascand un pattern de beaconing altfel foarte clar.
    all_timestamps = sorted(c["timestamp"] for c in external_connections)
    bursts = split_into_bursts(all_timestamps)
    timestamps = max(bursts, key=len) if bursts else []

    if len(bursts) > 1:
        report["reasons"].append(
            f"Activitate împărțită în {len(bursts)} sesiuni separate (gol > "
            f"{MAX_BURST_GAP_SECONDS // 60:.0f} min); regularitatea se analizează "
            f"doar pe cea mai mare ({len(timestamps)} evenimente)"
        )

    if len(timestamps) >= MIN_SAMPLES_FOR_BASELINE:
        intervals = [
            (timestamps[i+1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]
        if intervals:
            mean_interval = statistics.mean(intervals)
            stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0

            # NOU: folosim coeficientul de variație (stdev/medie), nu doar
            # deviația absolută. Motiv: un stdev de 5s înseamnă regularitate
            # STRaNSĂ la un interval de 60s (variație 8%), dar înseamnă
            # ZGOMOT COMPLET la un interval de 3s (variație 166%) - pragul
            # absolut singur confunda cele două situații (fals pozitiv găsit
            # empiric la VS Code: interval~3s, stdev~4.93s, sub pragul de 5s,
            # dar CV=1.64, deloc regulat de fapt).
            cv = stdev_interval / mean_interval if mean_interval > 0 else float("inf")

            is_regular = (
                cv < BEACONING_CV_THRESHOLD           # regularitate RELATIVĂ (procentuală)
                and stdev_interval < BEACONING_STDDEV_THRESHOLD  # + prag absolut, pt. siguranță suplimentară
                and mean_interval > 1
            )

            if is_regular:
                report["risk_score"] += BEACONING_WEIGHT
                report["reasons"].append(
                    f"Pattern de BEACONING extern: conexiuni la interval regulat de "
                    f"~{mean_interval:.0f}s (deviație std: {stdev_interval:.2f}s, "
                    f"variație relativă: {cv*100:.0f}%) - "
                    f"semn tipic de comunicare automatizată cu un server C2"
                )

    # --- 3. Volum neobișnuit (comparat cu ce văd celelalte procese) ---
    # Simplificat pentru MVP: procesele cu MULT mai multe conexiuni decat media generală
    report["_raw_intervals_mean"] = mean_interval if 'mean_interval' in dir() else None

    return report


def main():
    conn = sqlite3.connect(DB_PATH)
    by_process = load_connections(conn)

    if not by_process:
        print("[!] Nu există date în baza de date. Rulează mai întai collector.py sau generate_test_data.py")
        return

    # construim harta globală: ce IP-uri a atins fiecare proces
    all_destinations = defaultdict(set)
    for process_name, connections in by_process.items():
        for c in connections:
            all_destinations[c["remote_ip"]].add(process_name)

    print("=" * 70)
    print("RAPORT BASELINE + DETECȚIE ANOMALII")
    print("=" * 70)

    reports = []
    for process_name, connections in by_process.items():
        report = analyze_process(process_name, connections, all_destinations)
        reports.append(report)

    # sortăm după risc descrescător, ca să vezi mai întai ce e mai suspect
    reports.sort(key=lambda r: r["risk_score"], reverse=True)

    for r in reports:
        risk_label = "🔴 RISC RIDICAT" if r["risk_score"] >= 50 else (
            "🟡 RISC MODERAT" if r["risk_score"] > 0 else "🟢 NORMAL"
        )
        print(f"\nProces: {r['process_name']}")
        print(f"  Conexiuni totale: {r['total_connections']}")
        print(f"  Scor risc: {r['risk_score']}/100 -> {risk_label}")
        if r["reasons"]:
            print("  Motive:")
            for reason in r["reasons"]:
                print(f"    - {reason}")

    print("\n" + "=" * 70)
    conn.close()


if __name__ == "__main__":
    main()
