#!/usr/bin/env python3
"""
Etapa 2: Analiza baseline + detectie anomalii.

Citește din traffic_monitor.db (populat de collector.py sau de
generate_test_data.py) și pentru fiecare proces calculeaza:

1. Baseline de volum: cate conexiuni face procesul, în medie, pe ora
2. Set de destinatii "obișnuite" (IP-uri vazute recurent)
3. Regularitatea intervalelor dintre conexiuni (semnal de beaconing)

Apoi scoreaza fiecare proces 0-100 (risc de anomalie) și explica DE CE.

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
    Verifica daca un IP e privat/local (retea de-acasa, router, etc.)
    Trafic catre asemenea adrese NU poate fi exfiltrare externa,
    deci nu ar trebui sa contribuie la scorul de risc.

    Exemple de IP-uri private: 192.168.x.x, 10.x.x.x, 172.16-31.x.x, 127.x.x.x (localhost)
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False  # daca nu putem parsa IP-ul, tratam ca extern (mai sigur)

# Praguri - le poti ajusta pe masura ce vezi cum se comporta pe date reale
MIN_SAMPLES_FOR_BASELINE = 3       # sub atat, nu avem destule date ca sa tragem concluzii
BEACONING_STDDEV_THRESHOLD = 5.0   # (pastrat ca prag absolut minim, vezi mai jos de ce mai e nevoie de el)
BEACONING_CV_THRESHOLD = 0.15      # coeficient de variatie (stdev/medie) - sub 15% variatie = regulat, suspect
                                     # NOU: prag RELATIV, nu doar absolut. Un beacon la 3s cu stdev 2s
                                     # variaza enorm relativ (CV=0.67), dar un beacon la 60s cu stdev 5s
                                     # e foarte regulat relativ (CV=0.08) - pragul absolut singur nu
                                     # distinge cele doua cazuri corect, cel relativ da.
CONCENTRATION_WEIGHT = 30          # puncte de risc pt. trafic concentrat pe putine destinatii fixe
BEACONING_WEIGHT = 50              # puncte de risc pt. pattern de beaconing
VOLUME_ANOMALY_WEIGHT = 20         # puncte de risc pt. volum neobișnuit de mare

MAX_BURST_GAP_SECONDS = 600        # gol de peste 10 min = sesiune de activitate SEPARATa, nu continuare
                                     # DESCOPERIT EMPIRIC: media/deviatia standard NU sunt robuste la
                                     # valori extreme - un singur gol mare (ex. o pauza de zile între
                                     # doua sesiuni de trafic ale aceluiași proces) poate distruge complet
                                     # calculul de regularitate, mascand un pattern altfel aproape perfect
                                     # (caz real: 44 de sesiuni perfect regulate la ~62s, CV=0.2% izolat,
                                     # dar CV=781% daca intra în calcul și un gol de 35 de zile din urma)

# Praguri pentru regula de CONCENTRARE (înlocuiește vechea regula de "unicitate")
MAX_DISTINCT_IPS_FOR_CONCENTRATION = 3   # daca procesul vorbește cu MAI MULTE IP-uri distincte decat atat, îl consideram "divers" (normal), nu concentrat
CONCENTRATION_RATIO_THRESHOLD = 0.7      # daca un singur IP acopera peste 70% din conexiunile externe, e concentrare suspecta

# Praguri pentru reputatia externa (AbuseIPDB)

# Prag pentru deduplicare de sesiuni (vezi deduplicate_into_sessions mai jos)
SESSION_GAP_SECONDS = 3.0          # conexiuni catre aceeași destinatie la interval sub atat = aceeași "sesiune", nu evenimente separate


def deduplicate_into_sessions(connections: list) -> list:
    """
    Colectorul face polling periodic (ex. la 1s), deci o conexiune care
    traiește 1-2 secunde poate fi "vazuta" de 2+ ori consecutiv - o data
    la fiecare interogare cat timp conexiunea era înca activa.

    Fara deduplicare, asta strica regularitatea beaconing-ului: în loc de
    un eveniment "conexiune facuta" la fiecare 60s, avem PERECHI de
    evenimente (0s, 60s, 61s, 120s, 121s...) - intervalele devin neregulate,
    deși comportamentul de fond E regulat.

    Grupam conexiuni consecutive catre ACEEAȘI destinatie (ip+port), aflate
    la mai putin de SESSION_GAP_SECONDS una de alta, într-o singura "sesiune"
    - pastram doar primul timestamp din fiecare grup.
    """
    if not connections:
        return []

    # sortam dupa destinatie, apoi timp, ca sa grupam corect sesiunile
    sorted_conns = sorted(connections, key=lambda c: (c["remote_ip"], c["remote_port"], c["timestamp"]))

    sessions = []
    current_key = None
    last_timestamp = None

    for c in sorted_conns:
        key = (c["remote_ip"], c["remote_port"])
        if key != current_key or (c["timestamp"] - last_timestamp).total_seconds() > SESSION_GAP_SECONDS:
            # început de sesiune noua (destinatie diferita SAU gap mare de timp)
            sessions.append(c)
            current_key = key
        last_timestamp = c["timestamp"]

    # reordonam cronologic (am sortat dupa destinatie mai sus, pentru grupare)
    sessions.sort(key=lambda c: c["timestamp"])
    return sessions


def split_into_bursts(timestamps: list, max_gap_seconds: float = MAX_BURST_GAP_SECONDS) -> list:
    """
    Împarte o lista ordonata de timestamp-uri în "burst-uri" separate,
    acolo unde golul dintre doua timestamp-uri consecutive depașește
    max_gap_seconds. Complementul lui deduplicate_into_sessions: acolo
    uneam evenimente prea apropiate (polling dublu), aici separam
    evenimente prea departate (sesiuni de activitate distincte).

    De ce conteaza: analiza de regularitate (beaconing) calculeaza media
    și deviatia standard a intervalelor - ambele extrem de sensibile la
    o singura valoare extrema. Fara separare pe burst-uri, un gol mare
    între doua sesiuni de activitate distincte (ex. procesul a tacut
    zile întregi, apoi a reînceput) ar strica regularitatea calculata
    pe tot istoricul, deși fiecare sesiune în parte poate fi perfect
    regulata.
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
    """Grupeaza toate conexiunile pe proces."""
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
    Analizeaza un singur proces și întoarce un raport cu scor de risc.
    all_destinations = dict {ip: set(procese care s-au conectat la acel ip)}
    folosit ca sa știm daca o destinatie e "unica" pentru acest proces.
    """
    n = len(connections)
    report = {
        "process_name": process_name,
        "total_connections": n,
        "risk_score": 0,
        "reasons": [],
    }

    if n < MIN_SAMPLES_FOR_BASELINE:
        report["reasons"].append(f"Prea putine date ({n} conexiuni) - baseline nesigur")
        return report

    # NOU: deduplicam conexiunile în sesiuni, ÎNAINTE de orice alt calcul.
    # Fara asta, polling-ul frecvent (1s) "vede" aceeași conexiune de mai
    # multe ori și strica regularitatea intervalelor.
    connections = deduplicate_into_sessions(connections)
    n_before_dedup = n
    n = len(connections)
    if n < n_before_dedup:
        report["reasons"].append(
            f"Deduplicare: {n_before_dedup} înregistrari brute -> {n} sesiuni reale de conexiune"
        )

    if n < MIN_SAMPLES_FOR_BASELINE:
        report["reasons"].append(f"Prea putine sesiuni reale ({n}) dupa deduplicare - baseline nesigur")
        return report

    # NOU: separam conexiunile catre IP-uri PRIVATE (retea locala, router) de cele
    # catre IP-uri PUBLICE (internet). Doar traficul extern conteaza pentru riscul
    # de exfiltrare - trafic catre 192.168.x.x nu poate fi C2 extern.
    external_connections = [c for c in connections if not is_private_ip(c["remote_ip"])]
    n_external = len(external_connections)
    n_private = n - n_external

    if n_private > 0:
        report["reasons"].append(
            f"({n_private} conexiuni catre reteaua locala, excluse din calculul de risc)"
        )

    if n_external < MIN_SAMPLES_FOR_BASELINE:
        report["reasons"].append(
            f"Prea putine conexiuni externe ({n_external}) - risc extern nesigur de evaluat"
        )
        return report

    # --- 1. CONCENTRARE vs DIVERSITATE (înlocuiește vechea regula de "unicitate") ---
    # Ideea: nu conteaza daca un IP e "unic în tot sistemul" (aproape orice site
    # vizitat de firefox e "unic" - e normal, semn de diversitate/browsing uman).
    # Conteaza daca ACEST proces vorbește cu FOARTE PUtINE destinatii fixe,
    # concentrat - asta seamana cu un canal de C2, nu cu navigare normala.
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
        # semnal suplimentar: daca acel IP dominant nu e vazut la niciun alt proces,
        # crește suspiciunea (nu e o infrastructura comuna/partajata, gen CDN)
        seen_by_others = len(all_destinations.get(top_ip, set())) > 1
        report["risk_score"] += CONCENTRATION_WEIGHT
        report["reasons"].append(
            f"Trafic CONCENTRAT: {concentration_ratio*100:.0f}% din conexiunile externe "
            f"merg catre un singur IP ({top_ip}), din doar {distinct_ips} destinatii distincte total"
            + ("" if seen_by_others else " - IP vazut DOAR la acest proces, la niciun altul")
        )

    else:
        report["reasons"].append(
            f"Trafic divers: {distinct_ips} destinatii externe distincte - comportament tipic de navigare/utilizare normala"
        )

    # --- 2. Regularitatea intervalelor, CALCULATa DOAR PE TRAFIC EXTERN ---
    # (beaconing catre routerul local e normal; beaconing catre internet, nu)
    #
    # NOU: împartim mai întai pe burst-uri (vezi split_into_bursts) și analizam
    # doar cel mai mare - altfel un gol mare între doua sesiuni de activitate
    # distincte (zile/saptamani) distruge complet media/deviatia standard,
    # mascand un pattern de beaconing altfel foarte clar.
    all_timestamps = sorted(c["timestamp"] for c in external_connections)
    bursts = split_into_bursts(all_timestamps)
    timestamps = max(bursts, key=len) if bursts else []

    if len(bursts) > 1:
        report["reasons"].append(
            f"Activitate împartita în {len(bursts)} sesiuni separate (gol > "
            f"{MAX_BURST_GAP_SECONDS // 60:.0f} min); regularitatea se analizeaza "
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

            # NOU: folosim coeficientul de variatie (stdev/medie), nu doar
            # deviatia absoluta. Motiv: un stdev de 5s înseamna regularitate
            # STRaNSa la un interval de 60s (variatie 8%), dar înseamna
            # ZGOMOT COMPLET la un interval de 3s (variatie 166%) - pragul
            # absolut singur confunda cele doua situatii (fals pozitiv gasit
            # empiric la VS Code: interval~3s, stdev~4.93s, sub pragul de 5s,
            # dar CV=1.64, deloc regulat de fapt).
            cv = stdev_interval / mean_interval if mean_interval > 0 else float("inf")

            is_regular = (
                cv < BEACONING_CV_THRESHOLD           # regularitate RELATIVa (procentuala)
                and stdev_interval < BEACONING_STDDEV_THRESHOLD  # + prag absolut, pt. siguranta suplimentara
                and mean_interval > 1
            )

            if is_regular:
                report["risk_score"] += BEACONING_WEIGHT
                report["reasons"].append(
                    f"Pattern de BEACONING extern: conexiuni la interval regulat de "
                    f"~{mean_interval:.0f}s (deviatie std: {stdev_interval:.2f}s, "
                    f"variatie relativa: {cv*100:.0f}%) - "
                    f"semn tipic de comunicare automatizata cu un server C2"
                )

    # --- 3. Volum neobișnuit (comparat cu ce vad celelalte procese) ---
    # Simplificat pentru MVP: procesele cu MULT mai multe conexiuni decat media generala
    report["_raw_intervals_mean"] = mean_interval if 'mean_interval' in dir() else None

    return report


def main():
    conn = sqlite3.connect(DB_PATH)
    by_process = load_connections(conn)

    if not by_process:
        print("[!] Nu exista date în baza de date. Ruleaza mai întai collector.py sau generate_test_data.py")
        return

    # construim harta globala: ce IP-uri a atins fiecare proces
    all_destinations = defaultdict(set)
    for process_name, connections in by_process.items():
        for c in connections:
            all_destinations[c["remote_ip"]].add(process_name)

    print("=" * 70)
    print("RAPORT BASELINE + DETECtIE ANOMALII")
    print("=" * 70)

    reports = []
    for process_name, connections in by_process.items():
        report = analyze_process(process_name, connections, all_destinations)
        reports.append(report)

    # sortam dupa risc descrescator, ca sa vezi mai întai ce e mai suspect
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
