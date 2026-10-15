# TrafficMonitor

Instrument local de monitorizare a traficului de retea si detectie de anomalii.

## Premisa

Accesul neautorizat genereaza intotdeauna trafic de retea intre sistemul
compromis si un sistem controlat de atacator, chiar si atunci cand solutiile
anti-malware nu detecteaza nimic. Monitorizand comportamentul de trafic al
fiecarui proces (cine vorbeste cu cine, cat de des, cat de regulat) - nu
continutul pachetelor - putem detecta o compromitere si dupa ce apararile
clasice au esuat, reducand timpul cat un atacator sta nedetectat in sistem.

Nu e un instrument de preventie. E un instrument de **detectie**.

## Arhitectura

| Fisier | Rol |
|---|---|
| `watcher_v6.py` | Ruleaza continuu: colecteaza conexiunile, alerteaza live, detecteaza conexiuni primite si comportament nou |
| `baseline_v5.py` | Analiza de risc: scor 0-100 per proces (concentrare + beaconing) |
| `dashboard.py` | Interfata web Flask: arata starea si primeste deciziile utilizatorului |
| `destination_status.py` | Starile destinatiilor (de verificat / normal / suspect) si istoricul deciziilor |
| `companies.py` | Traduce domenii si blocuri de IP-uri in nume de companii ("Google", "Microsoft") |
| `retention.py` | sterge datele vechi din baza |
| `collector.py` | Colectare bruta, fara analiza (nu se ruleaza in paralel cu watcher-ul) |
| `traffic_monitor.db` | SQLite, partajata de toate componentele (nu se versioneaza) |

## Cum ruleaza

Doua procese, in terminale separate, pe aceeasi `traffic_monitor.db`:

```bash
# Terminal 1 - colectare + alertare live
python3 watcher_v6.py

# Terminal 2 - dashboard web
python3 dashboard.py
```

Apoi deschide `http://localhost:5000`. Ruleaza un singur watcher odata.

Fara `sudo`, notificarile desktop functioneaza, dar `psutil` vede doar
procesele utilizatorului curent. Cu `sudo` se vad toate procesele, dar
notificarile esueaza (vezi "Limitari").

## Interfata web

- **De verificat** - destinatii noi pentru programe cunoscute, cu butoanele
  "E normal" si "Nu recunosc", in limbaj simplu ("chrome s-a conectat pentru
  prima data la Google")
- **Deciziile tale** si **Istoric decizii** - ce ai hotarat si cand, cu
  posibilitatea de a anula o decizie
- **Procese active (24h)**, **Jurnal alerte**, **Conexiuni primite
  (inbound)**, **Conexiuni noi observate**

Se reimprospateaza la 5 secunde. Deciziile se aplica in ~1 secunda, fara
repornirea watcher-ului.

## Cum functioneaza detectia

### 1. Scor de risc (`baseline_v5.py`)

- **Concentrare**: procesul vorbeste cu foarte putine IP-uri fixe (<= 3),
  concentrat pe unul singur (>= 70% din trafic) - semn de canal C2
- **Beaconing**: intervalele dintre conexiuni sunt suspect de regulate
  (coeficient de variatie < 15%) - semn de comunicare automatizata
- Activitatea e impartita in sesiuni (goluri > 10 min), iar regularitatea se
  analizeaza pe cea mai mare, ca un gol de zile sa nu ascunda un beacon real

### 2. Conexiuni primite (inbound)

Conexiunile catre porturile pe care masina asculta genereaza alerta imediata,
inclusiv de la IP-uri private (un atacator din aceeasi retea locala).

### 3. Comportament nou, cu decizia utilizatorului

Pentru fiecare conexiune iesita, destinatia primeste o **entitate**: compania,
daca o cunoastem (Google, Microsoft, Amazon...), altfel domeniul sau blocul de
IP-uri (/24 pentru IPv4, /48 pentru IPv6).

```
conexiune iesita -> entitate (companie / domeniu / bloc IP)
   -> proces cunoscut sI entitate noua pentru el -> notificare + "de verificat"
   -> cooldown per proces (5 min) limiteaza notificarile, nu si lista
```

Fiecare destinatie are una din trei stari:

| Stare | Ce face |
|---|---|
| **de verificat** | Apare in dashboard; nu mai alerteaza; nu devine "normala" niciodata automat |
| **normal** ("E normal") | Nu mai alerteaza |
| **suspect** ("Nu recunosc") | Orice conexiune noua catre ea alerteaza critic, ignorand cooldown-ul |

Deciziile se iau la nivel de companie: "E normal" la Google acopera toate
blocurile Google.

## Grupare pe companii (`companies.py`)

Doua liste scrise de mana: domenii (`1e100.net` → Google) si intervale de
IP-uri publice cunoscute (acopera adresele fara reverse DNS). Pe datele reale
de dezvoltare, 96 din 97 de destinatii distincte au fost identificate;
restul raman "retea neidentificata". Aplicatia nu ghiceste niciodata o
companie.

Ca sa adaugi o mapare: editezi `DOMAIN_COMPANIES`, `_PREFIXES_BY_COMPANY` si,
pentru o companie noua, `COMPANIES` (cu o descriere), apoi rulezi
`python3 -m pytest -q test_companies.py` si repornesti watcher-ul. Randurile
existente din "De verificat" se contopesc automat pe noua companie.

## Retentia datelor (`retention.py`)

Ruleaza automat la pornirea watcher-ului si la fiecare 6 ore.

- `connections`: 14 zile
- `inbound_events`: 90 de zile
- tot restul (destinatii cunoscute, decizii, istoric) se pastreaza

in `connections` se scrie doar o conexiune **noua** (care nu era deschisa la
citirea precedenta), nu fiecare conexiune la fiecare secunda (ritmul vechi:
~275 MB/zi).

stergerea opreste cresterea bazei, dar nu micsoreaza fisierul. Pentru asta,
cu watcher-ul si dashboard-ul oprite: `python3 retention.py --vacuum`.
`python3 retention.py --dry-run` arata ce s-ar sterge, fara sa stearga.

## Securitatea dashboard-ului

Dashboard-ul asculta doar pe `127.0.0.1` si nu are autentificare. Fiindca
poate scrie decizii, accepta cereri doar daca `Host` si `Origin` sunt cele
ale dashboard-ului si corpul e JSON (un site deschis in alt tab nu poate
apasa "E normal" in numele utilizatorului). Textele care vin din retea
(nume de host, procese) sunt escapate inainte sa ajunga in pagina.

## Teste

```bash
python3 -m pytest -q
```

108 teste: baseline, watcher, starile destinatiilor, dashboard, retentie,
companii (inclusiv pe o lista reala de destinatii, `tests_real_keys.txt`) si
scrierea conexiunilor noi. `conftest.py` izoleaza jurnalul de alerte, ca
testele sa nu scrie in `alerts.log`-ul real.

## Limitari cunoscute

- **Grupare pe companii vs. detectie:** un program care vorbeste deja cu o
  companie mare de cloud (Amazon, Cloudflare) nu primeste alerta de
  "comportament nou" pentru o adresa noua a aceleiasi companii. Un server
  rau intentionat gazduit acolo scapa de aceasta regula; concentrarea si
  beaconing-ul raman active.
- **Liste manuale:** `companies.py` e incomplet si trebuie intretinut. Pe alte
  masini acoperirea va fi mai mica decat pe datele de dezvoltare.
- **Rularea cu `sudo`:** necesara ca `psutil` sa vada toate conexiunile, dar
  `notify-send` poate esua cu `ServiceUnknown` (root nu are acces la sesiunea
  D-Bus a utilizatorului).
- **Beaconing:** regularitatea se analizeaza doar pe sesiunea cea mai mare;
  una mai mica si mai veche e ignorata.
- **Fara autentificare** in dashboard (doar acces local).
- **Contoare:** dupa trecerea la "doar conexiuni noi", contoarele din
  dashboard (24h) scad treptat pe masura ce randurile vechi, scrise la
  secunda, ies din fereastra.

## Stadiu curent

- Prototip functional, testat pe date reale (Firefox, Chrome, Cursor,
  VS Code, curl simulat, nc) si pe VM-uri Kali/Metasploitable2
- Alerta "de verificat" si deciziile utilizatorului functioneaza cap-coada
- Gruparea pe companii a redus lista "de verificat" de la 29 la 10 pe datele
  reale

## Urmatorii pasi

- Rularea ca serviciu (un singur proces, pornit odata cu sistemul;
  rezolva conflictul `sudo` vs. notificari)
- Test pe 2-3 masini: cate alerte false pe zi, ce procent din destinatii e
  identificat pe date pe care lista nu le-a vazut
- Baza ASN pentru identificarea oricarei adrese (ex. iptoasn.com, domeniu
  public - verificat termenii licentei inainte de distribuire)
- Lista de sufixe publice pentru `extract_base_domain` (domenii tip
  `ceva.co.uk`)
- Fisier local de mapari (`companies_local.json`), fara editarea codului
- Versiuni pentru Windows si macOS

## Mediu de testare

- Ubuntu 24.04 ca host
- VirtualBox: VM-uri Kali Linux (atacator) si Metasploitable2 (tinta
  vulnerabila) pentru scenarii de test controlate