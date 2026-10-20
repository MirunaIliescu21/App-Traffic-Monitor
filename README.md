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

## Rularea ca serviciu (Linux)

Pe Linux, aplicatia ruleaza ca doua servicii systemd de **utilizator** (watcher
si dashboard), pornite automat la fiecare login. Se instaleaza fara `sudo`, ca
serviciile sa ruleze in sesiunea ta si notificarile desktop sa functioneze.

```bash
./install_service.sh                 # instalare + pornire
./install_service.sh --uninstall     # oprire + stergere (datele raman)

systemctl --user status trafficmonitor-watcher trafficmonitor-dashboard    # verificare rulare
journalctl --user -u trafficmonitor-watcher -f                             # log live
systemctl --user restart trafficmonitor-watcher trafficmonitor-dashboard   # dupa modificari de cod - restart
systemctl --user stop trafficmonitor-watcher                               # oprire temporara
```

Dashboard-ul: `http://localhost:5000`. Nu rula `watcher_v6.py` manual cat timp
serviciul e activ (doi watchere ar scrie in aceeasi baza).

Serviciile ruleaza cat timp utilizatorul e logat. La sleep sau capac inchis
procesul e inghetat si isi reia lucrul la trezire, fara repornire; in intervalul
de sleep nu se colecteaza nimic (in log apare un salt de timp). 
Verificare:
`systemctl --user show trafficmonitor-watcher -p ActiveEnterTimestamp -p NRestarts`
(`NRestarts=0` si aceeasi ora de pornire = nu s-a repornit).

Limitare: fiind serviciu de utilizator (fara root), `psutil` vede doar procesele
utilizatorului curent, nu si pe cele ale sistemului sau ale altor conturi.

### Rularea ca serviciu pe alta masina Linux
```
sudo apt install git python3-venv libnotify-bin
git clone https://github.com/MirunaIliescu21/App-Traffic-Monitor.git
cd App-Traffic-Monitor
python3 -m venv .venv
.venv/bin/pip install psutil flask pytest
.venv/bin/python -m pytest -q
PYTHON=$PWD/.venv/bin/python ./install_service.sh
systemctl --user status trafficmonitor-watcher trafficmonitor-dashboard
```

Folosim `venv` pentru ca Ubuntu 24.04 nu mai permite `pip install` direct in sistem. `PYTHON=...` ii spune scriptului sa foloseasca acel Python in servicii. Testele ar trebui sa dea 109 passed si 1 skipped. Apoi deschide `http://localhost:5000` pe acea masina.

Important:
- **Nu copia baza ta de date** pe cealalta masina. Ea contine istoricul tau, iar pentru pilot vrei sa pornesti de la zero.
- Prima zi vor veni probabil mai multe alerte, fiindca aplicatia inca invata ce e normal pe acea masina. Nu o judeca dupa primele ore.
- Persoana care foloseste masina trebuie sa stie ce se stocheaza (nume de procese, destinatii si ore, nu continutul traficului) si cum se dezinstaleaza (`./install_service.sh --uninstall`). Pentru clientii Infologica conteaza si acordul lor explicit.

**Ce masori dupa 2-3 zile**
1. Procentul de destinatii identificate. Pe acea masina:
   ```
   sqlite3 traffic_monitor.db "SELECT group_type, COUNT(*) FROM destination_status GROUP BY group_type;"
   ```
   Cate randuri sunt companii fata de domenii sau blocuri neidentificate.
2. Cate alerte "de verificat" apar pe zi si cate sunt reale. Noteaza numarul din "Jurnal alerte" la sfarsitul fiecarei zile si care ti s-au parut false.

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

Doua liste scrise de mana: domenii (`1e100.net` -> Google) si intervale de
IP-uri publice cunoscute (acopera adresele fara reverse DNS). Pe datele reale
de dezvoltare, 96 din 97 de destinatii distincte au fost identificate;
restul raman "retea neidentificata". Aplicatia nu ghiceste niciodata o
companie.

Ca sa adaugi o mapare: editezi `DOMAIN_COMPANIES`, `_PREFIXES_BY_COMPANY` si,
pentru o companie noua, `COMPANIES` (cu o descriere), apoi rulezi
`python3 -m pytest -q test_companies.py` si repornesti watcher-ul. Randurile
existente din "De verificat" se contopesc automat pe noua companie.

## Cum identifica aplicatia o destinatie

Pentru fiecare destinatie contactata, aplicatia incearca, in ordine:

1. **Liste scrise de mana** (`companies.py`): domenii cunoscute (ex. `github.com`) si blocuri de adrese ale unor companii mari. Daca gaseste o potrivire, destinatia primeste numele companiei.
2. **Baza ASN locala** (`asn.db`): pentru adrese care nu apar in liste, se afla ce organizatie le anunta pe internet. Daca ASN-ul apartine unei companii din `ASN_COMPANIES`, se foloseste numele companiei; altfel organizatia apare cu numele ei din baza publica (ex. `AS399358`).
3. **Destinatia exacta**, daca nu se potriveste nimic (un domeniu necunoscut sau un bloc de adrese neidentificat).

Deciziile utilizatorului ("E normal" / "Nu recunosc") se aplica la nivelul entitatii rezultate, nu al fiecarei adrese. Baza ASN vine de la [iptoasn.com](https://iptoasn.com) (domeniu public) si se descarca local, pe fiecare calculator:

```bash
python3 asn.py --update      # prima instalare si apoi cam o data pe luna
python3 asn.py --lookup 8.8.8.8
python3 asn.py --check       # ASN-urile mapate pe companii
systemctl --user restart trafficmonitor-watcher trafficmonitor-dashboard
```

**Limite:** un ASN spune cine anunta adresa, nu cine foloseste serverul (un site gazduit pe Amazon apare ca "Amazon"). Domeniile necunoscute nu trec prin baza ASN. Fara `asn.db` aplicatia merge, dar identifica mai putine destinatii.

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

## Avertizare de phishing (Firefox)

Pe langa monitorizarea conexiunilor, aplicatia te avertizeaza cand deschizi in Firefox un site al carui nume **imita un brand cunoscut** (OLX, banci, curieri, WhatsApp...), de exemplu `olx-plata.ro` sau `bcr-securizat.top`. Scopul: sa afli *inainte* sa introduci parole sau date de card.

**Cum functioneaza.** Un proces separat (`phishing_watcher.py`, serviciul `trafficmonitor-phishing`) citeste la fiecare 2 secunde istoricul Firefox (o copie a fisierului `places.sqlite`, fara drepturi de administrator) si verifica fiecare domeniu nou cu `phishing_check.py`. Verificarea e locala si offline: nimic nu paraseste calculatorul.

**Ce detecteaza** (`phishing_check.py`):
- numele unui brand in alt domeniu (`olx-plata.ro`) sau ca subdomeniu al altui site (`olx.ro.verificare.com`);
- litere sau cifre care imita litere (`0lx-plata.ro`, `paypa1.com`, litere chirilice);
- greseli de scriere intentionate la nume lungi (`faancourier.ro`);
- semnale slabe (adresa numerica, extensii ieftine, multe cratime), care singure nu declanseaza alerta.

Fiecare brand are domeniile lui oficiale in lista `BRANDS` din `phishing_check.py`; acolo adaugi branduri noi. Domeniile oficiale trebuie verificate de om pe site-ul real al brandului.

**Cand alerteaza.** De la scorul 60, cu o notificare critica (ramane pe ecran pana o inchizi) si o linie `[PHISHING ...]` in `alerts.log`. Orice intrare deliberata pe un site suspect alerteaza de fiecare data (adresa tastata, bookmark, tab nou, link, reincarcare). Se strang intr-o singura alerta doar redirecturile si navigarea in interiorul aceluiasi site, in 60 de secunde.

**Confidentialitate.** In baza de date (`phishing_events`) se retine doar numele domeniului suspect, nu adresa completa (poate contine token-uri), si nicio pagina normala.

**Cum il testezi in siguranta** (fara sa deschizi site-uri reale): in Firefox deschide `http://olx-test1.localhost:5000/`. Adresa duce doar la dashboard-ul tau local, iar numele contine "olx", deci apare alerta. Foloseste alt nume la fiecare test (`olx-test2`...), ca sa fie un domeniu nou.

```bash
python3 phishing_watcher.py                          # in terminal, pentru test
journalctl --user -u trafficmonitor-phishing -f      # jurnalul serviciului
```

**Limite (importante):**
- Doar **Firefox**, si nu vede **ferestrele private** (nu lasa nimic in istoric). Pentru Chrome/Edge trebuie un adaptor separat; acoperirea completa cere o extensie de browser.
- Istoricul vede *sosirea* pe o pagina, nu ce se intampla dupa: un refresh (F5) sau un formular trimis nu apar ca vizita noua.
- Prinde doar brandurile din lista `BRANDS`. Un site de phishing cu un nume fara legatura cu vreun brand cunoscut nu e detectat.
- Notificarile sunt testate doar pe Linux (macOS scris, netestat; Windows lipseste: alerta ramane doar in `alerts.log`).

## Mediu de testare

- Ubuntu 24.04 ca host
- VirtualBox: VM-uri Kali Linux (atacator) si Metasploitable2 (tinta
  vulnerabila) pentru scenarii de test controlate