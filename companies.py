#!/usr/bin/env python3
"""
Din "2001:4860:4840::/48" in "Google": nume de companii in loc de cifre.

Un utilizator non-tehnic nu poate descifra "13.69.68.0/24", dar intelege
"Microsoft". Acest modul traduce o destinatie (domeniu sau bloc de IP-uri,
cum le calculeaza watcher_v6.get_group_key) in numele companiei care o
detine, plus o descriere intr-o fraza.

TREI SURSE DE CUNOSTINTE, in aceasta ordine:
  1. DOMENII  - liste scrise de mana, sigure: daca reverse DNS spune
               "xx.1e100.net", e Google.
  2. PREFIXE  - intervale de IP-uri ale marilor furnizori, scrise de mana.
               Acopera adresele FARA reverse DNS.
  3. ASN      - baza publica iptoasn.com (asn.py), pentru orice adresa pe care
               listele nu o stiu. ASN-urile mari sunt legate de o companie
               (ASN_COMPANIES); restul devin o entitate "AS12345" cu numele
               organizatiei. Fara asn.db, acest pas se sare.

LIMITARI (cunoscute, asumate):
  - O destinatie pe care nici listele, nici baza ASN n-o stiu ramane
    "retea neidentificata". Nu ghicim niciodata o companie.
  - Prefixele marcate "verificat partial" vin din surse publice, nu dintr-o
    baza oficiala.
  - Compania nu spune cine a cumparat serviciul: un server tinut pe Amazon
    apare ca "Amazon", fie ca e Netflix sau altcineva.
"""

import ipaddress

# nume afisat -> descriere (o fraza, pentru utilizator)
COMPANIES = {
    "Google": "servicii Google (cautare, YouTube, Chrome, Google Cloud)",
    "Microsoft": "servicii Microsoft (Azure, Windows, Office, VS Code)",
    "Amazon": "Amazon Web Services si CloudFront, care gazduiesc multe site-uri si aplicatii",
    "Cloudflare": "retea care accelereaza si protejeaza multe site-uri",
    "Meta": "Facebook, Instagram, WhatsApp",
    "Akamai": "retea de livrare de continut, folosita de multe site-uri si aplicatii",
    "Fastly": "retea de livrare de continut, folosita de multe site-uri si aplicatii",
    "Edgecast": "retea de livrare de continut (folosita si de example.com)",
    "Netflix": "Netflix",
    "GitHub": "GitHub (apartine Microsoft)",
    "Spotify": "Spotify",
    "JetBrains": "JetBrains (PyCharm, IntelliJ si celelalte programe JetBrains)",
    "Mozilla": "Mozilla (Firefox)",
    "Canonical": "Canonical (Ubuntu)",
    "Digi": "Digi (RCS & RDS), furnizor de internet si servicii din Romania",
    "Universitatea Politehnica Bucuresti": "reteaua universitatii (pub.ro)",
}

# domeniu de baza (cum il intoarce extract_base_domain) -> companie
DOMAIN_COMPANIES = {
    # Google
    "1e100.net": "Google", "googleusercontent.com": "Google", "google.com": "Google",
    "googleapis.com": "Google", "gstatic.com": "Google", "youtube.com": "Google",
    "ytimg.com": "Google", "googlevideo.com": "Google", "gvt1.com": "Google",
    "gvt2.com": "Google", "doubleclick.net": "Google", "googlesyndication.com": "Google",
    "google-analytics.com": "Google",
    # Microsoft
    "microsoft.com": "Microsoft", "azure.com": "Microsoft", "windows.net": "Microsoft",
    "azureedge.net": "Microsoft", "msedge.net": "Microsoft", "office.com": "Microsoft",
    "office365.com": "Microsoft", "live.com": "Microsoft", "bing.com": "Microsoft",
    "msn.com": "Microsoft", "microsoftonline.com": "Microsoft", "windows.com": "Microsoft",
    "visualstudio.com": "Microsoft", "vsassets.io": "Microsoft", "trafficmanager.net": "Microsoft",
    "cloudapp.net": "Microsoft", "skype.com": "Microsoft", "outlook.com": "Microsoft",
    # Amazon
    "amazonaws.com": "Amazon", "awsglobalaccelerator.com": "Amazon", "cloudfront.net": "Amazon",
    "amazon.com": "Amazon",
    # Cloudflare
    "cloudflare.com": "Cloudflare", "cloudflare.net": "Cloudflare",
    # Meta
    "facebook.com": "Meta", "fbcdn.net": "Meta", "instagram.com": "Meta", "fb.com": "Meta",
    "whatsapp.net": "Meta", "whatsapp.com": "Meta", "cdninstagram.com": "Meta",
    # CDN-uri
    "akamaitechnologies.com": "Akamai", "akamai.net": "Akamai", "akamaiedge.net": "Akamai",
    "edgekey.net": "Akamai", "akamaized.net": "Akamai",
    "fastly.net": "Fastly", "fastlylb.net": "Fastly",
    "edgecastcdn.net": "Edgecast", "edgio.net": "Edgecast",
    # altii
    "netflix.com": "Netflix", "nflxso.net": "Netflix", "nflxvideo.net": "Netflix",
    "nflxext.com": "Netflix", "nflximg.net": "Netflix",
    "github.com": "GitHub", "githubusercontent.com": "GitHub", "githubassets.com": "GitHub",
    "github.io": "GitHub",
    "spotify.com": "Spotify", "scdn.co": "Spotify",
    "jetbrains.com": "JetBrains",
    "mozilla.com": "Mozilla", "mozilla.org": "Mozilla", "mozilla.net": "Mozilla",
    "ubuntu.com": "Canonical", "canonical.com": "Canonical",
    "rcs-rds.ro": "Digi", "digi.ro": "Digi",
    "pub.ro": "Universitatea Politehnica Bucuresti",
}

# companie -> intervale de IP-uri (CIDR). "vp" = verificat partial (vezi docstring)
_PREFIXES_BY_COMPANY = {
    "Google": [
        "2001:4860::/32", "2a00:1450::/32", "2607:f8b0::/32", "2404:6800::/32",
        "2600:1900::/28",                       # Google Cloud IPv6
        "172.217.0.0/16", "142.250.0.0/15", "216.58.192.0/19", "74.125.0.0/16",
        "64.233.160.0/19",
        "34.64.0.0/10", "34.128.0.0/10",        # Google Cloud IPv4
    ],
    "Microsoft": [
        "20.32.0.0/11", "20.64.0.0/10", "20.128.0.0/9",    # Azure
        "13.64.0.0/11", "13.104.0.0/14",                    # Azure + servicii Microsoft
        "40.64.0.0/10", "51.136.0.0/15", "51.140.0.0/14",
        "52.168.0.0/16", "104.40.0.0/13", "104.208.0.0/13",
        "51.10.0.0/15", "52.160.0.0/11", "51.132.0.0/16",
        "4.144.0.0/12", "4.192.0.0/10",                     # vp: Azure, confirmat din liste publice
        "2603:1000::/24", "2620:1ec::/36", "2a01:111::/32",
    ],
    "Amazon": [
        "3.160.0.0/14", "18.164.0.0/15",        # CloudFront
        "54.84.0.0/14", "52.0.0.0/11",          # AWS EC2
        "2600:9000::/28", "2600:1f00::/24", "2a05:d000::/25",
    ],
    "Cloudflare": [
        "104.16.0.0/13", "172.64.0.0/13", "162.158.0.0/15",
        "2606:4700::/32", "2a06:98c0::/29",
    ],
    "Fastly": ["146.75.0.0/16", "151.101.0.0/16", "199.232.0.0/16", "2a04:4e40::/29"],
    "GitHub": [
        "140.82.112.0/20", "185.199.108.0/22", "192.30.252.0/22",
        "2606:50c0::/32",                       # vp: adrese GitHub Pages
    ],
    "Edgecast": ["93.184.208.0/20"],
    "Digi": ["2a02:2f00::/28"],                 # vp
    "Universitatea Politehnica Bucuresti": ["141.85.0.0/16"],
}

# lista plata (retea, companie), cea mai specifica (prefix cel mai lung) prima
PREFIX_COMPANIES = sorted(
    ((ipaddress.ip_network(cidr), company)
     for company, cidrs in _PREFIXES_BY_COMPANY.items() for cidr in cidrs),
    key=lambda item: item[0].prefixlen,
    reverse=True,
)


def company_for(group_key: str, group_type: str) -> str | None:
    """Compania care detine destinatia, sau None daca nu o stim (nu ghicim)."""
    if group_type == "domeniu":
        return DOMAIN_COMPANIES.get(group_key.lower())
    if group_type in ("subnet", "ip"):
        try:
            net = ipaddress.ip_network(group_key, strict=False)
        except ValueError:
            return None
        for prefix, company in PREFIX_COMPANIES:
            if prefix.version == net.version and net.subnet_of(prefix):
                return company
    return None


# ASN-uri cunoscute -> companie. Pentru adrese care nu apar in listele de mai sus,
# baza ASN (asn.py) spune cui apartin; daca ASN-ul e aici, folosim numele companiei,
# altfel ASN-ul insusi devine "entitatea" (ex. AS399358). Verificare: python3 asn.py --check
ASN_COMPANIES = {
    15169: "Google", 36040: "Google", 396982: "Google", 19527: "Google",
    8075: "Microsoft", 8068: "Microsoft", 8069: "Microsoft", 3598: "Microsoft",
    16509: "Amazon", 14618: "Amazon", 8987: "Amazon", 7224: "Amazon",
    13335: "Cloudflare", 209242: "Cloudflare",
    32934: "Meta", 63293: "Meta",
    20940: "Akamai", 16625: "Akamai", 12222: "Akamai", 21342: "Akamai", 35994: "Akamai",
    54113: "Fastly",
    2906: "Netflix",
    36459: "GitHub",
    41231: "Canonical",
    8708: "Digi",
}


def asn_for(group_key: str, group_type: str) -> int | None:
    """ASN-ul unui bloc de adrese (dupa prima adresa din bloc), sau None."""
    if group_type not in ("subnet", "ip"):
        return None
    try:
        net = ipaddress.ip_network(group_key, strict=False)
    except ValueError:
        return None
    import asn
    return asn.lookup(str(net.network_address))


def entity_for(group_key: str, group_type: str) -> tuple[str, str]:
    """
    Unitatea dupa care tinem minte si decidem. In ordine:
      1. compania, daca o stim din domenii sau prefixe scrise de mana;
      2. compania sau organizatia din baza ASN (tip "companie" sau "asn");
      3. altfel destinatia exacta (domeniu sau bloc de adrese).
    Intoarce (cheie, tip).
    """
    company = company_for(group_key, group_type)
    if company:
        return company, "companie"
    asn_number = asn_for(group_key, group_type)
    if asn_number:
        company = ASN_COMPANIES.get(asn_number)
        if company:
            return company, "companie"
        return f"AS{asn_number}", "asn"
    return group_key, group_type


def display(entity_key: str, entity_type: str) -> tuple[str, str]:
    """(titlu, descriere) pentru utilizator - fara cifre acolo unde se poate."""
    if entity_type == "companie":
        return entity_key, COMPANIES.get(entity_key, "")
    if entity_type == "domeniu":
        return entity_key, "adresa de internet pe care n-o recunosc din lista mea de companii"
    if entity_type == "asn":
        import asn
        try:
            details = asn.info(int(entity_key.removeprefix("AS")))
        except ValueError:
            details = None
        if details:
            country, name = details
            title = asn.clean_name(name) or entity_key
            where = f", {country}" if country else ""
            return title, f"organizatie din baza publica de retele ({entity_key}{where}), care nu apare in lista mea de companii"
        return entity_key, "retea din baza publica ASN, care nu apare in lista mea de companii"
    return "o retea neidentificata", f"bloc de adrese {entity_key}, care nu apare in lista mea de companii"
