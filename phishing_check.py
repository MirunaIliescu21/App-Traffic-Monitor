"""
Verifica un domeniu deschis de utilizator: imita un brand cunoscut?

Ideea: un site de phishing (olx-plata.ro, bcr-securizat.top) nu e rau prin ce
trafic produce, ci prin CE NUME are. Pentru fiecare brand din lista de mai jos
cunoastem domeniile oficiale. Un domeniu care contine numele brandului, dar nu
e unul dintre cele oficiale, e suspect.

Ce prinde:
  - numele brandului in alt domeniu:   olx-plata.ro, bancatransilvania-login.ro
  - brandul folosit ca subdomeniu:     olx.ro.verificare-plata.com, olx.pay-secure.com
  - litere/cifre care imita litere:    0lx-plata.ro, paypa1.com, litere chirilice (xn--...)
  - greseli de scriere ale numelor lungi: faancourier.ro
  - semnale slabe (adresa numerica, extensii ieftine, multe cratime) - singure NU declanseaza alerta

Ce NU prinde: un site de phishing cu un nume fara legatura cu vreun brand din lista
(ex. un domeniu nou fara cuvinte cunoscute) si brandurile care lipsesc din lista.
Lista se completeaza si se verifica de om: fiecare domeniu oficial trebuie confirmat
pe site-ul real al brandului.
"""

import ipaddress
import re
from dataclasses import dataclass, field

ALERT_SCORE = 60   # de la acest scor se trimite avertisment

# brand -> cuvinte cheie (cum apare numele in domenii) si domeniile OFICIALE.
# Un cuvant cheie scurt (sub 6 litere) conteaza doar ca "cuvant" separat prin cratima
# (ca "ing" sa nu se potriveasca in "shopping"); unul lung conteaza oriunde in nume.
BRANDS = {
    "OLX": {"keys": ["olx"], "domains": ["olx.ro", "olx.com", "olx.pl", "olx.pt", "olx.bg", "olx.com.br"]},
    "eMAG": {"keys": ["emag"], "domains": ["emag.ro", "emag.hu", "emag.bg"]},
    "Vinted": {"keys": ["vinted"], "domains": ["vinted.ro", "vinted.com"]},
    "Banca Transilvania": {"keys": ["bancatransilvania"], "domains": ["bancatransilvania.ro"]},
    "BCR": {"keys": ["bcr"], "domains": ["bcr.ro"]},
    "ING": {"keys": ["ing"], "domains": ["ing.ro", "ing.com"]},
    "BRD": {"keys": ["brd"], "domains": ["brd.ro"]},
    "Raiffeisen": {"keys": ["raiffeisen"], "domains": ["raiffeisen.ro"]},
    "CEC Bank": {"keys": ["cec", "cecbank"], "domains": ["cec.ro"]},
    "UniCredit": {"keys": ["unicredit"], "domains": ["unicredit.ro"]},
    "Revolut": {"keys": ["revolut"], "domains": ["revolut.com"]},
    "PayPal": {"keys": ["paypal"], "domains": ["paypal.com"]},
    "Fan Courier": {"keys": ["fancourier"], "domains": ["fancourier.ro"]},
    "Sameday": {"keys": ["sameday"], "domains": ["sameday.ro"]},
    "Cargus": {"keys": ["cargus"], "domains": ["cargus.ro"]},
    "Posta Romana": {"keys": ["postaromana"], "domains": ["posta-romana.ro"]},
    "DHL": {"keys": ["dhl"], "domains": ["dhl.com"]},
    "ANAF": {"keys": ["anaf"], "domains": ["anaf.ro"]},
    "Ghiseul.ro": {"keys": ["ghiseul"], "domains": ["ghiseul.ro"]},
    "WhatsApp": {"keys": ["whatsapp"], "domains": ["whatsapp.com", "whatsapp.net"]},
    "Facebook": {"keys": ["facebook"], "domains": ["facebook.com", "fb.com"]},
}

# sufixe formate din doua parti (pentru a gasi "numele" domeniului corect) si platforme
# unde oricine isi poate face subdomeniu (acolo numele site-ului e subdomeniul)
_TWO_PART_SUFFIXES = {
    "com.ro", "org.ro", "net.ro", "info.ro", "firme.ro", "co.uk", "org.uk", "com.au", "com.br",
    "co.in", "co.jp", "com.tr", "com.ua", "github.io", "gitlab.io", "pages.dev", "netlify.app",
    "vercel.app", "web.app", "firebaseapp.com", "herokuapp.com", "blogspot.com", "weebly.com",
    "wixsite.com", "000webhostapp.com", "workers.dev", "glitch.me", "repl.co",
}

_CHEAP_TLDS = {"top", "xyz", "click", "icu", "buzz", "tk", "gq", "ml", "cf", "ga", "cyou", "sbs", "rest", "cam"}
_BAIT_WORDS = {"login", "verify", "verifica", "secure", "securizat", "plata", "payment", "pay", "confirm",
               "confirma", "update", "cont", "card", "account", "colet", "awb", "ramburs"}

# litere chirilice/grecesti si cifre care seamana cu litere latine
_CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x",
    "\u0456": "i", "\u03bf": "o",
})


def _normalize(text: str) -> str:
    return text.lower().translate(_CONFUSABLES).replace("rn", "m").replace("vv", "w")


@dataclass
class Verdict:
    score: int = 0
    reasons: list = field(default_factory=list)
    brand: str | None = None
    official_domain: str | None = None

    @property
    def alert(self) -> bool:
        return self.score >= ALERT_SCORE


# ---------- piese ----------

def _to_unicode(host: str) -> str:
    """Decodeaza numele scrise cu xn-- (ex. litere chirilice) ca sa le putem compara."""
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def split_host(host: str) -> tuple[list[str], str, str]:
    """(subdomenii, numele domeniului, extensia). 'a.b.olx-plata.com.ro' -> (['a','b'], 'olx-plata', 'com.ro')."""
    labels = host.split(".")
    n = 2 if len(labels) >= 2 and ".".join(labels[-2:]) in _TWO_PART_SUFFIXES else 1
    suffix = ".".join(labels[-n:])
    rest = labels[:-n]
    main = rest[-1] if rest else ""
    return rest[:-1], main, suffix


def is_official(host: str, domains: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _keyword_hit(label: str, keyword: str) -> bool:
    flat = label.replace("-", "").replace("_", "")
    if len(keyword) >= 6:
        return keyword in flat
    return keyword in [t for t in re.split(r"[-_]", label) if t]


def _within_one_edit(a: str, b: str) -> bool:
    """True daca a si b difera prin exact o litera adaugata, scoasa sau schimbata."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    if len(a) == len(b):
        return a[i + 1:] == b[i + 1:]
    return a[i:] == b[i + 1:]


def _is_public_ip(host: str) -> bool | None:
    """True/False pentru o adresa numerica (publica/locala), None daca nu e adresa."""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)


# ---------- verificarea ----------

def check_domain(host: str) -> Verdict:
    host = (host or "").lower().rstrip(".")
    verdict = Verdict()
    if not host or host == "localhost" or host.endswith(".local"):
        return verdict

    public_ip = _is_public_ip(host)
    if public_ip is False:
        return verdict
    if public_ip is True:
        verdict.score = 40
        verdict.reasons.append("adresa numerica in loc de nume de site")
        return verdict

    uhost = _to_unicode(host)
    subs, main, suffix = split_host(uhost)
    if not main:
        return verdict

    if any(is_official(host, info["domains"]) for info in BRANDS.values()):
        return verdict                # domeniu oficial al unui brand: nimic de verificat

    best = 0
    for brand, info in BRANDS.items():
        for key in info["keys"]:
            nkey = _normalize(key)
            score, reason = 0, ""
            if _keyword_hit(main, key):
                score, reason = 70, f"numele site-ului contine '{key}' ({brand}), dar nu e site-ul oficial"
            elif any(_keyword_hit(label, key) for label in subs):
                score, reason = 70, f"foloseste '{key}' ({brand}) ca subdomeniu al altui site"
            elif _keyword_hit(_normalize(main), nkey) or any(_keyword_hit(_normalize(l), nkey) for l in subs):
                score, reason = 85, f"foloseste litere sau cifre care imita numele {brand}"
            elif len(key) >= 8 and _within_one_edit(_normalize(main).replace("-", ""), nkey):
                score, reason = 75, f"nume foarte asemanator cu {brand} (posibila greseala de scriere intentionata)"
            if score > best:
                best = score
                verdict.brand = brand
                verdict.official_domain = info["domains"][0]
                verdict.reasons = [reason]

    # semnale slabe: se aduna, dar singure nu ajung la prag
    weak = 0
    if suffix.rsplit(".", 1)[-1] in _CHEAP_TLDS:
        weak += 15
        verdict.reasons.append(f"extensie des folosita in abuzuri (.{suffix.rsplit('.', 1)[-1]})")
    if main.count("-") >= 3:
        weak += 10
        verdict.reasons.append("multe cratime in numele site-ului")
    if any(label.startswith("xn--") for label in host.split(".")):
        weak += 10
        verdict.reasons.append("nume scris cu caractere speciale (xn--)")
    tokens = set(re.split(r"[-_.]", uhost))
    if best and tokens & _BAIT_WORDS:
        weak += 10
        verdict.reasons.append("cuvinte care cer actiune (login, plata, verifica...)")

    verdict.score = min(100, best + weak) if best else min(weak, ALERT_SCORE - 1)
    return verdict


def describe(host: str, verdict: Verdict) -> tuple[str, str]:
    """(titlu, text) pentru notificarea catre utilizator."""
    if verdict.brand:
        title = f"Site care seamana cu {verdict.brand}"
        text = (f"Ai deschis {host}. Adresa oficiala {verdict.brand} este {verdict.official_domain}. "
                f"Nu introduce parole sau date de card. Daca ai facut-o deja: blocheaza cardul si schimba parola acum.")
    else:
        title = "Site suspect"
        text = f"Ai deschis {host}. " + "; ".join(verdict.reasons)
    return title, text
