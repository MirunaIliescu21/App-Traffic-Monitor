"""
Teste pentru phishing_check.py.
Rulare: pytest test_phishing_check.py -v
"""

import pytest

import phishing_check as pc
from phishing_check import check_domain


class TestLegitimateSitesStaySilent:
    @pytest.mark.parametrize("host", [
        "olx.ro", "www.olx.ro", "m.olx.ro", "emag.ro", "www.fancourier.ro",
        "bancatransilvania.ro", "ing.ro", "www.paypal.com", "web.whatsapp.com",
        "posta-romana.ro", "olx.pl",
    ])
    def test_official_domains(self, host):
        v = check_domain(host)
        assert v.score == 0 and not v.alert

    @pytest.mark.parametrize("host", [
        "mail.google.com", "docs.google.com", "biziday.ro", "ocw.cs.pub.ro", "github.com",
        "www.pgcareers.com", "bgp.he.net",
    ])
    def test_unrelated_sites(self, host):
        assert not check_domain(host).alert

    def test_short_brand_word_does_not_match_inside_other_words(self):
        """REGRESIE de proiectare: 'ing' nu trebuie sa se potriveasca in 'shopping' sau 'booking'."""
        assert check_domain("shopping.ro").score == 0
        assert check_domain("booking.com").score == 0
        assert check_domain("myingaccount.com").score == 0

    def test_similar_ordinary_word_is_not_a_typo_of_short_brand(self):
        """'someday' difera printr-o litera de 'sameday', dar cuvintele scurte nu se verifica pe greseli de scriere."""
        assert check_domain("someday.com").score == 0

    def test_local_addresses_are_ignored(self):
        for host in ("localhost", "127.0.0.1", "192.168.1.5", "10.0.0.1", "printer.local", ""):
            assert check_domain(host).score == 0


class TestBrandImpersonationAlerts:
    @pytest.mark.parametrize("host", [
        "olx-plata.ro",
        "olx.ro.verificare-plata.com",
        "olx.pay-secure.com",
        "bancatransilvania-login.ro",
        "bcr-securizat.top",
        "ing-login.ro",
        "fancourier-colet.com",
        "dhl-express-awb.xyz",
        "olx-plata.github.io",
        "whatsapp-verify.net",
    ])
    def test_name_inside_other_domain(self, host):
        v = check_domain(host)
        assert v.alert, (host, v)
        assert v.brand and v.official_domain

    def test_brand_and_official_domain_reported(self):
        v = check_domain("olx-plata.ro")
        assert v.brand == "OLX"
        assert v.official_domain == "olx.ro"

    def test_digit_for_letter_trick(self):
        assert check_domain("0lx-plata.ro").alert
        assert check_domain("paypa1.com").alert

    def test_cyrillic_lookalike_letter(self):
        host = "\u043elx.ro".encode("idna").decode("ascii")      # prima litera e chirilica
        assert host.startswith("xn--")
        v = check_domain(host)
        assert v.alert and v.brand == "OLX"

    def test_typo_of_long_brand_name(self):
        assert check_domain("faancourier.ro").alert
        assert check_domain("raiffeisenn.ro").alert

    def test_same_name_with_other_extension_is_flagged(self):
        assert check_domain("bcr.xyz").alert

    def test_official_domain_inside_subdomain_trick(self):
        assert check_domain("bancatransilvania.ro.plata-card.com").alert


class TestWeakSignals:
    def test_numeric_address_alone_is_not_an_alert(self):
        v = check_domain("185.12.4.9")
        assert v.score > 0 and not v.alert
        assert "adresa numerica" in v.reasons[0]

    def test_cheap_extension_alone_is_not_an_alert(self):
        v = check_domain("random-site.xyz")
        assert 0 < v.score < pc.ALERT_SCORE
        assert not v.alert

    def test_many_hyphens_alone_is_not_an_alert(self):
        assert not check_domain("a-b-c-d-e.com").alert

    def test_weak_signals_never_reach_alert_threshold_without_a_brand(self):
        v = check_domain("a-b-c-d-e.xyz")
        assert v.score < pc.ALERT_SCORE


class TestHelpers:
    def test_split_host(self):
        assert pc.split_host("a.b.olx-plata.com.ro") == (["a", "b"], "olx-plata", "com.ro")
        assert pc.split_host("olx-plata.ro") == ([], "olx-plata", "ro")
        assert pc.split_host("olx-plata.github.io") == ([], "olx-plata", "github.io")

    def test_within_one_edit(self):
        assert pc._within_one_edit("fancourier", "faancourier")
        assert pc._within_one_edit("fancourier", "fancurier")
        assert pc._within_one_edit("fancourier", "fancouriar")
        assert not pc._within_one_edit("fancourier", "fancourier")
        assert not pc._within_one_edit("fancourier", "fanxxurier")

    def test_every_brand_has_keys_and_official_domains(self):
        for name, info in pc.BRANDS.items():
            assert info["keys"] and info["domains"], name
            for domain in info["domains"]:
                assert domain == domain.lower() and "/" not in domain

    def test_official_domains_never_flag_themselves(self):
        for name, info in pc.BRANDS.items():
            for domain in info["domains"]:
                assert check_domain(domain).score == 0, (name, domain)
                assert check_domain("www." + domain).score == 0, (name, domain)


class TestMessage:
    def test_message_names_brand_and_official_address(self):
        v = check_domain("olx-plata.ro")
        title, text = pc.describe("olx-plata.ro", v)
        assert "OLX" in title
        assert "olx-plata.ro" in text and "olx.ro" in text
        assert "card" in text

    def test_message_without_brand_lists_reasons(self):
        v = check_domain("185.12.4.9")
        _, text = pc.describe("185.12.4.9", v)
        assert "adresa numerica" in text
