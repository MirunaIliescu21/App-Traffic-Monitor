"""Teste pentru maparea destinațiilor pe companii, inclusiv pe lista reală a utilizatorului."""

import os

import pytest

import companies

REAL_KEYS = os.path.join(os.path.dirname(__file__), "tests_real_keys.txt")


class TestCompanyFor:
    @pytest.mark.parametrize("key,typ,expected", [
        ("1e100.net", "domeniu", "Google"),
        ("fbcdn.net", "domeniu", "Meta"),
        ("facebook.com", "domeniu", "Meta"),
        ("awsglobalaccelerator.com", "domeniu", "Amazon"),
        ("pub.ro", "domeniu", "Universitatea Politehnica București"),
        ("2001:4860:4840::/48", "subnet", "Google"),
        ("13.69.68.0/24", "subnet", "Microsoft"),
        ("51.11.192.0/24", "subnet", "Microsoft"),
        ("2606:4700:4403::/48", "subnet", "Cloudflare"),
        ("3.160.246.0/24", "subnet", "Amazon"),
        ("146.75.121.0/24", "subnet", "Fastly"),
    ])
    def test_known(self, key, typ, expected):
        assert companies.company_for(key, typ) == expected

    def test_unknown_domain_and_network_return_none(self):
        assert companies.company_for("exemplu-necunoscut.org", "domeniu") is None
        assert companies.company_for("88.211.219.0/24", "subnet") is None

    def test_garbage_key_does_not_crash(self):
        assert companies.company_for("nu-e-ip", "subnet") is None

    def test_ipv4_and_ipv6_never_cross_match(self):
        # un bloc IPv6 nu are voie să potrivească un prefix IPv4 și invers
        assert companies.company_for("::/48", "subnet") is None

    def test_domain_lookup_is_case_insensitive(self):
        assert companies.company_for("Google.COM", "domeniu") == "Google"


class TestEntityAndDisplay:
    def test_entity_for_known_is_company(self):
        assert companies.entity_for("1e100.net", "domeniu") == ("Google", "companie")

    def test_entity_for_unknown_is_unchanged(self):
        assert companies.entity_for("88.211.219.0/24", "subnet") == ("88.211.219.0/24", "subnet")

    def test_display_company_has_description(self):
        title, desc = companies.display("Microsoft", "companie")
        assert title == "Microsoft" and "Azure" in desc

    def test_display_unknown_network_hides_numbers_from_title(self):
        title, desc = companies.display("88.211.219.0/24", "subnet")
        assert title == "o rețea neidentificată" and "88.211.219.0/24" in desc

    def test_every_company_in_mappings_has_a_description(self):
        used = set(companies.DOMAIN_COMPANIES.values()) | {c for _, c in companies.PREFIX_COMPANIES}
        assert used <= set(companies.COMPANIES), used - set(companies.COMPANIES)


@pytest.mark.skipif(not os.path.exists(REAL_KEYS), reason="lista reală lipsește")
def test_real_user_destinations_collapse_to_few_entities():
    """Datele reale: 97 de destinații trebuie să devină puține entități, cu o singură neidentificată."""
    rows = [l.strip().split("|", 1) for l in open(REAL_KEYS, encoding="utf-8") if l.strip()]
    entities = {companies.entity_for(k, t) for t, k in rows}
    unknown = [e for e in entities if e[1] != "companie"]
    assert len(rows) >= 90
    assert len(entities) <= 15
    assert unknown == [("88.211.219.0/24", "subnet")]
