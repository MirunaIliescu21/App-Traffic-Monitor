"""Teste pentru baza ASN (asn.py) si pentru folosirea ei in companies.py. Fisier ip2asn sintetic, fara retea."""

import pytest

import asn
import companies
import destination_status as ds

# Format iptoasn: start, sfarsit, ASN, tara, nume (separate prin TAB).
# 64500-64505 sunt ASN-uri rezervate pentru documentatie; 198.51.100.0/24 si
# 203.0.113.0/24 sunt blocuri rezervate pentru documentatie.
SAMPLE = "\n".join([
    "1.0.0.0\t1.0.0.255\t64501\tUS\tTESTNET-ONE",
    "1.0.1.0\t1.0.3.255\t0\tNone\tNot routed",
    "198.51.100.0\t198.51.100.255\t15169\tUS\tGOOGLE",
    "203.0.113.0\t203.0.113.127\t64500\tAU\tTEST-AS-AP Test Telecom Pty Ltd",
    "203.0.113.128\t203.0.113.255\t64502\tRO\tOTHERNET",
    "2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t64503\tDE\tV6-ORG Example v6 GmbH",
    "linie stricata fara tab-uri",
    "x.y.z\t1.2.3.4\t64504\tUS\tBROKEN-IP",
    "",
])


@pytest.fixture
def built(tmp_path):
    tsv = tmp_path / "ip2asn.tsv"
    tsv.write_text(SAMPLE, encoding="utf-8")
    return asn.build(str(tsv))


class TestBuildAndLookup:
    def test_build_counts_valid_ranges_and_skips_not_routed_and_broken(self, built):
        n_ranges, n_asn = built
        assert (n_ranges, n_asn) == (5, 5)   # 1.0.0.0, 198.51, 203.0.113 x2, 2001:db8

    def test_lookup_inside_range_and_at_both_ends(self, built):
        assert asn.lookup("1.0.0.0") == 64501
        assert asn.lookup("1.0.0.77") == 64501
        assert asn.lookup("1.0.0.255") == 64501

    def test_lookup_adjacent_ranges_do_not_bleed(self, built):
        assert asn.lookup("203.0.113.127") == 64500
        assert asn.lookup("203.0.113.128") == 64502

    def test_lookup_in_gap_is_none(self, built):
        assert asn.lookup("1.0.1.5") is None        # "Not routed" nu intra in baza
        assert asn.lookup("9.9.9.9") is None

    def test_lookup_ipv6(self, built):
        assert asn.lookup("2001:db8::1") == 64503
        assert asn.lookup("2001:db8:ffff::5") == 64503
        assert asn.lookup("2001:db9::1") is None

    def test_lookup_invalid_input_does_not_crash(self, built):
        assert asn.lookup("nu-e-ip") is None
        assert asn.lookup("") is None

    def test_missing_database_returns_none_everywhere(self):
        assert asn.available() is False
        assert asn.lookup("1.0.0.1") is None
        assert asn.info(64501) is None

    def test_info_returns_country_and_name(self, built):
        assert asn.info(64500) == ("AU", "TEST-AS-AP Test Telecom Pty Ltd")
        assert asn.info(99999) is None

    def test_rebuild_replaces_database(self, built, tmp_path):
        other = tmp_path / "other.tsv"
        other.write_text("5.5.5.0\t5.5.5.255\t64510\tUS\tNEWNET\n", encoding="utf-8")
        asn.build(str(other))
        assert asn.lookup("5.5.5.5") == 64510
        assert asn.lookup("1.0.0.1") is None

    def test_gzip_source_is_supported(self, tmp_path):
        import gzip
        path = tmp_path / "ip2asn.tsv.gz"
        with gzip.open(path, "wt", encoding="utf-8") as f:
            f.write(SAMPLE)
        assert asn.build(str(path))[0] == 5


class TestCleanName:
    @pytest.mark.parametrize("raw, expected", [
        ("GTELECOM-AS-AP Gtelecom Pty Ltd", "Gtelecom Pty Ltd"),
        ("TEST-AS-AP Test Telecom Pty Ltd", "Test Telecom Pty Ltd"),
        ("CLOUDFLARENET", "CLOUDFLARENET"),
        ("GOOGLE", "GOOGLE"),
        ("Acme Hosting Ltd", "Acme Hosting Ltd"),
        ("RCS-RDS 73-75, Dr. Staicovici", "RCS-RDS 73-75, Dr. Staicovici"),
        ("", ""),
    ])
    def test_clean_name(self, raw, expected):
        assert asn.clean_name(raw) == expected


class TestEntitiesFromAsn:
    def test_asn_mapped_to_company(self, built):
        assert companies.entity_for("198.51.100.0/24", "subnet") == ("Google", "companie")

    def test_unmapped_asn_becomes_asn_entity(self, built):
        assert companies.entity_for("203.0.113.0/24", "subnet") == ("AS64500", "asn")

    def test_ipv6_block_resolved(self, built):
        assert companies.entity_for("2001:db8:1::/48", "subnet") == ("AS64503", "asn")

    def test_unknown_block_stays_unchanged(self, built):
        assert companies.entity_for("9.9.9.0/24", "subnet") == ("9.9.9.0/24", "subnet")

    def test_without_database_nothing_changes(self):
        assert companies.entity_for("203.0.113.0/24", "subnet") == ("203.0.113.0/24", "subnet")

    def test_hand_written_lists_win_over_asn(self, built, monkeypatch):
        monkeypatch.setattr(companies, "PREFIX_COMPANIES",
                            [(companies.ipaddress.ip_network("203.0.113.0/24"), "Cloudflare")])
        assert companies.entity_for("203.0.113.0/24", "subnet") == ("Cloudflare", "companie")

    def test_domains_are_not_looked_up_in_asn(self, built):
        assert companies.entity_for("he.net", "domeniu") == ("he.net", "domeniu")

    def test_display_asn_entity_uses_organization_name(self, built):
        title, desc = companies.display("AS64500", "asn")
        assert title == "Test Telecom Pty Ltd"
        assert "AS64500" in desc and "AU" in desc

    def test_display_asn_without_database_is_still_readable(self):
        title, desc = companies.display("AS64500", "asn")
        assert title == "AS64500" and desc

    def test_every_mapped_asn_points_to_a_described_company(self):
        assert set(companies.ASN_COMPANIES.values()) <= set(companies.COMPANIES)


class TestMigrationWithAsn:
    def test_blocks_of_same_asn_merge_and_decision_survives(self, built, tmp_path):
        import sqlite3
        conn = sqlite3.connect(":memory:")
        ds.init_tables(conn)
        for key in ("203.0.113.0/25", "203.0.113.0/24"):
            ds.record_pending(conn, "firefox", key, "subnet", "2026-10-15T10:00:00+00:00")
        ds.set_status(conn, "firefox", "203.0.113.0/24", ds.SUSPICIOUS)
        replaced = ds.migrate_to_entities(conn, companies.entity_for)
        assert replaced == 2
        assert ds.load_decisions(conn) == {("firefox", "AS64500"): ds.SUSPICIOUS}
