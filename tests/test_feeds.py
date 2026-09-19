# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Feed clients, exercised entirely offline.

No test here opens a socket. The fixtures under ``tests/fixtures/feed-cache`` are
hand-written to the documented schemas, the same way the build-tree fixtures are.
A suite that depends on CISA being reachable is one that fails for reasons
unrelated to the code, at the moment you most need it to be trustworthy.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from cra24.feeds import Cache, FeedSet, HttpClient, OfflineError
from cra24.feeds.base import Feed
from cra24.feeds.cache import CacheError
from cra24.feeds.epss import EpssFeed
from cra24.feeds.euvd import EuvdFeed
from cra24.feeds.kev import KevFeed
from cra24.feeds.nvd import NvdFeed
from cra24.feeds.osv import AffectedRange, OsvFeed, _parse_record


class TestOfflineContract:
    def test_offline_refuses_to_open_a_socket(self) -> None:
        with pytest.raises(OfflineError) as excinfo:
            HttpClient(offline=True).get("https://example.invalid/anything")
        assert "offline mode" in str(excinfo.value)
        assert "feeds sync" in str(excinfo.value)

    def test_a_feedset_with_no_cache_still_answers(self, tmp_path: Path) -> None:
        """A machine that has never synced must not crash, only know nothing."""
        feeds = FeedSet(cache=Cache(tmp_path / "empty"), offline=True)
        result = feeds.enrich("CVE-2024-1086")
        assert result.actively_exploited is None
        assert result.evidence[0].source == "feeds"

    def test_an_unknown_feed_name_is_refused_with_the_list(self, tmp_path: Path) -> None:
        from cra24.errors import ConfigError

        with pytest.raises(ConfigError) as excinfo:
            FeedSet(["kev", "nonsense"], cache=Cache(tmp_path))
        assert "nonsense" in str(excinfo.value)
        assert "kev" in str(excinfo.value)


class TestKev:
    def test_a_listed_cve_is_found(self, feed_cache: Cache) -> None:
        entry = KevFeed(feed_cache).lookup("CVE-2024-1086")
        assert entry is not None
        assert entry.date_added == "2024-05-30"
        assert "CISA KEV" in entry.summary()

    def test_lookup_is_case_insensitive(self, feed_cache: Cache) -> None:
        assert KevFeed(feed_cache).lookup("cve-2024-1086") is not None

    def test_ransomware_flag_is_read(self, feed_cache: Cache) -> None:
        assert KevFeed(feed_cache).lookup("CVE-2023-5678").ransomware is True
        assert KevFeed(feed_cache).lookup("CVE-2024-1086").ransomware is False

    def test_an_unlisted_cve_is_absent_not_an_error(self, feed_cache: Cache) -> None:
        assert KevFeed(feed_cache).lookup("CVE-9999-99999") is None

    def test_catalog_version_is_exposed(self, feed_cache: Cache) -> None:
        assert KevFeed(feed_cache).catalog_version() == "2026.09.17"


class TestEpss:
    def test_scores_parse_with_the_comment_header(self, feed_cache: Cache) -> None:
        score = EpssFeed(feed_cache).lookup("CVE-2024-1086")
        assert score is not None
        assert score.probability == pytest.approx(0.90723)
        assert score.date == "2026-09-17"

    @pytest.mark.parametrize(
        ("probability", "band"),
        [
            (0.9, "very high"),
            (0.2, "high"),
            (0.02, "moderate"),
            (0.0001, "low"),
        ],
    )
    def test_bands_are_words_a_human_can_act_on(self, probability: float, band: str) -> None:
        from cra24.feeds.epss import EpssScore

        assert EpssScore("CVE-X", probability, 0.5).band == band


class TestEuvd:
    def test_the_exploited_list_is_keyed_by_cve(self, feed_cache: Cache) -> None:
        record = EuvdFeed(feed_cache).exploited("CVE-2024-1086")
        assert record is not None
        assert record.id == "EUVD-2024-1086"
        assert record.exploited is True

    def test_newline_delimited_fields_are_split(self, feed_cache: Cache) -> None:
        """Several EUVD fields arrive as one string with embedded newlines."""
        record = EuvdFeed(feed_cache).exploited("CVE-2024-1086")
        assert "CVE-2024-1086" in record.aliases
        assert "GHSA-xxxx-yyyy-zzzz" in record.aliases

    def test_nested_vendor_and_product_names_are_flattened(self, feed_cache: Cache) -> None:
        record = EuvdFeed(feed_cache).exploited("CVE-2024-1086")
        assert record.vendors == ("Linux",)
        assert record.products == ("Kernel",)


class TestNvd:
    def test_cvss_is_read_from_the_cache(self, feed_cache: Cache) -> None:
        record = NvdFeed(feed_cache, HttpClient(offline=True)).lookup("CVE-2024-1086")
        assert record is not None
        assert record.base_score == 7.8
        assert record.severity_word() == "high"
        assert record.cvss_version == "3.1"

    def test_a_csaf_shaped_cvss_object_is_produced(self, feed_cache: Cache) -> None:
        record = NvdFeed(feed_cache, HttpClient(offline=True)).lookup("CVE-2024-1086")
        obj = record.cvss_object()
        assert obj["version"] == "3.1"
        assert obj["baseSeverity"] == "HIGH"

    def test_a_non_cve_identifier_is_not_looked_up(self, feed_cache: Cache) -> None:
        assert NvdFeed(feed_cache, HttpClient(offline=True)).lookup("GHSA-xxxx") is None

    def test_an_uncached_cve_returns_none_when_fetching_is_not_allowed(
        self, feed_cache: Cache
    ) -> None:
        feed = NvdFeed(feed_cache, HttpClient(offline=True))
        assert feed.lookup("CVE-1999-0001", allow_fetch=False) is None


class TestOsvParsing:
    def test_ranges_become_comparable_intervals(self, feed_cache: Cache) -> None:
        records = OsvFeed(feed_cache, HttpClient(offline=True)).query(
            "linux-raspberrypi",
            "6.6.22",
            purl="pkg:generic/linux-raspberrypi@6.6.22",
            allow_fetch=False,
        )
        assert records
        assert records[0].fixed_version() == "6.6.25"

    def test_several_intervals_do_not_collapse_into_one(self) -> None:
        """A record with two fixed ranges must stay two ranges."""
        doc = {
            "id": "CVE-X",
            "affected": [
                {
                    "package": {"ecosystem": "Linux", "name": "linux"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "5.0"},
                                {"fixed": "5.4"},
                                {"introduced": "6.0"},
                                {"fixed": "6.2"},
                            ],
                        }
                    ],
                }
            ],
        }
        record = _parse_record(doc)
        assert len(record.ranges) == 2
        assert record.fixed_version() == "5.4"
        assert record.affects("5.2") is True
        assert record.affects("5.9") is False
        assert record.affects("6.1") is True

    def test_git_ranges_are_skipped_not_misinterpreted(self) -> None:
        """A commit hash cannot be compared against a version string."""
        rng = AffectedRange(introduced="abc123", fixed="def456", type="GIT")
        assert rng.covers("6.6.22") is False

    def test_the_cve_is_found_in_aliases(self) -> None:
        record = _parse_record({"id": "GHSA-abcd", "aliases": ["CVE-2024-1086"]})
        assert record.cve == "CVE-2024-1086"


class TestEnrichment:
    def test_kev_presence_means_actively_exploited(self, offline_feeds: FeedSet) -> None:
        assert offline_feeds.enrich("CVE-2024-1086").actively_exploited is True

    def test_kev_absence_means_unknown_never_false(self, offline_feeds: FeedSet) -> None:
        """The judgement call this whole module exists to get right.

        KEV is conservative, curated and US-federal. Absence means CISA has not
        confirmed exploitation, which is not the same as confirming there is
        none — and a customer reporting an attack starts the clock regardless.
        """
        result = offline_feeds.enrich("CVE-2024-0727")
        assert result.actively_exploited is None
        assert any("absence is not evidence" in e.detail for e in result.evidence)

    def test_every_fact_names_the_feed_that_supplied_it(self, offline_feeds: FeedSet) -> None:
        result = offline_feeds.enrich("CVE-2024-1086")
        sources = {e.source for e in result.evidence}
        assert {"cisa-kev", "epss", "nvd", "enisa-euvd"} <= sources
        assert all(e.statement for e in result.evidence)

    def test_epss_is_labelled_as_a_prediction_not_evidence(
        self, offline_feeds: FeedSet
    ) -> None:
        result = offline_feeds.enrich("CVE-2024-1086")
        epss = next(e for e in result.evidence if e.source == "epss")
        assert "never evidence of active exploitation" in epss.detail

    def test_the_euvd_id_is_captured_for_the_srp_form(self, offline_feeds: FeedSet) -> None:
        assert offline_feeds.enrich("CVE-2024-1086").euvd_id == "EUVD-2024-1086"

    def test_osv_supplies_the_fixed_version(self, offline_feeds: FeedSet, product) -> None:
        from cra24.feeds.registry import best_component

        component = best_component(product, "CVE-2024-1086")
        result = offline_feeds.enrich("CVE-2024-1086", component)
        assert result.fixed_version == "6.6.25"

    def test_a_restricted_feedset_consults_only_what_it_was_given(
        self, feed_cache: Cache
    ) -> None:
        feeds = FeedSet(["kev"], cache=feed_cache, offline=True)
        result = feeds.enrich("CVE-2024-1086")
        assert result.consulted == ["kev"]
        assert result.epss is None


class TestCache:
    def test_a_missing_entry_points_at_the_fix(self, tmp_path: Path) -> None:
        from cra24.feeds.cache import CacheError

        with pytest.raises(CacheError) as excinfo:
            Cache(tmp_path).read_bytes("kev", "nope.json")
        assert "feeds sync" in str(excinfo.value)

    def test_the_payload_is_stored_byte_identical(self, tmp_path: Path) -> None:
        """So you can hash a cached artefact and show it is what the server sent."""
        cache = Cache(tmp_path)
        payload = b'{"hello": "world"}\n'
        entry = cache.write("test", "f.json", payload, url="https://example.invalid")
        assert cache.read_bytes("test", "f.json") == payload
        import hashlib

        assert entry.sha256 == hashlib.sha256(payload).hexdigest()

    def test_freshness_uses_the_recorded_fetch_time(self, tmp_path: Path) -> None:
        cache = Cache(tmp_path)
        cache.write("test", "f.json", b"{}")
        assert cache.is_fresh("test", "f.json", timedelta(hours=1))
        assert not cache.is_fresh("test", "f.json", timedelta(seconds=-1))

    def test_inventory_reports_what_is_cached(self, feed_cache: Cache) -> None:
        names = {e["feed"] for e in feed_cache.inventory()}
        assert {"kev", "epss", "euvd"} <= names


class TestFeedStatusNeverRaises:
    def test_a_corrupt_payload_does_not_break_status(self, tmp_path: Path) -> None:
        cache = Cache(tmp_path)
        cache.write("kev", "known_exploited_vulnerabilities.json", b"not json at all")
        status = KevFeed(cache).status()
        assert status.present is True
        assert status.records is None

    def test_every_feed_declares_a_host_and_a_purpose(self, tmp_path: Path) -> None:
        for feed in FeedSet(cache=Cache(tmp_path), offline=True).feeds.values():
            assert isinstance(feed, Feed)
            assert feed.host, f"{feed.name} does not say which host it contacts"
            assert feed.purpose
            assert feed.terms, f"{feed.name} does not state its terms of use"


class TestCacheContainment:
    """A cache entry name must not be able to leave the cache directory.

    The names are identifiers from outside: a CVE typed on the command line,
    but also one read out of an SBOM or a cve-check summary that some other
    build produced. ``root / feed / name`` is silently replaced by ``name`` when
    ``name`` is absolute, and one ``..`` too many walks out of the tree.
    """

    @pytest.fixture
    def cache(self, tmp_path: Path) -> Cache:
        return Cache(tmp_path / "cache")

    def test_an_ordinary_name_still_resolves_under_the_root(self, cache: Cache) -> None:
        p = cache.path("nvd", "cves/CVE-2024-1086.json")
        assert p == cache.root / "nvd" / "cves" / "CVE-2024-1086.json"

    @pytest.mark.parametrize(
        ("feed", "name"),
        [
            ("nvd", "cves/../../../../tmp/pwned.json"),
            ("nvd", "../escape.json"),
            ("nvd", "/etc/shadow"),
            ("../..", "x.json"),
            ("nvd", ""),
        ],
    )
    def test_an_escaping_name_is_refused(self, cache: Cache, feed: str, name: str) -> None:
        with pytest.raises(CacheError):
            cache.path(feed, name)

    def test_the_refusal_reaches_a_real_lookup(self, cache: Cache) -> None:
        """Not just the helper: the feed client must not write outside either."""
        with pytest.raises(CacheError):
            cache.write("nvd", "../../escaped.json", b"{}")


class TestResponseLimits:
    """A feed payload is advisory data, not an unbounded download."""

    def test_a_decompression_bomb_is_refused(self) -> None:
        import gzip

        from cra24.feeds.base import MAX_RESPONSE_BYTES, FeedError, _decompress

        bomb = gzip.compress(b"\0" * (MAX_RESPONSE_BYTES + 1024))
        assert len(bomb) < 1024 * 1024, "the point is that it is small compressed"
        with pytest.raises(FeedError, match="expands past"):
            _decompress(bomb, "gzip", "https://example.invalid/feed.json")

    def test_ordinary_gzip_still_round_trips(self) -> None:
        import gzip

        from cra24.feeds.base import _decompress

        payload = b'{"ok": true}'
        assert _decompress(gzip.compress(payload), "gzip", "https://x.invalid/f") == payload


class TestRedirectSafety:
    def test_https_is_not_followed_down_to_plaintext_http(self) -> None:
        """The answers end up in a filing; a TLS-stripping redirect is refused."""
        import urllib.error
        import urllib.request

        from cra24.feeds.base import _NoDowngradeRedirect

        handler = _NoDowngradeRedirect()
        request = urllib.request.Request("https://feed.invalid/a.json")
        with pytest.raises(urllib.error.HTTPError, match="refusing redirect"):
            handler.redirect_request(
                request, None, 302, "Found", {}, "http://feed.invalid/a.json"
            )

    def test_an_https_to_https_redirect_is_still_followed(self) -> None:
        import urllib.request

        from cra24.feeds.base import _NoDowngradeRedirect

        handler = _NoDowngradeRedirect()
        request = urllib.request.Request("https://feed.invalid/a.json")
        new = handler.redirect_request(
            request, None, 302, "Found", {}, "https://cdn.invalid/a.json"
        )
        assert new is not None
