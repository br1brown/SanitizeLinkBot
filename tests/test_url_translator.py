"""Test per UrlTranslator: ogni adapter converte gli URL verso il frontend alternativo."""

import pytest
from sanitizelinkbot.url_translator import UrlTranslator


@pytest.fixture
def translator():
    return UrlTranslator()


# ---------------------------------------------------------------------------
# YouTube
# ---------------------------------------------------------------------------


class TestYouTubeAdapter:
    def test_watch_url(self, translator):
        result = translator.translate("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        assert "dQw4w9WgXcQ" in result
        assert "youtube.com" not in result

    def test_youtu_be_short_link(self, translator):
        result = translator.translate("https://youtu.be/dQw4w9WgXcQ")
        assert "dQw4w9WgXcQ" in result
        assert "youtu.be" not in result

    def test_shorts_converted_to_watch(self, translator):
        result = translator.translate("https://www.youtube.com/shorts/abcDEF123")
        assert "abcDEF123" in result
        assert "shorts" not in result

    def test_channel_handle(self, translator):
        result = translator.translate("https://www.youtube.com/@MrBeast")
        assert "@MrBeast" in result
        assert "youtube.com" not in result

    def test_playlist(self, translator):
        result = translator.translate("https://www.youtube.com/playlist?list=PLxxx")
        assert "PLxxx" in result

    def test_search(self, translator):
        result = translator.translate(
            "https://www.youtube.com/results?search_query=cats"
        )
        assert "cats" in result

    def test_time_param_preserved(self, translator):
        result = translator.translate("https://www.youtube.com/watch?v=abc&t=120")
        assert "t=120" in result

    def test_tracking_params_dropped(self, translator):
        result = translator.translate("https://youtu.be/abc?si=tracker123")
        assert "si=" not in result


# ---------------------------------------------------------------------------
# Twitter / X
# ---------------------------------------------------------------------------


class TestTwitterAdapter:
    def test_status_url(self, translator):
        result = translator.translate("https://twitter.com/user/status/12345")
        assert "12345" in result
        assert "twitter.com" not in result
        assert "x.com" not in result

    def test_x_com_status_url(self, translator):
        result = translator.translate("https://x.com/user/status/12345")
        assert "12345" in result
        assert "x.com" not in result

    def test_profile_url(self, translator):
        result = translator.translate("https://twitter.com/nasa")
        assert "nasa" in result
        assert "twitter.com" not in result


# ---------------------------------------------------------------------------
# TikTok e Wikipedia: adapter disabilitati (frontend offline), URL invariati
# ---------------------------------------------------------------------------


class TestDisabledAdapters:
    def test_tiktok_not_translated(self, translator):
        url = "https://www.tiktok.com/@user/video/123456"
        assert translator.translate(url) == url

    def test_wikipedia_not_translated(self, translator):
        url = "https://it.wikipedia.org/wiki/Python"
        assert translator.translate(url) == url


# ---------------------------------------------------------------------------
# Google Search
# ---------------------------------------------------------------------------


class TestGoogleSearchAdapter:
    def test_search_redirected_to_duckduckgo(self, translator):
        result = translator.translate("https://www.google.com/search?q=python+testing")
        assert "duckduckgo.com" in result
        assert "python+testing" in result or "python" in result

    def test_non_search_google_not_translated(self, translator):
        url = "https://www.google.com/maps"
        # /maps non è /search → GoogleSearchAdapter ritorna None → URL invariato
        result = translator.translate(url)
        assert result == url


# ---------------------------------------------------------------------------
# Google Maps
# ---------------------------------------------------------------------------


class TestGoogleMapsAdapter:
    def test_maps_with_query(self, translator):
        result = translator.translate("https://maps.google.com/?q=Rome")
        assert "openstreetmap.org" in result
        assert "Rome" in result

    def test_maps_without_query(self, translator):
        result = translator.translate("https://maps.google.com/")
        assert "openstreetmap.org" in result


# ---------------------------------------------------------------------------
# Genius
# ---------------------------------------------------------------------------


class TestGeniusAdapter:
    def test_lyrics_page(self, translator):
        result = translator.translate(
            "https://genius.com/Rick-astley-never-gonna-give-you-up-lyrics"
        )
        assert result == "https://lyrics.leemoon.network/Rick-astley-never-gonna-give-you-up-lyrics"

    def test_homepage_not_translated(self, translator):
        url = "https://genius.com/"
        assert translator.translate(url) == url


# ---------------------------------------------------------------------------
# Fandom
# ---------------------------------------------------------------------------


class TestFandomAdapter:
    def test_wiki_page(self, translator):
        result = translator.translate("https://zelda.fandom.com/wiki/Link")
        assert result == "https://antifandom.com/zelda/wiki/Link"

    def test_wiki_root(self, translator):
        result = translator.translate("https://zelda.fandom.com/")
        assert result == "https://antifandom.com/zelda/"

    def test_non_fandom_not_translated(self, translator):
        url = "https://example.com/wiki/Page"
        assert translator.translate(url) == url


# ---------------------------------------------------------------------------
# UrlTranslator generale
# ---------------------------------------------------------------------------


class TestUrlTranslator:
    def test_unknown_domain_returned_unchanged(self, translator):
        url = "https://example.com/page?v=123"
        assert translator.translate(url) == url

    def test_malformed_url_returned_unchanged(self, translator):
        url = "not_a_url"
        assert translator.translate(url) == url

    def test_www_stripped_for_matching(self, translator):
        # youtube.com e www.youtube.com devono entrambi matchare
        r1 = translator.translate("https://youtube.com/watch?v=abc")
        r2 = translator.translate("https://www.youtube.com/watch?v=abc")
        assert r1 == r2

    def test_list_frontends_reflects_active_adapters(self, translator):
        # Ogni voce ha servizio/frontend/url valorizzati; nessuna riga per un adapter disabilitato
        frontends = translator.list_frontends()
        assert len(frontends) == len(translator.adapters)
        services = [service for service, _frontend, _url in frontends]
        assert "YouTube" in services
        assert "Genius" in services
        assert "Fandom" in services
        for service, frontend, url in frontends:
            assert service and frontend and url
