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
# TikTok
# ---------------------------------------------------------------------------


class TestTikTokAdapter:
    def test_regular_video(self, translator):
        result = translator.translate("https://www.tiktok.com/@user/video/123456")
        assert "user" in result
        assert "tiktok.com" not in result

    def test_vm_short_link_not_translated(self, translator):
        # vm.tiktok.com richiede risoluzione server-side → non traducibile
        url = "https://vm.tiktok.com/ZMxxxxxx/"
        assert translator.translate(url) == url


# ---------------------------------------------------------------------------
# Wikipedia
# ---------------------------------------------------------------------------


class TestWikipediaAdapter:
    def test_italian_wikipedia(self, translator):
        result = translator.translate("https://it.wikipedia.org/wiki/Python")
        assert "it" in result
        assert "Python" in result
        assert "wikipedia.org" not in result

    def test_english_wikipedia(self, translator):
        result = translator.translate("https://en.wikipedia.org/wiki/URL")
        assert "en" in result
        assert "URL" in result

    def test_www_wikipedia_not_translated(self, translator):
        # www.wikipedia.org non ha un codice lingua → None → URL invariato
        url = "https://www.wikipedia.org/"
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
