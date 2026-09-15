"""Test per PageSignals: metodi statici e logica di equivalenza."""

import pytest
from sanitizelinkbot.sanitizer import PageSignals, _title_matches_hostname

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sig(**kwargs) -> PageSignals:
    """Crea un PageSignals minimale con valori di default neutri."""
    defaults = dict(
        final_url="https://example.com/page",
        url_path="https://example.com/page",
        status=200,
        content_type="text/html",
        etag=None,
        lastmod=None,
        canonical=None,
        og_url=None,
        title=None,
        chunk_hash=None,
    )
    defaults.update(kwargs)
    return PageSignals(**defaults)


# ---------------------------------------------------------------------------
# _ok
# ---------------------------------------------------------------------------


class TestOk:
    def test_2xx_ok(self):
        assert PageSignals._ok(200)
        assert PageSignals._ok(204)
        assert PageSignals._ok(299)

    def test_3xx_ok(self):
        assert PageSignals._ok(301)
        assert PageSignals._ok(302)
        assert PageSignals._ok(399)

    def test_401_403_ok(self):
        assert PageSignals._ok(401)
        assert PageSignals._ok(403)

    def test_404_500_not_ok(self):
        assert not PageSignals._ok(404)
        assert not PageSignals._ok(500)
        assert not PageSignals._ok(199)


# ---------------------------------------------------------------------------
# is_url_ok
# ---------------------------------------------------------------------------


class TestIsUrlOk:
    def test_200_https(self):
        assert _sig(status=200, final_url="https://example.com").is_url_ok()

    def test_200_http(self):
        assert _sig(status=200, final_url="http://example.com").is_url_ok()

    def test_404_not_ok(self):
        assert not _sig(status=404, final_url="https://example.com").is_url_ok()

    def test_ftp_scheme_not_ok(self):
        assert not _sig(status=200, final_url="ftp://example.com").is_url_ok()

    def test_401_https_ok(self):
        # 401 conferma che la risorsa esiste (richiede autenticazione)
        assert _sig(status=401, final_url="https://example.com").is_url_ok()


# ---------------------------------------------------------------------------
# _norm_etag
# ---------------------------------------------------------------------------


class TestNormEtag:
    def test_none_returns_none(self):
        assert PageSignals._norm_etag(None) is None

    def test_empty_returns_none(self):
        assert PageSignals._norm_etag("") is None

    def test_strips_weak_prefix(self):
        assert PageSignals._norm_etag('W/"abc123"') == "abc123"

    def test_strips_double_quotes(self):
        assert PageSignals._norm_etag('"abc123"') == "abc123"

    def test_strips_single_quotes(self):
        assert PageSignals._norm_etag("'abc123'") == "abc123"

    def test_plain_value_unchanged(self):
        assert PageSignals._norm_etag("abc123") == "abc123"

    def test_whitespace_stripped(self):
        assert PageSignals._norm_etag('  "abc123"  ') == "abc123"

    def test_weak_with_spaces(self):
        assert PageSignals._norm_etag('W/ "xyz"') == "xyz"


# ---------------------------------------------------------------------------
# _same_html_type
# ---------------------------------------------------------------------------


class TestSameHtmlType:
    def test_both_html(self):
        assert PageSignals._same_html_type("text/html", "text/html")

    def test_html_and_xhtml_equivalent(self):
        assert PageSignals._same_html_type("text/html", "application/xhtml+xml")

    def test_html_with_charset(self):
        assert PageSignals._same_html_type("text/html; charset=utf-8", "text/html")

    def test_both_same_non_html(self):
        assert PageSignals._same_html_type("application/json", "application/json")

    def test_different_non_html(self):
        assert not PageSignals._same_html_type("application/json", "application/pdf")

    def test_html_vs_json_not_same(self):
        assert not PageSignals._same_html_type("text/html", "application/json")

    def test_none_a_returns_true(self):
        # Informazione mancante → consideriamo compatibili (non possiamo escludere)
        assert PageSignals._same_html_type(None, "text/html")

    def test_none_b_returns_true(self):
        assert PageSignals._same_html_type("text/html", None)

    def test_both_none_returns_true(self):
        assert PageSignals._same_html_type(None, None)


# ---------------------------------------------------------------------------
# _normalize_url_path
# ---------------------------------------------------------------------------


class TestNormalizeUrlPath:
    def test_none_returns_none(self):
        assert PageSignals._normalize_url_path(None) is None

    def test_empty_returns_none(self):
        assert PageSignals._normalize_url_path("") is None

    def test_strips_default_http_port(self):
        assert PageSignals._normalize_url_path(
            "http://example.com:80/page"
        ) == PageSignals._normalize_url_path("http://example.com/page")

    def test_strips_default_https_port(self):
        assert PageSignals._normalize_url_path(
            "https://example.com:443/page"
        ) == PageSignals._normalize_url_path("https://example.com/page")

    def test_keeps_non_default_port(self):
        result = PageSignals._normalize_url_path("https://example.com:8080/page")
        assert ":8080" in result

    def test_strips_trailing_slash(self):
        assert PageSignals._normalize_url_path(
            "https://example.com/page/"
        ) == PageSignals._normalize_url_path("https://example.com/page")

    def test_root_slash_kept(self):
        # La root "/" non deve diventare stringa vuota
        result = PageSignals._normalize_url_path("https://example.com/")
        assert result.endswith("/")

    def test_strips_query_string(self):
        a = PageSignals._normalize_url_path("https://example.com/page?foo=bar")
        b = PageSignals._normalize_url_path("https://example.com/page")
        assert a == b

    def test_strips_fragment(self):
        a = PageSignals._normalize_url_path("https://example.com/page#section")
        b = PageSignals._normalize_url_path("https://example.com/page")
        assert a == b

    def test_lowercase(self):
        assert PageSignals._normalize_url_path(
            "HTTPS://EXAMPLE.COM/Page"
        ) == PageSignals._normalize_url_path("https://example.com/Page")


# ---------------------------------------------------------------------------
# _normalize_title
# ---------------------------------------------------------------------------


class TestNormalizeTitle:
    def test_none_returns_none(self):
        assert PageSignals._normalize_title(None) is None

    def test_empty_returns_none(self):
        assert PageSignals._normalize_title("") is None
        assert PageSignals._normalize_title("   ") is None

    def test_html_entity_unescaped(self):
        assert PageSignals._normalize_title("Hello &amp; World") == "Hello & World"

    def test_zero_width_chars_removed(self):
        assert PageSignals._normalize_title("Hel\u200blo") == "Hello"
        assert PageSignals._normalize_title("Te\ufeffxt") == "Text"

    def test_non_breaking_space_normalized(self):
        assert PageSignals._normalize_title("Hello\u00a0World") == "Hello World"

    def test_multiple_spaces_collapsed(self):
        assert PageSignals._normalize_title("Hello   World") == "Hello World"

    def test_leading_trailing_stripped(self):
        assert PageSignals._normalize_title("  Hello  ") == "Hello"

    def test_normal_title_unchanged(self):
        assert PageSignals._normalize_title("Titolo normale") == "Titolo normale"


# ---------------------------------------------------------------------------
# _pick_charset
# ---------------------------------------------------------------------------


class TestPickCharset:
    def test_none_returns_utf8(self):
        assert PageSignals._pick_charset(None) == "utf-8"

    def test_no_charset_in_header_returns_utf8(self):
        assert PageSignals._pick_charset("text/html") == "utf-8"

    def test_charset_extracted(self):
        assert (
            PageSignals._pick_charset("text/html; charset=iso-8859-1") == "iso-8859-1"
        )

    def test_charset_with_quotes(self):
        assert PageSignals._pick_charset('text/html; charset="utf-8"') == "utf-8"

    def test_charset_uppercase_header(self):
        result = PageSignals._pick_charset("text/html; CHARSET=windows-1252")
        assert result == "windows-1252"


# ---------------------------------------------------------------------------
# equivalent_to
# ---------------------------------------------------------------------------


class TestEquivalentTo:
    def test_none_other_returns_false(self):
        assert not _sig().equivalent_to(None)

    def test_etag_match(self):
        a = _sig(etag='"abc"')
        b = _sig(etag='"abc"', url_path="https://other.com/different")
        assert a.equivalent_to(b)

    def test_weak_etag_matches_strong(self):
        a = _sig(etag='"abc"')
        b = _sig(etag='W/"abc"')
        assert a.equivalent_to(b)

    def test_different_etags_not_equal(self):
        a = _sig(etag='"abc"')
        b = _sig(etag='"xyz"')
        assert not a.equivalent_to(b)

    def test_lastmod_and_path_match(self):
        a = _sig(
            lastmod="Mon, 01 Jan 2024 00:00:00 GMT", url_path="https://example.com/page"
        )
        b = _sig(
            lastmod="Mon, 01 Jan 2024 00:00:00 GMT",
            url_path="https://example.com/page?utm=x",
        )
        assert a.equivalent_to(b)

    def test_lastmod_same_but_different_paths(self):
        a = _sig(
            lastmod="Mon, 01 Jan 2024 00:00:00 GMT",
            url_path="https://example.com/page1",
        )
        b = _sig(
            lastmod="Mon, 01 Jan 2024 00:00:00 GMT",
            url_path="https://example.com/page2",
        )
        assert not a.equivalent_to(b)

    def test_canonical_match(self):
        a = _sig(canonical="https://example.com/canonical")
        b = _sig(canonical="https://example.com/canonical")
        assert a.equivalent_to(b)

    def test_og_url_used_as_canonical_fallback(self):
        a = _sig(og_url="https://example.com/canonical")
        b = _sig(canonical="https://example.com/canonical")
        assert a.equivalent_to(b)

    def test_chunk_hash_match_same_content_type(self):
        a = _sig(chunk_hash="deadbeef", content_type="text/html")
        b = _sig(
            chunk_hash="deadbeef",
            content_type="text/html",
            url_path="https://other.com/x",
        )
        assert a.equivalent_to(b)

    def test_chunk_hash_match_different_content_type(self):
        a = _sig(chunk_hash="deadbeef", content_type="text/html")
        b = _sig(chunk_hash="deadbeef", content_type="application/json")
        assert not a.equivalent_to(b)

    def test_title_and_path_match(self):
        a = _sig(title="Pagina di esempio", url_path="https://example.com/page")
        b = _sig(title="Pagina di esempio", url_path="https://example.com/page?utm=x")
        assert a.equivalent_to(b)

    def test_same_title_different_paths(self):
        a = _sig(title="Home", url_path="https://example.com/")
        b = _sig(title="Home", url_path="https://other.com/")
        assert not a.equivalent_to(b)

    def test_check_url_false_no_match(self):
        a = _sig(url_path="https://example.com/page")
        b = _sig(url_path="https://example.com/page")
        # Nessun segnale forte → False senza check_url
        assert not a.equivalent_to(b, check_url=False)

    def test_check_url_true_matching_paths(self):
        a = _sig(url_path="https://example.com/page")
        b = _sig(url_path="https://example.com/page?utm=x")
        assert a.equivalent_to(b, check_url=True)

    def test_check_url_true_different_paths(self):
        a = _sig(url_path="https://example.com/page1")
        b = _sig(url_path="https://example.com/page2")
        assert not a.equivalent_to(b, check_url=True)


# ---------------------------------------------------------------------------
# _title_matches_hostname
# ---------------------------------------------------------------------------


class TestTitleMatchesHostname:
    def test_bare_brand_name_matches(self):
        assert _title_matches_hostname("Instagram", "instagram.com")
        assert _title_matches_hostname("TikTok", "tiktok.com")
        assert _title_matches_hostname("X", "x.com")

    def test_hyphenated_host_matches_spaced_title(self):
        assert _title_matches_hostname("Cool App", "cool-app.com")
        assert _title_matches_hostname("Some Cool Startup", "some-cool-startup.com")

    def test_missing_title_never_matches(self):
        assert not _title_matches_hostname(None, "instagram.com")
        assert not _title_matches_hostname("", "instagram.com")

    def test_real_content_title_does_not_match(self):
        assert not _title_matches_hostname(
            "Mario Rossi on Instagram: \"bella giornata\"", "instagram.com"
        )
        assert not _title_matches_hostname("Qualcuno (@utente) su X", "x.com")

    def test_word_boundary_avoids_false_positive(self):
        # "x" non deve combaciare con la "x" dentro "example.com"
        assert not _title_matches_hostname("x", "example.com")

    def test_subdomain_still_contains_hostname(self):
        assert _title_matches_hostname("Instagram", "www2.instagram.com")

    def test_unrelated_title_does_not_match(self):
        assert not _title_matches_hostname("Instagram", "example.com")

    def test_brand_with_tagline_after_dash_matches(self):
        # Placeholder reali: il nome del sito da solo non basta, c'è quasi sempre
        # una tagline fissa dietro un separatore ("Brand - tagline generica").
        assert _title_matches_hostname("TikTok - Make Your Day", "tiktok.com")
        assert _title_matches_hostname(
            "Facebook - log in or sign up", "facebook.com"
        )

    def test_brand_with_trailing_parenthetical_matches(self):
        assert _title_matches_hostname("X (formerly Twitter)", "x.com")

    def test_real_content_before_dash_does_not_match(self):
        # Il titolo di un articolo reale ("Titolo - Wikipedia") non deve scattare:
        # il primo segmento è il contenuto, non il nome del sito.
        assert not _title_matches_hostname(
            "Python (programming language) - Wikipedia", "en.wikipedia.org"
        )

    def test_empty_content_before_dash_matches(self):
        # YouTube (e altri siti che popolano <title> via JS) a volte rispondono con
        # "- YouTube": nessun titolo video prima del separatore, solo il brand dopo.
        # Deve scattare come placeholder per attivare il fallback crawler UA.
        assert _title_matches_hostname("- YouTube", "youtube.com")
        assert _title_matches_hostname("- YouTube", "www.youtube.com")

    def test_homesite_tagline_is_an_accepted_tradeoff(self):
        # Compromesso accettato: allargando il controllo per beccare "Brand - tagline"
        # sui siti-app JS, scatta anche su siti normali la cui homepage usa lo stesso
        # schema (falso positivo innocuo: fa solo una richiesta in più col crawler UA).
        assert _title_matches_hostname(
            "Wikipedia - Enciclopedia libera", "it.wikipedia.org"
        )
