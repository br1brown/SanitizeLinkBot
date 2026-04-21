"""Test per Sanitizer: metodi non-network e comportamento della cache/batch."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sanitizelinkbot.sanitizer import Sanitizer
from sanitizelinkbot.chat_prefs import SanitizerOpts


def _opts(show_title=False, show_url=True, use_privacy_frontend=False) -> SanitizerOpts:
    return SanitizerOpts(
        show_url=show_url,
        show_title=show_title,
        use_privacy_frontend=use_privacy_frontend,
    )


# ---------------------------------------------------------------------------
# is_key_to_remove
# ---------------------------------------------------------------------------


class TestIsKeyToRemove:
    def test_exact_match(self, sanitizer):
        assert sanitizer.is_key_to_remove("fbclid")
        assert sanitizer.is_key_to_remove("utm_source")
        assert sanitizer.is_key_to_remove("utm_medium")

    def test_prefix_match(self, sanitizer):
        assert sanitizer.is_key_to_remove("utm_campaign")
        assert sanitizer.is_key_to_remove("utm_anything_here")

    def test_suffix_match(self, sanitizer):
        assert sanitizer.is_key_to_remove("click_tracking")
        assert sanitizer.is_key_to_remove("ad_tracking")

    def test_case_insensitive(self, sanitizer):
        assert sanitizer.is_key_to_remove("FBCLID")
        assert sanitizer.is_key_to_remove("UTM_Source")

    def test_legitimate_param_kept(self, sanitizer):
        assert not sanitizer.is_key_to_remove("q")
        assert not sanitizer.is_key_to_remove("page")
        assert not sanitizer.is_key_to_remove("id")
        assert not sanitizer.is_key_to_remove("v")

    def test_empty_key_not_removed(self, sanitizer):
        assert not sanitizer.is_key_to_remove("")


# ---------------------------------------------------------------------------
# _strip_tracking_params
# ---------------------------------------------------------------------------


class TestStripTrackingParams:
    def test_removes_exact_key(self, sanitizer):
        result = sanitizer._strip_tracking_params(
            "https://example.com/page?fbclid=ABC123&q=python"
        )
        assert "fbclid" not in result
        assert "q=python" in result

    def test_removes_prefix_key(self, sanitizer):
        result = sanitizer._strip_tracking_params(
            "https://example.com/?utm_campaign=spring&v=42"
        )
        assert "utm_campaign" not in result
        assert "v=42" in result

    def test_removes_suffix_key(self, sanitizer):
        result = sanitizer._strip_tracking_params(
            "https://example.com/?click_tracking=x&page=2"
        )
        assert "click_tracking" not in result
        assert "page=2" in result

    def test_keeps_all_legitimate_params(self, sanitizer):
        url = "https://example.com/search?q=hello&page=2&sort=asc"
        result = sanitizer._strip_tracking_params(url)
        assert result == url

    def test_removes_fragment_with_frag_key(self, sanitizer):
        result = sanitizer._strip_tracking_params(
            "https://example.com/page#utm_campaign_anchor"
        )
        assert "#" not in result

    def test_keeps_legitimate_fragment(self, sanitizer):
        url = "https://example.com/page#section-2"
        result = sanitizer._strip_tracking_params(url)
        assert "#section-2" in result

    def test_keeps_wikipedia_style_fragments(self, conf):
        # 'ref' è una chiave di tracking, ma non deve matchare 'referenze'
        sanitizer = Sanitizer(
            exact_keys=set(), prefix_keys=(), ends_with=(),
            frag_keys=("ref", "fbclid", "utm_"), conf=conf
        )
        url = "https://it.wikipedia.org/wiki/Python#Referenze"
        result = sanitizer._strip_tracking_params(url)
        assert "#Referenze" in result

        url = "https://it.wikipedia.org/wiki/Ossido_di_diazoto#Utilizzi"
        result = sanitizer._strip_tracking_params(url)
        assert "#Utilizzi" in result

    def test_removes_fragment_with_exact_tracking_key(self, conf):
        sanitizer = Sanitizer(
            exact_keys=set(), prefix_keys=(), ends_with=(),
            frag_keys=("ref", "fbclid", "utm_"), conf=conf
        )
        result = sanitizer._strip_tracking_params("https://example.com/page#fbclid")
        assert "#" not in result

    def test_removes_fragment_with_tracking_key_value(self, conf):
        # ref=... deve essere rimosso, ref è in FRAG_KEYS
        sanitizer = Sanitizer(
            exact_keys=set(), prefix_keys=(), ends_with=(),
            frag_keys=("ref", "fbclid", "utm_"), conf=conf
        )
        result = sanitizer._strip_tracking_params("https://example.com/page#ref=12345")
        assert "#" not in result

    def test_removes_fragment_with_separator_prefix(self, conf):
        # utm_ è in FRAG_KEYS e finisce con _
        sanitizer = Sanitizer(
            exact_keys=set(), prefix_keys=(), ends_with=(),
            frag_keys=("ref", "fbclid", "utm_"), conf=conf
        )
        result = sanitizer._strip_tracking_params("https://example.com/#utm_campaign=winter")
        assert "#" not in result

    def test_empty_query_after_removal(self, sanitizer):
        result = sanitizer._strip_tracking_params(
            "https://example.com/?fbclid=x&utm_source=y"
        )
        assert (
            "?" not in result
            or result.endswith("?")
            or "=" not in result.split("?")[-1]
        )

    def test_malformed_url_returned_unchanged(self, sanitizer):
        # URL che non riesce a fare parsing → ritorna l'originale senza eccezioni
        bad = "not_a_url_at_all"
        result = sanitizer._strip_tracking_params(bad)
        assert result == bad

    def test_url_without_params_unchanged(self, sanitizer):
        url = "https://example.com/page"
        assert sanitizer._strip_tracking_params(url) == url

    def test_preserves_original_encoding_when_nothing_removed(self, sanitizer):
        """Se nessun parametro viene rimosso, l'URL deve essere restituito invariato.

        Bug storico: parse_qsl+urlencode normalizzava la percent-encoding anche per
        i parametri non toccati. Es. q=https://example.com/ diventava
        q=https%3A%2F%2Fexample.com%2F — semanticamente uguale ma string-diverso.
        Impattava URLs tipo Google Search con un URL come valore di q=.
        """
        # URL con un valore di parametro che contiene caratteri speciali non codificati
        url = "https://www.google.com/search?q=https://www.example.com/page?id=42"
        result = sanitizer._strip_tracking_params(url)
        # Nessun tracker → URL identico all'originale, encoding preservato
        assert result == url

    def test_encoding_normalized_only_for_changed_params(self, sanitizer):
        """Quando rimuoviamo un tracker, i parametri rimanenti vengono ricodificati.
        Questo è accettabile: l'URL è comunque semanticamente corretto.
        """
        # fbclid è un tracker, q non lo è
        url = "https://www.google.com/search?q=https://example.com/&fbclid=ABC"
        result = sanitizer._strip_tracking_params(url)
        assert "fbclid" not in result
        assert "q=" in result
        assert "example.com" in result

    def test_multiple_tracking_params_all_removed(self, sanitizer):
        result = sanitizer._strip_tracking_params(
            "https://example.com/?utm_source=x&utm_medium=y&fbclid=z&v=42"
        )
        assert "utm_source" not in result
        assert "utm_medium" not in result
        assert "fbclid" not in result
        assert "v=42" in result


# ---------------------------------------------------------------------------
# _extract_consent_continue (funzione modulo-level)
# ---------------------------------------------------------------------------


class TestExtractConsentContinue:
    def test_consent_google_extracts_continue(self):
        from sanitizelinkbot.sanitizer import _extract_consent_continue

        # Il valore di continue= è URL-encoded nella query string; parse_qsl lo decodifica
        url = (
            "https://consent.google.com/m"
            "?continue=https://maps.google.com/maps%3Fq%3D44.6,10.2"
            "&gl=IT&hl=it"
        )
        result = _extract_consent_continue(url)
        # parse_qsl decodifica %3F → ? e %3D → =
        assert result == "https://maps.google.com/maps?q=44.6,10.2"

    def test_non_consent_domain_returns_none(self):
        from sanitizelinkbot.sanitizer import _extract_consent_continue

        assert _extract_consent_continue("https://www.google.com/search?q=test") is None

    def test_consent_domain_no_continue_param_returns_none(self):
        from sanitizelinkbot.sanitizer import _extract_consent_continue

        url = "https://consent.google.com/m?gl=IT&hl=it"
        assert _extract_consent_continue(url) is None

    def test_continue_must_be_http(self):
        """continue= con valore non-http non deve essere restituito."""
        from sanitizelinkbot.sanitizer import _extract_consent_continue

        url = "https://consent.google.com/m?continue=javascript:alert(1)"
        assert _extract_consent_continue(url) is None


# ---------------------------------------------------------------------------
# _unwrap_link_wrapper (con ClearURLs mockato)
# ---------------------------------------------------------------------------


class TestUnwrapLinkWrapper:
    def test_no_clearurls_returns_original(self, sanitizer):
        url = "https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.com"
        assert sanitizer._unwrap_link_wrapper(url) == url

    def test_clearurls_not_loaded_returns_original(self, sanitizer):
        mock_loader = MagicMock()
        mock_loader.is_loaded = False
        sanitizer._clearurls = mock_loader
        url = "https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.com"
        assert sanitizer._unwrap_link_wrapper(url) == url

    def test_clearurls_returns_extracted_url(self, sanitizer):
        mock_loader = MagicMock()
        mock_loader.is_loaded = True
        mock_loader.find_providers.return_value = [MagicMock()]
        mock_loader.apply_redirections.return_value = "https://example.com"
        sanitizer._clearurls = mock_loader
        result = sanitizer._unwrap_link_wrapper("https://l.facebook.com/l.php?u=...")
        assert result == "https://example.com"

    def test_clearurls_no_match_returns_original(self, sanitizer):
        mock_loader = MagicMock()
        mock_loader.is_loaded = True
        mock_loader.find_providers.return_value = []
        mock_loader.apply_redirections.return_value = None
        sanitizer._clearurls = mock_loader
        url = "https://example.com/page"
        assert sanitizer._unwrap_link_wrapper(url) == url


# ---------------------------------------------------------------------------
# _clean_with_clearurls (con ClearURLs mockato)
# ---------------------------------------------------------------------------


class TestCleanWithClearurls:
    def test_no_clearurls_returns_original(self, sanitizer):
        url = "https://amazon.com/dp/B01?tag=affiliate&pd_rd_r=xyz"
        assert sanitizer._clean_with_clearurls(url) == url

    def test_no_providers_returns_original(self, sanitizer):
        mock_loader = MagicMock()
        mock_loader.is_loaded = True
        mock_loader.find_providers.return_value = []
        sanitizer._clearurls = mock_loader
        url = "https://unknown-domain.com/?fbclid=x"
        assert sanitizer._clean_with_clearurls(url) == url

    def test_apply_cleaning_called_with_providers(self, sanitizer):
        providers = [MagicMock()]
        mock_loader = MagicMock()
        mock_loader.is_loaded = True
        mock_loader.find_providers.return_value = providers
        mock_loader.apply_cleaning.return_value = "https://amazon.com/dp/B01"
        sanitizer._clearurls = mock_loader
        result = sanitizer._clean_with_clearurls("https://amazon.com/dp/B01?tag=x")
        assert result == "https://amazon.com/dp/B01"
        mock_loader.apply_cleaning.assert_called_once()


# ---------------------------------------------------------------------------
# sanitize_url: schema, mailto/tel, cache
# ---------------------------------------------------------------------------


class TestSanitizeUrl:
    async def test_empty_url_returns_empty(self, sanitizer):
        result = await sanitizer.sanitize_url("", opts=_opts())
        assert result == ("", None)

    async def test_mailto_returned_unchanged(self, sanitizer):
        url = "mailto:user@example.com"
        result, title = await sanitizer.sanitize_url(url, opts=_opts())
        assert result == url
        assert title is None

    async def test_tel_returned_unchanged(self, sanitizer):
        url = "tel:+391234567890"
        result, title = await sanitizer.sanitize_url(url, opts=_opts())
        assert result == url

    async def test_schema_added_if_missing(self, sanitizer):
        sanitizer._sanitize_url_impl = AsyncMock(
            return_value=("https://example.com", None)
        )
        await sanitizer.sanitize_url("example.com", opts=_opts())
        called_url = sanitizer._sanitize_url_impl.call_args[0][0]
        assert called_url.startswith("https://")

    async def test_cache_hit_skips_impl(self, sanitizer):
        sanitizer._sanitize_url_impl = AsyncMock(
            return_value=("https://clean.com", "Titolo")
        )
        opts = _opts()
        r1 = await sanitizer.sanitize_url("https://dirty.com?fbclid=x", opts=opts)
        r2 = await sanitizer.sanitize_url("https://dirty.com?fbclid=x", opts=opts)
        assert r1 == r2
        sanitizer._sanitize_url_impl.assert_called_once()

    async def test_different_opts_different_cache_entries(self, sanitizer):
        sanitizer._sanitize_url_impl = AsyncMock(
            return_value=("https://clean.com", None)
        )
        opts_a = _opts(show_title=False)
        opts_b = _opts(show_title=True)
        await sanitizer.sanitize_url("https://example.com", opts=opts_a)
        await sanitizer.sanitize_url("https://example.com", opts=opts_b)
        assert sanitizer._sanitize_url_impl.call_count == 2


# ---------------------------------------------------------------------------
# sanitize_batch: ordine, dedup, lista vuota
# ---------------------------------------------------------------------------


class TestSanitizeBatch:
    async def test_empty_list_returns_empty(self, sanitizer):
        result = await sanitizer.sanitize_batch(_opts(), [])
        assert result == []

    async def test_only_empty_strings(self, sanitizer):
        result = await sanitizer.sanitize_batch(_opts(), ["", "  ", ""])
        assert all(r == ("", None) for r in result)

    async def test_order_preserved(self, sanitizer):
        async def fake_sanitize(url, *, opts):
            return (f"clean:{url}", None)

        sanitizer.sanitize_url = fake_sanitize
        urls = ["https://a.com", "https://b.com", "https://c.com"]
        result = await sanitizer.sanitize_batch(_opts(), urls)
        assert [r[0] for r in result] == [f"clean:{u}" for u in urls]

    async def test_duplicate_urls_processed_once(self, sanitizer):
        call_count = 0

        async def fake_sanitize(url, *, opts):
            nonlocal call_count
            call_count += 1
            return ("https://clean.com", None)

        sanitizer.sanitize_url = fake_sanitize
        result = await sanitizer.sanitize_batch(
            _opts(), ["https://same.com", "https://same.com", "https://same.com"]
        )
        assert call_count == 1
        assert len(result) == 3
        assert all(r == ("https://clean.com", None) for r in result)

    async def test_mixed_duplicate_and_unique(self, sanitizer):
        async def fake_sanitize(url, *, opts):
            return (f"clean:{url}", None)

        sanitizer.sanitize_url = fake_sanitize
        urls = ["https://a.com", "https://b.com", "https://a.com"]
        result = await sanitizer.sanitize_batch(_opts(), urls)
        assert result[0] == result[2]  # stessa URL → stesso risultato
        assert result[0] != result[1]  # URL diversa → risultato diverso

    async def test_whitelist_url_passes_through(self, sanitizer, conf):
        # Con valida_link_post_pulizia=False e nessuna rete, test del whitelist path
        sanitizer._sanitize_url_impl = AsyncMock(
            return_value=("https://trusted.com/page", None)
        )
        result = await sanitizer.sanitize_batch(_opts(), ["https://trusted.com/page"])
        assert result[0][0] == "https://trusted.com/page"


# ---------------------------------------------------------------------------
# _sanitize_url_impl: fallback su URL originale quando il pulito dà 4xx
# ---------------------------------------------------------------------------


class TestSanitizeUrlImplFallback:
    """Verifica che un URL pulito che restituisce 4xx non venga mai restituito.

    Bug storico: check_url=True confronta solo il path (senza query), quindi
    original e cleaned avevano lo stesso path anche se cleaned dava 404.
    Il fix aggiunge is_url_ok() prima di equivalent_to().
    """

    async def test_cleaned_url_404_returns_original(self, sanitizer):
        from sanitizelinkbot.sanitizer import PageSignals
        from sanitizelinkbot.app_config import AppConfig

        # Sanitizer con validazione attiva
        conf_val = AppConfig(
            max_concurrency=2,
            cache_max_size=10,
            connections_per_host=2,
            max_redirects=5,
            timeout_sec=10,
            ttl_dns_cache=60,
            valida_link_post_pulizia=True,
            urlscan_api_key=None,
            log_level="DEBUG",
        )
        san = Sanitizer(
            exact_keys={"fbclid"},
            prefix_keys=(),
            ends_with=(),
            frag_keys=(),
            conf=conf_val,
        )

        # Segnali per l'URL originale: pagina funzionante
        sig_orig = PageSignals(
            final_url="https://example.com/page?fbclid=x&q=test",
            url_path="https://example.com/page",
            status=200,
            content_type="text/html",
            etag=None,
            lastmod=None,
            canonical=None,
            og_url=None,
            title="Pagina di esempio",
            chunk_hash=None,
        )
        # Segnali per l'URL pulito: 404
        sig_clean = PageSignals(
            final_url="https://example.com/page?q=test",
            url_path="https://example.com/page",
            status=404,
            content_type="text/html",
            etag=None,
            lastmod=None,
            canonical=None,
            og_url=None,
            title=None,
            chunk_hash=None,
        )

        san.do_redirect = AsyncMock(return_value=sig_orig)
        with patch(
            "sanitizelinkbot.sanitizer.PageSignals._fetch_signals",
            new=AsyncMock(return_value=sig_clean),
        ):
            result_url, _ = await san._sanitize_url_impl(
                "https://example.com/page?fbclid=x&q=test",
                opts=_opts(),
            )

        # Deve restituire l'originale, non l'URL pulito che dà 404
        assert (
            "fbclid" in result_url
        ), f"URL rotto restituito ({result_url!r}): il fallback sull'originale non ha funzionato"

    def test_youtube_timestamp_not_removed(self):
        """keys.json non deve contenere 't' come chiave esatta: è un timestamp YouTube.

        Bug storico: 't' era in EXACT_KEYS e veniva rimosso da ?v=abc&t=120 senza
        che la validazione lo rilevasse (la pagina HTML di YouTube è identica indipendentemente da t).
        """
        from sanitizelinkbot.utils import load_json_file, KEYS_PATH

        keys = load_json_file(KEYS_PATH, required=True)
        exact = [k.lower() for k in keys.get("EXACT_KEYS", [])]
        assert (
            "t" not in exact
        ), "La chiave 't' è in EXACT_KEYS: verrebbe rimosso il timestamp YouTube (?t=120)"
