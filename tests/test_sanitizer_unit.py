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
# keys.json reale: chiavi troppo generiche per stare nella lista globale (kgs, shem,
# shndl, client, sclient, oe, "is"...) sono in custom_providers.json, per dominio —
# vedi tests/test_clearurls_loader.py. Qui restano solo i controlli su cosa NON deve
# esserci in keys.json e su cosa non va mai toccato in generale (contenuto vs tracking).
# ---------------------------------------------------------------------------


class TestRealKeysJson:
    def _load_real_keys(self):
        from sanitizelinkbot.utils import load_json_file, KEYS_PATH

        return load_json_file(KEYS_PATH, required=True)

    def _sanitizer_with_real_keys(self, conf):
        keys = self._load_real_keys()
        return Sanitizer(
            exact_keys=set(keys.get("EXACT_KEYS", [])),
            prefix_keys=tuple(keys.get("PREFIX_KEYS", [])),
            ends_with=tuple(keys.get("ENDS_WITH", [])),
            frag_keys=tuple(keys.get("FRAG_KEYS", [])),
            domain_whitelist=keys.get("DOMAIN_WHITELIST", []),
            conf=conf,
        )

    def test_google_and_youtube_specific_params_not_global(self, conf):
        # kgs/shem/shndl/client/sclient/oe/is sono legati a un dominio preciso (Google o
        # YouTube): devono stare in custom_providers.json, MAI in keys.json, altrimenti
        # si applicherebbero ovunque (è il bug che ha rotto i link Discord con "is").
        sanitizer = self._sanitizer_with_real_keys(conf)
        for risky_key in ("kgs", "shem", "shndl", "client", "sclient", "oe", "is"):
            assert not sanitizer.is_key_to_remove(risky_key), (
                f"'{risky_key}' è nella lista globale keys.json: deve stare in "
                "custom_providers.json, legato al dominio giusto"
            )

    def test_discord_cdn_signature_params_kept(self, conf):
        # "is" NON è nella lista globale (nonostante ClearURLs/Rules#192 lo segnali come
        # nuovo tracker di condivisione YouTube): su cdn.discordapp.com "ex"/"is"/"hm" sono
        # una firma HMAC con scadenza che rende valido il link. Rimuovendo anche solo "is"
        # il link Discord smette di funzionare (404) — chiave troppo generica per essere
        # sicura a livello globale, il rischio segnalato quando fu aggiunta si è confermato.
        sanitizer = self._sanitizer_with_real_keys(conf)
        url = (
            "https://cdn.discordapp.com/attachments/123456789/987654321/foto.png"
            "?ex=66f1a2b3&is=66f0517c&hm=deadbeefcafebabe0123456789abcdef"
        )
        result = sanitizer._strip_tracking_params(url)
        assert "ex=" in result
        assert "is=" in result
        assert "hm=" in result

    def test_content_identifying_params_kept(self, conf):
        # 'stick' (relazione tra entità nel knowledge panel) e i token 'gaa_*' (accesso
        # gratuito Google News a contenuti a pagamento) non sono tracciamento: rimuoverli
        # cambierebbe cosa viene mostrato o romperebbe l'accesso. Vanno mantenuti.
        sanitizer = self._sanitizer_with_real_keys(conf)
        url = (
            "https://www.nytimes.com/article"
            "?gaa_at=la&gaa_n=AbC&gaa_ts=123&gaa_sig=xyz"
        )
        result = sanitizer._strip_tracking_params(url)
        assert "gaa_at" in result
        assert "gaa_n" in result
        assert "gaa_ts" in result
        assert "gaa_sig" in result

        stick_url = "https://www.google.com/search?q=test&stick=Ahjkfjw123"
        stick_result = sanitizer._strip_tracking_params(stick_url)
        assert "stick=" in stick_result

    def test_youtube_timestamp_not_removed(self):
        # Bug storico: "t" era in EXACT_KEYS e veniva rimosso da ?v=abc&t=120 senza che
        # la validazione lo rilevasse (la pagina YouTube è identica a prescindere da t).
        exact = [k.lower() for k in self._load_real_keys().get("EXACT_KEYS", [])]
        assert (
            "t" not in exact
        ), "La chiave 't' è in EXACT_KEYS: verrebbe rimosso il timestamp YouTube (?t=120)"

    def test_instagram_igsi_stkn_not_in_global_keys(self):
        # 'igsi' e 'stkn' sono parametri di share Instagram: vivono nel provider dedicato
        # di custom_providers.json, non più nella lista globale keys.json.
        exact = [k.lower() for k in self._load_real_keys().get("EXACT_KEYS", [])]
        assert "igsi" not in exact
        assert "stkn" not in exact


# ---------------------------------------------------------------------------
# _extract_consent_continue (funzione modulo-level)
# ---------------------------------------------------------------------------


class TestExtractConsentContinue:
    def test_consent_google_extracts_continue(self):
        from sanitizelinkbot.sanitizer import _extract_consent_continue

        # Il valore di continue= è URL-encoded nella query string; unquote() lo decodifica
        url = (
            "https://consent.google.com/m"
            "?continue=https://maps.google.com/maps%3Fq%3D44.6,10.2"
            "&gl=IT&hl=it"
        )
        result = _extract_consent_continue(url)
        # unquote() decodifica %3F → ? e %3D → =
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

    def test_continue_preserves_literal_plus(self):
        """Un '+' letterale nell'URL di destinazione (comune nei link Google Foto/Drive/Maps) non deve diventare uno spazio."""
        from sanitizelinkbot.sanitizer import _extract_consent_continue

        url = (
            "https://consent.google.com/m"
            "?continue=https://photos.google.com/share/AF1QipN+abc/def%3Fkey%3Dxyz+123"
            "&gl=IT&hl=it"
        )
        result = _extract_consent_continue(url)
        assert result == "https://photos.google.com/share/AF1QipN+abc/def?key=xyz+123"

    def test_consent_youtube_domain_supported(self):
        """consent.youtube.com usa lo stesso meccanismo di consent.google.com."""
        from sanitizelinkbot.sanitizer import _extract_consent_continue

        url = "https://consent.youtube.com/d?continue=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3Dabc123&gl=IT"
        assert (
            _extract_consent_continue(url) == "https://www.youtube.com/watch?v=abc123"
        )


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
            max_unwrap_hops=3,
            max_consent_hops=3,
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


# ---------------------------------------------------------------------------
# Aggressive query strip: copre tracker sconosciuti (non in keys.json/ClearURLs)
# tentando di rimuovere l'INTERA query e validando con PageSignals, invece di
# dover elencare ogni singolo nuovo parametro (es. il caso "stkn").
# ---------------------------------------------------------------------------


def _make_sanitizer(exact_keys=frozenset(), *, aggressive=True) -> Sanitizer:
    from sanitizelinkbot.app_config import AppConfig

    conf = AppConfig(
        max_concurrency=2,
        cache_max_size=10,
        connections_per_host=2,
        max_redirects=5,
        timeout_sec=10,
        ttl_dns_cache=60,
        valida_link_post_pulizia=True,
        max_unwrap_hops=3,
        max_consent_hops=3,
        urlscan_api_key=None,
        log_level="DEBUG",
        aggressive_query_strip=aggressive,
    )
    return Sanitizer(
        exact_keys=set(exact_keys),
        prefix_keys=(),
        ends_with=(),
        frag_keys=(),
        conf=conf,
    )


class TestAggressiveQueryStrip:
    def _signals(self, url, *, status=200, canonical=None, title=None):
        from sanitizelinkbot.sanitizer import PageSignals

        return PageSignals(
            final_url=url,
            url_path=url.split("?")[0],
            status=status,
            content_type="text/html",
            etag=None,
            lastmod=None,
            canonical=canonical,
            og_url=None,
            title=title,
            chunk_hash=None,
        )

    async def test_unknown_tracker_stripped_when_signals_match(self):
        """Un parametro MAI visto prima (non in EXACT_KEYS) sparisce se la pagina risulta identica.

        Simula il caso "stkn": il tracker non è enumerato da nessuna parte, ma la validazione
        via canonical conferma che è innocuo, quindi la versione senza query viene usata.
        """
        san = _make_sanitizer()  # nessuna chiave nota: "stkn_futuro" non verrebbe mai rimosso dalla pulizia standard
        dirty = "https://www.instagram.com/reel/XYZ/?stkn_futuro=abc123"
        clean_no_query = "https://www.instagram.com/reel/XYZ/"

        san.do_redirect = AsyncMock(
            return_value=self._signals(dirty, canonical=clean_no_query)
        )
        with patch(
            "sanitizelinkbot.sanitizer.PageSignals._fetch_signals",
            new=AsyncMock(
                return_value=self._signals(clean_no_query, canonical=clean_no_query)
            ),
        ):
            result_url, _ = await san._sanitize_url_impl(dirty, opts=_opts())

        assert "stkn_futuro" not in result_url, (
            f"Tracker sconosciuto non rimosso ({result_url!r}): il tentativo aggressivo "
            "dovrebbe coprire anche i parametri mai enumerati in keys.json"
        )

    async def test_content_param_kept_when_aggressive_strip_breaks_page(self):
        """Se rimuovere TUTTO cambia il contenuto (es. "page="), si ripiega sulla pulizia
        standard (che rimuove solo il tracker noto "fbclid") invece di restituire un link rotto.
        """
        san = _make_sanitizer({"fbclid"})
        dirty = "https://example.com/list?fbclid=x&page=2"
        aggressive_url = "https://example.com/list"
        standard_cleaned = "https://example.com/list?page=2"

        sig_orig = self._signals(dirty, title="Lista - Pagina 2")
        sig_aggressive_wrong_page = self._signals(aggressive_url, title="Lista - Pagina 1")
        sig_cleaned_ok = self._signals(standard_cleaned, title="Lista - Pagina 2")

        san.do_redirect = AsyncMock(return_value=sig_orig)
        with patch(
            "sanitizelinkbot.sanitizer.PageSignals._fetch_signals",
            new=AsyncMock(side_effect=[sig_aggressive_wrong_page, sig_cleaned_ok]),
        ):
            result_url, _ = await san._sanitize_url_impl(dirty, opts=_opts())

        assert "page=2" in result_url, (
            f"Contenuto perso ({result_url!r}): la rimozione aggressiva ha rotto la "
            "pagina e non si è ripiegato correttamente sulla pulizia standard"
        )
        assert "fbclid" not in result_url, "Il tracker noto fbclid doveva comunque sparire"

    async def test_disabled_via_config_skips_aggressive_attempt(self):
        """aggressive_query_strip=False: nessun tentativo di rimozione totale, solo comportamento standard."""
        san = _make_sanitizer({"fbclid"}, aggressive=False)
        dirty = "https://example.com/page?fbclid=x&unknown_future_tracker=1"
        standard_cleaned = "https://example.com/page?unknown_future_tracker=1"

        sig_orig = self._signals(dirty, title="Pagina")
        sig_cleaned = self._signals(standard_cleaned, title="Pagina")

        san.do_redirect = AsyncMock(return_value=sig_orig)
        fetch_mock = AsyncMock(return_value=sig_cleaned)
        with patch(
            "sanitizelinkbot.sanitizer.PageSignals._fetch_signals", new=fetch_mock
        ):
            result_url, _ = await san._sanitize_url_impl(dirty, opts=_opts())

        fetch_mock.assert_awaited_once()  # una sola chiamata: niente tentativo aggressivo
        assert "unknown_future_tracker=1" in result_url, (
            "Con il flag disattivato il parametro sconosciuto deve restare (comportamento pre-esistente)"
        )

    async def test_domain_learned_unsafe_skips_future_aggressive_attempts(self):
        """Dopo un fallimento su un dominio, i link successivi dello stesso dominio non
        devono rifare la richiesta HTTP inutile per il tentativo aggressivo: va dritti
        alla pulizia standard, che risolve comunque il link (solo più veloce).
        """
        san = _make_sanitizer({"fbclid"})
        url1 = "https://example.com/list?fbclid=x&page=2"
        url2 = "https://example.com/other?fbclid=y&page=5"

        sig_orig1 = self._signals(url1, title="Lista - Pagina 2")
        sig_aggressive_wrong = self._signals("https://example.com/list", title="Lista - Pagina 1")
        sig_cleaned_ok1 = self._signals("https://example.com/list?page=2", title="Lista - Pagina 2")

        san.do_redirect = AsyncMock(return_value=sig_orig1)
        with patch(
            "sanitizelinkbot.sanitizer.PageSignals._fetch_signals",
            new=AsyncMock(side_effect=[sig_aggressive_wrong, sig_cleaned_ok1]),
        ):
            await san._sanitize_url_impl(url1, opts=_opts())  # impara che example.com non è sicuro

        sig_orig2 = self._signals(url2, title="Altra - Pagina 5")
        sig_cleaned_ok2 = self._signals("https://example.com/other?page=5", title="Altra - Pagina 5")
        san.do_redirect = AsyncMock(return_value=sig_orig2)
        fetch_mock2 = AsyncMock(return_value=sig_cleaned_ok2)
        with patch(
            "sanitizelinkbot.sanitizer.PageSignals._fetch_signals", new=fetch_mock2
        ):
            result_url, _ = await san._sanitize_url_impl(url2, opts=_opts())

        fetch_mock2.assert_awaited_once()  # niente tentativo aggressivo: dominio già noto come non sicuro
        assert "page=5" in result_url and "fbclid" not in result_url
