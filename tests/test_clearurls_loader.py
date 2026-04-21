"""Test per clearurls_loader: compilazione, lookup e applicazione regole."""

import re
import pytest
from sanitizelinkbot.clearurls_loader import (
    _compile_param_rule,
    _compile_provider,
    _compile_index,
    ClearUrlsIndex,
    ClearUrlsLoader,
    ProviderRules,
)

# ---------------------------------------------------------------------------
# _compile_param_rule: verifica che le ancore ^(?: )$ funzionino
# ---------------------------------------------------------------------------


class TestCompileParamRule:
    def test_exact_name_matches(self):
        pat = _compile_param_rule("fbclid")
        assert pat.match("fbclid")

    def test_prefix_wildcard_matches(self):
        pat = _compile_param_rule("utm_.*")
        assert pat.match("utm_source")
        assert pat.match("utm_campaign")

    def test_exact_rule_does_not_match_substring(self):
        pat = _compile_param_rule("fbclid")
        # "my_fbclid" non deve matchare ($ ancora la fine)
        assert not pat.match("my_fbclid")

    def test_prefix_rule_does_not_partial_match(self):
        pat = _compile_param_rule("id")
        assert pat.match("id")
        assert not pat.match("video_id")

    def test_invalid_regex_returns_none(self):
        assert _compile_param_rule("[invalid") is None


# ---------------------------------------------------------------------------
# _compile_provider: parsing del dict JSON di un singolo provider
# ---------------------------------------------------------------------------


class TestCompileProvider:
    def test_invalid_url_pattern_returns_none(self):
        result = _compile_provider("Bad", {"urlPattern": "[invalid"})
        assert result is None

    def test_valid_provider_compiled(self):
        raw = {
            "urlPattern": r"^https?://example\.com",
            "completeProvider": False,
            "rules": ["fbclid", "utm_.*"],
            "referralMarketing": ["tag"],
            "exceptions": [r"^https?://example\.com/login"],
            "redirections": [],
            "rawRules": [],
        }
        provider = _compile_provider("TestProvider", raw)
        assert provider is not None
        assert provider.name == "TestProvider"
        assert len(provider.rules) == 2
        assert len(provider.referral_marketing) == 1
        assert len(provider.exceptions) == 1
        assert provider.complete_provider is False

    def test_complete_provider_flag(self):
        raw = {"urlPattern": r"^https?://tracker\.com", "completeProvider": True}
        provider = _compile_provider("Tracker", raw)
        assert provider.complete_provider is True

    def test_missing_keys_default_to_empty(self):
        raw = {"urlPattern": r"^https?://minimal\.com"}
        provider = _compile_provider("Minimal", raw)
        assert provider is not None
        assert provider.rules == ()
        assert provider.exceptions == ()

    def test_invalid_rule_regex_skipped(self):
        raw = {
            "urlPattern": r"^https?://example\.com",
            "rules": ["valid_rule", "[invalid"],
        }
        provider = _compile_provider("MixedRules", raw)
        assert len(provider.rules) == 1  # solo quella valida


# ---------------------------------------------------------------------------
# _compile_index: costruzione dell'indice by_domain e fallback
# ---------------------------------------------------------------------------

FAKE_JSON = {
    "providers": {
        "AmazonTracking": {
            "urlPattern": r"^https?://(?:[a-z0-9-]+\.)*?amazon(?:\.[a-z]{2,}){1,}",
            "completeProvider": False,
            "rules": ["tag", "ref"],
            "referralMarketing": [],
            "exceptions": [],
            "redirections": [],
            "rawRules": [],
        },
        "FacebookWrapper": {
            "urlPattern": r"^https?://l\.facebook\.com",
            "completeProvider": False,
            "rules": ["h"],
            "referralMarketing": [],
            "exceptions": [],
            "redirections": [r"https?://l\.facebook\.com/l\.php\?u=(https?[^&]+)"],
            "rawRules": [],
        },
        "GenericFallback": {
            # Nessun domain key estraibile → finisce nel fallback
            "urlPattern": r"^https?://.*\?.*__hsfp",
            "completeProvider": False,
            "rules": ["__hsfp"],
            "referralMarketing": [],
            "exceptions": [],
            "redirections": [],
            "rawRules": [],
        },
    }
}


class TestCompileIndex:
    def test_all_providers_present(self):
        index = _compile_index(FAKE_JSON)
        names = {p.name for p in index.providers}
        assert "AmazonTracking" in names
        assert "FacebookWrapper" in names
        assert "GenericFallback" in names

    def test_specific_before_universal(self):
        # Provider con dominio specifico (contengono \.) devono venire prima di quelli universali
        index = _compile_index(FAKE_JSON)
        names = [p.name for p in index.providers]
        # AmazonTracking e FacebookWrapper hanno \. → specifici
        # GenericFallback (.*\?.*) non ha \. → universale → deve stare dopo
        amazon_pos = names.index("AmazonTracking")
        facebook_pos = names.index("FacebookWrapper")
        generic_pos = names.index("GenericFallback")
        assert amazon_pos < generic_pos
        assert facebook_pos < generic_pos

    def test_empty_providers(self):
        index = _compile_index({"providers": {}})
        assert index.providers == []


# ---------------------------------------------------------------------------
# ClearUrlsIndex.find_providers
# ---------------------------------------------------------------------------


class TestFindProviders:
    def test_finds_specific_provider(self):
        index = _compile_index(FAKE_JSON)
        providers = index.find_providers("https://www.amazon.it/dp/B01?tag=x")
        assert any(p.name == "AmazonTracking" for p in providers)

    def test_url_pattern_is_truth_not_domain_name(self):
        # urlPattern è l'arbitro: un URL che non matcha il pattern non deve essere restituito
        # anche se si trovasse in una lookup dict per "amazon"
        index = _compile_index(FAKE_JSON)
        providers = index.find_providers("https://notamazon.com/page")
        assert not any(p.name == "AmazonTracking" for p in providers)

    def test_universal_provider_matches_any_url(self):
        # GenericFallback (pattern: ^https?://.*\?.*__hsfp) deve matchare su qualsiasi dominio
        index = _compile_index(FAKE_JSON)
        providers = index.find_providers("https://unknown-site.com/page?__hsfp=1")
        assert any(p.name == "GenericFallback" for p in providers)

    def test_no_match_returns_empty(self):
        index = _compile_index(FAKE_JSON)
        providers = index.find_providers("https://unknown.com/clean")
        assert providers == []


# ---------------------------------------------------------------------------
# ClearUrlsLoader: apply_redirections e apply_cleaning
# ---------------------------------------------------------------------------


def _loader_with_data(data: dict) -> ClearUrlsLoader:
    """Crea un ClearUrlsLoader con indice precompilato dai dati forniti."""
    from pathlib import Path

    loader = ClearUrlsLoader(Path("/fake/path.json"))
    loader._index = _compile_index(data)
    return loader


class TestApplyRedirections:
    def test_extracts_wrapped_url(self):
        loader = _loader_with_data(FAKE_JSON)
        wrapped = "https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.com&h=AT3abc"
        providers = loader.find_providers(wrapped)
        result = loader.apply_redirections(wrapped, providers)
        assert result == "https://example.com"

    def test_no_match_returns_none(self):
        loader = _loader_with_data(FAKE_JSON)
        url = "https://example.com/page"
        providers = loader.find_providers(url)
        assert loader.apply_redirections(url, providers) is None

    def test_exception_blocks_provider(self):
        data = {
            "providers": {
                "WithException": {
                    "urlPattern": r"^https?://example\.com",
                    "completeProvider": False,
                    "rules": [],
                    "referralMarketing": [],
                    "exceptions": [r"^https?://example\.com/safe"],
                    "redirections": [r"https?://example\.com\?target=(https?[^&]+)"],
                    "rawRules": [],
                }
            }
        }
        loader = _loader_with_data(data)
        url = "https://example.com/safe?target=https%3A%2F%2Fother.com"
        providers = loader.find_providers(url)
        # L'eccezione blocca il provider → nessun unwrap
        assert loader.apply_redirections(url, providers) is None

    def test_not_loaded_returns_empty_providers(self):
        from pathlib import Path

        loader = ClearUrlsLoader(Path("/fake/path.json"))
        assert loader.find_providers("https://example.com") == []

    def test_google_search_with_url_query_not_unwrapped(self):
        """Google /search?q=<url> non deve essere "sbucciato": la redirection ClearURLs
        di Google matcha solo /url?q=..., non /search?q=...

        Scenario: l'utente manda https://www.google.com/search?q=https://comune.roma.it/...
        Il bot deve restituire una URL google.com, non estrarre il valore di q= e
        restituire direttamente comune.roma.it.
        """
        import json
        from sanitizelinkbot.utils import CLEARURLS_PATH

        with open(CLEARURLS_PATH, encoding="utf-8") as f:
            data = json.load(f)
        loader = _loader_with_data(data)

        search_url = (
            "https://www.google.com/search"
            "?q=https://www.comune.roma.it/web/it/scheda-servizi.page%3FcontentId%3DINF40030"
        )
        providers = loader.find_providers(search_url)
        result = loader.apply_redirections(search_url, providers)

        # apply_redirections deve restituire None: /search?q= non è un link wrapper
        # La redirection Google è ancorata a /url?q=, non /search?q=
        assert result is None, (
            f"apply_redirections ha estratto la URL interna da /search?q=: {result!r}\n"
            "Il pattern di redirection di Google deve matchare solo /url?q=, non /search?q="
        )


class TestApplyCleaning:
    def test_removes_tracking_param(self):
        loader = _loader_with_data(FAKE_JSON)
        url = "https://www.amazon.it/dp/B01?tag=affiliate&color=red"
        providers = loader.find_providers(url)
        result = loader.apply_cleaning(url, providers)
        assert "tag=" not in result
        assert "color=red" in result

    def test_skips_complete_provider(self):
        data = {
            "providers": {
                "CompleteTracker": {
                    "urlPattern": r"^https?://tracker\.com",
                    "completeProvider": True,
                    "rules": ["id"],
                    "referralMarketing": [],
                    "exceptions": [],
                    "redirections": [],
                    "rawRules": [],
                }
            }
        }
        loader = _loader_with_data(data)
        url = "https://tracker.com/page?id=123"
        providers = loader.find_providers(url)
        # completeProvider → provider saltato, URL invariato
        assert loader.apply_cleaning(url, providers) == url

    def test_raw_rule_applied(self):
        data = {
            "providers": {
                "RawRuleProvider": {
                    "urlPattern": r"^https?://shop\.com",
                    "completeProvider": False,
                    "rules": [],
                    "referralMarketing": [],
                    "exceptions": [],
                    "redirections": [],
                    "rawRules": [r"\?.*"],  # rimuove tutto il query string
                }
            }
        }
        loader = _loader_with_data(data)
        url = "https://shop.com/product?ref=homepage&session=xyz"
        providers = loader.find_providers(url)
        result = loader.apply_cleaning(url, providers)
        assert "?" not in result
        assert result == "https://shop.com/product"

    def test_exception_skips_cleaning(self):
        data = {
            "providers": {
                "WithException": {
                    "urlPattern": r"^https?://example\.com",
                    "completeProvider": False,
                    "rules": ["fbclid"],
                    "referralMarketing": [],
                    "exceptions": [r"^https?://example\.com/api"],
                    "redirections": [],
                    "rawRules": [],
                }
            }
        }
        loader = _loader_with_data(data)
        url = "https://example.com/api?fbclid=ABC"
        providers = loader.find_providers(url)
        # Eccezione → provider saltato → fbclid resta
        assert loader.apply_cleaning(url, providers) == url

    def test_empty_providers_returns_unchanged(self):
        loader = _loader_with_data(FAKE_JSON)
        url = "https://unknown.com/?fbclid=x"
        result = loader.apply_cleaning(url, [])
        assert result == url
