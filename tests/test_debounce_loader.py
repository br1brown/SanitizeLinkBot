"""Test unitari per debounce_loader.py: regole compilate da dizionari nel formato JSON di Brave."""

from sanitizelinkbot.debounce_loader import (
    _compile_rule,
    _glob_to_regex,
    _decode_base64_param,
    DebounceIndex,
)
import base64


# ---------------------------------------------------------------------------
# _glob_to_regex: solo "*" è wildcard, il resto (incluso "?") è letterale
# ---------------------------------------------------------------------------


class TestGlobToRegex:
    def test_star_matches_any_sequence(self):
        pattern = _glob_to_regex("*://*.esempio.com/r?*")
        assert pattern.match("https://sub.esempio.com/r?url=abc")
        assert pattern.match("http://a.b.esempio.com/r?x=1&y=2")

    def test_question_mark_is_literal_not_wildcard(self):
        # "?" nei pattern Brave è letterale (inizio query string), non un wildcard a un carattere
        pattern = _glob_to_regex("*://esempio.com/r?*")
        assert pattern.match("https://esempio.com/r?url=abc")
        assert not pattern.match("https://esempio.com/rX")  # "?" non deve matchare "X"

    def test_no_match_for_unrelated_host(self):
        pattern = _glob_to_regex("*://*.esempio.com/*")
        assert not pattern.match("https://altrosito.com/pagina")


# ---------------------------------------------------------------------------
# DebounceRule.extract_target — le quattro azioni supportate dal formato Brave
# ---------------------------------------------------------------------------


class TestExtractTargetRedirect:
    def test_simple_query_param(self):
        rule = _compile_rule(
            {
                "include": ["*://*.tracker.example/click*"],
                "exclude": [],
                "action": "redirect",
                "param": "url",
            }
        )
        url = "https://go.tracker.example/click?url=https%3A%2F%2Fdestinazione.it%2Fpagina"
        assert rule.extract_target(url) == "https://destinazione.it/pagina"

    def test_preserves_literal_plus_in_target(self):
        """Un '+' letterale nell'URL di destinazione non deve diventare uno spazio."""
        rule = _compile_rule(
            {
                "include": ["*://*.tracker.example/click*"],
                "exclude": [],
                "action": "redirect",
                "param": "url",
            }
        )
        url = "https://go.tracker.example/click?url=https://destinazione.it/AF1QipN+abc"
        assert rule.extract_target(url) == "https://destinazione.it/AF1QipN+abc"

    def test_missing_param_returns_none(self):
        rule = _compile_rule(
            {
                "include": ["*://*.tracker.example/click*"],
                "exclude": [],
                "action": "redirect",
                "param": "url",
            }
        )
        assert rule.extract_target("https://go.tracker.example/click?other=1") is None

    def test_excluded_url_is_not_covered(self):
        rule = _compile_rule(
            {
                "include": ["*://*.tracker.example/*"],
                "exclude": ["*://safe.tracker.example/*"],
                "action": "redirect",
                "param": "url",
            }
        )
        assert not rule.covers("https://safe.tracker.example/click?url=https://x.it")
        assert rule.covers("https://go.tracker.example/click?url=https://x.it")


class TestExtractTargetBase64:
    def test_decodes_urlsafe_base64(self):
        rule = _compile_rule(
            {
                "include": ["*://*.shortener.example/*"],
                "exclude": [],
                "action": "base64,redirect",
                "param": "cr",
            }
        )
        dest = "https://destinazione.it/pagina?a=1"
        encoded = base64.urlsafe_b64encode(dest.encode()).decode().rstrip("=")
        url = f"https://x.shortener.example/go?cr={encoded}"
        assert rule.extract_target(url) == dest

    def test_invalid_base64_returns_none(self):
        rule = _compile_rule(
            {
                "include": ["*://*.shortener.example/*"],
                "exclude": [],
                "action": "base64,redirect",
                "param": "cr",
            }
        )
        assert rule.extract_target("https://x.shortener.example/go?cr=%%%non-valido%%%") is None


class TestExtractTargetRegexPath:
    def test_extracts_group_from_path(self):
        rule = _compile_rule(
            {
                "include": ["*://click.esempio.com/*"],
                "exclude": [],
                "action": "regex-path",
                "param": r"^/CL0/([^/]+)/.*$",
            }
        )
        url = "https://click.esempio.com/CL0/https%3A%2F%2Fdestinazione.it%2F/1/abcdef"
        assert rule.extract_target(url) == "https://destinazione.it/"

    def test_prepend_scheme_applied_when_missing(self):
        rule = _compile_rule(
            {
                "include": ["*://*.cdn.ampproject.org/c/s/*"],
                "exclude": [],
                "action": "regex-path",
                "param": r"^/c/s/(.*)$",
                "prepend_scheme": "https",
            }
        )
        url = "https://esempio-com.cdn.ampproject.org/c/s/esempio.com/articolo"
        assert rule.extract_target(url) == "https://esempio.com/articolo"


class TestExtractTargetRegexPathTemplate:
    def test_builds_url_from_template(self):
        rule = _compile_rule(
            {
                "include": ["*://y2u.be/*"],
                "exclude": [],
                "action": "regex-path-template",
                "param": r"^/([^/]+)$",
                "redirect_url_template": "https://www.youtube.com/watch?v=$1",
            }
        )
        assert (
            rule.extract_target("https://y2u.be/dQw4w9WgXcQ")
            == "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        )


# ---------------------------------------------------------------------------
# DebounceIndex.extract_target — prima regola che copre l'URL vince
# ---------------------------------------------------------------------------


class TestDebounceIndex:
    def test_first_matching_rule_wins(self):
        rule_a = _compile_rule(
            {
                "include": ["*://a.example/*"],
                "exclude": [],
                "action": "redirect",
                "param": "url",
            }
        )
        rule_b = _compile_rule(
            {
                "include": ["*://b.example/*"],
                "exclude": [],
                "action": "redirect",
                "param": "url",
            }
        )
        index = DebounceIndex(rules=[rule_a, rule_b])
        result = index.extract_target("https://b.example/go?url=https://finale.it")
        assert result == "https://finale.it"

    def test_uncovered_url_returns_none(self):
        index = DebounceIndex(rules=[])
        assert index.extract_target("https://qualsiasi.it/pagina") is None


# ---------------------------------------------------------------------------
# _decode_base64_param: alfabeti diversi e padding mancante
# ---------------------------------------------------------------------------


class TestDecodeBase64Param:
    def test_missing_padding_is_restored(self):
        # "a" (1 byte) codificato senza padding: base64 valido richiede multipli di 4
        encoded = base64.urlsafe_b64encode(b"a").decode().rstrip("=")
        assert _decode_base64_param(encoded) == "a"

    def test_garbage_returns_none(self):
        assert _decode_base64_param("!!!non-base64!!!") is None
