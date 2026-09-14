"""Test per GetterUrl: estrazione URL da entità Telegram e da testo libero."""

from types import SimpleNamespace

from telegram import MessageEntity
from sanitizelinkbot.getter_url import GetterUrl


def _url_entity(text: str, url: str) -> MessageEntity:
    """Costruisce l'entità URL con offset/length in unità UTF-16, come farebbe Telegram."""
    start = text.index(url)
    prefix_units = len(text[:start].encode("utf-16-le")) // 2
    url_units = len(url.encode("utf-16-le")) // 2
    return MessageEntity(type=MessageEntity.URL, offset=prefix_units, length=url_units)


class TestUrlsFromEntities:
    def test_simple_ascii_message(self):
        url = "https://example.com/page"
        text = f"guarda qui: {url}"
        entity = _url_entity(text, url)
        assert GetterUrl.urls_from_entities(text, [entity]) == [url]

    def test_astral_emoji_before_url_offset_not_shifted(self):
        """Un'emoji fuori dal BMP (2 unità UTF-16, 1 code point Python) prima dell'URL
        non deve sfasare l'estrazione: bug storico, tagliava la 'h' iniziale di 'https'.
        """
        url = "https://www.hwupgrade.it/news/web/articolo_157624.html"
        text = f"non dimezzato i compensi\U0001F605\n{url}"
        entity = _url_entity(text, url)
        assert GetterUrl.urls_from_entities(text, [entity]) == [url]

    def test_multiple_astral_emoji_before_url(self):
        url = "https://example.com/x"
        text = f"\U0001F605\U0001F600\U0001F602 {url}"
        entity = _url_entity(text, url)
        assert GetterUrl.urls_from_entities(text, [entity]) == [url]

    def test_text_link_entity_uses_entity_url(self):
        text = "clicca qui"
        entity = MessageEntity(
            type=MessageEntity.TEXT_LINK, offset=0, length=len(text), url="https://hidden.example/"
        )
        assert GetterUrl.urls_from_entities(text, [entity]) == ["https://hidden.example/"]

    def test_no_entities_returns_empty(self):
        assert GetterUrl.urls_from_entities("qualsiasi testo", None) == []
        assert GetterUrl.urls_from_entities(None, []) == []


def _message(text=None, entities=None, caption=None, caption_entities=None):
    """Oggetto minimale con gli stessi attributi di un telegram.Message."""
    return SimpleNamespace(
        text=text, entities=entities, caption=caption, caption_entities=caption_entities
    )


class TestExtractUrls:
    def test_none_or_empty_text_returns_empty(self):
        assert GetterUrl.extract_urls(None) == []
        assert GetterUrl.extract_urls("") == []

    def test_https_url_in_free_text(self):
        assert GetterUrl.extract_urls("guarda qui: https://example.com/page") == [
            "https://example.com/page"
        ]

    def test_bare_domain_without_protocol(self):
        # niente "https://": deve comunque riconoscere un dominio nudo con path
        assert GetterUrl.extract_urls("vai su example.com/articolo") == [
            "example.com/articolo"
        ]

    def test_www_prefixed_url(self):
        assert GetterUrl.extract_urls("www.example.com/page") == ["www.example.com/page"]

    def test_multiple_urls_in_same_text(self):
        text = "prima https://a.com poi https://b.com"
        assert GetterUrl.extract_urls(text) == ["https://a.com", "https://b.com"]

    def test_email_address_not_matched_as_url(self):
        # il lookbehind negativo (?<![\w@]) esclude il dominio dopo la "@" di una email
        assert GetterUrl.extract_urls("scrivimi a mario@example.com") == []


class TestUrlsFromMessage:
    def test_prefers_entities_over_regex(self, monkeypatch):
        message = _message(text="testo", entities=["fake-entity"])
        monkeypatch.setattr(
            GetterUrl, "urls_from_entities", lambda text, entities: ["https://from-entity.example"]
        )
        assert GetterUrl.urls_from_message(message) == ["https://from-entity.example"]

    def test_combines_text_and_caption_entities(self, monkeypatch):
        message = _message(
            text="t", entities=["e1"], caption="c", caption_entities=["e2"]
        )
        mapping = {
            ("t", ("e1",)): ["https://text.example"],
            ("c", ("e2",)): ["https://caption.example"],
        }

        def fake_urls_from_entities(text, entities):
            return mapping.get((text, tuple(entities) if entities else ()), [])

        monkeypatch.setattr(GetterUrl, "urls_from_entities", fake_urls_from_entities)
        assert GetterUrl.urls_from_message(message) == [
            "https://text.example",
            "https://caption.example",
        ]

    def test_deduplicates_preserving_order(self, monkeypatch):
        message = _message(text="t", entities=["e"])
        monkeypatch.setattr(
            GetterUrl,
            "urls_from_entities",
            lambda text, entities: ["https://dup.example", "https://dup.example"],
        )
        assert GetterUrl.urls_from_message(message) == ["https://dup.example"]

    def test_falls_back_to_regex_when_no_entities(self):
        message = _message(text="link: https://regex-fallback.example/x")
        assert GetterUrl.urls_from_message(message) == ["https://regex-fallback.example/x"]

    def test_falls_back_to_regex_on_caption_when_no_entities(self):
        message = _message(caption="vedi https://caption-fallback.example")
        assert GetterUrl.urls_from_message(message) == ["https://caption-fallback.example"]

    def test_no_text_no_caption_returns_empty(self):
        assert GetterUrl.urls_from_message(_message()) == []
