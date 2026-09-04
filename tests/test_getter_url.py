"""Test per GetterUrl: estrazione URL da entità Telegram e da testo libero."""

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
