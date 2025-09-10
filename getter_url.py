from __future__ import annotations

# modulo: getter_url.py
# scopo: estrarre url da testo o dalle entita di telegram

from utils import logger
import re
from collections.abc import Iterable
from telegram import MessageEntity


class GetterUrl:
    """fornisce metodi per trovare url nel testo e nelle entita telegram"""

    _URL_REGEX = re.compile(
        r"""
        (?<![\w@])
        (?:
            https?://
          | www\.
          | (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})
        )
        [^\s<>"'“”()]+
        (?:\([^\s<>"'“”()]*\)[^\s<>"'“”()]* )*
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    @classmethod
    def extract_urls(cls, text: str | None) -> list[str]:
        """estrae tutti gli url presenti in una stringa usando la regex"""
        if not text:
            return []
        url_list = [m.group(0) for m in cls._URL_REGEX.finditer(text)]
        logger.debug("Extracted %d URLs from text", len(url_list))
        return url_list

    @staticmethod
    def urls_from_entities(
        text: str | None, entities: Iterable[MessageEntity] | None
    ) -> list[str]:
        """estrae url dalle entita telegram di tipo url o text_link"""
        result: list[str] = []
        if not text or not entities:
            return result
        for entity in entities:
            if entity.type in {MessageEntity.URL, MessageEntity.TEXT_LINK}:
                if entity.type == MessageEntity.URL:
                    url_text = text[entity.offset : entity.offset + entity.length]
                    result.append(url_text)
                elif entity.type == MessageEntity.TEXT_LINK and entity.url:
                    result.append(entity.url)
        if result:
            logger.debug("Found %d URLs in Telegram entities", len(result))
        return result

    @classmethod
    def urls_from_message(cls, message) -> list[str]:
        """estrae url da un oggetto message di telegram, preferendo le entita"""
        collected: list[str] = []
        collected.extend(cls.urls_from_entities(message.text, message.entities))
        collected.extend(
            cls.urls_from_entities(message.caption, message.caption_entities)
        )
        if collected:
            # deduplica preservando l ordine
            return list(dict.fromkeys(collected))

        regex_found: list[str] = []
        if getattr(message, "text", None):
            regex_found.extend(cls.extract_urls(message.text))
        if getattr(message, "caption", None):
            regex_found.extend(cls.extract_urls(message.caption))
        return list(dict.fromkeys(regex_found))
