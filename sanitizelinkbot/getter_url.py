from __future__ import annotations

# getter_url.py — estrae URL da messaggi Telegram o da testo libero.
# Strategia: prima le entità Telegram (più affidabili), poi regex come fallback.

from .utils import logger
import re
from collections.abc import Iterable
from telegram import MessageEntity


class GetterUrl:
    """Metodi statici per trovare URL nel testo e nelle entità Telegram."""

    # Regex per estrarre URL da testo libero (fallback quando mancano entità Telegram).
    # Lookbehind negativo (?<![\w@]): evita di matchare email (user@host) e menzioni (@user).
    # Supporta: https://..., www., e domini nudi (example.com/path).
    _URL_REGEX = re.compile(
        r"""
        (?<![\w@])
        (?:
            https?://
          | www\.
          | (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})
        )
        [^\s<>"'""()]+
        (?:\([^\s<>"'""()]*\)[^\s<>"'""()]* )*
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    @classmethod
    def extract_urls(cls, text: str | None) -> list[str]:
        """Estrae URL da una stringa con la regex. Usato come fallback se mancano entità Telegram."""
        if not text:
            return []
        url_list = [url_match.group(0) for url_match in cls._URL_REGEX.finditer(text)]
        logger.debug("Estratti %d URL dal testo", len(url_list))
        return url_list

    @staticmethod
    def urls_from_entities(
        text: str | None, entities: Iterable[MessageEntity] | None
    ) -> list[str]:
        """Estrae URL dalle entità Telegram di tipo URL o TEXT_LINK.
        Le entità sono più affidabili della regex: Telegram le calcola server-side
        e gestiscono correttamente URL con caratteri non-ASCII e link nascosti sotto testo.
        """
        result: list[str] = []
        if not text or not entities:
            return result
        for entity in entities:
            if entity.type == MessageEntity.URL:
                # Usiamo offset+length dell'entità per estrarre l'URL esatto dal testo
                result.append(text[entity.offset : entity.offset + entity.length])
            elif entity.type == MessageEntity.TEXT_LINK and entity.url:
                result.append(
                    entity.url
                )  # link nascosto sotto testo: l'URL è nell'entità stessa
        if result:
            logger.debug("Trovati %d URL nelle entità Telegram", len(result))
        return result

    @classmethod
    def urls_from_message(cls, message) -> list[str]:
        """Estrae URL da un messaggio Telegram: entità (testo + caption), poi regex come fallback.
        Gestisce sia messaggi di testo che messaggi con caption (foto, video, documenti).
        """
        collected: list[str] = []
        collected.extend(cls.urls_from_entities(message.text, message.entities))
        collected.extend(
            cls.urls_from_entities(message.caption, message.caption_entities)
        )

        if collected:
            # dict.fromkeys: deduplicazione O(n) che preserva l'ordine (più efficiente di un set)
            return list(dict.fromkeys(collected))

        # Fallback regex: usato solo se il messaggio non ha entità (es. testo copiato senza formattazione)
        regex_found: list[str] = []
        if getattr(
            message, "text", None
        ):  # getattr difensivo: non tutti i tipi di messaggio hanno .text
            regex_found.extend(cls.extract_urls(message.text))
        if getattr(
            message, "caption", None
        ):  # .caption: testo allegato a foto/video/documenti
            regex_found.extend(cls.extract_urls(message.caption))
        return list(dict.fromkeys(regex_found))
