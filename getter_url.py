from __future__ import annotations

# Modulo: getter_url.py
# Scopo: estrarre URL da testo grezzo o direttamente dalle entità di Telegram.
# Note di stile: variabili e funzioni con nomi esplicativi e commenti per ogni istruzione.

from utils import logger  # logger condiviso per debug e diagnostica
import re  # modulo per espressioni regolari
from collections.abc import Iterable  # tipo per annotare collezioni iterabili
from telegram import MessageEntity  # tipo per le entità Telegram (URL, menzioni, ecc.)


class GetterUrl:
    """Trova URL nel testo oppure legge URL direttamente dalle entità Telegram."""

    # Compilo una regex che intercetta URL comuni, evitando menzioni (@utente) ed email.
    _URL_REGEX = re.compile(
        r"""
        (?<![\w@])
        (?:
            https?://
          | www\.
          | (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})
        )
        [^\s<>"'“”()]+
        (?:\([^\s<>"'“”()]*\)[^\s<>"'“”()]*)*
        """,
        re.IGNORECASE | re.VERBOSE,  # ignora maiuscole/minuscole, formato leggibile
    )

    @classmethod
    def estrai_urls(cls, text: str | None) -> list[str]:
        """Estrae tutti gli URL presenti in una stringa usando la regex di classe."""
        # Se il testo è vuoto o None, non c'è nulla da estrarre → ritorno lista vuota.
        if not text:
            return []
        # Applico la regex e raccolgo tutti i match completi.
        url_list = [match.group(0) for match in cls._URL_REGEX.finditer(text)]
        # Log di debug con il numero di URL trovati.
        logger.debug("estrai urls trovati %d url nel testo", len(url_list))
        # Ritorno la lista di URL rilevati.
        return url_list

    @staticmethod
    def url_da_tg(
        text: str | None, entities: Iterable[MessageEntity] | None
    ) -> list[str]:
        """Estrae URL direttamente dalle entità Telegram (URL espliciti o TEXT_LINK)."""
        # Inizializzo la lista risultato.
        url_list: list[str] = []
        # Se non ho testo o entità, non posso ricavare nulla → ritorno lista vuota.
        if not text or not entities:
            return url_list
        # Scorro tutte le entità presenti nel messaggio.
        for entity in entities:
            # Prendo in considerazione solo i tipi URL o TEXT_LINK.
            if entity.type in {MessageEntity.URL, MessageEntity.TEXT_LINK}:
                # Caso 1: entità di tipo URL → l'URL è una porzione del testo in base a offset/length.
                if entity.type == MessageEntity.URL:
                    url_text = text[entity.offset : entity.offset + entity.length]
                    url_list.append(url_text)
                # Caso 2: entità di tipo TEXT_LINK → l'URL è nel campo entity.url.
                elif entity.type == MessageEntity.TEXT_LINK and entity.url:
                    url_list.append(entity.url)
        # Se ho raccolto almeno un URL, lo segnalo nei log.
        if url_list:
            logger.debug("url da tg trovati %d url nelle entita", len(url_list))
        # Ritorno tutte le URL emerse dalle entità.
        return url_list

    @classmethod
    def url_da_msg(cls, message) -> list[str]:
        """Estrae URL da un oggetto messaggio di Telegram, privilegiando le entità."""
        # Creo una lista vuota in cui aggiungerò i risultati.
        collected_urls: list[str] = []
        # 1) Prima provo a leggere le entità Telegram (prioritarie perché più affidabili).
        collected_urls.extend(cls.url_da_tg(message.text, message.entities))
        collected_urls.extend(cls.url_da_tg(message.caption, message.caption_entities))
        # Se ho trovato URL tramite entità, deduplica e ritorno subito.
        if collected_urls:
            return list(dict.fromkeys(collected_urls))  # deduplica preservando l'ordine

        # 2) In assenza di entità, uso la regex su testo e caption.
        regex_found: list[str] = []
        # Se c'è testo, cerco URL nel testo.
        if getattr(message, "text", None):
            regex_found.extend(cls.estrai_urls(message.text))
        # Se c'è caption, cerco URL nella caption.
        if getattr(message, "caption", None):
            regex_found.extend(cls.estrai_urls(message.caption))
        # Deduplica e ritorno la lista.
        return list(dict.fromkeys(regex_found))
