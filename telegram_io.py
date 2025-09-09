from __future__ import annotations

# Modulo: telegram_io.py
# Scopo: costruire il testo di risposta da inviare su Telegram (HTML semplice).

from utils import logger  # logger condiviso
import re  # regex per neutralizzare menzioni/hashtag/comandi
import html  # escape HTML sicuro

from app_config import AppConfig  # per leggere le opzioni di output


class TelegramIO:
    """Costruisce l'output testuale con titolo (opzionale) e URL pulito per Telegram."""

    @staticmethod
    def _neutralizza(test: str) -> str:
        """Inserisce caratteri zero‑width per evitare trigger di menzioni/hashtag/comandi a inizio parola."""
        # Se la stringa è vuota, la ritorno com'è.
        if not test:
            return test
        # Neutralizzo @qualcosa all'inizio di parola.
        test = re.sub(r"(?<!\S)@(\w+)", "@\u2060\\g<1>", test)
        # Neutralizzo #qualcosa all'inizio di parola.
        test = re.sub(r"(?<!\S)#(\w+)", "#\u2060\\g<1>", test)
        # Neutralizzo /comando all'inizio di parola.
        test = re.sub(r"(?<!\S)/(\w+)", "/\u2060\\g<1>", test)
        # Ritorno il testo neutralizzato.
        return test

    @staticmethod
    def get_output(
        lista_link_puliti: list[tuple[str, str | None]], conf: AppConfig
    ) -> str:
        """Compone il testo finale con blocchi separati: titolo opzionale (blockquote) + URL."""
        # Se la lista è vuota, segnalo che non ho rilevato collegamenti.
        if not lista_link_puliti:
            logger.debug("get output nessun link pulito")
            return "nessun collegamento rilevato"

        # Raccolgo i blocchi formattati (uno per URL).
        blocks: list[str] = []
        for url_pulito, eventuale_titolo in lista_link_puliti:
            # Pezzi che compongono un singolo blocco.
            parts: list[str] = []

            # Se nelle opzioni di output è abilitato show_title e il titolo esiste, preparo un blockquote.
            if conf.show_title and eventuale_titolo:
                titolo_safe = html.escape(TelegramIO._neutralizza(eventuale_titolo))
                parts.append(f"<blockquote>{titolo_safe}</blockquote>")

            # Aggiungo sempre l'URL (escapato) su una nuova riga.
            parts.append(html.escape(url_pulito))
            # Unisco le parti del blocco con una riga vuota tra titolo e URL.
            blocks.append("\n".join(parts))

        # Unisco i blocchi con una riga vuota di separazione.
        output_testo = "\n\n".join(blocks)
        # Loggo quante sezioni ho prodotto.
        logger.debug("get output testo pronto con %d blocchi", len(blocks))
        # Ritorno il testo finito.
        return output_testo
