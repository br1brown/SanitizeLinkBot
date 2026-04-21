from __future__ import annotations

# telegram_io.py — compone il testo di risposta HTML da inviare su Telegram.

from .chat_prefs import SanitizerOpts
from .utils import logger
import re
import html


class TelegramIO:
    """Costruisce l'output HTML per Telegram a partire dagli URL sanificati."""

    @staticmethod
    def _neutralize_triggers(text: str) -> str:
        """Inserisce word-joiner (U+2060, invisibile) per spezzare @menzioni, #hashtag e /comandi.
        Senza questo, un titolo di pagina che inizia con "@" attiverebbe una menzione Telegram.
        """
        if not text:
            return text
        text = re.sub(r"(?<!\S)@(\w+)", "@\u2060\\g<1>", text)  # menzioni
        text = re.sub(r"(?<!\S)#(\w+)", "#\u2060\\g<1>", text)  # hashtag
        text = re.sub(r"(?<!\S)/(\w+)", "/\u2060\\g<1>", text)  # comandi /bot
        return text

    @staticmethod
    def build_output(
        cleaned_links: list[tuple[str, str | None]], opts: SanitizerOpts
    ) -> str:
        """Costruisce il messaggio HTML per uno o più URL sanificati.

        Due modalità in base alle opzioni:
        - show_url=True:  URL in chiaro come testo (obbligatorio per incollare/copiare)
        - show_url=False: URL nascosto dentro un <a href>, titolo come testo cliccabile
        Il titolo appare in <blockquote> se show_url=True, come testo del link se show_url=False.
        """
        if not cleaned_links:
            logger.debug("Nessun link pulito da produrre")
            return "nessun collegamento rilevato"

        blocks: list[str] = []
        # dict.fromkeys deduplica preservando l'ordine (tuple è hashable, a differenza di list)
        for cleaned_url, maybe_title in list(dict.fromkeys(cleaned_links)):
            parts: list[str] = []
            title = (maybe_title or "").strip()

            if opts.show_url:
                if opts.show_title and title:
                    safe_title = html.escape(TelegramIO._neutralize_triggers(title))
                    parts.append(f"<blockquote>{safe_title}</blockquote>")
                parts.append(
                    html.escape(cleaned_url)
                )  # URL sempre escaped: può contenere < > &
            else:
                if opts.show_title and title:
                    safe_title = html.escape(TelegramIO._neutralize_triggers(title))
                    safe_href = html.escape(
                        cleaned_url, quote=True
                    )  # quote=True: escape anche " per href="..."
                    parts.append(f'<a href="{safe_href}">{safe_title}</a>')
                else:
                    parts.append(html.escape(cleaned_url))

            blocks.append("\n".join(parts))

        text = "\n\n".join(blocks)
        logger.debug(
            "Preparato il testo di output con %d blocchi (show_url=%s, show_title=%s)",
            len(blocks),
            getattr(opts, "show_url", None),
            getattr(opts, "show_title", None),
        )
        return text

    @staticmethod
    def build_plain_output(
        cleaned_link: tuple[str, str | None], opts: SanitizerOpts
    ) -> str:
        """Variante per inline query: un solo URL, niente HTML (InputTextMessageContent non supporta parse_mode)."""
        if not cleaned_link:
            return "nessun collegamento rilevato"

        cleaned_url, maybe_title = cleaned_link
        parts: list[str] = []
        title = (maybe_title or "").strip()

        if opts.show_url and opts.show_title and title:
            safe_title = html.escape(TelegramIO._neutralize_triggers(title))
            parts.append(safe_title)
        parts.append(html.escape(cleaned_url))

        logger.debug(
            "Preparato l'output semplice (show_url=%s, show_title=%s)",
            getattr(opts, "show_url", None),
            getattr(opts, "show_title", None),
        )
        return "\n".join(parts)
