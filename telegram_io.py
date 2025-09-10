from __future__ import annotations

# modulo: telegram_io.py
# scopo: comporre il testo di risposta da inviare su telegram in html semplice

from utils import logger
import re
import html
from app_config import AppConfig


class TelegramIO:
    """costruisce l output con titolo opzionale e url pulito per telegram"""

    @staticmethod
    def _neutralize_triggers(text: str) -> str:
        """inserisce caratteri zero width per evitare trigger di menzioni hashtag e comandi"""
        if not text:
            return text
        text = re.sub(r"(?<!\S)@(\w+)", "@\u2060\\g<1>", text)
        text = re.sub(r"(?<!\S)#(\w+)", "#\u2060\\g<1>", text)
        text = re.sub(r"(?<!\S)/(\w+)", "/\u2060\\g<1>", text)
        return text

    @staticmethod
    def build_output(
        cleaned_links: list[tuple[str, str | None]], conf: AppConfig
    ) -> str:
        """compone il testo con blocchi separati, titolo in blockquote e url"""
        if not cleaned_links:
            logger.debug("No cleaned links to output")
            return "nessun collegamento rilevato"

        blocks: list[str] = []
        for cleaned_url, maybe_title in list(dict.fromkeys(cleaned_links)):
            parts: list[str] = []
            if conf.show_title and maybe_title:
                safe_title = html.escape(TelegramIO._neutralize_triggers(maybe_title))
                parts.append(f"<blockquote>{safe_title}</blockquote>")
            parts.append(html.escape(cleaned_url))
            blocks.append("\n".join(parts))

        text = "\n\n".join(blocks)
        logger.debug("Prepared output text with %d blocks", len(blocks))
        return text
