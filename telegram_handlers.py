from __future__ import annotations

# modulo: telegram_handlers.py
# scopo: orchestrare la logica degli handler telegram e coordinare sanitizer e io

from utils import logger, render_from_file
import hashlib
from collections.abc import Iterable
from telegram import (
    InlineQueryResultArticle,
    InputTextMessageContent,
    Update,
    MessageEntity,
    ReactionTypeEmoji,
)
from telegram.constants import ChatType, ParseMode
from telegram.ext import ContextTypes

from sanitizer import Sanitizer
from getter_url import GetterUrl
from telegram_io import TelegramIO
from app_config import AppConfig


class TelegramHandlers:
    """gestisce gli update telegram e prepara le risposte"""

    def __init__(self, sanitizer: Sanitizer, conf: AppConfig) -> None:
        self.sanitizer = sanitizer
        self.conf = conf

    async def _sanitize_and_reply(
        self, target_message, detected_links: list[str]
    ) -> tuple[int, int | None]:
        """pulisce i link in parallelo, costruisce il testo e risponde come reply"""
        cleaned = await self.sanitizer.sanitize_batch(detected_links)
        reply_text = TelegramIO.build_output(cleaned, self.conf)
        reply_message = await target_message.reply_text(
            reply_text,
            disable_web_page_preview=len(cleaned) > 1,
            parse_mode=ParseMode.HTML,
        )
        reply_id = reply_message.message_id
        try:
            await self._react(target_message, None)
        except Exception:
            pass
        return len(cleaned), reply_id

    @staticmethod
    def _contains_mention(
        text: str | None,
        entities: Iterable[MessageEntity] | None,
        bot_username: str,
        bot_id: int,
    ) -> bool:
        """controlla menzioni con entita e fallback testuale"""
        if not text:
            return False
        if entities:
            for entity in entities:
                if entity.type == MessageEntity.MENTION:
                    mention_text = text[
                        entity.offset : entity.offset + entity.length
                    ].lower()
                    if mention_text == f"@{bot_username}":
                        return True
                elif entity.type == MessageEntity.TEXT_MENTION and entity.user:
                    if entity.user.id == bot_id:
                        return True
        return f"@{bot_username}" in text.lower()

    @staticmethod
    def is_mentioned(message, context: ContextTypes.DEFAULT_TYPE) -> bool:
        """verifica se il messaggio contiene una menzione esplicita al bot"""
        bot_username = (context.bot.username or "").lower()
        bot_id = context.bot.id
        return TelegramHandlers._contains_mention(
            message.text, message.entities, bot_username, bot_id
        ) or TelegramHandlers._contains_mention(
            message.caption, message.caption_entities, bot_username, bot_id
        )

    async def _react(self, message, emoji: str | None) -> bool:
        """imposta o rimuove una reaction sul messaggio"""
        try:
            if emoji:
                await message.set_reaction([ReactionTypeEmoji(emoji)])
            else:
                await message.set_reaction([])
            return True
        except Exception as err:
            logger.debug("Unable to set reaction %r: %s", emoji, err)
            return False

    async def acknowledge_and_extract(self, message) -> list[str]:
        """mette una reaction neutra ed estrae i link dal messaggio"""
        await self._react(message, "👀")
        detected_links = GetterUrl.urls_from_message(message)
        if not detected_links:
            success = await self._react(message, "❌")
            if not success:
                success = await self._react(message, "👎")
            if not success:
                await self._react(message, None)
            return []
        return detected_links

    async def handle_groups(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """gestisce le menzioni al bot nei gruppi, risponde alla reply target"""
        wrapper_message = update.effective_message
        if not wrapper_message or not self.is_mentioned(wrapper_message, context):
            logger.debug("Groups handler ignored because no mention or empty message")
            return
        if not wrapper_message.reply_to_message:
            logger.debug("Groups handler has no reply_to_message to process")
            return

        target_message = wrapper_message.reply_to_message
        detected_links = await self.acknowledge_and_extract(target_message)

        user = update.effective_user
        chat = update.effective_chat

        if not detected_links:
            logger.info(
                "GROUP: mention by %s (@%s) in '%s' — cleaned=%d",
                user.full_name,
                user.username,
                chat.title,
                0,
            )
            return

        cleaned_count, reply_id = await self._sanitize_and_reply(
            target_message, detected_links
        )
        logger.info(
            "GROUP: mention by %s (@%s) in '%s' — cleaned=%d reply_id=%s",
            user.full_name,
            user.username,
            chat.title,
            cleaned_count,
            reply_id,
        )

    async def handle_private(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """gestisce la chat privata pulendo i link presenti nel messaggio"""
        if update.effective_chat.type != ChatType.PRIVATE:
            return
        message = update.effective_message
        detected_links = await self.acknowledge_and_extract(message)
        user = update.effective_user

        if not detected_links:
            logger.info(
                "PRIVATE: from '%s' (@%s) — detected=%d cleaned=%d reply_id=%s",
                getattr(user, "full_name", "n/a"),
                getattr(user, "username", "n/a"),
                0,
                0,
                "n/a",
            )
            return

        cleaned_count, reply_id = await self._sanitize_and_reply(
            message, detected_links
        )
        logger.info(
            "PRIVATE: from '%s' (@%s) — cleaned=%d reply_id=%s",
            getattr(user, "full_name", "n/a"),
            getattr(user, "username", "n/a"),
            cleaned_count,
            reply_id,
        )

    async def handle_inline(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """gestisce le inline query pulendo solo il primo url digitato"""
        inline_query = update.inline_query
        if not inline_query:
            return

        query_text = (inline_query.query or "").strip()
        urls = GetterUrl.extract_urls(query_text)
        if not urls:
            return

        raw_url = urls[0]
        clean_url, maybe_title = await self.sanitizer.sanitize_url(raw_url)
        result_id = hashlib.md5(clean_url.encode("utf-8")).hexdigest()

        result = InlineQueryResultArticle(
            id=result_id,
            title=maybe_title or "URL",
            description=clean_url,
            input_message_content=InputTextMessageContent(
                (maybe_title or "") + "\n" + clean_url
            ),
        )
        await inline_query.answer([result], cache_time=0, is_personal=True)

        user = inline_query.from_user if hasattr(inline_query, "from_user") else None
        logger.info(
            "INLINE: from '%s' (@%s, id=%s) — result_id=%s",
            getattr(user, "full_name", "n/a") if user else "n/a",
            getattr(user, "username", "n/a") if user else "n/a",
            getattr(user, "id", "n/a") if user else "n/a",
            result_id,
        )

    async def cmd_start(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """risponde con un messaggio di benvenuto"""
        user = update.effective_user
        first_name = user.first_name if user and user.first_name else "utente"
        text = render_from_file("start", first_name=first_name)
        await update.message.reply_text(
            text, parse_mode=ParseMode.HTML, disable_web_page_preview=True
        )

    async def cmd_help(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """mostra un aiuto su come usare il bot"""
        bot_username = context.bot.username or (await context.bot.get_me()).username
        mention_bot = f"@{bot_username}" if bot_username else "@.."
        text = render_from_file("help", mention_bot=mention_bot)
        await update.message.reply_text(
            text, parse_mode=ParseMode.HTML, disable_web_page_preview=True
        )
