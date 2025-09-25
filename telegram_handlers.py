from __future__ import annotations

# modulo: telegram_handlers.py
# scopo: orchestrare la logica degli handler telegram e coordinare sanitizer e io
import json, os
from utils import logger, render_from_file
import hashlib
from collections.abc import Iterable
from telegram import (
    InlineQueryResultArticle,
    InputTextMessageContent,
    Update,
    MessageEntity,
    ReactionTypeEmoji,
    InlineKeyboardButton,
    InlineKeyboardMarkup
)
from telegram.constants import ChatType, ParseMode
from telegram.ext import ContextTypes, CallbackQueryHandler

from sanitizer import Sanitizer
from getter_url import GetterUrl
from telegram_io import TelegramIO
from app_config import AppConfig
from chat_prefs import ChatPrefs, SanitizerOpts


class TelegramHandlers:
    """gestisce gli update telegram e prepara le risposte"""

    def __init__(self, sanitizer: Sanitizer) -> None:
        self.sanitizer = sanitizer
        ChatPrefs.load()

    async def _sanitize_and_reply(
        self, target_message, detected_links: list[str]
    ) -> tuple[int, int | None]:
        chat_id = target_message.chat.id
        opts = ChatPrefs.build_opts(chat_id)

        cleaned = await self.sanitizer.sanitize_batch(detected_links, opts=opts)

        reply_text = TelegramIO.build_output(cleaned, opts)

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

    async def handle_private(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """gestisce la chat privata pulendo i link presenti nel messaggio"""
        if update.effective_chat.type != ChatType.PRIVATE:
            return
        message = update.effective_message
        detected_links = await self.acknowledge_and_extract(message)

        if not detected_links:
            logger.info("PRIVATE: detected=%d cleaned=%d reply_id=%s", 0, 0, "n/a")
            return

        cleaned_count, reply_id = await self._sanitize_and_reply(
            message, detected_links
        )
        logger.info("PRIVATE: cleaned=%d reply_id=%s", cleaned_count, reply_id)

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

        # preferenze per l'utente che sta facendo l'inline
        uid = inline_query.from_user.id
        opts = ChatPrefs.build_opts(uid)

        clean_url, maybe_title = await self.sanitizer.sanitize_url(raw_url, opts=opts)
        result_id = hashlib.md5(clean_url.encode("utf-8")).hexdigest()
        reply_text = TelegramIO.build_plain_output((clean_url, maybe_title), opts)

        result = InlineQueryResultArticle(
            id=result_id,
            title=maybe_title or "URL",
            description=clean_url,
            input_message_content=InputTextMessageContent(reply_text),
        )
        await inline_query.answer([result], cache_time=0, is_personal=True)

        # Log minimalista: nessuna PII
        logger.info("INLINE: result_id=%s", result_id)

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

    async def cmd_sanifica(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """/sanifica — funziona SOLO se usato in risposta a un messaggio."""
        wrapper = update.effective_message
        if not wrapper or not wrapper.reply_to_message:
            if wrapper:
                await wrapper.reply_text("Usa /sanifica rispondendo a un messaggio che contiene link.")
            return

        target = wrapper.reply_to_message
        detected_links = await self.acknowledge_and_extract(target)
        if not detected_links:
            return

        await self._sanitize_and_reply(target, detected_links)


    def _flag(self, v: bool) -> str:
        return "🟢" if v else "🔴"  # palla verde/rossa

    def _build_settings_keyboard(self, prefs) -> InlineKeyboardMarkup:
        return InlineKeyboardMarkup([
            [InlineKeyboardButton(f"URL in chiaro {self._flag(prefs.show_url)}", callback_data="toggle:show_url")],
            [InlineKeyboardButton(f"Titolo pagina {self._flag(prefs.show_title)}", callback_data="toggle:show_title")],
            [InlineKeyboardButton(f"Frontend alternativo {self._flag(prefs.translate_url)}", callback_data="toggle:translate_url")],
        ])


    async def cmd_settings(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """mostra le impostazioni correnti della chat con bottoni toggle"""
        try:
            chat_id = update.effective_chat.id
            prefs = ChatPrefs.get(chat_id)

            text =  render_from_file("settings")

            await update.message.reply_text(
                text,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
                reply_markup=self._build_settings_keyboard(prefs),
            )
            logger.info("SETTINGS: shown for chat_id=%s", chat_id)
        except Exception as e:
            logger.error("Failed to render settings: %s", e)
            await update.message.reply_text(
                "Si è verificato un errore durante la lettura delle impostazioni."
            )

    async def handle_toggle(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """gestisce i click sui bottoni delle impostazioni"""
        query = update.callback_query
        await query.answer()
        try:
            chat_id = query.message.chat.id
            data = query.data or ""
            if not data.startswith("toggle:"):
                return

            key = data.split(":", 1)[1]
            # sicurezza: consenti solo le chiavi supportate
            if key not in {"show_url", "show_title", "translate_url"}:
                await query.answer("Opzione non valida", show_alert=True)
                return

            current = getattr(ChatPrefs.get(chat_id), key)
            ChatPrefs.set(chat_id, key, not current)

            # ricarica prefs aggiornate e aggiorna tastiera
            prefs = ChatPrefs.get(chat_id)
            await query.edit_message_reply_markup(
                reply_markup=self._build_settings_keyboard(prefs)
            )
        except Exception as e:
            logger.error("Failed to toggle setting: %s", e)
            await query.answer("Errore nell’aggiornamento", show_alert=True)
