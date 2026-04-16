from __future__ import annotations

# modulo: telegram_handlers.py
# scopo: orchestrare la logica degli handler telegram e coordinare sanitizer e io
import hashlib
from .utils import logger, render_from_file
from telegram import (
    InlineQueryResultArticle,
    InputTextMessageContent,
    LinkPreviewOptions,
    Update,
    ReactionTypeEmoji,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)
from telegram.constants import ChatType, ParseMode
from telegram.ext import ContextTypes

from .sanitizer import Sanitizer
from .getter_url import GetterUrl
from .telegram_io import TelegramIO
from .chat_prefs import ChatPrefs, PREF_KEYS, SanitizerOpts


class TelegramHandlers:
    """gestisce gli update telegram e prepara le risposte"""

    def __init__(self, sanitizer: Sanitizer) -> None:
        self.sanitizer = sanitizer
        ChatPrefs.load()

    async def _react(self, message, *candidates: str | None) -> bool:
        """imposta o rimuove una reaction; prova i candidati in ordine come fallback"""
        for emoji in candidates:
            try:
                reactions = [ReactionTypeEmoji(emoji)] if emoji else []
                await message.set_reaction(reactions)
                return True
            except Exception as err:
                logger.debug("Unable to set reaction %r: %s", emoji, err)
        return False



    async def _send_cleaned_reply(self, target_message, cleaned, opts: SanitizerOpts):
        """Helper interno per inviare l'output sanificato"""
        reply_text = TelegramIO.build_output(cleaned, opts)
        return await target_message.reply_text(
            reply_text,
            link_preview_options=LinkPreviewOptions(is_disabled=len(cleaned) > 1),
            parse_mode=ParseMode.HTML,
            quote=True,
        )

    async def handle_group(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """gestisce i gruppi: automatico se group_auto è attivo"""
        message = update.effective_message
        if not message:
            return
        
        chat_id = message.chat.id
        prefs = ChatPrefs.get(chat_id)
        
        if not prefs.group_auto:
            return

        detected = GetterUrl.urls_from_message(message)
        if not detected:
            logger.debug("GROUP auto: no links, skipping silently")
            return

        # Procediamo con la sanificazione
        opts = ChatPrefs.build_opts(chat_id)
        await self._react(message, "👀")
        
        cleaned = await self.sanitizer.sanitize_batch(opts, detected)
        
        from .utils import urls_are_semantically_equivalent
        
        is_unchanged = len(cleaned) == len(detected) and all(
            urls_are_semantically_equivalent(c[0], d) for c, d in zip(cleaned, detected)
        )
        if is_unchanged:
            # Feedback discreto: link già pulito, nessuna risposta in chat
            await self._react(message, "👍")
        else:
            reply = await self._send_cleaned_reply(message, cleaned, opts)
            await self._react(message, None)
            logger.info("GROUP: cleaned=%d reply_id=%s", len(cleaned), reply.message_id)

    async def handle_private(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """gestisce la chat privata: feedback sempre garantito"""
        if update.effective_chat.type != ChatType.PRIVATE:
            return
        message = update.effective_message
        
        await self._react(message, "👀")
        detected = GetterUrl.urls_from_message(message)
        
        if not detected:
            logger.info("PRIVATE: 0 links detected")
            await self._react(message, "❌", "👎", None)
            return

        opts = ChatPrefs.build_opts(message.chat.id)
        cleaned = await self.sanitizer.sanitize_batch(opts, detected)
        reply = await self._send_cleaned_reply(message, cleaned, opts)
        await self._react(message, None)
        logger.info("PRIVATE: cleaned=%d reply_id=%s", len(cleaned), reply.message_id)

    async def cmd_sanifica(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """/sanifica — trigger esplicito in risposta a un messaggio"""
        wrapper = update.effective_message
        if not wrapper or not wrapper.reply_to_message:
            if wrapper:
                await wrapper.reply_text("Usa /sanifica in risposta a un messaggio con link.", quote=True)
            return

        target = wrapper.reply_to_message
        await self._react(target, "👀")
        
        detected = GetterUrl.urls_from_message(target)
        if not detected:
            await self._react(target, "❌", "👎", None)
            return

        opts = ChatPrefs.build_opts(wrapper.chat.id)
        cleaned = await self.sanitizer.sanitize_batch(opts, detected)

        await self._send_cleaned_reply(target, cleaned, opts)
        await self._react(target, None)

    async def handle_inline(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """gestisce le inline query"""
        inline_query = update.inline_query
        if not inline_query:
            return

        query_text = (inline_query.query or "").strip()
        urls = GetterUrl.extract_urls(query_text)
        if not urls:
            return

        raw_url = urls[0]
        opts = ChatPrefs.build_opts(inline_query.from_user.id)

        clean_url, maybe_title = await self.sanitizer.sanitize_url(raw_url, opts=opts)
        result_id = hashlib.md5(clean_url.encode("utf-8")).hexdigest()
        reply_text = TelegramIO.build_plain_output((clean_url, maybe_title), opts)

        result = InlineQueryResultArticle(
            id=result_id,
            title=maybe_title or "URL Sanificato",
            description=clean_url,
            input_message_content=InputTextMessageContent(reply_text),
        )
        await inline_query.answer([result], cache_time=0, is_personal=True)
        logger.info("INLINE: result_id=%s", result_id)

    # --- SETTINGS & UI ---

    def _flag(self, v: bool) -> str:
        return "🟢" if v else "🔴"

    def _build_settings_keyboard(self, prefs, is_group: bool = False) -> InlineKeyboardMarkup:
        rows = [
            [InlineKeyboardButton(f"URL in chiaro {self._flag(prefs.show_url)}", callback_data="toggle:show_url")],
            [InlineKeyboardButton(f"Titolo pagina {self._flag(prefs.show_title)}", callback_data="toggle:show_title")],
            [InlineKeyboardButton(f"Frontend alternativo [beta] {self._flag(prefs.translate_url)}", callback_data="toggle:translate_url")],
        ]
        if is_group:
            rows.append([InlineKeyboardButton(f"Modalità automatica {self._flag(prefs.group_auto)}", callback_data="toggle:group_auto")])
        rows.append([InlineKeyboardButton("Chiudi ✕", callback_data="toggle:close")])
        return InlineKeyboardMarkup(rows)

    async def cmd_settings(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        try:
            chat = update.effective_chat
            is_group = chat.type in (ChatType.GROUP, ChatType.SUPERGROUP)
            prefs = ChatPrefs.get(chat.id)
            text = render_from_file("settings_group" if is_group else "settings_private")
            await update.message.reply_text(
                text,
                parse_mode=ParseMode.HTML,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
                reply_markup=self._build_settings_keyboard(prefs, is_group),
            )
            logger.info("SETTINGS: shown for chat_id=%s", chat.id)
        except Exception as e:
            logger.error("Failed to show settings: %s", e)

    async def handle_toggle(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        await query.answer()
        try:
            chat_id = query.message.chat.id
            data = query.data or ""
            if not data.startswith("toggle:"): return
            key = data.split(":", 1)[1]

            if key == "close":
                prefs = ChatPrefs.get(chat_id)
                # --- RIPRISTINO OVERVIEW IMPOSTAZIONI ---
                summary = (
                    f"⚙️ <b>Impostazioni aggiornate</b>\n"
                    f"URL in chiaro {self._flag(prefs.show_url)}  "
                    f"Titolo {self._flag(prefs.show_title)}  "
                    f"Frontend alt. {self._flag(prefs.translate_url)}"
                )
                if query.message.chat.type in (ChatType.GROUP, ChatType.SUPERGROUP):
                    summary += f"  Modalità auto {self._flag(prefs.group_auto)}"
                
                await query.edit_message_text(summary, parse_mode=ParseMode.HTML, reply_markup=None)
                return

            if key in PREF_KEYS:
                current = getattr(ChatPrefs.get(chat_id), key)
                await ChatPrefs.set(chat_id, key, not current)
                
                # Refresh tastiera
                prefs = ChatPrefs.get(chat_id)
                is_group = query.message.chat.type in (ChatType.GROUP, ChatType.SUPERGROUP)
                await query.edit_message_reply_markup(reply_markup=self._build_settings_keyboard(prefs, is_group))
        except Exception as e:
            logger.error("Failed to toggle setting: %s", e)
            await query.answer("Errore nell’aggiornamento", show_alert=True)

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        first_name = user.first_name if user and user.first_name else "utente"
        text = render_from_file("start", first_name=first_name)
        await update.message.reply_text(text, parse_mode=ParseMode.HTML, link_preview_options=LinkPreviewOptions(is_disabled=True))

    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        bot_username = context.bot.username or ""
        text = render_from_file("help", mention_bot=f"@{bot_username}")
        await update.message.reply_text(text, parse_mode=ParseMode.HTML, link_preview_options=LinkPreviewOptions(is_disabled=True))