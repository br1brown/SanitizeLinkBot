from __future__ import annotations

# telegram_handlers.py — riceve gli update Telegram e orchestra sanitizer + output.
# Ogni handler corrisponde a un contesto diverso: chat privata, gruppo, inline, comandi.

import hashlib
import html
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
    """Gestisce gli update Telegram e prepara le risposte."""

    def __init__(self, sanitizer: Sanitizer) -> None:
        self.sanitizer = sanitizer
        ChatPrefs.load()  # inizializza il DB SQLite al primo avvio

    async def _react(self, message, *candidates: str | None) -> bool:
        """Imposta una reaction sul messaggio, provando i candidati in ordine come fallback.
        None come candidato rimuove la reaction (utile per togliere 👀 dopo aver risposto).
        """
        for emoji in candidates:
            try:
                reactions = [ReactionTypeEmoji(emoji)] if emoji else []
                await message.set_reaction(reactions)
                return True
            except Exception as err:
                logger.debug("Impossibile impostare la reaction %r: %s", emoji, err)
        return False

    async def _send_cleaned_reply(self, target_message, cleaned, opts: SanitizerOpts):
        """Invia il testo sanificato come risposta al messaggio target."""
        reply_text = TelegramIO.build_output(cleaned, opts)
        return await target_message.reply_text(
            reply_text,
            # Anteprima link disabilitata per batch: con più URL genererebbe preview multipli rumorosi
            link_preview_options=LinkPreviewOptions(is_disabled=len(cleaned) > 1),
            parse_mode=ParseMode.HTML,
            do_quote=True,
        )

    async def handle_group(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handler modalità automatica nei gruppi: agisce solo se group_auto è attivo nelle impostazioni."""
        message = update.effective_message
        if not message:
            return

        chat_id = message.chat.id
        prefs = ChatPrefs.get(chat_id)

        if not prefs.group_auto:
            return  # modalità automatica disabilitata: ignoriamo silenziosamente

        detected = GetterUrl.urls_from_message(message)
        if not detected:
            logger.debug("GRUPPO auto: nessun link, salto in silenzio")
            return

        opts = ChatPrefs.build_opts(chat_id)
        await self._react(message, "👀")  # feedback visivo: stiamo elaborando

        cleaned = await self.sanitizer.sanitize_batch(opts, detected)

        # Import locale per evitare import circolare: telegram_handlers → utils → (potenzialmente) altri moduli
        from .utils import urls_are_semantically_equivalent

        is_unchanged = len(cleaned) == len(detected) and all(
            urls_are_semantically_equivalent(cleaned_item[0], original)
            for cleaned_item, original in zip(cleaned, detected)
        )
        if is_unchanged:
            # Link già pulito: reaction silenziosa, nessun messaggio in chat (meno rumore nel gruppo)
            await self._react(message, "👍")
        else:
            reply = await self._send_cleaned_reply(message, cleaned, opts)
            await self._react(message, None)  # rimuove 👀 dopo aver inviato la risposta
            logger.info("GRUPPO: puliti=%d reply_id=%s", len(cleaned), reply.message_id)

    async def handle_private(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handler chat privata: risponde sempre, anche se il link era già pulito."""
        if update.effective_chat.type != ChatType.PRIVATE:
            return
        message = update.effective_message

        await self._react(message, "👀")
        detected = GetterUrl.urls_from_message(message)

        if not detected:
            logger.info("PRIVATA: rilevati 0 link")
            # ❌ preferito, 👎 come fallback se il bot non ha il permesso di usare ❌
            await self._react(message, "❌", "👎", None)
            return

        opts = ChatPrefs.build_opts(message.chat.id)
        cleaned = await self.sanitizer.sanitize_batch(opts, detected)
        reply = await self._send_cleaned_reply(message, cleaned, opts)
        await self._react(message, None)
        logger.info("PRIVATA: puliti=%d reply_id=%s", len(cleaned), reply.message_id)

    async def cmd_sanifica(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """/sanifica — trigger esplicito in risposta a un messaggio con link."""
        wrapper = update.effective_message
        if not wrapper or not wrapper.reply_to_message:
            if wrapper:
                await wrapper.reply_text(
                    "Usa /sanifica in risposta a un messaggio con link.", do_quote=True
                )
            return

        target = wrapper.reply_to_message  # il messaggio che contiene i link da pulire
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
        """Handler inline query: @bot <url> → restituisce l'URL sanificato come risultato selezionabile."""
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

        # ID deterministico basato sull'URL pulito: stesso URL → stesso ID, evita duplicati nella cache Telegram
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

    # --- SETTINGS ---

    def _flag(self, enabled: bool) -> str:
        return "🟢" if enabled else "🔴"

    def _build_settings_keyboard(
        self, prefs, is_group: bool = False
    ) -> InlineKeyboardMarkup:
        rows = [
            [
                InlineKeyboardButton(
                    f"URL in chiaro {self._flag(prefs.show_url)}",
                    callback_data="toggle:show_url",
                )
            ],
            [
                InlineKeyboardButton(
                    f"Titolo pagina {self._flag(prefs.show_title)}",
                    callback_data="toggle:show_title",
                )
            ],
            [
                InlineKeyboardButton(
                    f"Frontend alternativo [beta] {self._flag(prefs.use_privacy_frontend)}",
                    callback_data="toggle:use_privacy_frontend",
                )
            ],
        ]
        if is_group:
            rows.append(
                [
                    InlineKeyboardButton(
                        f"Modalità automatica {self._flag(prefs.group_auto)}",
                        callback_data="toggle:group_auto",
                    )
                ]
            )
        rows.append([InlineKeyboardButton("Chiudi ✕", callback_data="toggle:close")])
        return InlineKeyboardMarkup(rows)

    async def cmd_settings(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        try:
            chat = update.effective_chat
            is_group = chat.type in (ChatType.GROUP, ChatType.SUPERGROUP)
            prefs = ChatPrefs.get(chat.id)
            text = render_from_file(
                "settings_group" if is_group else "settings_private"
            )
            await update.message.reply_text(
                text,
                parse_mode=ParseMode.HTML,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
                reply_markup=self._build_settings_keyboard(prefs, is_group),
            )
            logger.info("IMPOSTAZIONI: mostrate per chat_id=%s", chat.id)
        except Exception as exc:
            logger.error("Impossibile mostrare le impostazioni: %s", exc)

    async def handle_toggle(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Handler callback dei pulsanti inline delle impostazioni."""
        query = update.callback_query
        await query.answer()  # risposta immediata a Telegram per togliere il loading sul bottone
        try:
            chat_id = query.message.chat.id
            data = query.data or ""
            if not data.startswith("toggle:"):
                return
            # maxsplit=1: gestisce correttamente chiavi che contengono ":" (es. "toggle:a:b")
            key = data.split(":", 1)[1]

            if key == "close":
                prefs = ChatPrefs.get(chat_id)
                summary = (
                    f"⚙️ <b>Impostazioni aggiornate</b>\n"
                    f"URL in chiaro {self._flag(prefs.show_url)}  "
                    f"Titolo {self._flag(prefs.show_title)}  "
                    f"Frontend alt. {self._flag(prefs.use_privacy_frontend)}"
                )
                if query.message.chat.type in (ChatType.GROUP, ChatType.SUPERGROUP):
                    summary += f"  Modalità auto {self._flag(prefs.group_auto)}"
                await query.edit_message_text(
                    summary, parse_mode=ParseMode.HTML, reply_markup=None
                )
                return

            if key in PREF_KEYS:
                current = getattr(
                    ChatPrefs.get(chat_id), key
                )  # getattr dinamico: evita un if/elif per ogni chiave
                await ChatPrefs.set(chat_id, key, not current)
                prefs = ChatPrefs.get(chat_id)
                is_group = query.message.chat.type in (
                    ChatType.GROUP,
                    ChatType.SUPERGROUP,
                )
                await query.edit_message_reply_markup(
                    reply_markup=self._build_settings_keyboard(prefs, is_group)
                )

        except Exception as exc:
            logger.error("Impossibile cambiare l'impostazione: %s", exc)
            await query.answer("Errore nell'aggiornamento", show_alert=True)

    async def cmd_scan(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """/scan [url] — analizza un URL con urlscan.io e restituisce screenshot e report."""
        message = update.effective_message
        if not message:
            return

        # URL dagli argomenti del comando o dal messaggio citato
        target_url: str | None = None
        if context.args:
            candidates = GetterUrl.extract_urls(context.args[0].strip())
            if candidates:
                target_url = candidates[0]
        elif message.reply_to_message:
            urls = GetterUrl.urls_from_message(message.reply_to_message)
            if urls:
                target_url = urls[0]

        if not target_url:
            await message.reply_text(
                "Usa <code>/scan &lt;url&gt;</code> oppure rispondi a un messaggio con un link.",
                parse_mode=ParseMode.HTML,
                do_quote=True,
            )
            return

        # Il client urlscan viene inizializzato lazy al primo _get_session()
        urlscan = self.sanitizer.urlscan
        if urlscan is None:
            await self.sanitizer._get_session()
            urlscan = self.sanitizer.urlscan
        if urlscan is None:
            await message.reply_text(
                "Il comando /scan non è disponibile: configura <code>URLSCAN_API_KEY</code> nel file env.",
                parse_mode=ParseMode.HTML,
                do_quote=True,
            )
            return

        notice = await message.reply_text(
            "🔍 Analisi in corso tramite <b>urlscan.io</b> (servizio esterno).\n"
            "La scansione è <b>pubblica</b>: l'URL sarà visibile su urlscan.io.",
            parse_mode=ParseMode.HTML,
            link_preview_options=LinkPreviewOptions(is_disabled=True),
            do_quote=True,
        )

        uuid = await urlscan.submit_scan(target_url, visibility="public")
        if not uuid:
            await notice.edit_text("Impossibile avviare la scansione. Riprova più tardi.")
            return

        result = await urlscan.wait_for_result(uuid)
        report_url = f"https://urlscan.io/result/{uuid}/"

        if not result:
            await notice.edit_text(
                f"La scansione è ancora in corso.\nConsulta il report quando sarà pronto: {report_url}"
            )
            return

        overall = (result.get("verdicts") or {}).get("overall", {})
        is_malicious = overall.get("malicious", False)
        score = overall.get("score", 0)
        tags = overall.get("tags") or []
        categories = overall.get("categories") or []

        engines = (result.get("verdicts") or {}).get("engines", {})
        engines_malicious = engines.get("malicious", 0)
        engines_total = engines.get("enginesTotal", 0)

        page = result.get("page") or {}
        domain = page.get("domain", "")
        page_title = page.get("title", "")

        stats_malicious = (result.get("stats") or {}).get("malicious", 0)

        if is_malicious:
            verdict_line = "🔴 <b>Malevolo</b>"
        elif score > 0 or stats_malicious > 0:
            verdict_line = "⚠️ <b>Sospetto</b>"
        else:
            verdict_line = "✅ <b>Nessuna minaccia rilevata</b>"

        lines = [verdict_line]
        if domain:
            row = f"<code>{html.escape(domain)}</code>"
            if page_title:
                row += f" — {html.escape(page_title)}"
            lines.append(row)
        if engines_total > 0:
            lines.append(f"Motori antivirus: {engines_malicious}/{engines_total} lo segnalano")
        label_tags = tags + [c for c in categories if c not in tags]
        if label_tags:
            lines.append("Tag: " + ", ".join(html.escape(t) for t in label_tags[:5]))
        if stats_malicious > 0:
            lines.append(f"Risorse malevole caricate: {stats_malicious}")
        lines.append(f'\n<a href="{report_url}">Report completo →</a>')

        verdict_text = "\n".join(lines)
        await notice.edit_text(
            verdict_text,
            parse_mode=ParseMode.HTML,
            link_preview_options=LinkPreviewOptions(is_disabled=True),
        )

        logger.info("SCAN: uuid=%s malicious=%s score=%s", uuid, is_malicious, score)

    async def cmd_start(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        user = update.effective_user
        first_name = user.first_name if user and user.first_name else "utente"
        text = render_from_file("start", first_name=first_name)
        await update.message.reply_text(
            text,
            parse_mode=ParseMode.HTML,
            link_preview_options=LinkPreviewOptions(is_disabled=True),
        )

    async def cmd_help(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        bot_username = context.bot.username or ""
        text = render_from_file("help", mention_bot=f"@{bot_username}")
        if self.sanitizer.conf.urlscan_api_key:
            text += "\n\n" + render_from_file("scan_info")
        text += '\n\nCodice sorgente: <a href="https://github.com/br1brown/SanitizeLinkBot">GitHub</a>'
        await update.message.reply_text(
            text,
            parse_mode=ParseMode.HTML,
            link_preview_options=LinkPreviewOptions(is_disabled=True),
        )
