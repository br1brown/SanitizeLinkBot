from __future__ import annotations

# Modulo: telegram_handlers.py
# Scopo: orchestrare la logica degli handler Telegram e coordinare Sanitizer e I/O.

from utils import logger, render_from_file  # logger e rendering dei template di testo

import hashlib  # per generare ID stabili dei risultati inline
from collections.abc import Iterable  # annotazioni
from telegram import (  # tipi Telegram usati dagli handler
    InlineQueryResultArticle,
    InputTextMessageContent,
    Update,
    MessageEntity,
    ReactionTypeEmoji,
)
from telegram.constants import (
    ChatType,
    ParseMode,
)  # costanti per tipologie chat e formattazione
from telegram.ext import ContextTypes  # tipi per il context

from sanitizer import Sanitizer  # pulizia URL
from getter_url import GetterUrl  # estrazione URL dai messaggi
from telegram_io import TelegramIO  # composizione testo di output
from app_config import AppConfig  # configurazione applicativa


class TelegramHandlers:
    """Gestisce gli update di Telegram e la preparazione delle risposte."""

    def __init__(self, sanitizer: Sanitizer, conf: AppConfig) -> None:
        # Conservo riferimenti condivisi a sanitizer e configurazione.
        self.sanitizer = sanitizer
        self.conf = conf

    async def _sanifica_e_rispondi(
        self, target_message, lista_link_rilevati: list[str]
    ) -> tuple[int, int | None]:
        """Pulisce i link in parallelo, costruisce il testo e risponde nel thread del messaggio."""
        # Pulisco tutti i link rilevati (in batch, con deduplica e concorrenza).
        lista_link_puliti = await self.sanitizer.sanifica_in_batch(lista_link_rilevati)

        # Preparo il testo formattato per Telegram.
        testo_risposta = TelegramIO.get_output(lista_link_puliti, self.conf)

        # Invio la risposta come 'reply' al messaggio bersaglio.
        reply_message = await target_message.reply_text(
            testo_risposta,
            disable_web_page_preview=len(lista_link_puliti)
            > 1,  # anteprime disabilitate se tanti link
            parse_mode=ParseMode.HTML,  # permette blockquote + escaping
        )
        # Salvo l'ID del messaggio di risposta per log/diagnostica.
        reply_id = reply_message.message_id

        # Provo a togliere la reaction di "presa in carico" o a metterne una neutra.
        try:
            await self._react(target_message, None)
        except Exception:
            # Qualunque errore nelle reaction non è critico: ignoro.
            pass

        # Ritorno il conteggio dei link e l'ID messaggio di risposta.
        return len(lista_link_puliti), reply_id

    @staticmethod
    def is_menzionato(messaggio, context: ContextTypes.DEFAULT_TYPE) -> bool:
        """Verifica se il messaggio contiene una menzione esplicita al bot."""
        # Estraggo username e ID del bot.
        bot_username = (context.bot.username or "").lower()
        bot_id = context.bot.id

        def _contiene_menzione(
            test: str | None, entities: Iterable[MessageEntity] | None
        ) -> bool:
            """Controlla menzioni @username e text_mention verso l'ID del bot."""
            # Se non c'è testo, non posso trovare menzioni.
            if not test:
                return False
            # Se ho entità, le scorro per trovare MENTION o TEXT_MENTION.
            if entities:
                for entity in entities:
                    if entity.type == MessageEntity.MENTION:
                        mention_text = test[
                            entity.offset : entity.offset + entity.length
                        ].lower()
                        if mention_text == f"@{bot_username}":
                            return True
                    elif entity.type == MessageEntity.TEXT_MENTION and entity.user:
                        if entity.user.id == bot_id:
                            return True
            # Fallback: cerco la stringa @username nel testo intero.
            return f"@{bot_username}" in test.lower()

        # Verifico su testo e su caption.
        return _contiene_menzione(
            messaggio.text, messaggio.entities
        ) or _contiene_menzione(messaggio.caption, messaggio.caption_entities)

    async def _react(self, message, emoji: str | None) -> bool:
        """Imposta o rimuove una reaction sul messaggio in modo silenzioso."""
        try:
            # Se ho un'emoji, imposto quella; altrimenti rimuovo le reaction.
            if emoji:
                await message.set_reaction([ReactionTypeEmoji(emoji)])
            else:
                await message.set_reaction([])
            return True
        except Exception as error:
            # In caso di fallimento, lo loggo in debug e ritorno False.
            logger.debug("impossibile impostare reaction %r %s", emoji, error)
            return False

    async def presaInCarico(self, messaggio) -> list[str]:
        """Mette una reaction di 'presa in carico' ed estrae i link dal messaggio."""
        # Metto una reaction 'occhi' per segnalare che sto lavorando al messaggio.
        await self._react(messaggio, "👀")

        # Estraggo link dal messaggio (entità → testo/caption).
        lista_link_rilevati = GetterUrl.url_da_msg(messaggio)

        # Se non ho trovato link, metto una reaction negativa e ritorno lista vuota.
        if not lista_link_rilevati:
            esito = await self._react(messaggio, "❌")
            if not esito:
                esito = await self._react(messaggio, "👎")
            if not esito:
                await self._react(messaggio, None)
            return []

        # Altrimenti ritorno la lista dei link trovati.
        return lista_link_rilevati

    async def handle_gruppi(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Gestisce le menzioni al bot nei gruppi: rispondo al messaggio citato con i link puliti."""
        # Prendo il messaggio "wrapper" (quello che contiene la menzione).
        messaggio = update.effective_message
        # Se non ho messaggio o non c'è menzione, esco.
        if not messaggio or not self.is_menzionato(messaggio, context):
            logger.debug("handle gruppi ignorato nessuna menzione o messaggio nullo")
            return
        # Se non è una reply a un messaggio (da pulire), non posso operare.
        if not messaggio.reply_to_message:
            logger.debug("handle gruppi manca reply to message")
            return

        # Il target effettivo è il messaggio a cui è stata fatta la reply.
        target_message = messaggio.reply_to_message
        # Estraggo i link dal messaggio target.
        lista_link_rilevati = await self.presaInCarico(target_message)
        # Raccolgo info per log.
        user = update.effective_user
        chat = update.effective_chat

        # Se non ho trovato link, loggo e termino.
        if not lista_link_rilevati:
            logger.info(
                "GRUPPO: menzione da %s username %s in %s puliti zero",
                user.full_name,
                user.username,
                chat.title,
            )
            return

        # Pulisce e risponde con i risultati.
        puliti, reply_id = await self._sanifica_e_rispondi(
            target_message, lista_link_rilevati
        )
        # Log finale di riepilogo attività.
        logger.info(
            "GRUPPO: menzione da %s username %s in %s puliti %d reply %s",
            user.full_name,
            user.username,
            chat.title,
            puliti,
            reply_id,
        )

    async def handle_privato(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Gestisce la chat privata pulendo i link presenti nel messaggio ricevuto."""
        # Elaboro solo se la chat è privata.
        if update.effective_chat.type != ChatType.PRIVATE:
            return

        # Estraggo il messaggio e poi i link.
        messaggio = update.effective_message
        lista_link_rilevati = await self.presaInCarico(messaggio)
        # Prendo l'utente per i log.
        user = update.effective_user

        # Se non ho link, loggo e termino.
        if not lista_link_rilevati:
            logger.info(
                "PRIVATO: da '%s' (@%s) — trovati=%d, puliti=%d, reply_msg_id=%s",
                getattr(user, "full_name", "n/a"),
                getattr(user, "username", "n/a"),
                0,
                0,
                "n/a",
            )
            return

        # Pulisco e rispondo.
        puliti, reply_id = await self._sanifica_e_rispondi(
            messaggio, lista_link_rilevati
        )
        # Log riepilogativo.
        logger.info(
            "PRIVATO: da '%s' (@%s) — puliti=%d, reply_msg_id=%s",
            getattr(user, "full_name", "n/a"),
            getattr(user, "username", "n/a"),
            puliti,
            reply_id,
        )

    async def handle_inline(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Gestisce le inline query pulendo solo il primo URL digitato."""
        # Estraggo la query inline.
        inline_query = update.inline_query
        # Se non c'è query inline, non c'è niente da fare.
        if not inline_query:
            return

        # Prendo il testo della query, togliendo spazi superflui.
        testo_query = (inline_query.query or "").strip()

        # Estraggo TUTTI i link presenti nel testo digitato inline.
        lista_url = GetterUrl.estrai_urls(testo_query)
        # Se non c'è nessun link, non rispondo (Telegram non mostrerà nulla).
        if not lista_url:
            return

        # Prendo SOLO il primo link da pulire (UX semplice in modalità inline).
        raw_url = lista_url[0]
        # Sanifico l'URL singolo (segue redirect, rimuove tracking, ecc.).
        clean_url, maybe_title = await self.sanitizer.sanifica_url(raw_url)

        # Creo un ID stabile per il risultato (hash MD5 dell'URL pulito).
        result_id = hashlib.md5(clean_url.encode("utf-8")).hexdigest()
        # Preparo il risultato in forma di articolo.
        result = InlineQueryResultArticle(
            id=result_id,
            title=maybe_title or "URL",
            description=clean_url,
            input_message_content=InputTextMessageContent(
                (maybe_title or "") + "\n" + clean_url
            ),
        )

        # Rispondo alla query inline con un solo risultato, disabilitando la cache.
        await inline_query.answer([result], cache_time=0, is_personal=True)

        # Log informativo sulla query inline ricevuta e gestita.
        user = inline_query.from_user if hasattr(inline_query, "from_user") else None
        logger.info(
            "INLINE: da '%s' (@%s, id=%s) —  result_id=%s",
            getattr(user, "full_name", "n/a") if user else "n/a",
            getattr(user, "username", "n/a") if user else "n/a",
            getattr(user, "id", "n/a") if user else "n/a",
            result_id,
        )

    async def cmd_start(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Risponde con un messaggio di benvenuto e istruzioni d'uso rapide."""
        # Recupero l'utente per salutare per nome.
        user = update.effective_user
        first_name = user.first_name if user and user.first_name else "utente"
        # Renderizzo il template 'start.html' con il nome.
        text = render_from_file("start", first_name=first_name)
        # Invio la risposta in HTML, senza anteprime.
        await update.message.reply_text(
            text, parse_mode=ParseMode.HTML, disable_web_page_preview=True
        )

    async def cmd_help(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Mostra un aiuto rapido su come usare il bot in chat privata e nei gruppi."""
        # Ottengo l'username del bot (o lo carico on demand).
        bot_username = context.bot.username or (await context.bot.get_me()).username
        mention_bot = f"@{bot_username}" if bot_username else "@.."
        # Renderizzo il template 'help.html' con la mention del bot.
        text = render_from_file("help", mention_bot=mention_bot)
        # Invio il testo formattato in HTML senza anteprime.
        await update.message.reply_text(
            text, parse_mode=ParseMode.HTML, disable_web_page_preview=True
        )
