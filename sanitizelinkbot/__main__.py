from __future__ import annotations

# __main__.py — punto di ingresso: crea l'applicazione Telegram, registra gli handler, avvia il polling.

# Permette di lanciare il file direttamente da VS Code come script (F5) oltre che con -m
if __name__ == "__main__" and not __package__:
    import sys, os, runpy

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    runpy.run_module("sanitizelinkbot", run_name="__main__")
    sys.exit()

from .sanitizer import Sanitizer
from .telegram_handlers import TelegramHandlers
from .clearurls_loader import ClearUrlsLoader
from .utils import (
    logger,
    set_log_level,
    get_telegram_token,
    load_json_file,
    KEYS_PATH,
    CLEARURLS_PATH,
    PROJECT_ROOT,
)
from . import app_config

import asyncio
import os
from pathlib import Path

from telegram import BotCommand
from telegram.ext import (
    CallbackQueryHandler,
    CommandHandler,
    Application,
    InlineQueryHandler,
    MessageHandler,
    filters,
)


def _load_env_file() -> None:
    """Carica variabili d'ambiente dal file '.env' se presente.
    Non sovrascrive variabili già impostate nell'ambiente di sistema.
    """
    env_path = os.path.join(PROJECT_ROOT, ".env")
    if not os.path.isfile(env_path):
        logger.debug("Nessun file .env trovato in %s, salto", env_path)
        return
    loaded = 0
    with open(env_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition(
                "="
            )  # partition invece di split: gestisce "KEY=a=b" correttamente
            key, value = key.strip(), value.strip()
            if key and key not in os.environ:
                os.environ[key] = value
                loaded += 1
    logger.debug("Caricate %d variabili d'ambiente da %s", loaded, env_path)


# Carica env PRIMA di leggere la configurazione: le variabili devono essere già in os.environ
_load_env_file()

CONFIG = app_config.AppConfig.load()
KEYS = load_json_file(KEYS_PATH)

# ClearURLs: caricamento sincrono all'avvio (il loop asyncio non è ancora attivo).
# Se il file manca, il loader resta in stato "non caricato" e viene ignorato dalla pipeline.
# Il file viene scaricato dal task monthly_updater al primo giro (~5 minuti dopo l'avvio).
_clearurls_loader = ClearUrlsLoader(Path(CLEARURLS_PATH))
_clearurls_loader.load_sync()


async def main() -> None:
    """Avvia il bot, registra gli handler e mantiene il polling."""
    try:
        telegram_token = get_telegram_token()
        # concurrent_updates=True: gli update vengono elaborati in parallelo invece che in coda
        application = (
            Application.builder().token(telegram_token).concurrent_updates(True).build()
        )
    except RuntimeError as error:
        logger.error(
            "Avvio interrotto a causa di una configurazione non valida: %s", error
        )
        return

    sanitizer = Sanitizer(
        exact_keys=set(KEYS.get("EXACT_KEYS", [])),
        prefix_keys=tuple(KEYS.get("PREFIX_KEYS", [])),
        ends_with=tuple(KEYS.get("ENDS_WITH", [])),
        frag_keys=tuple(KEYS.get("FRAG_KEYS", [])),
        domain_whitelist=KEYS.get("DOMAIN_WHITELIST", []),
        conf=CONFIG,
        clearurls=_clearurls_loader,
    )
    handlers = TelegramHandlers(sanitizer)

    # L'ordine di registrazione conta: handlers con pattern più specifici prima
    application.add_handler(CommandHandler("settings", handlers.cmd_settings))
    application.add_handler(
        CallbackQueryHandler(handlers.handle_toggle, pattern=r"^toggle:")
    )
    application.add_handler(InlineQueryHandler(handlers.handle_inline))
    application.add_handler(CommandHandler("start", handlers.cmd_start))
    application.add_handler(CommandHandler("help", handlers.cmd_help))
    application.add_handler(CommandHandler("sanifica", handlers.cmd_sanifica))
    if CONFIG.urlscan_api_key:
        application.add_handler(CommandHandler("scan", handlers.cmd_scan))

    # group=1: questi handler non interferiscono con i CommandHandler sopra (group=0 di default)
    application.add_handler(
        MessageHandler(
            filters.ChatType.PRIVATE
            & (filters.TEXT | filters.CAPTION)
            & ~filters.COMMAND,
            handlers.handle_private,
        ),
        group=1,
    )
    application.add_handler(
        MessageHandler(
            filters.ChatType.GROUPS
            & (filters.TEXT | filters.CAPTION)
            & ~filters.COMMAND,
            handlers.handle_group,
        ),
        group=1,
    )

    set_log_level(CONFIG.log_level)
    logger.info("Il bot è configurato e in esecuzione")

    await application.initialize()
    await application.start()

    # Riutilizziamo la sessione HTTP del Sanitizer per il monthly_updater:
    # evita di aprire una seconda sessione aiohttp con connessioni separate
    _http_session = await sanitizer._get_session()
    _clearurls_update_task = asyncio.create_task(
        _clearurls_loader.run_periodic_updater(_http_session),
        name="clearurls-periodic-updater",
    )
    logger.info("Aggiornamento periodico di ClearURLs configurato (ciclo di 5 giorni)")

    # Verifica le impostazioni BotFather necessarie per il funzionamento corretto
    me = await application.bot.get_me()
    missing_flags = []
    # getattr con fallback: questi campi sono opzionali nell'oggetto Bot
    if not bool(getattr(me, "supports_inline_queries", False)):
        missing_flags.append("Inline Mode")
    if not bool(getattr(me, "can_join_groups", False)):
        missing_flags.append("Allow Groups")
    if not bool(getattr(me, "can_read_all_group_messages", False)):
        missing_flags.append("Privacy OFF (Group Privacy)")
    if missing_flags:
        logger.warning(
            "Alcune impostazioni di BotFather potrebbero mancare: %s",
            ", ".join(missing_flags),
        )

    if not CONFIG.urlscan_api_key:
        logger.warning(
            "URLSCAN_API_KEY non configurata: il comando /scan non sarà disponibile"
        )

    bot_commands = [
        BotCommand("start", "Messaggio di benvenuto"),
        BotCommand("help", "Come usare il bot"),
        BotCommand("sanifica", "Pulisci i link in un messaggio (in risposta)"),
        BotCommand("settings", "Impostazioni della chat"),
    ]
    if CONFIG.urlscan_api_key:
        bot_commands.insert(
            -1,
            BotCommand("scan", "Analizza un URL con urlscan.io — scansione pubblica"),
        )
    await application.bot.set_my_commands(bot_commands)

    try:
        await application.updater.start_polling(
            allowed_updates=["message", "inline_query", "callback_query"]
        )
        # await su un Event mai settato: modo idiomatico per tenere vivo il loop asyncio
        await asyncio.Event().wait()
    finally:
        # Cancella il task ClearURLs prima di chiudere la sessione HTTP che usa
        _clearurls_update_task.cancel()
        try:
            await _clearurls_update_task
        except asyncio.CancelledError:
            pass
        await application.updater.stop()
        await application.stop()
        await application.shutdown()
        await sanitizer.close()
        logger.info("Bot arrestato correttamente")


if __name__ == "__main__":
    try:
        import uvloop

        uvloop.install()  # uvloop: event loop alternativo più veloce, disponibile solo su Linux/Mac
        logger.info(
            "uvloop abilitato per un miglioramento delle prestazioni di asyncio"
        )
    except ImportError:
        pass  # Windows o dipendenza assente: asyncio standard è comunque corretto

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterruzione richiesta dall'utente")
