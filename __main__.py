from __future__ import annotations

# Modulo: __main__.py
# Scopo: punto d'ingresso del bot. Crea l'app Telegram, registra gli handler e avvia il polling.

from sanitizer import Sanitizer  # core: pulizia URL
from telegram_handlers import TelegramHandlers  # orchestrazione handler Telegram

from utils import (  # utilità condivise
    logger,
    set_log_level,
    get_telegram_token,
    load_json_file,
    render_from_file,
    CONFIG_PATH,
    KEYS_PATH,
)
import app_config  # modulo della AppConfig

import asyncio  # per ciclo event‑loop asincrono

from telegram import Update  # tipi Telegram
from telegram.ext import (  # componenti PTB
    CommandHandler,
    Application,
    ContextTypes,
    InlineQueryHandler,
    MessageHandler,
    filters,
)


# Carico la configurazione obbligatoria e le chiavi opzionali all'avvio modulo.
CONFIG = app_config.AppConfig.load(CONFIG_PATH)
KEYS = load_json_file(KEYS_PATH)


async def main() -> None:
    """Avvia il bot: costruisce Application, registra gli handler, e mantiene il polling."""
    try:
        # 1) Leggo il token Telegram e costruisco l'oggetto Application (builder pattern).
        telegram_token = get_telegram_token()
        application = Application.builder().token(telegram_token).build()
    except RuntimeError as error:
        # Token mancante o configurazione corrotta: loggo e interrompo l'avvio.
        logger.error("Avvio interrotto per configurazione non valida: %s", error)
        return

    # 2) Istanzio il Sanitizer con le liste prese da keys.json e la config runtime.
    sanitizer = Sanitizer(
        exact_keys=set(KEYS.get("EXACT_KEYS", [])),
        prefix_keys=tuple(KEYS.get("PREFIX_KEYS", [])),
        ends_with=tuple(KEYS.get("ENDS_WITH", [])),
        frag_keys=tuple(KEYS.get("FRAG_KEYS", [])),
        domain_whitelist=KEYS.get("DOMAIN_WHITELIST", {}),
        conf=CONFIG,
    )
    # 3) Creo il contenitore degli handler.
    handlers = TelegramHandlers(sanitizer, CONFIG)

    # ---------- Registrazione handler ----------
    # /start e /help (gruppo=0 per priorità alta).
    application.add_handler(CommandHandler("start", handlers.cmd_start), group=0)
    application.add_handler(CommandHandler("help", handlers.cmd_help), group=0)

    # Messaggi nei gruppi/supergruppi: testo o caption non comando → gestisco menzioni con reply.
    group_filter = (
        filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND
    )
    application.add_handler(
        MessageHandler(group_filter, handlers.handle_gruppi), group=1
    )

    # Messaggi in chat privata: testo o caption non comando → pulizia diretta.
    private_filter = (
        filters.ChatType.PRIVATE & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND
    )
    application.add_handler(
        MessageHandler(private_filter, handlers.handle_privato), group=1
    )

    # Inline query: attivo il relativo handler.
    application.add_handler(InlineQueryHandler(handlers.handle_inline), group=0)

    # Log informativo: app pronta e in esecuzione.
    logger.info("configurazione caricata bot in esecuzione")

    # ---------- Ciclo di vita dell'app Telegram ----------
    # Inizializzo l'applicazione (apre risorse interne PTB).
    await application.initialize()
    # Avvio la fase di start (apre connessioni HTTP/long polling).
    await application.start()
    try:
        # Attivo il polling degli update (compat con PTB 20).
        await application.updater.start_polling(allowed_updates=Update.ALL_TYPES)
        # Attendo indefinitamente finché non arriva un segnale di stop (Ctrl+C ecc.).
        await asyncio.Event().wait()
    finally:
        # Spegnimento ordinato: stop updater, stop app, shutdown e chiusura sessione HTTP del Sanitizer.
        await application.updater.stop()
        await application.stop()
        await application.shutdown()
        await sanitizer.close()
        logger.info("Bot arrestato correttamente")


if __name__ == "__main__":
    # Eseguo il main asincrono; intercetto Ctrl+C per una chiusura pulita.
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterruzione richiesta dall'utente (Ctrl+C)")
