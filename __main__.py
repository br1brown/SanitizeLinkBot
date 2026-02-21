from __future__ import annotations

# modulo: __main__.py
# scopo: punto di ingresso del bot, crea l app telegram, registra gli handler e avvia il polling

from sanitizer import Sanitizer
from telegram_handlers import TelegramHandlers

from utils import (
    logger,
    set_log_level,
    get_telegram_token,
    load_json_file,
    render_from_file,
    KEYS_PATH,
    BASE_DIR,
)
import app_config

import asyncio
import os

from telegram import BotCommand
from telegram.ext import (
    CallbackQueryHandler,
    CommandHandler,
    Application,
    ContextTypes,
    InlineQueryHandler,
    MessageHandler,
    filters,
)


def _load_env_file() -> None:
    """Carica variabili d'ambiente dal file 'env' se presente.
    Non sovrascrive variabili già impostate nell'ambiente."""
    env_path = os.path.join(BASE_DIR, "env")
    if not os.path.isfile(env_path):
        logger.debug("No env file found at %s, skipping", env_path)
        return
    loaded = 0
    with open(env_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if key and key not in os.environ:
                os.environ[key] = value
                loaded += 1
    logger.debug("Loaded %d env vars from %s", loaded, env_path)


# FIX 6: carica il file env PRIMA di leggere la configurazione
_load_env_file()

# carico configurazione e chiavi all avvio
CONFIG = app_config.AppConfig.load()
KEYS = load_json_file(KEYS_PATH)


async def main() -> None:
    """avvia il bot, registra gli handler e mantiene il polling"""
    try:
        telegram_token = get_telegram_token()
        application = Application.builder().token(telegram_token).build()
    except RuntimeError as error:
        logger.error("Startup aborted due to invalid configuration: %s", error)
        return

    sanitizer = Sanitizer(
        exact_keys=set(KEYS.get("EXACT_KEYS", [])),
        prefix_keys=tuple(KEYS.get("PREFIX_KEYS", [])),
        ends_with=tuple(KEYS.get("ENDS_WITH", [])),
        frag_keys=tuple(KEYS.get("FRAG_KEYS", [])),
        domain_whitelist=KEYS.get("DOMAIN_WHITELIST", []),
        conf=CONFIG,
    )
    handlers = TelegramHandlers(sanitizer)

    application.add_handler(CommandHandler("settings", handlers.cmd_settings))
    application.add_handler(CallbackQueryHandler(handlers.handle_toggle, pattern=r"^toggle:"))
    
    application.add_handler(InlineQueryHandler(handlers.handle_inline))

    application.add_handler(CommandHandler("start", handlers.cmd_start))
    application.add_handler(CommandHandler("help", handlers.cmd_help))
    application.add_handler(CommandHandler("sanifica", handlers.cmd_sanifica))
    
    private_filter = (
        filters.ChatType.PRIVATE & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND
    )
    application.add_handler(
        MessageHandler(private_filter, handlers.handle_private), group=1
    )

    group_filter = (
        (filters.ChatType.GROUPS) & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND
    )
    application.add_handler(
        MessageHandler(group_filter, handlers.handle_group), group=1
    )

    logger.info("Bot is configured and running")

    await application.initialize()
    await application.start()
    me = await application.bot.get_me()
    missing_botfather_flags = []
    if not bool(getattr(me, "supports_inline_queries", False)):
        missing_botfather_flags.append("Inline Mode")
    if not bool(getattr(me, "can_join_groups", False)):
        missing_botfather_flags.append("Allow Groups")
    if not bool(getattr(me, "can_read_all_group_messages", False)):
        missing_botfather_flags.append("Privacy ON")
    if missing_botfather_flags:
        logger.error(
            "Startup aborted: enable in BotFather before first use: %s",
            ", ".join(missing_botfather_flags),
        )
        await application.stop()
        await application.shutdown()
        await sanitizer.close()
        return

    await application.bot.set_my_commands([
        BotCommand("start", "Messaggio di benvenuto"),
        BotCommand("help", "Come usare il bot"),
        BotCommand("sanifica", "Pulisci i link in un messaggio (in risposta)"),
        BotCommand("settings", "Impostazioni della chat"),
    ])
    try:
        await application.updater.start_polling(
            allowed_updates=["message", "inline_query", "callback_query"]
        )
        await asyncio.Event().wait()
    finally:
        await application.updater.stop()
        await application.stop()
        await application.shutdown()
        await sanitizer.close()
        logger.info("Bot shut down cleanly")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\ninterruzione richiesta dall utente")
