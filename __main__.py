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
    CONFIG_PATH,
    KEYS_PATH,
)
import app_config

import asyncio

from telegram import Update
from telegram.ext import (
    CommandHandler,
    Application,
    ContextTypes,
    InlineQueryHandler,
    MessageHandler,
    filters,
)

# carico configurazione e chiavi all avvio
CONFIG = app_config.AppConfig.load(CONFIG_PATH)
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
        domain_whitelist=KEYS.get("DOMAIN_WHITELIST", {}),
        conf=CONFIG,
    )
    handlers = TelegramHandlers(sanitizer, CONFIG)

    # registrazione handler
    application.add_handler(CommandHandler("start", handlers.cmd_start), group=0)
    application.add_handler(CommandHandler("help", handlers.cmd_help), group=0)

    group_filter = (
        filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND
    )
    application.add_handler(
        MessageHandler(group_filter, handlers.handle_groups), group=1
    )

    private_filter = (
        filters.ChatType.PRIVATE & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND
    )
    application.add_handler(
        MessageHandler(private_filter, handlers.handle_private), group=1
    )

    application.add_handler(InlineQueryHandler(handlers.handle_inline), group=0)

    logger.info("Bot is configured and running")

    await application.initialize()
    await application.start()
    try:
        await application.updater.start_polling(allowed_updates=Update.ALL_TYPES)
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
