from __future__ import annotations
from ast import Await  # permette di usare annotazioni di tipo "forward" (nomi definiti dopo)
 
"""
Dipendenze:
- python-telegram-bot >= 20

Installazione:
  pip install python-telegram-bot
  pip install aiohttp
"""
import json
import re  # modulo per lavorare con espressioni regolari (regex), tipo <regex.h> ma alto livello
import asyncio  # loop/eventi per async/await (equiv. a un event loop applicativo)
from urllib.parse import (
    urlsplit,  # smonta un URL in parti (schema, netloc, path, query, fragment)
    urlunsplit,  # ricompone le parti in un URL
    parse_qsl,  # parse della query string "a=1&b=2" → lista di coppie [("a","1"),("b","2")]
    urlencode,  # fa l'operazione inversa: lista coppie → stringa query URL-encoded
)
import os 
import sys
import aiohttp
import asyncio
from urllib.parse import urljoin

# Tipi opzionali (per IDE)
from typing import Iterable 

# Libreria di terze parti: python-telegram-bot 
from telegram import (
    Update,          # oggetto che rappresenta un aggiornamento da Telegram (messaggi, ecc.)
    MessageEntity,   # metadati dentro al testo (link, mention, ecc.)
)
from telegram.constants import ChatType  # enum con i tipi di chat (privata, gruppo, supergruppo)
from telegram.ext import (
    Application,     # oggetto principale: costruisce e avvia il bot
    ContextTypes,    # tipi per il contesto passato ai callback
    MessageHandler,  # handler che esegue una funzione quando arriva un messaggio che matcha dei filtri
    filters,         # raccolta di filtri predefiniti (per tipo chat, presenza testo, ecc.)
)



class Sanitizer:
    """
    Responsabile di: follow redirect, pulizia parametri di tracking, pulizia fragment.
    Inietti le liste/insiemi dal config nel costruttore.
    """
    _TRAILING_PUNCT = ".,;:!?)”»’'\""

    def __init__(
        self,
        *,
        exact_keys: set[str],
        prefix_keys: tuple[str, ...],
        ends_with: tuple[str, ...],
        frag_keys: tuple[str, ...],
        domain_whitelist: dict[str, dict] | None = None,
    ) -> None:
        self.EXACT_KEYS = set(map(str.lower, exact_keys or set()))
        self.PREFIX_KEYS = tuple(k.lower() for k in (prefix_keys or ()))
        self.ENDS_WITH = tuple(k.lower() for k in (ends_with or ()))
        self.FRAG_KEYS = tuple(k.lower() for k in (frag_keys or ()))
        self.DOMAIN_WHITELIST = { (k or "").lower(): v for k, v in (domain_whitelist or {}).items() }

    def _da_rimuovere(self, key: str) -> bool:
        k = (key or "").lower()
        if k in self.EXACT_KEYS:
            return True
        if any(k.startswith(p) for p in self.PREFIX_KEYS):
            return True
        if any(k.endswith(s) for s in self.ENDS_WITH):
            return True
        return False

    async def segui_redirect(self, url: str, *, max_redirects: int = 10, timeout: int = 10) -> str:
        """
        Ritorna l'URL finale dopo aver seguito i redirect via HEAD (più veloce di GET).
        In caso di errore restituisce l'URL passato.
        """
        if not url:
            return url

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/91.0.4472.124 Safari/537.36"
            )
        }

        try:
            timeout_conf = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_conf) as session:
                current = url
                redirects = 0

                while redirects < max_redirects:
                    try:
                        async with session.head(current, headers=headers, allow_redirects=False) as resp:
                            if resp.status not in (301, 302, 303, 307, 308):
                                return current
                            location = resp.headers.get("Location")
                            if not location:
                                return current
                            current = urljoin(current, location)
                            redirects += 1
                    except aiohttp.ClientError:
                        return current
                return current
        except Exception:
            return url

    def _togli_punteggiatura(self, u: str) -> str:
        while u and u[-1] in self._TRAILING_PUNCT:
            u = u[:-1]
        return u

    async def sanifica_url(self, raw_url: str) -> str:
        """
        Pulisce un URL: segue redirect, normalizza schema, rimuove parametri e frammenti di tracking.
        """
        if not raw_url:
            return raw_url

        u = await self.segui_redirect(raw_url)

        # aggiungi schema se mancante
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", u):
            u = "https://" + u

        try:
            parts = urlsplit(u)
            domain = parts.netloc.lower().lstrip("www.")
            if domain in self.DOMAIN_WHITELIST:
                return self._togli_punteggiatura(u)

            original_params = parse_qsl(parts.query, keep_blank_values=True)
            filtered_params = [(k, v) for (k, v) in original_params if not self._da_rimuovere(k)]
            new_query = urlencode(filtered_params, doseq=True)

            new_fragment = parts.fragment
            if new_fragment:
                frag = new_fragment.lstrip("#").lower()
                if frag.startswith(self.FRAG_KEYS):
                    new_fragment = ""

            pulito = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, new_fragment))
            return self._togli_punteggiatura(pulito)
        except Exception:
            return raw_url.strip()

    async def pulizia_massiva(self, links: list[str]) -> list[str]:
        return [await self.sanifica_url(u) for u in (links or [])]



class GetterUrl:
    """
    Estrazione URL: da testo grezzo e da entità Telegram (URL / TEXT_LINK).
    """
    _URL_REGEX = re.compile(
        r"""
        (?<!\w@)                                 # evita email: niente \w@ subito prima
        (?:                                       # schema | www. | dominio nudo
            https?://
          | www\.
          | (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
            (?:[a-z]{2,63})
        )
        [^\s<>'"“”()]+
        """,
        re.IGNORECASE | re.VERBOSE
    )

    @classmethod
    def estrai_urls(cls, text: Optional[str]) -> list[str]:
        if not text:
            return []
        return [m.group(0) for m in cls._URL_REGEX.finditer(text)]

    @staticmethod
    def url_da_tg(text: Optional[str], entities: Optional[Iterable[MessageEntity]]) -> list[str]:
        urls: List[str] = []
        if not text or not entities:
            return urls
        for ent in entities:
            if ent.type in {MessageEntity.URL, MessageEntity.TEXT_LINK}:
                if ent.type == MessageEntity.URL:
                    urls.append(text[ent.offset : ent.offset + ent.length])
                elif ent.type == MessageEntity.TEXT_LINK and ent.url:
                    urls.append(ent.url)
        return urls

    @classmethod
    def url_da_msg(cls, msg) -> list[str]:
        """
        Raccoglie URL da: testo, caption, e relative entità. Deduplica mantenendo l'ordine.
        """
        found: list[str] = []
        if msg.text:
            found.extend(cls.estrai_urls(msg.text))
        if msg.caption:
            found.extend(cls.estrai_urls(msg.caption))

        found.extend(cls.url_da_tg(msg.text, msg.entities))
        found.extend(cls.url_da_tg(msg.caption, msg.caption_entities))

        return list(dict.fromkeys(found))


class TelegramIO:
    """
    Utility I/O per Telegram: formattazione output, detection menzione, invio risposta.
    """

    @staticmethod
    def get_output(clean_links: list[str], *, header: str = "🔗 Link:") -> str:
        if not clean_links:
            return "0 link. 👀"
        uniq = list(dict.fromkeys(clean_links))
        if len(uniq) == 1:
            return uniq[0]
        lines = [header] + [f"- {u}" for u in uniq]
        return "\n".join(lines)

    @staticmethod
    def menzionato(msg, context: ContextTypes.DEFAULT_TYPE) -> bool:
        """
        True se il messaggio (o la caption) menziona questo bot.
        """
        bot_username = (context.bot.username or "").lower()
        bot_id = context.bot.id

        def _check(text: Optional[str], entities: Optional[Iterable[MessageEntity]]) -> bool:
            if not text:
                return False
            if entities:
                for ent in entities:
                    if ent.type == MessageEntity.MENTION:
                        mention = text[ent.offset : ent.offset + ent.length].lower()
                        if mention == f"@{bot_username}":
                            return True
                    elif ent.type == MessageEntity.TEXT_MENTION and ent.user:
                        if ent.user.id == bot_id:
                            return True
            if f"@{bot_username}" in text.lower():
                return True
            return False

        return _check(msg.text, msg.entities) or _check(msg.caption, msg.caption_entities)

    @staticmethod
    async def send_risposta(msg, clean_links: list[str]) -> None:
        text = TelegramIO.get_output(clean_links)
        await msg.reply_text(text, disable_web_page_preview=len(clean_links) > 1)



class TelegramHandlers:
    """
    Contiene gli handler PTB e orchestra GetterUrl + Sanitizer + TelegramIO.
    """
    def __init__(self, sanitizer: Sanitizer) -> None:
        self.sanitizer = sanitizer

    async def handle_gruppi(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        msg = update.effective_message
        if not msg or not TelegramIO.menzionato(msg, context):
            return
        if not msg.reply_to_message:
            return

        target = msg.reply_to_message
        raw_links = GetterUrl.url_da_msg(target)
        if not raw_links:
            await msg.reply_text("Non trovo link nel messaggio a cui stai rispondendo. 👀")
            return

        clean_links = await self.sanitizer.pulizia_massiva(raw_links)
        await TelegramIO.send_risposta(target, clean_links)

    async def handle_privato(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat = update.effective_chat
        if chat.type != ChatType.PRIVATE:
            return

        msg = update.effective_message
        raw_links = GetterUrl.url_da_msg(msg)
        if not raw_links:
            await msg.reply_text("Mandami dei link e te li restituisco puliti. 🔧🔗")
            return

        clean_links = await self.sanitizer.pulizia_massiva(raw_links)
        await TelegramIO.send_risposta(msg, clean_links)




# Base dir e config
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
TOKEN_PATH = os.path.join(BASE_DIR, "token.txt")

def load_cfg():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print("Manca config.json, crealo: "+ CONFIG_PATH)
        sys.exit(1)

async def main() -> None:
    cfg = load_cfg()

    sanitizer = Sanitizer(
        exact_keys=set(cfg.get("EXACT_KEYS", [])),
        prefix_keys=tuple(cfg.get("PREFIX_KEYS", [])),
        ends_with=tuple(cfg.get("ENDS_WITH", [])),
        frag_keys=tuple(cfg.get("FRAG_KEYS", [])),
        domain_whitelist=cfg.get("DOMAIN_WHITELIST", {}),
    )
    handlers = TelegramHandlers(sanitizer)

    try:
        with open(TOKEN_PATH, "r") as f:
            telegram_token = f.read().strip()
    except FileNotFoundError:
        print("Put your Telegram bot token to 'token.txt' file")
        sys.exit(1)

    app = Application.builder().token(telegram_token).build()

    # GRUPPI: testo o caption
    group_filter = (filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION))
    app.add_handler(MessageHandler(group_filter, handlers.handle_gruppi))

    # PRIVATO: testo o caption
    private_filter = (filters.ChatType.PRIVATE & (filters.TEXT | filters.CAPTION))
    app.add_handler(MessageHandler(private_filter, handlers.handle_privato))

    print("Bot in esecuzione… Premi Ctrl+C per uscire")

    await app.initialize()
    me = await app.bot.get_me()
    print(f"Bot: @{me.username}")

    await app.start()
    try:
        await app.updater.start_polling(allowed_updates=Update.ALL_TYPES)
        await asyncio.Event().wait()
    finally:
        await app.updater.stop()
        await app.stop()
        await app.shutdown()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
