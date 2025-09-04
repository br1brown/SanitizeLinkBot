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
import html
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
    CommandHandler,  # per i comandi quelli con la barra
    Application,     # oggetto principale: costruisce e avvia il bot
    ContextTypes,    # tipi per il contesto passato ai callback
    MessageHandler,  # handler che esegue una funzione quando arriva un messaggio che matcha dei filtri
    filters,         # raccolta di filtri predefiniti (per tipo chat, presenza testo, ecc.)
)



class Sanitizer:
    """
    Responsabile di: follow redirect, pulizia parametri di tracking, pulizia fragment.
    Inietti le liste/insiemi dal keys nel costruttore.
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
        chiave_lower = (key or "").lower()
        if chiave_lower in self.EXACT_KEYS:
            return True
        if any(chiave_lower.startswith(p) for p in self.PREFIX_KEYS):
            return True
        if any(chiave_lower.endswith(s) for s in self.ENDS_WITH):
            return True
        return False

    async def segui_redirect(self, url: str, *, max_redirects: int = 10, timeout: int = 50) -> tuple[str, str | None]:
        """
        Ritorna una tupla (url_finale, titolo_pagina).
        Se non trova il titolo o c'è errore, titolo_pagina = None.
        """
        if not url:
            return url, None

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
                        async with session.head(
                            current, headers=headers, allow_redirects=False
                        ) as resp:
                            if resp.status not in (301, 302, 303, 307, 308):
                                break
                            location = resp.headers.get("Location")
                            if not location:
                                break
                            current = urljoin(current, location)
                            redirects += 1
                    except aiohttp.ClientError:
                        return current, None

                # una volta trovato l'URL finale → GET per leggere il titolo
                titolo = None
                try:
                    async with session.get(current, headers=headers) as resp:
                        if resp.status == 200 and resp.content_type == "text/html":
                            text = await resp.text(errors="ignore")
                            match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                            if match:
                                titolo = match.group(1).strip()
                except Exception:
                    pass

                return current, titolo
        except Exception:
            return url, None

    def _togli_punteggiatura(self, url_corrente: str) -> str:
        while url_corrente and url_corrente[-1] in self._TRAILING_PUNCT:
            url_corrente = url_corrente[:-1]
        return url_corrente

    async def sanifica_url(self, raw_url: str) -> tuple[str, str | None]:
        """
        Pulisce un URL: segue redirect, normalizza schema, rimuove parametri e frammenti di tracking.
        Ritorna (url_pulito, titolo_pagina | None).
        """
        if not raw_url:
            return raw_url, None

        # aggiungi schema se mancante PRIMA di seguire i redirect
        url_corrente = raw_url
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url_corrente):
            url_corrente = "https://" + url_corrente

        # ora segui i redirect e ottieni anche il titolo
        try:
            final_url, title = await self.segui_redirect(url_corrente)  # segui_redirect ora deve restituire (url, title)
        except Exception:
            final_url, title = url_corrente, None

        final_title = self._normalize_title(title)
        
        try:
            parts = urlsplit(final_url)
            domain = parts.netloc.lower().lstrip("www.")
            if domain in self.DOMAIN_WHITELIST:
                return self._togli_punteggiatura(final_url), final_title

            original_params = parse_qsl(parts.query, keep_blank_values=True)
            filtered_params = [(k, v) for (k, v) in original_params if not self._da_rimuovere(k)]
            new_query = urlencode(filtered_params, doseq=True)

            new_fragment = parts.fragment
            if new_fragment:
                frag = new_fragment.lstrip("#").lower()
                # evita TypeError quando FRAG_KEYS è vuota e consenti match prefissi
                if self.FRAG_KEYS and any(frag.startswith(pref) for pref in self.FRAG_KEYS):
                    new_fragment = ""

            pulito = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, new_fragment))
            return self._togli_punteggiatura(pulito), final_title
        except Exception:
            return raw_url.strip(), final_title

    async def pulizia_massiva(self, links: list[str]) -> list[tuple[str, str | None]]:
        return [await self.sanifica_url(u) for u in (links or [])]
    
    def _normalize_title(self, raw: str) -> str:
        if not raw:
            return None
        # decodifica entità HTML (&amp;, &#39;, ecc.)
        titolo_norm = html.unescape(raw)
        # comprimi e rifila spazi/newline
        titolo_norm = re.sub(r"\s+", " ", titolo_norm).strip()
        # evita titoli “vuoti” dopo la pulizia
        return titolo_norm or None

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
    def get_output(clean_links: list[tuple[str, str | None]],split = "\n", litemcheck = "\n") -> str:
        if not clean_links:
            return "0 link. 👀"

        uniq = list(dict.fromkeys(clean_links))  # deduplica mantenendo l’ordine

        if len(uniq) == 1:
            url, title = uniq[0]
            return f"{title}{split}{url}" if title else url

        lines = []
        for url, title in uniq:
            if title:
                lines.append(f"{litemcheck}{title}{split}{url}")
            else:
                lines.append(f"{litemcheck}{url}")
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


class TelegramHandlers:
    """
    Contiene gli handler PTB e orchestra GetterUrl + Sanitizer + TelegramIO.
    """
    
    async def pulisciEmanda(self, target, raw_links) -> None:
        clean_links = await self.sanitizer.pulizia_massiva(raw_links)
        text = TelegramIO.get_output(clean_links)
        
        await target.reply_text(text, disable_web_page_preview=len(clean_links) > 1)
        

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

        await self.pulisciEmanda(target,raw_links)

    async def handle_privato(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        chat = update.effective_chat
        if chat.type != ChatType.PRIVATE:
            return

        msg = update.effective_message
        raw_links = GetterUrl.url_da_msg(msg)
        if not raw_links:
            return

        await self.pulisciEmanda(msg,raw_links)

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        text = (
            f"👋 *Benvenuto {user.first_name}!* \n\n"
            "Io sono *Sanitize Link* e mi occupo di pulire i link dai parametri di tracking, "
            "seguendo automaticamente anche i redirect.\n\n"
            "🔧 Invia /help per sapere come funziono."
        )
        await update.message.reply_text(
            text,
            parse_mode="Markdown",
            disable_web_page_preview=True,
        )

    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        bot_username = context.bot.username
        if not bot_username:
            me = await context.bot.get_me()
            bot_username = me.username

        mention_bot = f"@{bot_username}" if bot_username else "@..."


        help_text = (
            "ℹ️ *Come funziona Sanitize Link*\n\n"
            "📌 *In privato*\n"
            "Mandami un messaggio con uno o più link. Io li analizzerò e ti restituirò la versione pulita, "
            "senza parametri di tracciamento e dopo aver seguito eventuali redirect.\n\n"
            "👥 *Nei gruppi*\n"
            f"Rispondi a un messaggio che contiene dei link e menzionami (`{mention_bot}`).\n"
            "Io ripulirò i link di quel messaggio e te li manderò subito.\n\n"
            "✅ *Cosa faccio*: \n"
            "- Rimuovo parametri di tracking (utm, fbclid, ecc.)\n"
            "- Seguo i redirect fino all'URL finale\n"
            "- Rimuovo i frammenti inutili (#...)\n\n"
            "👉 In questo modo ottieni link più brevi, leggibili e rispettosi della privacy.\n\n"
            "📂 Codice sorgente: [GitHub](https://github.com/br1brown/SanitizeLinkBot.git)"
        )
        await update.message.reply_text(
            help_text,
            parse_mode="Markdown",
            disable_web_page_preview=True,
        )


# Base dir e config
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
KEYS_PATH = os.path.join(BASE_DIR, "keys.json")
TOKEN_PATH = os.path.join(BASE_DIR, "token.txt")

def load_keys():
    try:
        with open(KEYS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print("Manca keys.json, crealo: "+ KEYS_PATH)
        sys.exit(1)

async def main() -> None:
    keys = load_keys()

    sanitizer = Sanitizer(
        exact_keys=set(keys.get("EXACT_KEYS", [])),
        prefix_keys=tuple(keys.get("PREFIX_KEYS", [])),
        ends_with=tuple(keys.get("ENDS_WITH", [])),
        frag_keys=tuple(keys.get("FRAG_KEYS", [])),
        domain_whitelist=keys.get("DOMAIN_WHITELIST", {}),
    )
    handlers = TelegramHandlers(sanitizer)

    try:
        with open(TOKEN_PATH, "r") as f:
            telegram_token = f.read().strip()
    except FileNotFoundError:
        print("Put your Telegram bot token to 'token.txt' file")
        sys.exit(1)

    app = Application.builder().token(telegram_token).build()

    # Comandi base
    app.add_handler(CommandHandler("start", handlers.cmd_start), group=0)
    app.add_handler(CommandHandler("help", handlers.cmd_help), group=0)

    # GRUPPI: testo o caption - NO COMANDI
    group_filter = (
        filters.ChatType.GROUPS
        & (filters.TEXT | filters.CAPTION)
        & ~filters.COMMAND            # escludi /help ecc.
    )
    app.add_handler(MessageHandler(group_filter, handlers.handle_gruppi), group=1)

    # PRIVATO: testo o caption
    private_filter = (
        filters.ChatType.PRIVATE
        & (filters.TEXT | filters.CAPTION)
        & ~filters.COMMAND            # escludi /help ecc.
    )
    app.add_handler(MessageHandler(private_filter, handlers.handle_privato), group=1)


    print("Bot in esecuzione… Premi Ctrl+C per uscire")

    await app.initialize()
    bot_info = await app.bot.get_me()

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
