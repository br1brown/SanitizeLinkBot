from __future__ import annotations

"""
Dipendenze:
- python-telegram-bot >= 20

Installazione:
  pip install python-telegram-bot
  pip install aiohttp
"""

import json
import re
import asyncio
from urllib.parse import (
    urlsplit, urlunsplit, parse_qsl, urlencode, urljoin
)
import os
import sys
import aiohttp
import html
from typing import Iterable, Optional, List, Tuple

from telegram import Update, MessageEntity
from telegram.constants import ChatType
from telegram.ext import (
    CommandHandler, Application, ContextTypes, MessageHandler, filters
)

import logging

# ---------- LOGGING SETUP "VERBOSO MA UTILE" ----------
# Globale WARNING+: librerie esterne non sporcano la console.
# Il logger del bot può essere abbassato via env LOG_LEVEL (default INFO).
_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=logging.WARNING,  # livello globale: WARNING+
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)

# Silenzia logger noti delle HTTP lib a WARNING+
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)

logger = logging.getLogger("sanitize-link-bot")
logger.setLevel(getattr(logging, _LOG_LEVEL, logging.INFO))


class AppConfig:
    """
    Raccoglie sia config generica che parametri operativi con default chiari.
    """
    def __init__(self, raw: dict) -> None:
        # separatore titolo/url (es.: "\n" = a capo, oppure " — ")
        self.split: str         = raw.get("split", "\n")
        # prefisso elemento elenco (es.: "- " oppure "• ")
        self.litemcheck: str    = raw.get("litemcheck", "- ")
        # mostrare o meno il titolo pagina accanto al link
        self.show_title: bool   = bool(raw.get("show_title", True))
        # limite massimo redirect che seguiamo per evitare loop
        self.max_redirects: int = int(raw.get("max_redirects", 10))
        # timeout globale per le richieste HTTP
        self.timeout_sec: int   = int(raw.get("timeout_sec", 50))

    @classmethod
    def load(cls, path: str) -> 'AppConfig':
        logger.debug("Caricamento configurazione da file: %s", path)
        conf = cls(load_json_file(path))
        logger.info("Configurazione applicativa caricata")
        logger.debug("Config dettagli: %s", conf)
        return conf

    def __repr__(self) -> str:
        return (
            f"AppConfig(split={self.split!r}, litemcheck={self.litemcheck!r}, "
            f"show_title={self.show_title}, max_redirects={self.max_redirects}, "
            f"timeout_sec={self.timeout_sec})"
        )


class Sanitizer:
    """
    - Segue i redirect fino all'URL finale (HEAD + fallback GET per titolo)
    - Rimuove parametri tracking (utm, fbclid, ecc.)
    - Rimuove/normalizza fragment (#...)
    - Restituisce (url_pulito, titolo_opzionale)

    Privacy: non logghiamo URL in INFO. I dettagli finiscono a DEBUG.
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
        conf: AppConfig,
    ) -> None:
        logger.debug("Init Sanitizer (chiavi & whitelist)")
        self.EXACT_KEYS = set(map(str.lower, exact_keys or set()))
        self.PREFIX_KEYS = tuple(k.lower() for k in (prefix_keys or ()))
        self.ENDS_WITH = tuple(k.lower() for k in (ends_with or ()))
        self.FRAG_KEYS = tuple(k.lower() for k in (frag_keys or ()))
        self.DOMAIN_WHITELIST = { (k or "").lower(): v for k, v in (domain_whitelist or {}).items() }
        self.conf = conf
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Lazy init della sessione HTTP condivisa."""
        if self._session is None or self._session.closed:
            logger.debug("Creo aiohttp.ClientSession (timeout=%ss)", self.conf.timeout_sec)
            timeout_conf = aiohttp.ClientTimeout(total=self.conf.timeout_sec)
            self._session = aiohttp.ClientSession(timeout=timeout_conf)
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            logger.debug("Chiusura sessione HTTP")
            await self._session.close()
            self._session = None

    def _da_rimuovere(self, key: str) -> bool:
        k = (key or "").lower()
        decision = (
            k in self.EXACT_KEYS
            or any(k.startswith(p) for p in self.PREFIX_KEYS)
            or any(k.endswith(s) for s in self.ENDS_WITH)
        )
        logger.debug("Parametro '%s' da rimuovere? %s", key, decision)
        return decision

    async def segui_redirect(self, url: str) -> tuple[str, Optional[str]]:
        """
        Ritorna (url_finale, titolo_pagina | None). Qui gestiamo solo la parte "navigazione".
        - Usiamo HEAD per scoprire redirect senza scaricare il body.
        - Poi GET per leggere eventuale <title>.
        """
        if not url:
            logger.debug("segui_redirect: URL vuoto")
            return url, None
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/91.0.4472.124 Safari/537.36"
            )
        }
        try:
            session = await self._get_session()
            current = url
            redirects = 0
            logger.debug("Inizio follow redirect")

            while redirects < self.conf.max_redirects:
                try:
                    logger.debug("HEAD %s", current)
                    async with session.head(current, headers=headers, allow_redirects=False) as resp:
                        status = resp.status
                        location = resp.headers.get("Location")
                        logger.debug("HEAD status=%s, location=%s", status, location)
                        if status not in (301, 302, 303, 307, 308) or not location:
                            break
                        current = urljoin(current, location)
                        redirects += 1
                        logger.debug("Redirect #%s", redirects)
                except aiohttp.ClientError as e:
                    logger.warning("Errore durante HEAD: %s (uso URL attuale)", e)
                    return current, None

            titolo = None
            try:
                logger.debug("GET per titolo")
                async with session.get(current, headers=headers) as resp:
                    ct = resp.content_type
                    logger.debug("GET status=%s, content_type=%s", resp.status, ct)
                    if resp.status == 200 and ct and ct.startswith("text/html"):
                        text = await resp.text(errors="ignore")
                        m = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                        if m:
                            titolo = m.group(1).strip()
                            logger.debug("Titolo pagina trovato")
            except Exception as e:
                logger.debug("Impossibile leggere titolo pagina: %s", e)

            logger.debug("URL finale dopo redirect determinato")
            return current, titolo
        except Exception as e:
            logger.error("Errore imprevisto in segui_redirect: %s", e)
            return url, None

    def _togli_punteggiatura(self, url_corrente: str) -> str:
        """
        Alcuni URL possono avere punteggiatura terminale (es. in un testo, tipo '...') da togliere.
        Gestiamo anche il caso delle parentesi chiuse in eccesso.
        """
        originale = url_corrente
        while url_corrente and url_corrente[-1] in self._TRAILING_PUNCT + "\u00A0":
            # non rimuovere ")" se hai un "(" nel path più del numero di ")"
            if url_corrente.endswith(")") and url_corrente.count("(") < url_corrente.count(")"):
                break
            url_corrente = url_corrente[:-1]
        if originale != url_corrente:
            logger.debug("Rimozione punteggiatura terminale")
        return url_corrente

    def _normalize_title(self, raw: Optional[str]) -> Optional[str]:
        """Normalizza titolo HTML: unescape entità e comprime whitespace."""
        if not raw:
            return None
        titolo_norm = html.unescape(raw)
        titolo_norm = re.sub(r"\s+", " ", titolo_norm).strip()
        if raw != titolo_norm:
            logger.debug("Titolo normalizzato")
        return titolo_norm or None

    async def sanifica_url(self, raw_url: str) -> tuple[str, Optional[str]]:
        if not raw_url:
            logger.debug("sanifica_url: URL vuoto")
            return raw_url, None

        url_corrente = raw_url.strip()
        logger.info("Sanificazione URL in ingresso")

        if re.match(r"^(mailto:|tel:)", url_corrente, re.IGNORECASE):
            logger.debug("Protocollo non web, restituisco com'è")
            return url_corrente, None

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url_corrente):
            logger.debug("Schema mancante: aggiungo https://")
            url_corrente = "https://" + url_corrente

        try:
            final_url, title = await self.segui_redirect(url_corrente)
        except Exception as e:
            logger.warning("Errore durante follow redirect: %s (uso URL corrente)", e)
            final_url, title = url_corrente, None

        final_title = self._normalize_title(title)

        try:
            parts = urlsplit(final_url)
            domain = parts.netloc.lower().lstrip("www.")
            logger.debug("Parsing URL finale: domain=%s, path=%s, query=%s, fragment=%s",
                         domain, parts.path, parts.query, parts.fragment)

            if domain in self.DOMAIN_WHITELIST:
                logger.info("Dominio whitelisted: salto rimozione parametri")
                return self._togli_punteggiatura(final_url), final_title

            original_params = parse_qsl(parts.query, keep_blank_values=True)
            filtered_params = [(k, v) for (k, v) in original_params if not self._da_rimuovere(k)]
            new_query = urlencode(filtered_params, doseq=True)

            new_fragment = parts.fragment
            if new_fragment:
                frag = new_fragment.lstrip("#").lower()
                if self.FRAG_KEYS and any(frag.startswith(pref) for pref in self.FRAG_KEYS):
                    logger.info("Rimozione fragment per regola FRAG_KEYS")
                    new_fragment = ""

            pulito = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, new_fragment))
            pulito = self._togli_punteggiatura(pulito)
            logger.info("URL pulito prodotto")
            return pulito, final_title
        except Exception as e:
            logger.error("Errore in sanificazione dettagliata: %s (ritorno URL grezzo)", e)
            return raw_url.strip(), final_title

    async def pulizia_massiva(self, links: list[str]) -> list[tuple[str, Optional[str]]]:
        """
        Sanifica una lista di URL in parallelo (con semaforo per non esagerare).
        Deduplica preservando l'ordine.
        """
        if not links:
            logger.debug("pulizia_massiva: lista vuota")
            return []

        logger.debug("Avvio pulizia massiva di %d link", len(links))
        sem = asyncio.Semaphore(5)

        async def _one(u: str):
            async with sem:
                logger.debug("Pulizia singolo URL (massiva)")
                return await self.sanifica_url(u)

        results = await asyncio.gather(*(_one(u) for u in links))
        dedup = list(dict.fromkeys(results))  # deduplica preservando ordine
        if len(dedup) != len(results):
            logger.debug("Deduplica effettuata: %d duplicati rimossi", len(results) - len(dedup))
        logger.info("Pulizia massiva completata: input=%d, output=%d", len(links), len(dedup))
        return dedup


class GetterUrl:
    """
    Estrazione URL: da testo grezzo e da entità Telegram (URL / TEXT_LINK).
    parser di input
    """
    _URL_REGEX = re.compile(
        r"""
        (?<!\w@)
        (?:
            https?://
          | www\.
          | (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})
        )
        [^\s<>'"“”()]+
        """,
        re.IGNORECASE | re.VERBOSE
    )

    @classmethod
    def estrai_urls(cls, text: Optional[str]) -> List[str]:
        """Estrae URL testuali tramite regex robusta da messaggi normali/caption."""
        if not text:
            return []
        urls = [m.group(0) for m in cls._URL_REGEX.finditer(text)]
        logger.debug("estrai_urls: trovati %d URL nel testo", len(urls))
        return urls

    @staticmethod
    def url_da_tg(text: Optional[str], entities: Optional[Iterable[MessageEntity]]) -> List[str]:
        """
        Estrae URL da entità Telegram (MessageEntity.URL e MessageEntity.TEXT_LINK).
        Questo copre i casi in cui Telegram riconosce l'URL anche senza testo esplicito.
        """
        urls: List[str] = []
        if not text or not entities:
            return urls
        for ent in entities:
            if ent.type in {MessageEntity.URL, MessageEntity.TEXT_LINK}:
                if ent.type == MessageEntity.URL:
                    url = text[ent.offset : ent.offset + ent.length]
                    urls.append(url)
                elif ent.type == MessageEntity.TEXT_LINK and ent.url:
                    urls.append(ent.url)
        if urls:
            logger.debug("url_da_tg: trovati %d URL nelle entità", len(urls))
        return urls

    @classmethod
    def url_da_msg(cls, msg) -> List[str]:
        """
        Entry-point unico per estrarre link da un messaggio Telegram (testo/caption + entità).
        Ritorna una lista piatta di stringhe URL.
        """
        found: List[str] = []
        if msg.text:
            found.extend(cls.estrai_urls(msg.text))
        if msg.caption:
            found.extend(cls.estrai_urls(msg.caption))
        found.extend(cls.url_da_tg(msg.text, msg.entities))
        found.extend(cls.url_da_tg(msg.caption, msg.caption_entities))
        logger.debug("URL totali trovati nel messaggio: %d", len(found))
        return found


class TelegramIO:
    """Utility I/O per Telegram: formattazione output e risposta."""

    @staticmethod
    def get_output(clean_links: list[tuple[str, Optional[str]]], conf: AppConfig) -> str:
        """
        Converte la lista (url, titolo?) in testo finale pronto da inviare su Telegram.
        Rispetta la config: può includere titolo, separatore personalizzato e prefisso elenco.
        """
        if not clean_links:
            logger.debug("get_output: nessun link pulito")
            return "0 link. 👀"

        lines = []
        for url, title in clean_links:
            if conf.show_title and title:
                lines.append(f"{title}{conf.split}{url}")
            else:
                lines.append(f"{url}")

        output = f"\n{conf.litemcheck}".join(lines)
        logger.debug("get_output: testo pronto (%d righe)", len(lines))
        return output


class TelegramHandlers:
    """
    Orchestrazione: GetterUrl + Sanitizer + Output.
    INFO: un solo log “di business” per messaggio (gruppo o privato).
    """
    def __init__(self, sanitizer: Sanitizer, conf: AppConfig) -> None:
        self.sanitizer = sanitizer
        self.conf = conf

    async def _pulisci_e_manda(self, target, raw_links: List[str]) -> Tuple[int, int, Optional[int]]:
        """Elabora e risponde. Ritorna (num_trovati, num_puliti, reply_msg_id)."""
        num_trovati = len(raw_links)
        logger.debug("_pulisci_e_manda: %d link in ingresso", num_trovati)
        clean_links = await self.sanitizer.pulizia_massiva(raw_links)
        text = TelegramIO.get_output(clean_links, self.conf)
        reply = await target.reply_text(text, disable_web_page_preview=len(clean_links) > 1)
        reply_id = getattr(reply, "message_id", None)
        logger.debug("_pulisci_e_manda: risposta inviata (reply_msg_id=%s)", reply_id)
        return num_trovati, len(clean_links), reply_id

    @staticmethod
    def menzionato(msg, context: ContextTypes.DEFAULT_TYPE) -> bool:
        """
        Rileva se il bot è stato menzionato (solo quando richiesto).
        Copre sia @username che menzione diretta (TEXT_MENTION con user id).
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
            # fallback testo grezzo
            if f"@{bot_username}" in text.lower():
                return True
            return False

        mentioned = _check(msg.text, msg.entities) or _check(msg.caption, msg.caption_entities)
        logger.debug("menzionato? %s", mentioned)
        return mentioned

    async def handle_gruppi(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """
        Handler per GRUPPI:
        - Si attiva solo se il bot è menzionato e il messaggio è in reply a un altro messaggio.
        - Estrae link dal messaggio a cui si è risposto.
        - Restituisce i link puliti come risposta a quel messaggio.
        """
        msg = update.effective_message
        if not msg or not self.menzionato(msg, context):
            logger.debug("handle_gruppi: ignorato (nessuna menzione o msg nullo)")
            return
        if not msg.reply_to_message:
            logger.debug("handle_gruppi: manca reply_to_message, niente da processare")
            return

        target = msg.reply_to_message
        raw_links = GetterUrl.url_da_msg(target)
        user = update.effective_user
        chat = update.effective_chat

        if not raw_links:
            await msg.reply_text("Non trovo link nel messaggio a cui stai rispondendo. 👀")
            logger.info(
                "GRUPPO menzione: da '%s' (@%s) in '%s' — trovati=%d, puliti=%d, reply_msg_id=%s",
                getattr(user, "full_name", "n/a"),
                getattr(user, "username", "n/a"),
                getattr(chat, "title", "n/a"),
                0,
                0,
                "n/a",
            )
            return

        trovati, puliti, reply_id = await self._pulisci_e_manda(target, raw_links)
        logger.info(
            "GRUPPO menzione: da '%s' (@%s) in '%s' — trovati=%d, puliti=%d, reply_msg_id=%s",
            getattr(user, "full_name", "n/a"),
            getattr(user, "username", "n/a"),
            getattr(chat, "title", "n/a"),
            trovati,
            puliti,
            reply_id,
        )

    async def handle_privato(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """
        Handler per CHAT PRIVATE:
        - Estrae link dal messaggio ricevuto e risponde subito con i link puliti.
        """
        if update.effective_chat.type != ChatType.PRIVATE:
            return
        msg = update.effective_message
        raw_links = GetterUrl.url_da_msg(msg)
        user = update.effective_user

        if not raw_links:
            logger.info(
                "PRIVATO: da '%s' (@%s) — trovati=%d, puliti=%d, reply_msg_id=%s",
                getattr(user, "full_name", "n/a"),
                getattr(user, "username", "n/a"),
                0,
                0,
                "n/a",
            )
            return

        trovati, puliti, reply_id = await self._pulisci_e_manda(msg, raw_links)
        logger.info(
            "PRIVATO: da '%s' (@%s) — trovati=%d, puliti=%d, reply_msg_id=%s",
            getattr(user, "full_name", "n/a"),
            getattr(user, "username", "n/a"),
            trovati,
            puliti,
            reply_id,
        )

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Messaggio di benvenuto, tono amichevole + invito a /help."""
        user = update.effective_user
        text = (
            f"👋 *Benvenuto {user.first_name}!* \n\n"
            "Io sono *Sanitize Link* e pulisco i link dai parametri di tracking, "
            "seguendo automaticamente anche i redirect.\n\n"
            "🔧 Invia /help per sapere come funziono."
        )
        await update.message.reply_text(text, parse_mode="Markdown", disable_web_page_preview=True)

    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Istruzioni rapide d'uso per privato e gruppi."""
        bot_username = context.bot.username or (await context.bot.get_me()).username
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
        await update.message.reply_text(help_text, parse_mode="Markdown", disable_web_page_preview=True)


# ---------- CONFIG CENTRALIZZATA ----------

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
KEYS_PATH   = os.path.join(BASE_DIR, "keys.json")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
TOKEN_PATH  = os.path.join(BASE_DIR, "token.txt")


def load_json_file(path: str) -> dict:
    """
    Carica JSON di configurazione/chiavi da file.
    WARNING: in caso di JSON corrotto solleva eccezione esplicita (non silenziamo).
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            logger.debug("Caricato JSON da %s (chiavi: %s)", path, list(data.keys()))
            return data
    except FileNotFoundError:
        logger.warning("File non trovato: %s (uso default vuoto)", path)
        return {}
    except json.JSONDecodeError as e:
        logger.error("Errore nel parsing JSON di %s: %s", path, e)
        raise RuntimeError(f"Errore nel parsing di {path}: {e}") from e


CONFIG = AppConfig.load(CONFIG_PATH)
KEYS   = load_json_file(KEYS_PATH)


def get_telegram_token() -> str:
    # priorità: env > file
    env = os.getenv("TELEGRAM_BOT_TOKEN")
    if env:
        token = env.strip()
        logger.info("Token Telegram letto da variabile d'ambiente")
        return token
    try:
        with open(TOKEN_PATH, "r", encoding="utf-8") as f:
            token = f.read().strip()
            logger.info("Token Telegram letto da file token.txt")
            return token
    except FileNotFoundError as e:
        logger.error("Token mancante. Imposta TELEGRAM_BOT_TOKEN o crea 'token.txt'.")
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN o 'token.txt'") from e


async def main() -> None:
    """
    Entry point asincrono del bot:
    - Costruisce l'Application PTB
    - Registra handler
    - Avvia il polling
    - Gestisce una shutdown pulita
    """
    try:
        telegram_token = get_telegram_token()
        app = Application.builder().token(telegram_token).build()
    except RuntimeError as e:
        logger.error("Avvio interrotto per configurazione invalida: %s", e)
        return

    # istanzia Sanitizer con chiavi + config
    sanitizer = Sanitizer(
        exact_keys=set(KEYS.get("EXACT_KEYS", [])),
        prefix_keys=tuple(KEYS.get("PREFIX_KEYS", [])),
        ends_with=tuple(KEYS.get("ENDS_WITH", [])),
        frag_keys=tuple(KEYS.get("FRAG_KEYS", [])),
        domain_whitelist=KEYS.get("DOMAIN_WHITELIST", {}),
        conf=CONFIG,
    )
    handlers = TelegramHandlers(sanitizer, CONFIG)

    # ---------- REGISTRAZIONE HANDLER ----------
    app.add_handler(CommandHandler("start", handlers.cmd_start), group=0)
    app.add_handler(CommandHandler("help", handlers.cmd_help), group=0)

    group_filter = (filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND)
    app.add_handler(MessageHandler(group_filter, handlers.handle_gruppi), group=1)

    private_filter = (filters.ChatType.PRIVATE & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND)
    app.add_handler(MessageHandler(private_filter, handlers.handle_privato), group=1)

    logger.info("Config caricata. Bot in esecuzione")

    # ---------- LIFECYCLE PTB ----------
    await app.initialize()   # prepara bot e rete
    await app.start()        # apre connessioni
    try:
        # start_polling con Updater legacy (PTB20 lo espone per compat),
        # allowed_updates=Update.ALL_TYPES => ascolto tutto
        await app.updater.start_polling(allowed_updates=Update.ALL_TYPES)
        # Blocco per sempre (o finché SIGINT). Event() è più chiaro di "while True: await sleep(...)"
        await asyncio.Event().wait()
    finally:
        # Sequenza shutdown ordinata
        await app.updater.stop()
        await app.stop()
        await app.shutdown()
        # Chiudiamo anche la sessione HTTP del Sanitizer (buona norma)
        await sanitizer.close()
        logger.info("Bot arrestato correttamente")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # Graceful exit se viene premuto Ctrl+C in console.
        print("\nInterrotto dall'utente (Ctrl+C).")
