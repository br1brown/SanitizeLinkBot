from __future__ import annotations

"""
Dipendenze:
- python-telegram-bot >= 20
- aiohttp

Installazione rapida:
    pip install python-telegram-bot aiohttp

Linee guida adottate in questa revisione:
1) Commenti e docstring uniformi, in italiano, sintetici ma didattici.
3) Nomi più espliciti per alcune funzioni/variabili interne (es. _parametro_da_rimuovere, sanifica_in_batch).
4) Evitate abbreviazioni poco leggibili per i blocchi di configurazione (es. output_conf, redirect_conf, ...).
5) Messaggi verso l'utente: tono formale, professionale, chiaro e accessibile.
"""

import json
import re
import asyncio
from urllib.parse import (
    urlsplit, urlunsplit, parse_qsl, urlencode, urljoin
)
import os
import aiohttp
import html

from collections.abc import Iterable

from telegram import Update, MessageEntity, ReactionTypeEmoji
from telegram.constants import ChatType, ParseMode

from telegram.ext import (
    CommandHandler, Application, ContextTypes, MessageHandler, filters
)

import logging

# ---------- LOGGING ----------
# Livello globale WARNING+ per silenziare librerie; il livello specifico del bot è definito dopo il caricamento config.
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)
logger = logging.getLogger("sanitize-link-bot")


class AppConfig:
    """Configurazione applicativa con validazione essenziale.

    Le sezioni richieste corrispondono a:
    - Output
    - Redirect
    - Batch
    - HTTP
    - Formatting
    - Logging (opzionale, solo "level")
    """

    def __init__(self, raw: dict) -> None:
        output_conf = raw["Output"]
        redirect_conf = raw["Redirect"]
        batch_conf = raw["Batch"]
        http_conf = raw["HTTP"]
        formatting_conf = raw["Formatting"]
        logging_conf = raw.get("Logging", {})

        # Output
        self.show_title: bool = bool(output_conf["show_title"])

        # Redirect
        self.max_redirects: int = int(redirect_conf["max_redirects"])
        self.timeout_sec: int = int(redirect_conf["timeout_sec"])

        # Batch
        self.max_concurrency: int = int(batch_conf["max_concurrency"])

        # HTTP
        self.connections_per_host: int = int(http_conf["connections_per_host"])  # obbligatorio

        # Formatting
        self.trailing_punct: str = formatting_conf["trailing_punct"]

        # Logging (opzionale)
        self.log_level: str | None = (logging_conf.get("level") or "").upper() or None

    @classmethod
    def load(cls, path: str) -> "AppConfig":
        """Carica la configurazione da file e ne verifica la presenza delle sezioni obbligatorie."""
        logger.debug("Caricamento configurazione da file: %s", path)
        try:
            conf = cls(load_json_file(path))
        except KeyError as e:
            missing = str(e).strip("'")
            raise RuntimeError(
                f"Configurazione incompleta: manca la chiave richiesta '{missing}' in {path}"
            ) from e
        logger.info("Configurazione applicativa caricata")
        logger.debug("Dettagli configurazione: %s", conf)
        return conf

    def __repr__(self) -> str:
        return (
            "AppConfig("
            f"show_title={self.show_title}, "
            f"max_redirects={self.max_redirects}, timeout_sec={self.timeout_sec}, "
            f"max_concurrency={self.max_concurrency}, connections_per_host={self.connections_per_host}, "
            f"trailing_punct={self.trailing_punct!r}, log_level={self.log_level!r}"
            ")"
        )


class Sanitizer:
    """Sanifica URL e, opzionalmente, recupera il titolo della pagina.

    Funzioni principali:
    - Segue redirect multipli (HEAD + GET parziale; meta refresh riconosciuto)
    - Rimuove parametri di tracking (utm, fbclid, ecc.)
    - Rimuove/normalizza fragment (#...)
    - Restituisce (url_pulito, titolo_opzionale)

    Politica titoli:
      - Normalizzazione minima (unescape HTML, rimozione caratteri invisibili, compattazione spazi)
      - Nessuna potatura del contenuto
      - Escape HTML solo in output (TelegramIO)
    """

    _TRAILING_PUNCT_DEFAULT = ".,;:!?)”»’'\""

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
        logger.debug("Inizializzazione Sanitizer: chiavi di rimozione e whitelist domini")
        self.EXACT_KEYS = set(map(str.lower, exact_keys or set()))
        self.PREFIX_KEYS = tuple(k.lower() for k in (prefix_keys or ()))
        self.ENDS_WITH = tuple(k.lower() for k in (ends_with or ()))
        self.FRAG_KEYS = tuple(k.lower() for k in (frag_keys or ()))
        self.DOMAIN_WHITELIST = {(k or "").lower(): v for k, v in (domain_whitelist or {}).items()}
        self.conf = conf
        self._session: aiohttp.ClientSession | None = None
        # Punteggiatura dal config (fallback al default solo se stringa vuota)
        self._TRAILING_PUNCT = conf.trailing_punct or self._TRAILING_PUNCT_DEFAULT

    async def _get_session(self) -> aiohttp.ClientSession:
        """Inizializza pigramente la sessione HTTP condivisa (se non già aperta)."""
        if self._session is None or self._session.closed:
            logger.debug(
                "Creo aiohttp.ClientSession (timeout=%ss, limit_per_host=%s)",
                self.conf.timeout_sec, self.conf.connections_per_host or "default"
            )
            timeout_conf = aiohttp.ClientTimeout(total=self.conf.timeout_sec)
            connector = aiohttp.TCPConnector(
                limit_per_host=self.conf.connections_per_host if self.conf.connections_per_host > 0 else None
            )
            self._session = aiohttp.ClientSession(timeout=timeout_conf, connector=connector)
        return self._session

    async def close(self) -> None:
        """Chiude la sessione HTTP se aperta."""
        if self._session and not self._session.closed:
            logger.debug("Chiusura sessione HTTP")
            await self._session.close()
            self._session = None

    def _parametro_da_rimuovere(self, key: str) -> bool:
        """Determina se un parametro di query deve essere rimosso in base alle regole (exact/prefix/suffix)."""
        k = (key or "").lower()
        decision = (
            k in self.EXACT_KEYS
            or any(k.startswith(p) for p in self.PREFIX_KEYS)
            or any(k.endswith(s) for s in self.ENDS_WITH)
        )
        logger.debug("Parametro '%s' marcato per rimozione: %s", key, decision)
        return decision

    def _normalize_title(self, raw: str | None) -> str | None:
        """Normalizza il titolo senza alterarne il contenuto: unescape HTML, rimozione caratteri invisibili,
        sostituzione NBSP con spazio e compattazione dello whitespace."""
        if not raw:
            return None
        t = html.unescape(raw)
        t = re.sub(r"[\u200B-\u200D\uFEFF]", "", t)  # zero-width
        t = t.replace("\u00A0", " ")
        t = re.sub(r"\s+", " ", t).strip()
        return t or None

    async def segui_redirect(self, url: str, *, fetch_title: bool = True) -> tuple[str, str | None]:
        """Segue i redirect fino all'URL finale e, se richiesto, esegue un GET completo per estrarre il titolo."""
        if not url:
            logger.debug("segui_redirect: URL vuoto")
            return url, None

        headers = {
            "User-Agent": "..",
            "Accept-Language": "it-IT,it;q=0.9,en;q=0.8",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        def _estrai_titolo(html_text: str) -> str | None:
            flags = re.IGNORECASE | re.DOTALL
            m = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\'](.*?)["\']', html_text, flags)
            if m:
                return m.group(1)
            m = re.search(r"<title>(.*?)</title>", html_text, flags)
            if m:
                return m.group(1)
            return None

        def _meta_refresh_target(html_chunk: str, base_url: str) -> str | None:
            flags = re.IGNORECASE
            m = re.search(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\']([^"\']+)["\']', html_chunk, flags)
            if not m:
                return None
            content = m.group(1)
            m2 = re.search(r'url\s*=\s*[\'\"]?([^\'\";]+)', content, flags)
            if not m2:
                return None
            return urljoin(base_url, m2.group(1).strip())

        try:
            session = await self._get_session()
            current = url
            redirects = 0
            logger.debug("Inizio follow redirect")

            # Redirect classici (HEAD)
            while redirects < self.conf.max_redirects:
                try:
                    async with session.head(current, headers=headers, allow_redirects=False) as resp:
                        loc = resp.headers.get("Location")
                        if resp.status in (301, 302, 303, 307, 308) and loc:
                            current = urljoin(current, loc)
                            redirects += 1
                            continue
                except aiohttp.ClientError:
                    # Alcuni shortener non supportano HEAD
                    pass
                break

            # GET parziale per ulteriori redirect + meta refresh
            while redirects < self.conf.max_redirects:
                try:
                    async with session.get(
                        current,
                        headers={**headers, "Range": "bytes=0-4095"},
                        allow_redirects=False,
                    ) as resp:
                        loc = resp.headers.get("Location")
                        if resp.status in (301, 302, 303, 307, 308) and loc:
                            current = urljoin(current, loc)
                            redirects += 1
                            continue
                        if resp.status == 200 and resp.content_type and resp.content_type.startswith("text/html"):
                            chunk = await resp.text(errors="ignore")
                            tgt = _meta_refresh_target(chunk, current)
                            if tgt:
                                current = tgt
                                redirects += 1
                                continue
                except aiohttp.ClientError as e:
                    logger.debug("GET parziale fallita su %s: %s", current, e)
                break

            title_norm: str | None = None
            if fetch_title:
                try:
                    logger.debug("GET finale per estrazione titolo")
                    async with session.get(current, headers=headers) as resp:
                        if resp.status == 200 and resp.content_type and resp.content_type.startswith("text/html"):
                            text = await resp.text(errors="ignore")
                            raw_title = _estrai_titolo(text)
                            title_norm = self._normalize_title(raw_title)
                except Exception as e:
                    logger.debug("Impossibile leggere il titolo: %s", e)
                    return current, None

            return current, title_norm

        except Exception as e:
            logger.error("Errore imprevisto in segui_redirect: %s", e)
            return url, None

    def _togli_punteggiatura_finale(self, url_corrente: str) -> str:
        """Rimuove punteggiatura terminale comune (e NBSP). Evita di rimuovere ")" se sbilanciata."""
        originale = url_corrente
        while url_corrente and url_corrente[-1] in self._TRAILING_PUNCT + "\u00A0":
            if url_corrente.endswith(")") and url_corrente.count("(") < url_corrente.count(")"):
                break
            url_corrente = url_corrente[:-1]
        if originale != url_corrente:
            logger.debug("Rimossa punteggiatura terminale")
        return url_corrente

    async def sanifica_url(self, raw_url: str) -> tuple[str, str | None]:
        """Sanifica un singolo URL e, se abilitato, ne estrae il titolo."""
        if not raw_url:
            logger.debug("sanifica_url: URL vuoto")
            return raw_url, None

        url_corrente = raw_url.strip()
        logger.debug("Sanificazione URL in ingresso")

        if re.match(r"^(mailto:|tel:)", url_corrente, re.IGNORECASE):
            logger.debug("Protocollo non web: restituzione invariata")
            return url_corrente, None

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url_corrente):
            logger.debug("Schema mancante: aggiungo https://")
            url_corrente = "https://" + url_corrente

        try:
            final_url, title = await self.segui_redirect(url_corrente, fetch_title=self.conf.show_title)
        except Exception as e:
            logger.info(f"HEAD fallita su {url_corrente}, eseguo fallback GET ({e})")
            final_url, title = url_corrente, None

        final_title = "" if not self.conf.show_title else (title or None)

        try:
            parts = urlsplit(final_url)
            domain = parts.netloc.lower().lstrip("www")
            logger.debug(
                "Parsing URL finale: domain=%s, path=%s, query=%s, fragment=%s",
                domain, parts.path, parts.query, parts.fragment,
            )

            if domain in self.DOMAIN_WHITELIST:
                logger.info("Dominio in whitelist: nessuna rimozione parametri")
                return self._togli_punteggiatura_finale(final_url), final_title

            original_params = parse_qsl(parts.query, keep_blank_values=True)
            filtered_params = [(k, v) for (k, v) in original_params if not self._parametro_da_rimuovere(k)]
            new_query = urlencode(filtered_params, doseq=True)

            new_fragment = parts.fragment
            if new_fragment:
                frag = new_fragment.lstrip("#").lower()
                if self.FRAG_KEYS and any(frag.startswith(pref) for pref in self.FRAG_KEYS):
                    logger.info("Rimozione fragment in base a FRAG_KEYS")
                    new_fragment = ""

            pulito = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, new_fragment))
            pulito = self._togli_punteggiatura_finale(pulito)
            logger.debug("URL pulito prodotto")
            return pulito, final_title
        except Exception as e:
            logger.error("Errore durante la sanificazione dettagliata: %s (ritorno URL grezzo)", e)
            return raw_url.strip(), final_title

    async def sanifica_in_batch(self, links: list[str]) -> list[tuple[str, str | None]]:
        """Sanifica una lista di URL in parallelo (con semaforo) e deduplica preservando l'ordine."""
        if not links:
            logger.debug("sanifica_in_batch: lista vuota")
            return []

        logger.debug("Avvio sanificazione batch di %d link", len(links))
        sem = asyncio.Semaphore(self.conf.max_concurrency)

        async def _one(u: str):
            async with sem:
                logger.debug("Sanificazione URL (batch)")
                return await self.sanifica_url(u)

        results = await asyncio.gather(*(_one(u) for u in links))
        dedup = list(dict.fromkeys(results))  # deduplica preservando ordine
        if len(dedup) != len(results):
            logger.debug("Deduplica effettuata: %d duplicati rimossi", len(results) - len(dedup))
        logger.info("Sanificazione batch completata: input=%d, output=%d", len(links), len(dedup))
        return dedup


class GetterUrl:
    """Estrae URL da testo grezzo e dalle entità Telegram (URL / TEXT_LINK)."""

    _URL_REGEX = re.compile(
        r"""
        (?<!\w@)
        (?:
            https?://
          | www\.
          | (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})
        )
        [^\s<>\'\"“”()]+
        """,
        re.IGNORECASE | re.VERBOSE
    )

    @classmethod
    def estrai_urls(cls, text: str | None) -> list[str]:
        """Estrae tutti gli URL da una stringa di testo."""
        if not text:
            return []
        urls = [m.group(0) for m in cls._URL_REGEX.finditer(text)]
        logger.debug("estrai_urls: trovati %d URL nel testo", len(urls))
        return urls

    @staticmethod
    def url_da_tg(text: str | None, entities: Iterable[MessageEntity] | None) -> list[str]:
        """Estrae URL da entità Telegram (URL e TEXT_LINK)."""
        urls: list[str] = []
        if not text or not entities:
            return urls
        for ent in entities:
            if ent.type in {MessageEntity.URL, MessageEntity.TEXT_LINK}:
                if ent.type == MessageEntity.URL:
                    url = text[ent.offset: ent.offset + ent.length]
                    urls.append(url)
                elif ent.type == MessageEntity.TEXT_LINK and ent.url:
                    urls.append(ent.url)
        if urls:
            logger.debug("url_da_tg: trovati %d URL nelle entità", len(urls))
        return urls

    @classmethod
    def url_da_msg(cls, msg) -> list[str]:
        """Estrae tutti gli URL pertinenti da un messaggio (testo, caption, entità)."""
        found: list[str] = []
        if msg.text:
            found.extend(cls.estrai_urls(msg.text))
        if msg.caption:
            found.extend(cls.estrai_urls(msg.caption))
        found.extend(cls.url_da_tg(msg.text, msg.entities))
        found.extend(cls.url_da_tg(msg.caption, msg.caption_entities))
        logger.debug("URL totali trovati nel messaggio: %d", len(found))
        return found


class TelegramIO:
    """Utility per la produzione dell'output destinato a Telegram."""

    @staticmethod
    def _neutralizza(s: str) -> str:
        """Inserisce ZWSP per neutralizzare mention, hashtag e comandi a inizio parola."""
        if not s:
            return s
        s = re.sub(r'(?<!\S)@(\w+)', '@\u2060\\g<1>', s)
        s = re.sub(r'(?<!\S)#(\w+)', '#\u2060\\g<1>', s)
        s = re.sub(r'(?<!\S)/(\w+)', '/\u2060\\g<1>', s)
        return s

    @staticmethod
    def get_output(clean_links: list[tuple[str, str | None]], conf: AppConfig) -> str:
        """Compone il testo di risposta con link puliti e titoli (se abilitati)."""
        if not clean_links:
            logger.debug("get_output: nessun link pulito")
            return "Nessun collegamento rilevato."

        blocks: list[str] = []
        for url, title in clean_links:
            pieces: list[str] = []
            if conf.show_title and title:
                t = html.escape(TelegramIO._neutralizza(title))
                pieces.append(f"<blockquote>{t}</blockquote>")
            pieces.append(html.escape(url))  # Telegram autolinka, ma sempre escapato
            blocks.append("\n".join(pieces))

        output = "\n\n".join(blocks)
        logger.debug("get_output: testo pronto (%d blocchi)", len(blocks))
        return output


class TelegramHandlers:
    """Coordina le componenti: estrazione URL, sanificazione e risposta."""

    def __init__(self, sanitizer: Sanitizer, conf: AppConfig) -> None:
        self.sanitizer = sanitizer
        self.conf = conf

    async def _sanifica_e_rispondi(self, target, raw_links: list[str]) -> tuple[int, int, int | None]:
        """Deduplica i link in ingresso, li sanifica in batch e invia la risposta."""

        def _normalizza_per_dedup(u: str) -> str:
            u = (u or "").strip()
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", u):
                u = "https://" + u
            u = self.sanitizer._togli_punteggiatura_finale(u)
            return u.lower()

        visti = set()
        dedup_links: list[str] = []
        for u in raw_links:
            k = _normalizza_per_dedup(u)
            if k not in visti:
                visti.add(k)
                dedup_links.append(u)

        num_trovati = len(dedup_links)  # conteggio realistico

        clean_links = await self.sanitizer.sanifica_in_batch(dedup_links)
        text = TelegramIO.get_output(clean_links, self.conf)

        reply = await target.reply_text(
            text,
            disable_web_page_preview=len(clean_links) > 1,
            parse_mode=ParseMode.HTML
        )
        reply_id = getattr(reply, "message_id", None)

        # rimozione dopo l'invio
        try:
            await self._react(target, None)
        except Exception:
            pass

        return num_trovati, len(clean_links), reply_id

    @staticmethod
    def menzionato(msg, context: ContextTypes.DEFAULT_TYPE) -> bool:
        """Verifica se il bot è stato menzionato (mention o text_mention)."""
        bot_username = (context.bot.username or "").lower()
        bot_id = context.bot.id

        def _check(text: str | None, entities: Iterable[MessageEntity] | None) -> bool:
            if not text:
                return False
            if entities:
                for ent in entities:
                    if ent.type == MessageEntity.MENTION:
                        mention = text[ent.offset: ent.offset + ent.length].lower()
                        if mention == f"@{bot_username}":
                            return True
                    elif ent.type == MessageEntity.TEXT_MENTION and ent.user:
                        if ent.user.id == bot_id:
                            return True
            return f"@{bot_username}" in text.lower()

        return _check(msg.text, msg.entities) or _check(msg.caption, msg.caption_entities)

    async def _react(self, message, emoji: str | None) -> bool:
        """Imposta (o rimuove) una reaction sul messaggio target.
        Ritorna True se l'operazione va a buon fine, False altrimenti (nessun messaggio di errore)."""
        try:
            if emoji:
                await message.set_reaction([ReactionTypeEmoji(emoji)])
            else:
                await message.set_reaction([])  # rimuove tutte le reaction
            return True
        except Exception as e:
            logger.debug("Impossibile impostare reaction %r: %s", emoji, e)
            return False

    async def presaInCarico(self, msg) -> list[str]:
        """Acknowledge con 👀, estrai link; se vuoto, prova fallback reaction.
        Non invia MAI messaggi. Ritorna la lista di link grezzi."""
        # 1) acknowledge immediato
        await self._react(msg, "👀")

        # 2) estrazione link
        raw_links = GetterUrl.url_da_msg(msg)

        # 3) nessun link: gestisci solo reaction (NO messaggi)
        if not raw_links:
            ok = await self._react(msg, "❌")
            if not ok:
                ok = await self._react(msg, "👎")
            if not ok:
                # come ultima spiaggia, rimuovi reaction per non lasciare gli 👀 appesi
                await self._react(msg, None)
            return []

        # link presenti: lascia gli 👀; il caller deciderà cosa fare dopo
        return raw_links

    async def handle_gruppi(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Gestisce la menzione nei gruppi su messaggi in risposta."""
        msg = update.effective_message
        if not msg or not self.menzionato(msg, context):
            logger.debug("handle_gruppi: ignorato (nessuna menzione o messaggio nullo)")
            return
        if not msg.reply_to_message:
            logger.debug("handle_gruppi: manca reply_to_message")
            return

        target = msg.reply_to_message
        raw_links = await self.presaInCarico(target)
        user = update.effective_user
        chat = update.effective_chat

        if not raw_links:
            # già gestito da presaInCarico (solo reaction), ma aggiungo log
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

        trovati, puliti, reply_id = await self._sanifica_e_rispondi(target, raw_links)
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
        """Gestisce i messaggi in chat privata."""
        if update.effective_chat.type != ChatType.PRIVATE:
            return
        msg = update.effective_message
        raw_links = await self.presaInCarico(msg)
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

        trovati, puliti, reply_id = await self._sanifica_e_rispondi(msg, raw_links)
        logger.info(
            "PRIVATO: da '%s' (@%s) — trovati=%d, puliti=%d, reply_msg_id=%s",
            getattr(user, "full_name", "n/a"),
            getattr(user, "username", "n/a"),
            trovati,
            puliti,
            reply_id,
        )

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Messaggio di benvenuto con istruzioni sintetiche."""
        user = update.effective_user
        first_name = html.escape(user.first_name) if user and user.first_name else "Utente"
        text = (
            f"<b>Benvenuto {first_name}.</b>\n\n"
            "Sono <b>Sanitize Link</b>: rimuovo parametri di tracciamento dai collegamenti e seguo i redirect per restituire l'URL finale.\n\n"
            "Invia <code>/help</code> per maggiori dettagli."
        )
        await update.message.reply_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Guida rapida all'utilizzo, in tono formale e didattico."""
        bot_username = context.bot.username or (await context.bot.get_me()).username
        mention_bot = f"@{bot_username}" if bot_username else "@.."
        help_text = (
            "<b>Sanitize Link — Guida rapida</b>\n\n"
            "<b>Uso in chat privata</b><br>"
            "Invia un messaggio con uno o più collegamenti. Il sistema restituisce la versione pulita, priva di parametri di tracciamento, dopo aver seguito eventuali redirect.\n\n"
            "<b>Uso nei gruppi</b><br>"
            f"Rispondi a un messaggio contenente collegamenti e menziona il bot (<code>{html.escape(mention_bot)}</code>). Verranno inviati gli URL puliti relativi a quel messaggio.\n\n"
            "<b>Operazioni effettuate</b><br>"
            "• Rimozione di parametri di tracciamento (es. utm, fbclid)" "<br>"
            "• Follow dei redirect fino all'URL finale" "<br>"
            "• Rimozione di frammenti non necessari (#...)\n\n"
            "<b>Vantaggi</b><br>"
            "Collegamenti più brevi, leggibili e rispettosi della privacy.\n\n"
            "Codice sorgente: <a href=\"https://github.com/br1brown/SanitizeLinkBot.git\">GitHub</a>"
        )
        await update.message.reply_text(help_text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


# ---------- PERCORSI CONFIG ----------

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
KEYS_PATH = os.path.join(BASE_DIR, "keys.json")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
TOKEN_PATH = os.path.join(BASE_DIR, "token.txt")


def load_json_file(path: str) -> dict:
    """Carica un file JSON da disco, sollevando un errore chiaro in caso di formato non valido."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            logger.debug("Caricato JSON da %s (chiavi: %s)", path, list(data.keys()))
            return data
    except FileNotFoundError:
        logger.warning("File non trovato: %s (eventuali chiavi obbligatorie verranno richieste altrove)", path)
        return {}
    except json.JSONDecodeError as e:
        logger.error("Errore nel parsing JSON di %s: %s", path, e)
        raise RuntimeError(f"Errore nel parsing di {path}: {e}") from e


CONFIG = AppConfig.load(CONFIG_PATH)
KEYS = load_json_file(KEYS_PATH)

# Impostazione del livello logger: preferenza a config, poi variabile d'ambiente LOG_LEVEL, infine INFO
_env_level = (os.getenv("LOG_LEVEL", "").upper() or None)
_final_level = CONFIG.log_level or _env_level or "INFO"
try:
    logger.setLevel(getattr(logging, _final_level, logging.INFO))
except Exception:
    pass


def get_telegram_token() -> str:
    """Ottiene il token Telegram con priorità: variabile d'ambiente > file locale."""
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
        logger.error("Token mancante. Impostare TELEGRAM_BOT_TOKEN o creare 'token.txt'")
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN o 'token.txt'") from e


async def main() -> None:
    """Avvia il bot: costruzione Application, registrazione handler, polling e spegnimento ordinato."""
    try:
        telegram_token = get_telegram_token()
        app = Application.builder().token(telegram_token).build()
    except RuntimeError as e:
        logger.error("Avvio interrotto per configurazione non valida: %s", e)
        return

    # Istanziamento Sanitizer con chiavi e configurazione
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

    logger.info("Configurazione caricata. Bot in esecuzione")

    # ---------- CICLO DI VITA PTB ----------
    await app.initialize()   # prepara bot e rete
    await app.start()        # apre connessioni
    try:
        # start_polling con Updater legacy (PTB20 lo espone per compatibilità), ascolta tutti gli update
        await app.updater.start_polling(allowed_updates=Update.ALL_TYPES)
        # Attesa finché non arriva un segnale di arresto (Ctrl+C)
        await asyncio.Event().wait()
    finally:
        # Sequenza di spegnimento ordinata
        await app.updater.stop()
        await app.stop()
        await app.shutdown()
        await sanitizer.close()
        logger.info("Bot arrestato correttamente")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterruzione richiesta dall'utente (Ctrl+C)")
