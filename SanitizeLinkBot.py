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
# livello globale WARNING+ per silenziare librerie; il livello specifico del bot è definito dopo il caricamento config
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
    """config generale del bot, valida e carica da json (non troppo sofisticata, giusto controllo chiavi)"""

    # chiavi richieste minime per il config (non fa type check profondo, solo presenza)
    _REQUIRED_KEYS = {
        "Output": {"show_title"},
        "Batch": {"max_concurrency"},
        "HTTP": {"connections_per_host", "max_redirects", "timeout_sec"},
        "Formatting": {"trailing_punct"},
    }

    def __init__(self, raw: dict) -> None:
        # qui prendo le sezioni già validate in load (quindi mi fido che ci siano)
        output_conf     = raw["Output"]
        batch_conf      = raw["Batch"]
        http_conf       = raw["HTTP"]
        formatting_conf = raw["Formatting"]
        logging_conf    = raw.get("Logging", {}) or {}

        # output
        self.show_title: bool = bool(output_conf["show_title"])

        # batch
        self.max_concurrency: int = int(batch_conf["max_concurrency"])

        # http
        self.connections_per_host: int = int(http_conf["connections_per_host"])
        self.ttl_dns_cache : int = int(http_conf["ttl_dns_cache"])
        self.max_redirects: int = int(http_conf["max_redirects"])
        self.timeout_sec:   int = int(http_conf["timeout_sec"])

        # formatting
        self.trailing_punct: str = str(formatting_conf["trailing_punct"])

        # logging (opzionale, normalizza livello tipo "info"/"warning"...)
        self.log_level: str | None = self._normalize_log_level(logging_conf.get("level"))

    @classmethod
    def load(cls, path: str) -> "AppConfig":
        """carica il config da file e controlla che ci siano tutte le sezioni"""
        logger.debug("Caricamento configurazione: %s", path)
        raw = load_json_file(path, required=True)

        missing_items: list[str] = []
        # controllo che ogni sezione abbia le chiavi richieste
        for section, keys in cls._REQUIRED_KEYS.items():
            if section not in raw or not isinstance(raw[section], dict):
                missing_items.append(f"- sezione mancante: {section}")
                continue
            missing_keys = [k for k in keys if k not in raw[section]]
            if missing_keys:
                missing_items.append(f"- {section}: chiavi mancanti {missing_keys}")

        if missing_items:
            # se mancano cose, faccio crashare subito con lista errori
            msg = "Configurazione incompleta:\n" + "\n".join(missing_items)
            logger.error(msg)
            raise RuntimeError(msg)

        conf = cls(raw)
        logger.info("Configurazione applicativa caricata correttamente")
        logger.debug("Dettagli configurazione: %s", conf)
        return conf

    @staticmethod
    def _normalize_log_level(level_value) -> str | None:
        """accetta sia stringhe che numeri e prova a convertirli in un livello logging valido"""
        if not level_value:
            return None

        # se è intero -> prova a tradurlo in nome
        if isinstance(level_value, int):
            name = logging.getLevelName(level_value)
            if isinstance(name, str) and name.isupper():
                return name
            logging.warning("Log level numerico non riconosciuto (%r); fallback a INFO", level_value)
            return "INFO"

        # se è stringa -> normalizza upper e controlla se è tra i validi
        if isinstance(level_value, str):
            candidate = level_value.strip().upper()
            valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
            if candidate in valid:
                return candidate
            logging.warning("Log level stringa non valido (%r); fallback a INFO", level_value)
            return "INFO"

        logging.warning("Tipo log level non supportato (%r); fallback a INFO", type(level_value).__name__)
        return "INFO"

    def __repr__(self) -> str:
        # giusto per debugging: printa i valori più utili
        return (
            "AppConfig("
            f"show_title={self.show_title}, "
            f"max_redirects={self.max_redirects}, timeout_sec={self.timeout_sec}, "
            f"max_concurrency={self.max_concurrency}, connections_per_host={self.connections_per_host}, "
            f"trailing_punct={self.trailing_punct!r}, log_level={self.log_level!r}"
            ")"
        )


class Sanitizer:
    """gestisce la pulizia degli url (segue redirect, rimuove parametri di tracking, normalizza titoli ecc)"""

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
        # preparo tutte le liste di chiavi per capire cosa togliere
        self.EXACT_KEYS = set(map(str.lower, exact_keys or set()))
        self.PREFIX_KEYS = tuple(k.lower() for k in (prefix_keys or ()))
        self.ENDS_WITH = tuple(k.lower() for k in (ends_with or ()))
        self.FRAG_KEYS = tuple(k.lower() for k in (frag_keys or ()))
        self.DOMAIN_WHITELIST = {(k or "").lower(): v for k, v in (domain_whitelist or {}).items()}
        self.conf = conf
        self._session: aiohttp.ClientSession | None = None
        # se config non dà trailing_punct uso default
        self._TRAILING_PUNCT = conf.trailing_punct or self._TRAILING_PUNCT_DEFAULT

    async def _get_session(self) -> aiohttp.ClientSession:
        """apre la sessione http se non esiste già"""
        if self._session is None or self._session.closed:
            logger.debug(
                "Creo aiohttp.ClientSession (timeout=%ss, limit_per_host=%s)",
                self.conf.timeout_sec, self.conf.connections_per_host or "default"
            )
            connector = aiohttp.TCPConnector(
                limit_per_host=self.conf.connections_per_host if self.conf.connections_per_host > 0 else None,
                ttl_dns_cache = self.conf.ttl_dns_cache,
                enable_http2 = True,
            )
            timeout_conf = aiohttp.ClientTimeout(total=self.conf.timeout_sec, connect=self.conf.timeout_sec/3)
            self._session = aiohttp.ClientSession(timeout=timeout_conf, connector=connector)
        return self._session

    async def close(self) -> None:
        """chiude la sessione http se è aperta"""
        if self._session and not self._session.closed:
            logger.debug("Chiusura sessione HTTP")
            await self._session.close()
            self._session = None

    def _parametro_da_rimuovere(self, key: str) -> bool:
        """decide se un parametro query deve sparire (match esatto, prefix o suffix)"""
        k = (key or "").lower()
        decision = (
            k in self.EXACT_KEYS
            or any(k.startswith(p) for p in self.PREFIX_KEYS)
            or any(k.endswith(s) for s in self.ENDS_WITH)
        )
        logger.debug("Parametro '%s' marcato per rimozione: %s", key, decision)
        return decision

    def _normalize_title(self, raw: str | None) -> str | None:
        """pulizia base del titolo html: unescape, togli invisibili, compatta spazi"""
        if not raw:
            return None
        t = html.unescape(raw)
        t = re.sub(r"[\u200B-\u200D\uFEFF]", "", t)  # zero-width
        t = t.replace("\u00A0", " ")
        t = re.sub(r"\s+", " ", t).strip()
        return t or None

    async def segui_redirect(self, url_iniziale: str, fetch_title: bool = True):
        """segue redirect multipli (http/meta/js) e opzionalmente tira fuori il titolo finale"""
        # qui dentro fa un giro con head, poi get parziale, poi fallback su host noti (shortener)

        def _estrai_titolo(html_text: str) -> str | None:
            m = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
            return m.group(1).strip() if m else None

        def _meta_refresh_target(html_text: str, base_url: str) -> str | None:
            m = re.search(
                r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\']\s*\d+\s*;\s*url\s*=\s*([^"\']+)["\']',
                html_text,
                re.IGNORECASE,
            )
            return urljoin(base_url, m.group(1).strip()) if m else None

        def _js_redirect_target(html_text: str, base_url: str) -> str | None:
            # prova a capire se c'è un redirect via javascript
            patterns = [
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
                r'location\.replace\(\s*["\']([^"\']+)["\']\s*\)',
                r'location\.assign\(\s*["\']([^"\']+)["\']\s*\)',
            ]
            for pat in patterns:
                m = re.search(pat, html_text, re.IGNORECASE)
                if m and m.group(1):
                    return urljoin(base_url, m.group(1).strip())
            return None

        # ciclo redirect finché non arrivo all'url finale o supero il limite
        current = url_iniziale
        redirects = 0
        title_norm = None

        timeout = aiohttp.ClientTimeout(total=15)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            while redirects < self.conf.max_redirects:
                try:
                    # primo tentativo: head
                    async with session.head(current, allow_redirects=False) as resp:
                        if resp.status in (301, 302, 303, 307, 308):
                            loc = resp.headers.get("Location")
                            if loc:
                                current = urljoin(current, loc)
                                redirects += 1
                                continue
                except aiohttp.ClientError:
                    break

                try:
                    # get parziale per meta refresh o js redirect
                    async with session.get(
                        current,
                        headers={"Range": "bytes=0-16383"},
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (301, 302, 303, 307, 308):
                            loc = resp.headers.get("Location")
                            if loc:
                                current = urljoin(current, loc)
                                redirects += 1
                                continue
                        if resp.status == 200 and resp.content_type and resp.content_type.startswith("text/html"):
                            text = await resp.text(errors="ignore")
                            tgt = _meta_refresh_target(text, current) or _js_redirect_target(text, current)
                            if tgt:
                                current = tgt
                                redirects += 1
                                continue
                except aiohttp.ClientError:
                    break

                # fallback: se host è uno shortener noto provo get completa
                try:
                    host = urlsplit(current).netloc.lower()
                except Exception:
                    host = ""

                try:
                    async with session.get(current, allow_redirects=False) as resp:
                        if resp.status in (301, 302, 303, 307, 308):
                            loc = resp.headers.get("Location")
                            if loc:
                                current = urljoin(current, loc)
                                redirects += 1
                                continue
                        if resp.status == 200 and resp.content_type and resp.content_type.startswith("text/html"):
                            text_full = await resp.text(errors="ignore")
                            tgt = _meta_refresh_target(text_full, current) or _js_redirect_target(text_full, current)
                            if tgt:
                                current = tgt
                                redirects += 1
                                continue
                except aiohttp.ClientError:
                    break

                break 

            # ultimo step: se richiesto, provo a leggere il titolo
            if fetch_title:
                try:
                    async with session.get(current) as resp:
                        if resp.status == 200 and resp.content_type and resp.content_type.startswith("text/html"):
                            text = await resp.text(errors="ignore")
                            raw_title = _estrai_titolo(text)
                            if raw_title:
                                title_norm = self._normalize_title(raw_title)
                except aiohttp.ClientError:
                    pass

        return current, title_norm

    def _togli_punteggiatura_finale(self, url_corrente: str) -> str:
        """taglia punteggiatura extra alla fine (tipo punto o parentesi sbilanciate)"""
        originale = url_corrente
        while url_corrente and url_corrente[-1] in self._TRAILING_PUNCT + "\u00A0":
            if url_corrente.endswith(")") and url_corrente.count("(") < url_corrente.count(")"):
                break
            url_corrente = url_corrente[:-1]
        if originale != url_corrente:
            logger.debug("Rimossa punteggiatura terminale")
        return url_corrente

    async def sanifica_url(self, raw_url: str) -> tuple[str, str | None]:
        """sanifica un singolo url (segue redirect, rimuove parametri, sistema schema mancante ecc)"""
        if not raw_url:
            logger.debug("sanifica_url: URL vuoto")
            return raw_url, None

        url_corrente = raw_url.strip()
        logger.debug("Sanificazione URL in ingresso")

        # gestisce mailto: o tel: -> li lascia così
        if re.match(r"^(mailto:|tel:)", url_corrente, re.IGNORECASE):
            logger.debug("Protocollo non web: restituzione invariata")
            return url_corrente, None

        # se manca schema -> aggiunge https
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
            domain = re.sub(r'^www\.', '', parts.netloc, flags=re.IGNORECASE).lower()
            logger.debug(
                "Parsing URL finale: domain=%s, path=%s, query=%s, fragment=%s",
                domain, parts.path, parts.query, parts.fragment,
            )

            if domain in self.DOMAIN_WHITELIST:
                # se dominio è in whitelist non tolgo niente
                return self._togli_punteggiatura_finale(final_url), final_title

            # filtro parametri query
            original_params = parse_qsl(parts.query, keep_blank_values=True)
            filtered_params = [(k, v) for (k, v) in original_params if not self._parametro_da_rimuovere(k)]
            new_query = urlencode(filtered_params, doseq=True)

            # gestisco fragment
            new_fragment = parts.fragment
            if new_fragment:
                frag = new_fragment.lstrip("#").lower()
                if self.FRAG_KEYS and any(frag.startswith(pref) for pref in self.FRAG_KEYS):
                    new_fragment = ""

            pulito = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, new_fragment))
            pulito = self._togli_punteggiatura_finale(pulito)
            logger.debug("URL pulito prodotto")
            return pulito, final_title
        except Exception as e:
            logger.error("Errore durante la sanificazione dettagliata: %s (ritorno URL grezzo)", e)
            return raw_url.strip(), final_title

    async def sanifica_in_batch(self, links: list[str]) -> list[tuple[str, str | None]]:
        """fa sanificazione su lista di url in parallelo (con deduplica e semaforo per limitare concorrenza)"""
        # normalizzo input
        normalized = [(u or "").strip() for u in links]

        # deduplica mantenendo ordine
        from collections import OrderedDict
        unique_urls: "OrderedDict[str, list[int]]" = OrderedDict()
        for idx, url in enumerate(normalized):
            if url:
                unique_urls.setdefault(url, []).append(idx)

        if not unique_urls:
            return [("", None) for _ in normalized]

        # semaforo per limitare concorrenti
        sem = getattr(self, "_semaforo", asyncio.Semaphore(getattr(self.conf, "max_concurrency", 10)))

        async def _one(url: str) -> tuple[str, str | None]:
            async with sem:
                try:
                    return await self.sanifica_url(url)
                except Exception:
                    return (url, None)

        # creo task solo per url unici
        tasks = {url: asyncio.create_task(_one(url)) for url in unique_urls}
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        # ricompongo i risultati
        resolved: dict[str, tuple[str, str | None]] = {}
        for url, res in zip(tasks.keys(), results):
            if isinstance(res, Exception):
                resolved[url] = (url, None)
            else:
                resolved[url] = res

        # ricostruisci la lista finale nell’ordine degli input
        out: list[tuple[str, str | None]] = [("", None) for _ in normalized]
        for url, idxs in unique_urls.items():
            for idx in idxs:
                out[idx] = resolved[url]

        return out


class GetterUrl:
    """estrae url sia dal testo grezzo sia dalle entità telegram (url / text_link)"""

    _URL_REGEX = re.compile(
        r"""
        (?<!\w@)              # evita cose tipo user@host (non voglio toccare email/menzioni)
        (?:
            https?://         # schema esplicito
          | www\.             # o www.
          | (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})  # dominio nudo tipo example.com
        )
        [^\s<>\'\"“”()]+      # il corpo dell'url (stop a spazi, virgolette, parentesi ecc)
        """,
        re.IGNORECASE | re.VERBOSE
    )

    @classmethod
    def estrai_urls(cls, text: str | None) -> list[str]:
        """prende tutti gli url dal testo usando la regex sopra"""
        if not text:
            return []
        urls = [m.group(0) for m in cls._URL_REGEX.finditer(text)]
        logger.debug("estrai_urls: trovati %d URL nel testo", len(urls))
        return urls

    @staticmethod
    def url_da_tg(text: str | None, entities: Iterable[MessageEntity] | None) -> list[str]:
        """estrae url direttamente dalle entità telegram (sia URL che TEXT_LINK)"""
        urls: list[str] = []
        if not text or not entities:
            return urls
        for ent in entities:
            if ent.type in {MessageEntity.URL, MessageEntity.TEXT_LINK}:
                if ent.type == MessageEntity.URL:
                    # qui l'url è "in chiaro" nel testo
                    url = text[ent.offset: ent.offset + ent.length]
                    urls.append(url)
                elif ent.type == MessageEntity.TEXT_LINK and ent.url:
                    # qui l'ancora ha un link incorporato
                    urls.append(ent.url)
        if urls:
            logger.debug("url_da_tg: trovati %d URL nelle entità", len(urls))
        return urls

    @classmethod
    def url_da_msg(cls, msg) -> list[str]:
        # 1) prova con le entità (ordine già “telegram”)
        urls = []
        urls.extend(cls.url_da_tg(msg.text, msg.entities))
        urls.extend(cls.url_da_tg(msg.caption, msg.caption_entities))
        if urls:
            return urls  # se Telegram ha già taggato i link, fidati di quest’ordine

        # 2) fallback: usa la regex su testo/caption
        found = []
        if msg.text:
            found.extend(cls.estrai_urls(msg.text))
        if msg.caption:
            found.extend(cls.estrai_urls(msg.caption))
        return found


class TelegramIO:
    """utility per costruire l'output da mandare su telegram (titolo opzionale + url pulito)"""

    @staticmethod
    def _neutralizza(s: str) -> str:
        """inserisce zero-width space per evitare mention/hashtag/comandi involontari all'inizio parola"""
        if not s:
            return s
        # qui uso zwsp per spezzare pattern che telegram riconoscerebbe (senza cambiare la resa visiva)
        s = re.sub(r'(?<!\S)@(\w+)', '@\u2060\\g<1>', s)   # @username -> @​username
        s = re.sub(r'(?<!\S)#(\w+)', '#\u2060\\g<1>', s)   # #hashtag -> #​hashtag
        s = re.sub(r'(?<!\S)/(\w+)', '/\u2060\\g<1>', s)   # /command -> /​command
        return s

    @staticmethod
    def get_output(clean_links: list[tuple[str, str | None]], conf: AppConfig) -> str:
        """compone il testo finale con blocchi separati: (titolo se attivo) + url escapato"""
        if not clean_links:
            logger.debug("get_output: nessun link pulito")
            return "Nessun collegamento rilevato."

        blocks: list[str] = []
        for url, title in clean_links:
            pieces: list[str] = []

            # se i titoli sono abilitati e c'è il titolo, lo metto in blockquote
            if conf.show_title and title:
                # escape html + neutralizzazione per non innescare roba tipo @ o / all'inizio
                t = html.escape(TelegramIO._neutralizza(title))
                pieces.append(f"<blockquote>{t}</blockquote>")

            # l'url lo lascio "nudo": telegram fa autolink, però sempre escapato per sicurezza
            pieces.append(html.escape(url))
            blocks.append("\n".join(pieces))

        output = "\n\n".join(blocks)  # riga vuota fra un blocco e l'altro (leggibile)
        logger.debug("get_output: testo pronto (%d blocchi)", len(blocks))
        return output


class TelegramHandlers:
    """orchestra tutto: prende i link, li sanifica e risponde su telegram"""

    def __init__(self, sanitizer: Sanitizer, conf: AppConfig) -> None:
        # tengo riferimenti condivisi (sanitizer e config)
        self.sanitizer = sanitizer
        self.conf = conf

    async def _sanifica_e_rispondi(self, target, raw_links: list[str]) -> tuple[int, int, int | None]:
        """deduplica i link, li pulisce in batch, manda la risposta; ritorna (trovati, puliti, reply_id)"""

        def _normalizza_per_dedup(u: str) -> str:
            # normalizzo base per scovare duplicati tipo example.com e https://example.com
            u = (u or "").strip()
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", u):
                u = "https://" + u
            u = self.sanitizer._togli_punteggiatura_finale(u)
            return u.lower()

        # deduplica preservando l'ordine originale
        visti = set()
        dedup_links: list[str] = []
        for u in raw_links:
            k = _normalizza_per_dedup(u)
            if k not in visti:
                visti.add(k)
                dedup_links.append(u)

        num_trovati = len(dedup_links)  # numeri "onesti": quanti link unici ho davvero

        # sanifica in parallelo
        clean_links = await self.sanitizer.sanifica_in_batch(dedup_links)

        # costruisce testo finale (titolo opzionale + url)
        text = TelegramIO.get_output(clean_links, self.conf)

        # invia risposta in thread del messaggio target
        reply = await target.reply_text(
            text,
            disable_web_page_preview=len(clean_links) > 1,  # se sono tanti link evito anteprime
            parse_mode=ParseMode.HTML
        )
        reply_id = getattr(reply, "message_id", None)

        # best effort: tolgo reaction (se messa prima) senza far rumore
        try:
            await self._react(target, None)
        except Exception:
            pass

        return num_trovati, len(clean_links), reply_id

    @staticmethod
    def menzionato(msg, context: ContextTypes.DEFAULT_TYPE) -> bool:
        """controlla se nel messaggio compare una mention esplicita al bot (stringa o text_mention)"""
        bot_username = (context.bot.username or "").lower()
        bot_id = context.bot.id

        def _check(text: str | None, entities: Iterable[MessageEntity] | None) -> bool:
            if not text:
                return False
            if entities:
                for ent in entities:
                    if ent.type == MessageEntity.MENTION:
                        # esempio: "@mio_bot"
                        mention = text[ent.offset: ent.offset + ent.length].lower()
                        if mention == f"@{bot_username}":
                            return True
                    elif ent.type == MessageEntity.TEXT_MENTION and ent.user:
                        # menzione "ricca" con user id
                        if ent.user.id == bot_id:
                            return True
            # fallback: cerca la stringa nel testo (non affidabile ma utile)
            return f"@{bot_username}" in text.lower()

        # controllo sia su testo sia su caption
        return _check(msg.text, msg.entities) or _check(msg.caption, msg.caption_entities)

    async def _react(self, message, emoji: str | None) -> bool:
        """setta (o rimuove) una reaction sul messaggio; silenziosa se fallisce"""
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
        """fa "ack" con 👀, estrae i link dal messaggio e gestisce il caso vuoto solo con reaction"""
        # metto subito occhi per segnalare che sto lavorando
        await self._react(msg, "👀")

        # estraggo link da testo/caption + entità
        raw_links = GetterUrl.url_da_msg(msg)

        # se non c'è nulla, metto ❌ (o 👎) e non mando messaggi
        if not raw_links:
            ok = await self._react(msg, "❌")
            if not ok:
                ok = await self._react(msg, "👎")
            if not ok:
                # se nemmeno questo, tolgo la reaction così non resta appeso l'ack
                await self._react(msg, None)
            return []

        # se ci sono link, lascio gli occhi (il caller poi risponderà con i risultati)
        return raw_links

    async def handle_gruppi(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """gestisce menzioni in gruppi: funziona solo se rispondi a un messaggio e menzioni il bot"""
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
            # niente da fare: ho già gestito con reaction
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
        """gestisce la chat privata: basta scrivere un messaggio con link e rispondo con i puliti"""
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
        """risposta al /start (breve welcome + istruzioni base)"""
        user = update.effective_user
        first_name = html.escape(user.first_name) if user and user.first_name else "Utente"
        text = (
            f"<b>Benvenuto {first_name}.</b>\n\n"
            "Sono <b>Sanitize Link</b>: rimuovo parametri di tracciamento dai collegamenti e seguo i redirect per restituire l'URL finale.\n\n"
            "Invia /help per maggiori dettagli."
        )
        await update.message.reply_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """risposta a /help (guida compatta, tono formale come in originale)"""
        bot_username = context.bot.username or (await context.bot.get_me()).username
        mention_bot = f"@{bot_username}" if bot_username else "@.."
        help_text = (
            "<b>Sanitize Link — Guida rapida</b>\n\n"
            "<b>Uso in chat privata</b>\n"
            "Invia un messaggio con uno o più collegamenti. Il sistema restituisce la versione pulita, priva di parametri di tracciamento, dopo aver seguito eventuali redirect.\n\n"
            "<b>Uso nei gruppi</b>\n"
            f"Rispondi a un messaggio contenente collegamenti e menziona il bot (<code>{html.escape(mention_bot)}</code>). Verranno inviati gli URL puliti relativi a quel messaggio.\n\n"
            "<b>Operazioni effettuate</b>\n"
            "• Rimozione di parametri di tracciamento (es. utm, fbclid)\n"
            "• Follow dei redirect fino all'URL finale\n"
            "• Rimozione di frammenti non necessari (#...)\n\n"
            "<b>Vantaggi</b>\n"
            "Collegamenti più brevi, leggibili e rispettosi della privacy.\n\n"
            "Codice sorgente: <a href=\"https://github.com/br1brown/SanitizeLinkBot.git\">GitHub</a>"
        )
        await update.message.reply_text(help_text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


# ---------- PERCORSI CONFIG ----------

# base dir del progetto (funziona sia quando esegui lo script che quando è importato)
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
KEYS_PATH = os.path.join(BASE_DIR, "keys.json")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
TOKEN_PATH = os.path.join(BASE_DIR, "token.txt")


def load_json_file(path: str, *, required: bool = False) -> dict:
    """
    carica un file json e restituisce un dict.
    - se required=True e il file non c'è -> errore chiaro.
    - se required=False e manca -> restituisce {} e logga info.
    - se il json non è un dict -> errore.
    - se il json è malformato -> errore con dettaglio parsing.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as e:
        if required:
            logger.error("File di configurazione richiesto non trovato: %s", path)
            raise RuntimeError(f"File richiesto non trovato: {path}") from e
        logger.info("File opzionale non trovato: %s (uso valori vuoti/di default)", path)
        return {}
    except json.JSONDecodeError as e:
        logger.error("Errore nel parsing JSON di %s: %s", path, e)
        raise RuntimeError(f"Errore nel parsing di {path}: {e}") from e

    if not isinstance(data, dict):
        logger.error("Il file %s non contiene un oggetto JSON (dict).", path)
        raise RuntimeError(f"Contenuto non valido in {path}: atteso un oggetto JSON (dict)")

    logger.debug("Caricato JSON da %s (chiavi: %s)", path, list(data.keys()))
    return data


# carico config e chiavi (qui se manca il config obbligatorio, esplode già in AppConfig.load)
CONFIG = AppConfig.load(CONFIG_PATH)
KEYS = load_json_file(KEYS_PATH)

# livello logging preferito: prima quello del config, poi env LOG_LEVEL, altrimenti info
_env_level = (os.getenv("LOG_LEVEL", "").upper() or None)
_final_level = CONFIG.log_level or _env_level or "INFO"
try:
    logger.setLevel(getattr(logging, _final_level, logging.INFO))
except Exception:
    # se qualcosa va storto nel settaggio, ignoro e resto col default
    pass


def get_telegram_token() -> str:
    """prende il token del bot: prima da env TELEGRAM_BOT_TOKEN, poi da token.txt (fallback semplice)"""
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
    """avvia il bot: costruzione application, registrazione handler, polling e spegnimento ordinato"""
    try:
        # prendo il token e costruisco l'app ptb
        telegram_token = get_telegram_token()
        app = Application.builder().token(telegram_token).build()
    except RuntimeError as e:
        # se manca token o config è rotto, lascio log e abbandono
        logger.error("Avvio interrotto per configurazione non valida: %s", e)
        return

    # istanzio il sanitizer con le chiavi prese da keys.json + config runtime
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
    # comandi base
    app.add_handler(CommandHandler("start", handlers.cmd_start), group=0)
    app.add_handler(CommandHandler("help", handlers.cmd_help), group=0)

    # gruppi: testo/caption non comando + tipo group/supergroup → gestisco menzioni con reply
    group_filter = (filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND)
    app.add_handler(MessageHandler(group_filter, handlers.handle_gruppi), group=1)

    # privato: testo/caption non comando
    private_filter = (filters.ChatType.PRIVATE & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND)
    app.add_handler(MessageHandler(private_filter, handlers.handle_privato), group=1)

    logger.info("Configurazione caricata. Bot in esecuzione")

    # ---------- CICLO DI VITA PTB ----------
    await app.initialize()   # prepara internals del bot
    await app.start()        # apre connessioni http/long polling
    try:
        # uso updater.start_polling (compat di ptb20) per ascoltare tutto
        await app.updater.start_polling(allowed_updates=Update.ALL_TYPES)
        # attendo fino a stop esterno (ctrl+c, signal ecc)
        await asyncio.Event().wait()
    finally:
        # spegnimento ordinato: stop updater, stop app, shutdown, e chiusura sessione http del sanitizer
        await app.updater.stop()
        await app.stop()
        await app.shutdown()
        await sanitizer.close()
        logger.info("Bot arrestato correttamente")


if __name__ == "__main__":
    # entrypoint classico: run dell'async main con gestione ctrl+c "umana"
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterruzione richiesta dall'utente (Ctrl+C)")
