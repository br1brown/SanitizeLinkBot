from __future__ import annotations

import json
import re
import asyncio
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, urljoin
import os
import aiohttp
import html
import hashlib

from collections.abc import Iterable

from telegram import (
    InlineQueryResultArticle,
    InputMessageContent,
    InputTextMessageContent,
    Update,
    MessageEntity,
    ReactionTypeEmoji,
)
from telegram.constants import ChatType, ParseMode

from telegram.ext import (
    CommandHandler,
    Application,
    ContextTypes,
    InlineQueryHandler,
    MessageHandler,
    filters,
)

import logging

# logging di base per ridurre il rumore delle librerie e avere un formato uniforme
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)
# logger principale del bot con nome leggibile
logger = logging.getLogger("sanitize-link-bot")


# classe che gestisce la configurazione dell applicazione in modo semplice e centralizzato
class AppConfig:
    """config generale del bot caricata da json con controllo chiavi minime

    questa classe non fa validazioni complesse sui tipi ma verifica la presenza delle chiavi richieste
    """

    # elenco delle chiavi minime attese per ogni sezione di configurazione
    _REQUIRED_KEYS = {
        "Output": {"show_title"},
        "Batch": {"max_concurrency"},
        "HTTP": {"connections_per_host", "max_redirects", "timeout_sec"},
    }

    def __init__(self, raw: dict) -> None:
        # lettura delle sezioni gia validate in load
        output_conf = raw["Output"]
        batch_conf = raw["Batch"]
        http_conf = raw["HTTP"]
        logging_conf = raw.get("Logging", {}) or {}

        # opzioni output
        self.show_title: bool = bool(output_conf["show_title"])

        # opzioni batch
        self.max_concurrency: int = int(batch_conf["max_concurrency"])

        # opzioni http di base e di sicurezza
        self.connections_per_host: int = int(http_conf["connections_per_host"])
        self.ttl_dns_cache: int = int(http_conf["ttl_dns_cache"])
        self.max_redirects: int = int(http_conf["max_redirects"])
        self.timeout_sec: int = int(http_conf["timeout_sec"])
        self.valida_link_post_pulizia: bool = bool(
            http_conf.get("valida_link_post_pulizia", True)
        )

        # livello di log opzionale normalizzato in stringa
        self.log_level: str | None = self._normalize_log_level(
            logging_conf.get("level")
        )

    @classmethod
    def load(cls, path: str) -> "AppConfig":
        """carica la configurazione da file json e verifica che le sezioni obbligatorie esistano

        in caso di mancanze lancia un errore con indicazioni esplicite per facilitare la correzione
        """
        logger.debug("caricamento configurazione %s", path)
        raw = load_json_file(path, required=True)

        missing_items: list[str] = []
        # controllo che ogni sezione abbia le chiavi richieste
        for section, keys in cls._REQUIRED_KEYS.items():
            if section not in raw or not isinstance(raw[section], dict):
                missing_items.append(f"- sezione mancante {section}")
                continue
            missing_keys = [k for k in keys if k not in raw[section]]
            if missing_keys:
                missing_items.append(f"- {section} chiavi mancanti {missing_keys}")

        if missing_items:
            # se mancano elementi blocco l avvio subito con un messaggio sintetico
            messaggio = "configurazione incompleta\n" + "\n".join(missing_items)
            logger.error(messaggio)
            raise RuntimeError(messaggio)

        conf = cls(raw)
        logger.info("configurazione applicativa caricata correttamente")
        logger.debug("dettagli configurazione %s", conf)
        return conf

    @staticmethod
    def _normalize_log_level(level_value) -> str | None:
        """accetta sia numeri sia stringhe e restituisce un nome livello valido per logging

        se il valore non e valido usa info come fallback
        """
        if not level_value:
            return None

        if isinstance(level_value, int):
            name = logging.getLevelName(level_value)
            if isinstance(name, str) and name.isupper():
                return name
            logging.warning("log level numerico non riconosciuto fallback a info")
            return "INFO"

        if isinstance(level_value, str):
            candidate = level_value.strip().upper()
            valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
            if candidate in valid:
                return candidate
            logging.warning("log level stringa non valido fallback a info")
            return "INFO"

        logging.warning("tipo log level non supportato fallback a info")
        return "INFO"

    def __repr__(self) -> str:
        # rappresentazione breve utile per i log di debug
        return (
            "AppConfig("
            f"show_title={self.show_title}, "
            f"max_redirects={self.max_redirects}, timeout_sec={self.timeout_sec}, "
            f"max_concurrency={self.max_concurrency}, connections_per_host={self.connections_per_host}, "
            ")"
        )


# classe che si occupa della pulizia degli url e della risoluzione dei redirect
class Sanitizer:
    """gestisce la pulizia degli url e opzionalmente estrae il titolo della pagina

    rimuove parametri di tracciamento secondo liste configurabili e valida il risultato
    """

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
        logger.debug("inizializzazione sanitizer con set di regole e whitelist domini")
        # normalizzazione delle liste di chiavi per confronti case insensitive
        self.EXACT_KEYS = set(map(str.lower, exact_keys or set()))
        self.PREFIX_KEYS = tuple(k.lower() for k in (prefix_keys or ()))
        self.ENDS_WITH = tuple(k.lower() for k in (ends_with or ()))
        self.FRAG_KEYS = tuple(k.lower() for k in (frag_keys or ()))
        self.DOMAIN_WHITELIST = {
            (k or "").lower(): v for k, v in (domain_whitelist or {}).items()
        }
        self.conf = conf
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """crea una sessione http condivisa con timeouts e limiti ragionevoli se non esiste gia

        una singola sessione riduce overhead e consente il riuso delle connessioni
        """
        if self._session is None or self._session.closed:
            logger.debug(
                "creazione di aiohttp clientsession con timeout e limit per host"
            )
            connector = aiohttp.TCPConnector(
                limit_per_host=(
                    self.conf.connections_per_host
                    if self.conf.connections_per_host > 0
                    else None
                ),
                ttl_dns_cache=self.conf.ttl_dns_cache,
            )
            timeout_conf = aiohttp.ClientTimeout(
                total=self.conf.timeout_sec, connect=self.conf.timeout_sec / 3
            )
            self._session = aiohttp.ClientSession(
                timeout=timeout_conf, connector=connector
            )
        return self._session

    async def close(self) -> None:
        """chiude la sessione http se ancora aperta per liberare risorse"""
        if self._session and not self._session.closed:
            logger.debug("chiusura sessione http")
            await self._session.close()
            self._session = None

    async def _check_url_ok(self, url: str) -> bool:
        """verifica che un url risponda con codice accettabile come esistenza

        considera validi codici 2xx e 3xx e tollera 401 e 403 per siti che bloccano i bot
        """
        try:
            session = await self._get_session()
            async with session.get(
                url,
                headers={"Range": "bytes=0-0"},
                allow_redirects=True,
                max_redirects=self.conf.max_redirects,
            ) as resp:
                if 200 <= resp.status < 300 or 300 <= resp.status < 400:
                    return True
                if resp.status in (401, 403) and url.startswith(
                    ("http://", "https://")
                ):
                    return True
                return False
        except Exception:
            return False

    def is_parametro_da_rimuovere(self, key: str) -> bool:
        """stabilisce se un parametro query va rimosso in base a match esatto prefisso o suffisso"""
        k = (key or "").lower()
        decision = (
            k in self.EXACT_KEYS
            or any(k.startswith(p) for p in self.PREFIX_KEYS)
            or any(k.endswith(s) for s in self.ENDS_WITH)
        )
        logger.debug("parametro %s marcato per rimozione %s", key, decision)
        return decision

    def _estrai_titolo(self, html_text: str) -> str | None:
        # estrae il contenuto del tag title e normalizza gli spazi
        m = re.search(
            r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL
        )
        if not m:
            return None
        r = m.group(1).strip()
        if not r:
            return None
        t = html.unescape(r)
        t = re.sub(r"[\u200B-\u200D\uFEFF]", "", t)
        t = t.replace("\u00a0", " ")
        t = re.sub(r"\s+", " ", t).strip()
        return t or None

    async def segui_redirect(self, url_iniziale: str):
        """segue redirect http meta refresh e javascript fino a un limite ragionevole

        restituisce l url finale e un eventuale titolo se presente
        """

        def _meta_refresh_target(html_text: str, base_url: str) -> str | None:
            m = re.search(
                r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\']\s*\d+\s*;\s*url\s*=\s*([^"\']+)["\']',
                html_text,
                re.IGNORECASE,
            )
            return urljoin(base_url, m.group(1).strip()) if m else None

        def _js_redirect_target(html_text: str, base_url: str) -> str | None:
            # prova pattern comuni usati per cambiare location via javascript
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

        current = url_iniziale
        redirects = 0
        title_norm = None

        session = await self._get_session()

        while redirects < self.conf.max_redirects:
            try:
                # tentativo veloce con head per leggere location senza scaricare il corpo
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
                # get parziale per intercettare meta refresh o redirect via script
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
                    if (
                        resp.status == 200
                        and resp.content_type
                        and resp.content_type.startswith("text/html")
                    ):
                        text = await resp.text(errors="ignore")
                        tgt = _meta_refresh_target(
                            text, current
                        ) or _js_redirect_target(text, current)
                        if tgt:
                            current = tgt
                            redirects += 1
                            continue
            except aiohttp.ClientError:
                break

            try:
                host = urlsplit(current).netloc.lower()
            except Exception:
                host = ""

            try:
                # ultimo tentativo con get completa utile su alcuni shortener
                async with session.get(current, allow_redirects=False) as resp:
                    if resp.status in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("Location")
                        if loc:
                            current = urljoin(current, loc)
                            redirects += 1
                            continue
                    if (
                        resp.status == 200
                        and resp.content_type
                        and resp.content_type.startswith("text/html")
                    ):
                        text_full = await resp.text(errors="ignore")
                        tgt = _meta_refresh_target(
                            text_full, current
                        ) or _js_redirect_target(text_full, current)
                        if tgt:
                            current = tgt
                            redirects += 1
                            continue
            except aiohttp.ClientError:
                break

            break

        if self.conf.show_title:
            try:
                async with session.get(current) as resp:
                    if (
                        resp.status == 200
                        and resp.content_type
                        and resp.content_type.startswith("text/html")
                    ):
                        text = await resp.text(errors="ignore")
                        title_norm = self._estrai_titolo(text)

            except Exception as e:
                logger.error(
                    "errore durante la sanificazione ritorno url grezzo %s",
                    e,
                )
        # rimozione di punteggiatura terminale eccessiva mantenendo parentesi bilanciate
        while current and current[-1] in ".,;:!?)”»’'\"" + "\u00a0":
            if current.endswith(")") and current.count("(") < current.count(")"):
                break
            current = current[:-1]

        return current, title_norm

    async def sanifica_url(self, raw_url: str) -> tuple[str, str | None]:
        """pulizia di un singolo url con gestione schema redirect query e frammenti"""
        if not raw_url:
            logger.debug("sanifica url url vuoto")
            return raw_url, None

        url_corrente = raw_url.strip()
        final_url = url_corrente
        final_title = ""

        if re.match(r"^(mailto:|tel:)", url_corrente, re.IGNORECASE):
            logger.debug("protocollo non web restituzione invariata")
            return url_corrente, None

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url_corrente):
            logger.debug("schema mancante aggiungo https")
            url_corrente = "https://" + url_corrente

        try:
            url_post_redirect, title = await self.segui_redirect(url_corrente)
            final_title = "" if not self.conf.show_title else (title or None)
        except Exception as e:
            logger.info(f"head fallita su {url_corrente} eseguo fallback get {e}")
            url_post_redirect, title = url_corrente, None

        try:
            parts = urlsplit(url_post_redirect)
            domain = re.sub(r"^www\\.", "", parts.netloc, flags=re.IGNORECASE).lower()
            logger.debug(
                "parsing url finale domain %s path %s query %s fragment %s",
                domain,
                parts.path,
                parts.query,
                parts.fragment,
            )

            if domain in self.DOMAIN_WHITELIST:
                return url_post_redirect, final_title

            original_params = parse_qsl(parts.query, keep_blank_values=True)
            filtered_params = [
                (k, v)
                for (k, v) in original_params
                if not self.is_parametro_da_rimuovere(k)
            ]
            new_query = urlencode(filtered_params, doseq=True)

            new_fragment = parts.fragment
            if new_fragment:
                frag = new_fragment.lstrip("#").lower()
                if self.FRAG_KEYS and any(
                    frag.startswith(pref) for pref in self.FRAG_KEYS
                ):
                    new_fragment = ""

            final_url = urlunsplit(
                (parts.scheme, parts.netloc, parts.path, new_query, new_fragment)
            )

            if self.conf.valida_link_post_pulizia and final_url != url_post_redirect:
                esito = await self._check_url_ok(final_url)
                if not esito:
                    logger.info(
                        "validazione fallita per url pulito restituisco url finale originale"
                    )
                    return url_post_redirect, final_title

            logger.debug("url pulito prodotto")
            return final_url, final_title
        except Exception as e:
            logger.error(
                "errore durante la sanificazione dettagliata ritorno url grezzo %s",
                e,
            )
        return url_post_redirect, final_title

    async def sanifica_in_batch(self, links: list[str]) -> list[tuple[str, str | None]]:
        """sanificazione di una lista di url con deduplica e limite di concorrenza"""
        normalized = [(u or "").strip() for u in links]

        from collections import OrderedDict

        unique_urls: "OrderedDict[str, list[int]]" = OrderedDict()
        for idx, url in enumerate(normalized):
            if url:
                unique_urls.setdefault(url, []).append(idx)

        if not unique_urls:
            return [("", None) for _ in normalized]

        semaforo_concorrenza = getattr(
            self,
            "_semaforo",
            asyncio.Semaphore(getattr(self.conf, "max_concurrency", 10)),
        )

        async def _one(url: str) -> tuple[str, str | None]:
            async with semaforo_concorrenza:
                try:
                    return await self.sanifica_url(url)
                except Exception:
                    return (url, None)

        tasks = {url: asyncio.create_task(_one(url)) for url in unique_urls}
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        resolved: dict[str, tuple[str, str | None]] = {}
        for url, risultato_task in zip(tasks.keys(), results):
            if isinstance(risultato_task, Exception):
                resolved[url] = (url, None)
            else:
                resolved[url] = risultato_task

        output_lista: list[tuple[str, str | None]] = [("", None) for _ in normalized]
        for url, idxs in unique_urls.items():
            for idx in idxs:
                output_lista[idx] = resolved[url]

        return output_lista


# classe che estrae gli url da messaggi di testo o da entita telegram
class GetterUrl:
    """trova url nel testo oppure legge url direttamente dalle entita telegram"""

    # regex per intercettare url comuni evitando menzioni ed email
    _URL_REGEX = re.compile(
        r"""
        (?<![\w@])
        (?:
            https?://
          | www\.
          | (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})
        )
        [^\s<>"'“”()]+
        (?:\([^\s<>"'“”()]*\)[^\s<>"'“”()]*)*
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    @classmethod
    def estrai_urls(cls, text: str | None) -> list[str]:
        """estrae tutti gli url presenti in una stringa usando la regex di classe"""
        if not text:
            return []
        lista_url = [m.group(0) for m in cls._URL_REGEX.finditer(text)]
        logger.debug("estrai urls trovati %d url nel testo", len(lista_url))
        return lista_url

    @staticmethod
    def url_da_tg(
        text: str | None, entities: Iterable[MessageEntity] | None
    ) -> list[str]:
        """estrae url direttamente dalle entita telegram sia url sia text link"""
        lista_url: list[str] = []
        if not text or not entities:
            return lista_url
        for ent in entities:
            if ent.type in {MessageEntity.URL, MessageEntity.TEXT_LINK}:
                if ent.type == MessageEntity.URL:
                    url = text[ent.offset : ent.offset + ent.length]
                    lista_url.append(url)
                elif ent.type == MessageEntity.TEXT_LINK and ent.url:
                    lista_url.append(ent.url)
        if lista_url:
            logger.debug("url da tg trovati %d url nelle entita", len(lista_url))
        return lista_url

    @classmethod
    def url_da_msg(cls, messaggio) -> list[str]:
        # prima prova a leggere le entita telegram con priorita
        lista_url = []
        lista_url.extend(cls.url_da_tg(messaggio.text, messaggio.entities))
        lista_url.extend(cls.url_da_tg(messaggio.caption, messaggio.caption_entities))
        if lista_url:
            return list(dict.fromkeys(lista_url))

        # in assenza di entita usa la regex su testo e caption
        trovati_regex = []
        if messaggio.text:
            trovati_regex.extend(cls.estrai_urls(messaggio.text))
        if messaggio.caption:
            trovati_regex.extend(cls.estrai_urls(messaggio.caption))
        return list(dict.fromkeys(trovati_regex))


# classe che prepara le risposte pronte per telegram come testo semplice
class TelegramIO:
    """costruisce l output da inviare su telegram con titolo opzionale e url pulito"""

    @staticmethod
    def _neutralizza(s: str) -> str:
        """inserisce caratteri zero width per evitare menzioni hashtag o comandi involontari a inizio parola"""
        if not s:
            return s
        s = re.sub(r"(?<!\S)@(\w+)", "@\u2060\\g<1>", s)
        s = re.sub(r"(?<!\S)#(\w+)", "#\u2060\\g<1>", s)
        s = re.sub(r"(?<!\S)/(\w+)", "/\u2060\\g<1>", s)
        return s

    @staticmethod
    def get_output(
        lista_link_puliti: list[tuple[str, str | None]], conf: AppConfig
    ) -> str:
        """compone il testo finale con blocchi separati opzionalmente con titolo in blockquote"""
        if not lista_link_puliti:
            logger.debug("get output nessun link pulito")
            return "nessun collegamento rilevato"

        blocks: list[str] = []
        for url, title in lista_link_puliti:
            pieces: list[str] = []

            if conf.show_title and title:
                t = html.escape(TelegramIO._neutralizza(title))
                pieces.append(f"<blockquote>{t}</blockquote>")

            pieces.append(html.escape(url))
            blocks.append("\n".join(pieces))

        output = "\n\n".join(blocks)
        logger.debug("get output testo pronto con %d blocchi", len(blocks))
        return output


# classe che orchestra la logica degli handler telegram e coordina sanitizer e io
class TelegramHandlers:
    """gestisce gli update di telegram e la preparazione delle risposte"""

    def __init__(self, sanitizer: Sanitizer, conf: AppConfig) -> None:
        # mantengo riferimenti condivisi a sanitizer e configurazione
        self.sanitizer = sanitizer
        self.conf = conf

    async def _sanifica_e_rispondi(
        self, target, lista_link_rilevati: list[str]
    ) -> tuple[int, int | None]:
        """pulisce i link in parallelo costruisce il testo e risponde nel thread del messaggio"""

        lista_link_puliti = await self.sanitizer.sanifica_in_batch(lista_link_rilevati)

        text = TelegramIO.get_output(lista_link_puliti, self.conf)

        reply = await target.reply_text(
            text,
            disable_web_page_preview=len(lista_link_puliti) > 1,
            parse_mode=ParseMode.HTML,
        )
        reply_id = getattr(reply, "message_id", None)

        try:
            await self._react(target, None)
        except Exception:
            pass

        return len(lista_link_puliti), reply_id

    @staticmethod
    def is_menzionato(messaggio, context: ContextTypes.DEFAULT_TYPE) -> bool:
        """verifica se il messaggio contiene una menzione esplicita al bot"""
        bot_username = (context.bot.username or "").lower()
        bot_id = context.bot.id

        def _check(text: str | None, entities: Iterable[MessageEntity] | None) -> bool:
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
            return f"@{bot_username}" in text.lower()

        return _check(messaggio.text, messaggio.entities) or _check(
            messaggio.caption, messaggio.caption_entities
        )

    async def _react(self, message, emoji: str | None) -> bool:
        """imposta o rimuove una reaction sul messaggio in modo silenzioso"""
        try:
            if emoji:
                await message.set_reaction([ReactionTypeEmoji(emoji)])
            else:
                await message.set_reaction([])
            return True
        except Exception as e:
            logger.debug("impossibile impostare reaction %r %s", emoji, e)
            return False

    async def presaInCarico(self, messaggio) -> list[str]:
        """mette una reaction di presa in carico ed estrae i link dal messaggio"""
        await self._react(messaggio, "👀")

        lista_link_rilevati = GetterUrl.url_da_msg(messaggio)

        if not lista_link_rilevati:
            esito = await self._react(messaggio, "❌")
            if not esito:
                esito = await self._react(messaggio, "👎")
            if not esito:
                await self._react(messaggio, None)
            return []

        return lista_link_rilevati

    async def handle_gruppi(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """gestisce le menzioni al bot nei gruppi tramite risposta al messaggio con i link"""

        messaggio = update.effective_message
        if not messaggio or not self.is_menzionato(messaggio, context):
            logger.debug("handle gruppi ignorato nessuna menzione o messaggio nullo")
            return
        if not messaggio.reply_to_message:
            logger.debug("handle gruppi manca reply to message")
            return

        target = messaggio.reply_to_message
        lista_link_rilevati = await self.presaInCarico(target)
        user = update.effective_user
        chat = update.effective_chat

        if not lista_link_rilevati:
            logger.info(
                "GRUPPO: menzione da %s username %s in %s puliti zero",
                getattr(user, "full_name", "n a"),
                getattr(user, "username", "n a"),
                getattr(chat, "title", "n a"),
            )
            return

        puliti, reply_id = await self._sanifica_e_rispondi(target, lista_link_rilevati)
        logger.info(
            "GRUPPO: menzione da %s username %s in %s puliti %d reply %s",
            getattr(user, "full_name", "n a"),
            getattr(user, "username", "n a"),
            getattr(chat, "title", "n a"),
            puliti,
            reply_id,
        )

    async def handle_privato(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """gestisce la chat privata pulendo i link presenti nel messaggio"""
        if update.effective_chat.type != ChatType.PRIVATE:
            return

        messaggio = update.effective_message
        lista_link_rilevati = await self.presaInCarico(messaggio)
        user = update.effective_user

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

        puliti, reply_id = await self._sanifica_e_rispondi(
            messaggio, lista_link_rilevati
        )
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
        """gestisce le inline query pulendo solo il primo url digitato"""
        inline_query = update.inline_query
        if not inline_query:
            return

        testo_query = (inline_query.query or "").strip()
        # qui estraiamo tutti i link che ci sono nel testo

        lista_url = GetterUrl.estrai_urls(
            testo_query
        )  # estrae tutti i link presenti nel testo digitato inline
        if not lista_url:
            return

        raw = lista_url[0]  # SOLO il primo link
        clean_url, title = await self.sanitizer.sanifica_url(
            raw
        )  # usa la tua sanificazione singola

        rid = hashlib.md5(clean_url.encode("utf-8")).hexdigest()
        result = InlineQueryResultArticle(
            id=rid,
            title=title or "URL",
            description=clean_url,
            input_message_content=InputTextMessageContent(
                (title or "") + "\n" + clean_url
            ),
        )

        await inline_query.answer([result], cache_time=0, is_personal=True)
        
        user = inline_query.from_user if hasattr(inline_query, "from_user") else None
        logger.info(
            "INLINE: da '%s' (@%s, id=%s) — clean='%s', result_id=%s",
            getattr(user, "full_name", "n/a"),
            getattr(user, "username", "n/a"),
            getattr(user, "id", "n/a"),
            len(lista_url),
            rid,
        )

    async def cmd_start(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """risponde con un messaggio di benvenuto e una breve istruzione di uso"""
        user = update.effective_user
        first_name = user.first_name if user and user.first_name else "utente"
        text = render_from_file("start", first_name=first_name)
        await update.message.reply_text(
            text, parse_mode=ParseMode.HTML, disable_web_page_preview=True
        )

    async def cmd_help(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """mostra un aiuto rapido su come usare il bot in chat privata e nei gruppi"""
        bot_username = context.bot.username or (await context.bot.get_me()).username
        mention_bot = f"@{bot_username}" if bot_username else "@.."
        text = render_from_file("help", mention_bot=mention_bot)
        await update.message.reply_text(
            text, parse_mode=ParseMode.HTML, disable_web_page_preview=True
        )


# ---------- percorsi config ----------
# percorsi di base usati per caricare file di configurazione
BASE_DIR = (
    os.path.dirname(os.path.abspath(__file__))
    if "__file__" in globals()
    else os.getcwd()
)
KEYS_PATH = os.path.join(BASE_DIR, "keys.json")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
TOKEN_PATH = os.path.join(BASE_DIR, "token.txt")


# caricamento di template html con sostituzione semplice tramite format
def render_from_file(filename: str, **ctx) -> str:
    """carica un file da templates con estensione html e applica format sui placeholder"""
    path = os.path.join(BASE_DIR, filename + ".html")
    with open(path, "r", encoding="utf-8") as f:
        s = f.read()
    # escape html solo sui valori stringa per sicurezza
    safe_ctx = {
        k: (html.escape(v) if isinstance(v, str) else v) for k, v in ctx.items()
    }
    return s.format(**safe_ctx)


# lettura di file json con messaggi di errore chiari e orientati all utente
def load_json_file(path: str, *, required: bool = False) -> dict:
    """
    carica un file json e restituisce un dict
    se required e true e il file manca lancia un errore con indicazione esplicita
    se il json non e un oggetto dict lancia un errore descrittivo
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as e:
        if required:
            logger.error("File di configurazione richiesto non trovato: %s", path)
            raise RuntimeError(f"File richiesto non trovato: {path}") from e
        logger.info(
            "File opzionale non trovato: %s (uso valori vuoti/di default)", path
        )
        return {}
    except json.JSONDecodeError as e:
        logger.error("Errore nel parsing JSON di %s: %s", path, e)
        raise RuntimeError(f"Errore nel parsing di {path}: {e}") from e

    if not isinstance(data, dict):
        logger.error("Il file %s non contiene un oggetto JSON (dict).", path)
        raise RuntimeError(
            f"Contenuto non valido in {path}: atteso un oggetto JSON (dict)"
        )

    logger.debug("Caricato JSON da %s (chiavi: %s)", path, list(data.keys()))
    return data


# caricamento della configurazione obbligatoria e delle chiavi opzionali
CONFIG = AppConfig.load(CONFIG_PATH)
KEYS = load_json_file(KEYS_PATH)

# definizione del livello di log finale usando prima config poi variabile di ambiente e poi default
_env_level = os.getenv("LOG_LEVEL", "").upper() or None
_final_level = (
    CONFIG.log_level or _env_level or "INFO"
)  # priorita config poi env poi default info
try:
    logger.setLevel(getattr(logging, _final_level, logging.INFO))
except Exception:
    pass


# lettura del token telegram da variabile di ambiente o da file di fallback
def get_telegram_token() -> str:
    """restituisce il token del bot leggendo prima da variabile e poi da file di testo"""
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
        logger.error(
            "Token mancante. Impostare TELEGRAM_BOT_TOKEN o creare 'token.txt'"
        )
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN o 'token.txt'") from e


# punto di ingresso asincrono che costruisce l applicazione registra gli handler e avvia il polling
async def main() -> None:
    """avvia il bot preparando application e ciclo di polling con spegnimento ordinato"""
    try:
        # prendo il token e costruisco l'app ptb
        telegram_token = get_telegram_token()
        # builder pattern come in molte api c sharp
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

    # ---------- registrazione handler ----------
    # registrazione degli handler in gruppi per ordine di esecuzione prevedibile
    app.add_handler(CommandHandler("start", handlers.cmd_start), group=0)
    app.add_handler(CommandHandler("help", handlers.cmd_help), group=0)

    # gruppi: testo/caption non comando + tipo group/supergroup → gestisco menzioni con reply
    group_filter = (
        filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND
    )
    app.add_handler(MessageHandler(group_filter, handlers.handle_gruppi), group=1)

    # privato: testo/caption non comando
    private_filter = (
        filters.ChatType.PRIVATE & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND
    )
    app.add_handler(MessageHandler(private_filter, handlers.handle_privato), group=1)

    app.add_handler(InlineQueryHandler(handlers.handle_inline), group=0)

    logger.info("configurazione caricata bot in esecuzione")

    # ciclo di vita dell applicazione telegram con fase di start polling e shutdown pulito
    await app.initialize()  # prepara internals del bot
    await app.start()  # apre connessioni http/long polling
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
    # esecuzione del main asincrono con gestione di ctrl c
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterruzione richiesta dall'utente (Ctrl+C)")
