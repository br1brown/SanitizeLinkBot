from __future__ import annotations

# sanitizer.py — pulizia URL, follow redirect, validazione post-pulizia, cache LRU.
# Flusso: sanitize_batch → sanitize_url → _sanitize_url_impl → do_redirect / _fetch_signals

from .url_translator import UrlTranslator
from .chat_prefs import SanitizerOpts
from .clearurls_loader import ClearUrlsLoader
from .utils import logger
from .urlscan_client import UrlScanClient
from collections import OrderedDict
from email.message import Message as _EmailMessage

import re
import html
import asyncio
from urllib.parse import (
    urlsplit,
    urlunsplit,
    parse_qsl,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)
import hashlib
from dataclasses import dataclass
from typing import Optional

import ssl
import os
import certifi
import aiohttp

from .app_config import AppConfig

# Regex compilate a livello di modulo (non dentro le funzioni) per non ricompilare
# l'automa ad ogni chiamata — re.compile() costa e _fetch_signals è chiamata spesso.
# I pattern _B operano su bytes (prima della decodifica), gli altri su str (dopo).
_RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_RE_CANONICAL = re.compile(
    r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']', re.IGNORECASE
)
_RE_OGURL = re.compile(
    r'<meta[^>]+property=["\']og:url["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_RE_OGTITLE = re.compile(
    r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_RE_TWTITLE = re.compile(
    r'<meta[^>]+name=["\']twitter:title["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_RE_META_REFRESH = re.compile(
    r'<meta\s+http-equiv=["\']refresh["\']\s+content=["\']\s*\d+\s*;\s*url\s*=\s*([^"\']+)["\']',
    re.IGNORECASE,
)
# Redirect JavaScript: copre i pattern più comuni nei link shortener e landing page.
# Non eseguiamo JS (troppo pesante), ma questi pattern appaiono quasi sempre come
# stringhe letterali nel sorgente e sono leggibili con una regex semplice.
# Pattern coperti:
#   window.location = "https://..."          (assegnazione diretta)
#   window.location.href = "https://..."     (assegnazione a .href)
#   window.location.replace("https://...")   (replace: non lascia history)
#   location.href = "https://..."            (senza window.)
#   location.replace("https://...")
# Non coperti: redirect costruiti dinamicamente (es. var url = base + path; location.href = url)
_RE_JS_REDIRECT = re.compile(
    r"""(?:window\.)?location(?:\.href)?\s*=\s*["'](?P<url>https?://[^"']+)["']"""
    r"""|(?:window\.)?location\.replace\(\s*["'](?P<url2>https?://[^"']+)["']\s*\)""",
    re.IGNORECASE,
)
_RE_HEAD_CLOSE_B = re.compile(
    rb"</head\b[^>]*>", re.IGNORECASE
)  # segnale di stop lettura
_RE_TITLE_CLOSE_B = re.compile(
    rb"</title\s*>", re.IGNORECASE
)  # stop alternativo (solo show_title)
_RE_META_CHARSET_B = re.compile(
    rb'<meta[^>]+charset=["\']?\s*([a-zA-Z0-9_\-]+)\s*["\'>]', re.IGNORECASE
)

# Caratteri zero-width (U+200B..200D, FEFF) usati da alcuni siti per fingerprinting:
# pre-compilata per non ricreare l'automa in _normalize_title.
_RE_ZERO_WIDTH = re.compile(r"[\u200B-\u200D\uFEFF]")

# Domini noti che servono una pagina di consenso/interstitial GDPR anziché la destinazione reale.
# L'URL reale si trova nel parametro "continue=" della query string.
# Esempio: consent.google.com/m?continue=https://maps.google.com/maps?q=...
_CONSENT_DOMAINS = frozenset(
    {
        "consent.google.com",  # pagina consenso cookie Google (EU/GDPR)
    }
)


def _extract_consent_continue(url: str) -> str | None:
    """Se l'URL è una pagina di consenso nota, restituisce l'URL reale dal parametro continue=.

    Restituisce None se l'URL non è un interstitial di consenso, così il chiamante
    può trattare None come "nessuna azione richiesta".
    """
    try:
        parts = urlsplit(url)
        if parts.netloc.lower() not in _CONSENT_DOMAINS:
            return None
        for param_key, param_val in parse_qsl(parts.query):
            if param_key == "continue" and param_val.startswith(
                ("http://", "https://")
            ):
                return param_val
    except Exception:
        pass
    return None


# PageSignals raccoglie i "segnali" di una pagina per capire se due URL puntano
# allo stesso contenuto. Usato nella validazione post-pulizia: se dopo aver rimosso
# i parametri i segnali corrispondono, la pulizia era sicura; se no, i parametri
# cambiavano il contenuto e il bot restituisce l'URL originale non pulito.
@dataclass
class PageSignals:
    final_url: str  # URL finale dopo tutti i redirect
    url_path: str  # final_url normalizzato (no query, no fragment, lowercase)
    status: int  # codice HTTP risposta
    content_type: str  # MIME type (es. "text/html")
    etag: Optional[
        str
    ]  # header ETag: cambia se il file cambia — segnale più affidabile
    lastmod: Optional[str]  # header Last-Modified
    canonical: Optional[
        str
    ]  # <link rel="canonical"> — la pagina dichiara il suo URL "vero"
    og_url: Optional[str]  # <meta property="og:url"> — proxy di canonical su molti CMS
    title: Optional[str]  # titolo pagina (<title>, og:title, twitter:title)
    chunk_hash: Optional[str]  # SHA-256 dei primi N byte HTML — "stesso contenuto"

    @staticmethod
    def _ok(status) -> bool:
        # 401/403 inclusi perché confermano che la risorsa esiste (solo accesso negato)
        return 200 <= status < 300 or 300 <= status < 400 or status in (401, 403)

    def is_url_ok(self) -> bool:
        return self._ok(self.status) and self.final_url.startswith(
            ("http://", "https://")
        )

    @staticmethod
    def _norm_etag(etag_raw: str | None) -> str | None:
        """Rimuove prefisso W/ (weak ETag) e virgolette per confronti affidabili."""
        if not etag_raw:
            return None
        etag_raw = etag_raw.strip()
        if etag_raw.startswith("W/"):
            etag_raw = etag_raw[2:].strip()
        if len(etag_raw) >= 2 and (
            (etag_raw[0] == etag_raw[-1] == '"') or (etag_raw[0] == etag_raw[-1] == "'")
        ):
            etag_raw = etag_raw[1:-1]
        return etag_raw or None

    @staticmethod
    def _same_html_type(ct_a: str | None, ct_b: str | None) -> bool:
        """text/html e application/xhtml+xml sono equivalenti per i nostri scopi."""
        if not ct_a or not ct_b:
            return True  # beneficio del dubbio se uno dei due manca
        ct_a = ct_a.lower().split(";")[0].strip()
        ct_b = ct_b.lower().split(";")[0].strip()
        htmlish = ("text/html", "application/xhtml+xml")
        return (ct_a in htmlish and ct_b in htmlish) or (ct_a == ct_b)

    @staticmethod
    def _normalize_url_path(url: str | None) -> str | None:
        """URL normalizzato per confronti stabili: lowercase, porta default omessa, no trailing slash, no query/fragment."""
        if not url:
            return None
        parsato = urlparse(url)
        scheme = (parsato.scheme or "http").lower()
        host = (parsato.hostname or "").lower()
        port = parsato.port or ""
        # La porta di default non aggiunge informazione e varia tra risposte dello stesso server
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = ""
        netloc = host if not port else f"{host}:{port}"
        path = parsato.path or "/"
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        # query="" e fragment="" escludono parametri dal confronto — ci interessano solo scheme+host+path
        return urlunparse((scheme, netloc, path, "", "", ""))

    @staticmethod
    def _no_content(
        url: str, status: int, content_type: str, etag, lastmod
    ) -> "PageSignals":
        """PageSignals senza corpo HTML: per risposte non-2xx o file troppo grandi da scaricare."""
        return PageSignals(
            final_url=url,
            url_path=PageSignals._normalize_url_path(url),
            status=status,
            content_type=content_type,
            etag=etag,
            lastmod=lastmod,
            canonical=None,
            og_url=None,
            title=None,
            chunk_hash=None,
        )

    def equivalent_to(
        self, other: Optional["PageSignals"], check_url: bool = False
    ) -> bool:
        """True se i due PageSignals indicano la stessa pagina.

        Gerarchia dal più al meno affidabile:
          - ETag identico — il server stesso certifica "stesso contenuto"
          - Last-Modified uguale + stesso path — file non cambiato sulla stessa risorsa
          - canonical/og:url identico — la pagina dichiara il suo URL canonico
          - Hash HTML identico + stesso Content-Type — stesso contenuto byte per byte
          - Titolo identico + stesso path — segnale debole (molte pagine diversa hanno lo stesso titolo)
          - Path identico (solo se check_url=True) — ultimo fallback nella validazione post-pulizia
        """
        if not self or not other:
            return False

        etag_self = PageSignals._norm_etag(self.etag)
        etag_otr = PageSignals._norm_etag(other.etag)
        if etag_self and etag_otr and etag_self == etag_otr:
            return True

        # Last-Modified da solo non basta: due pagine diverse sullo stesso server
        # potrebbero avere lo stesso timestamp; richiediamo anche il path uguale
        if (
            self.lastmod
            and other.lastmod
            and self.lastmod == other.lastmod
            and PageSignals._normalize_url_path(self.url_path)
            == PageSignals._normalize_url_path(other.url_path)
        ):
            return True

        # Se non c'è canonical, usiamo og:url come proxy — molti CMS lo impostano uguale
        canonical_a = PageSignals._normalize_url_path(self.canonical or self.og_url)
        canonical_b = PageSignals._normalize_url_path(other.canonical or other.og_url)
        if canonical_a and canonical_b and canonical_a == canonical_b:
            return True

        if (
            self.chunk_hash
            and other.chunk_hash
            and self.chunk_hash == other.chunk_hash
            and self._same_html_type(self.content_type, other.content_type)
        ):
            return True

        if (
            self.title
            and other.title
            and self.title == other.title
            and PageSignals._normalize_url_path(self.url_path)
            == PageSignals._normalize_url_path(other.url_path)
        ):
            return True

        if check_url:
            return PageSignals._normalize_url_path(
                self.url_path
            ) == PageSignals._normalize_url_path(other.url_path)

        return False

    @staticmethod
    def _normalize_title(raw: str | None) -> str | None:
        """Pulisce il titolo per confronti affidabili: unescape HTML, rimozione zero-width chars, collasso spazi."""
        if not raw:
            return None
        txt = html.unescape(raw.strip())
        # Caratteri zero-width (U+200B..200D, FEFF) usati da alcuni siti per fingerprinting:
        # due titoli identici a occhio nudo potrebbero differire nel confronto stringa
        txt = _RE_ZERO_WIDTH.sub("", txt)
        txt = txt.replace("\u00a0", " ")  # non-breaking space → spazio normale
        txt = re.sub(r"\s+", " ", txt).strip()
        return txt or None

    @staticmethod
    def _pick_charset(raw_ct_header: str | None) -> str:
        """Estrae charset da Content-Type con email.Message invece di split manuale.
        email.Message gestisce correttamente tutte le varianti RFC 2045:
        'text/html; charset=utf-8', 'text/html;charset=\"UTF-8\"', ecc.
        Default: utf-8 (standard del web moderno, funziona sulla maggior parte delle pagine).
        """
        msg = _EmailMessage()
        msg["content-type"] = raw_ct_header or ""
        return msg.get_param("charset") or "utf-8"

    @staticmethod
    async def _fetch_signals(
        url: str, sanita: "Sanitizer", opts: SanitizerOpts, _depth: int = 0
    ) -> "PageSignals | None":
        """Richiesta HTTP leggera che raccoglie i segnali della pagina.

        Legge solo i byte necessari: ci fermiamo a </head> (o </title>) per non
        scaricare l'intera pagina — canonical, titolo e meta-refresh sono tutti
        nella <head>. I redirect HTTP 3xx sono già seguiti da aiohttp in automatico.
        _depth è interno: conta gli hop da meta-refresh, massimo 1 per evitare loop.
        """
        MAX_BYTES = 512 * 1024  # oltre 512KB non scarichiamo (PDF, video, ecc.)

        canonical_url: Optional[str] = None
        og_url: Optional[str] = None
        titolo_pagina: Optional[str] = None

        # User-Agent da browser reale: alcuni siti rispondono 403 agli user-agent non riconosciuti,
        # il che farebbe fallire la validazione pur non essendo un problema dell'URL pulito
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/126.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
        }

        if opts.show_title:
            # Titolo richiesto: leggiamo fino a 1MB e ci fermiamo a </title>.
            # Non mandiamo Range perché non sappiamo a che offset si troverà il titolo.
            max_bytes = 1_048_576
            chunk_size = 16_384
        else:
            # Solo validazione: 128KB bastano quasi sempre per trovare </head>
            headers["Range"] = "bytes=0-131071"
            max_bytes = 131_072
            chunk_size = 8_192

        try:
            session = await sanita._get_session()
            async with session.get(
                url, headers=headers, timeout=sanita.conf.timeout_sec
            ) as resp:

                raw_cl = resp.headers.get("Content-Length")
                raw_ct = resp.headers.get("Content-Type")
                content_type = (raw_ct or "").split(";")[0].strip().lower()
                final_url = str(
                    resp.url
                )  # URL finale dopo i redirect HTTP seguiti da aiohttp

                if not (200 <= resp.status < 300):
                    return PageSignals._no_content(
                        final_url,
                        resp.status,
                        content_type,
                        resp.headers.get("ETag"),
                        resp.headers.get("Last-Modified"),
                    )

                # Content-Length dichiarato troppo grande: evitiamo di aprire lo stream
                if raw_cl:
                    try:
                        if int(raw_cl) > MAX_BYTES:
                            return PageSignals._no_content(
                                final_url,
                                resp.status,
                                content_type,
                                resp.headers.get("ETag"),
                                resp.headers.get("Last-Modified"),
                            )
                    except (ValueError, TypeError):
                        pass  # Content-Length malformato: ignoriamo e proviamo comunque

                # Accumuliamo i chunk in una lista: concatenazione b"" += b"" in loop
                # è O(n^2) in alcune versioni di Python/OS, .join() è sempre O(n).
                chunks = []
                bytes_accumulated = 0
                async for blocco in resp.content.iter_chunked(chunk_size):
                    chunks.append(blocco)
                    bytes_accumulated += len(blocco)

                    # Stop quando troviamo il tag di chiusura o superiamo il limite
                    stop_pattern = (
                        _RE_TITLE_CLOSE_B if opts.show_title else _RE_HEAD_CLOSE_B
                    )
                    # Uniamo solo l'ultimo pezzo per il check per non rifare il join ad ogni iterazione
                    if stop_pattern.search(blocco) or bytes_accumulated >= max_bytes:
                        break

                primo_chunk = b"".join(chunks)

                # Charset: prima lo leggiamo dall'header HTTP, poi lo sovrascriviamo
                # con quello dichiarato nel <meta charset>  se presente (più affidabile)
                charset = PageSignals._pick_charset(raw_ct)

                if "html" in content_type and primo_chunk:
                    meta_cs = _RE_META_CHARSET_B.search(primo_chunk[:8192])
                    if meta_cs:
                        try:
                            cand = meta_cs.group(1).decode("ascii", "ignore").lower()
                            if cand:
                                charset = cand
                        except Exception:
                            pass

                    # Tre tentativi di decodifica in ordine di affidabilità:
                    # 1. charset dichiarato strict — se fallisce, il file è mal-dichiarato
                    # 2. UTF-8 ignore — salta byte invalidi ma recupera il testo
                    # 3. latin-1 — non fallisce mai (mappa ogni byte 0-255)
                    try:
                        head_text = primo_chunk.decode(charset, errors="strict")
                    except Exception:
                        try:
                            head_text = primo_chunk.decode("utf-8", errors="ignore")
                        except Exception:
                            head_text = primo_chunk.decode("latin-1", errors="ignore")

                    match_canonical = _RE_CANONICAL.search(head_text)
                    if match_canonical:
                        # urljoin risolve href relativi (es. "/page" → "https://example.com/page")
                        canonical_url = urljoin(
                            final_url, match_canonical.group(1).strip()
                        )

                    match_ogurl = _RE_OGURL.search(head_text)
                    if match_ogurl:
                        og_url = urljoin(final_url, match_ogurl.group(1).strip())

                    # Titolo: <title> è preferito; og:title e twitter:title sono fallback
                    # per siti che popolano il <title> via JavaScript (vuoto nel HTML statico)
                    for title_pattern in (_RE_TITLE, _RE_OGTITLE, _RE_TWTITLE):
                        if titolo_pagina:
                            break
                        match_title = title_pattern.search(head_text)
                        if match_title:
                            titolo_pagina = PageSignals._normalize_title(
                                match_title.group(1)
                            )

                    # Meta-refresh e redirect JavaScript: aiohttp non li segue (non è un browser).
                    # Stesso guard _depth == 0: massimo 1 hop aggiuntivo per evitare loop.
                    # Meta-refresh ha priorità perché è più affidabile (standard HTML);
                    # il JS è fallback per link shortener e landing page che non usano meta-refresh.
                    if _depth == 0:
                        match_refresh = _RE_META_REFRESH.search(head_text)
                        if match_refresh and match_refresh.group(1):
                            target = urljoin(final_url, match_refresh.group(1).strip())
                            return await PageSignals._fetch_signals(
                                target, sanita, opts, _depth=1
                            )

                        # Fallback JS: cerchiamo solo se il meta-refresh non ha trovato nulla
                        match_js = _RE_JS_REDIRECT.search(head_text)
                        if match_js:
                            # La regex ha due named group alternativi (url / url2): uno dei due sarà None
                            js_target = match_js.group("url") or match_js.group("url2")
                            if js_target:
                                return await PageSignals._fetch_signals(
                                    js_target.strip(), sanita, opts, _depth=1
                                )

                if resp.status >= 400:
                    titolo_pagina = (
                        None  # titoli di pagine di errore non sono utili all'utente
                    )

                return PageSignals(
                    final_url=final_url,
                    url_path=PageSignals._normalize_url_path(final_url),
                    status=resp.status,
                    content_type=content_type,
                    etag=resp.headers.get("ETag"),
                    lastmod=resp.headers.get("Last-Modified"),
                    canonical=canonical_url,
                    og_url=og_url,
                    title=titolo_pagina,
                    # Hash dei primi N byte: stessi byte = stessa pagina con buona probabilità
                    chunk_hash=(
                        hashlib.sha256(primo_chunk).hexdigest() if primo_chunk else None
                    ),
                )

        except Exception:
            return (
                None  # errore di rete (timeout, SSL, DNS): il chiamante usa il fallback
            )


class Sanitizer:
    """Orchestratore della pulizia URL: rimozione tracker, redirect, validazione, cache LRU."""

    def __init__(
        self,
        *,
        exact_keys: set[str],
        prefix_keys: tuple[str, ...],
        ends_with: tuple[str, ...],
        frag_keys: tuple[str, ...],
        domain_whitelist: list[str] | None = None,
        conf: AppConfig,
        clearurls: (
            ClearUrlsLoader | None
        ) = None,  # se None il bot funziona con solo keys.json
    ) -> None:

        logger.debug(
            "Sanitizer inizializzato con i set di regole e la whitelist dei domini"
        )

        # Lowercase immediato: i nomi dei parametri URL sono case-insensitive (RFC 3986)
        self.EXACT_KEYS = set(map(str.lower, exact_keys or set()))

        # Consolidamento regex per PREFIX e SUFFIX: un solo match vs N startswith()
        prefixes = [re.escape(k.lower()) for k in (prefix_keys or ())]
        self._PREFIX_RE = re.compile(f"^(?:{'|'.join(prefixes)})") if prefixes else None

        suffixes = [re.escape(k.lower()) for k in (ends_with or ())]
        self._SUFFIX_RE = re.compile(f"(?:{'|'.join(suffixes)})$") if suffixes else None

        self.FRAG_KEYS = tuple(rule_key.lower() for rule_key in (frag_keys or ()))
        self.DOMAIN_WHITELIST = set(domain_whitelist or [])
        self.conf = conf
        self._clearurls = (
            clearurls  # nessun lock necessario: il loader usa swap atomico internamente
        )

        # Sessione e SSL context creati lazy al primo uso: in __init__ il loop asyncio
        # potrebbe non essere ancora attivo (python-telegram-bot lo gestisce internamente)
        self._session: aiohttp.ClientSession | None = None
        self._ssl_ctx: ssl.SSLContext | None = None

        # LRU con OrderedDict: pop + reinserimento sposta l'elemento in coda (MRU),
        # popitem(last=False) rimuove il più vecchio. functools.lru_cache non funziona
        # su metodi async e non supporta la chiave composita url+opzioni che ci serve.
        self._cache_lru: OrderedDict[str, tuple[str, str | None]] = OrderedDict()
        self._cache_maxlen = conf.cache_max_size

        # Semaforo: senza limite un batch di 50 URL lancerebbe 50 richieste simultanee
        self._semaforo = asyncio.Semaphore(conf.max_concurrency)

        self.TRADUCI_URL = UrlTranslator()
        self.urlscan: UrlScanClient | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Sessione HTTP condivisa con SSLContext esplicito (certifi).
        certifi invece del bundle OS: il bundle di sistema è assente su Docker Alpine
        e varia da macchina a macchina — certifi è identico ovunque.
        """
        if self._session is None or self._session.closed:
            if self._ssl_ctx is None:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.load_verify_locations(cafile=certifi.where())
                # Bundle CA aggiuntivo per ambienti aziendali con proxy HTTPS intercettante
                extra = os.getenv("EXTRA_CA_BUNDLE")
                if extra and os.path.exists(extra):
                    ctx.load_verify_locations(cafile=extra)
                self._ssl_ctx = ctx

            connector = aiohttp.TCPConnector(
                limit_per_host=(
                    self.conf.connections_per_host
                    if self.conf.connections_per_host > 0
                    else None
                ),
                ssl=self._ssl_ctx,
                ttl_dns_cache=self.conf.ttl_dns_cache,
            )
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=self.conf.timeout_sec,
                    connect=self.conf.timeout_sec
                    / 3,  # se non risponde in 1/3 del timeout, è giù
                ),
                connector=connector,
            )

            if self.conf.urlscan_api_key:
                self.urlscan = UrlScanClient(self.conf.urlscan_api_key, self._session)

        return self._session

    async def close(self) -> None:
        """Chiude la sessione HTTP: va chiamata allo shutdown del bot."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    def is_key_to_remove(self, key: str) -> bool:
        """True se il parametro va rimosso: match esatto, prefisso o suffisso."""
        lowered_key = (key or "").lower()
        if lowered_key in self.EXACT_KEYS:
            return True
        if self._PREFIX_RE and self._PREFIX_RE.match(lowered_key):
            return True
        if self._SUFFIX_RE and self._SUFFIX_RE.search(lowered_key):
            return True
        return False

    def _unwrap_link_wrapper(self, url: str) -> str:
        """Estrae l'URL vero da link wrapper (es. l.facebook.com?u=...) senza richieste HTTP.
        ClearURLs conosce questi pattern e li risolve direttamente — più veloce e senza
        lasciare tracce nei log del server wrapper.
        """
        if self._clearurls is None or not self._clearurls.is_loaded:
            return url
        providers = self._clearurls.find_providers(url)
        extracted = self._clearurls.apply_redirections(url, providers)
        return extracted if extracted else url

    def _clean_with_clearurls(self, url: str) -> str:
        """Rimuove parametri tracker specifici del dominio (es. Amazon "tag=", YouTube "feature=").
        keys.json non può coprire questi perché rimuovere "tag" da qualsiasi URL sarebbe sbagliato.
        """
        if self._clearurls is None or not self._clearurls.is_loaded:
            return url
        providers = self._clearurls.find_providers(url)
        if not providers:
            return url
        return self._clearurls.apply_cleaning(url, providers)

    def _strip_tracking_params(self, url: str) -> str:
        """Rimuove parametri tracker universali (utm_*, fbclid, gclid, ecc.) presenti su qualsiasi sito.
        Complementa _clean_with_clearurls che copre invece i tracker specifici per dominio.
        """
        try:
            parts = urlsplit(url)

            # parse_qsl invece di parse_qs: mantiene l'ordine e i duplicati,
            # necessario per ricostruire l'URL identico all'originale
            all_params = parse_qsl(parts.query, keep_blank_values=True)
            filtered_params = [
                (param_key, param_val)
                for param_key, param_val in all_params
                if not self.is_key_to_remove(param_key)
            ]

            # Alcuni tracker usano il fragment invece della query (es. #utm_source=newsletter)
            new_fragment = parts.fragment
            if new_fragment:
                fragment_lower = new_fragment.lstrip("#").lower()
                if self.FRAG_KEYS:
                    # Logica conservativa: rimuoviamo il fragment solo se è un match esatto,
                    # se segue il pattern "chiave=valore", o se la chiave di tracking finisce
                    # già con un separatore (es. "utm_"). Evita di rompere link Wikipedia tipo #Referenze.
                    match = False
                    for frag_prefix in self.FRAG_KEYS:
                        if fragment_lower == frag_prefix:
                            match = True
                            break
                        if fragment_lower.startswith(frag_prefix + "="):
                            match = True
                            break
                        if frag_prefix.endswith(("_", "-", ".")) and fragment_lower.startswith(frag_prefix):
                            match = True
                            break
                    if match:
                        new_fragment = ""

            # Se nulla è cambiato restituiamo l'URL originale senza ricodificare.
            # parse_qsl+urlencode normalizza la percent-encoding anche per i parametri
            # non toccati (es. q=https://... → q=https%3A%2F%2F...): evitarlo quando
            # l'URL è già pulito preserva l'encoding originale del mittente.
            if (
                len(filtered_params) == len(all_params)
                and new_fragment == parts.fragment
            ):
                return url

            new_query = urlencode(filtered_params, doseq=True)
            return urlunsplit(
                (parts.scheme, parts.netloc, parts.path, new_query, new_fragment)
            )

        except Exception:
            return url  # URL malformato: restituiamo intatto

    async def do_redirect(
        self, url_iniziale: str, opts: SanitizerOpts
    ) -> "PageSignals | None":
        """Unwrap link wrapper + fetch segnali. Non pulisce i parametri (quello è _sanitize_url_impl)."""
        try:
            return await PageSignals._fetch_signals(
                self._unwrap_link_wrapper(url_iniziale), self, opts
            )
        except Exception:
            logger.exception("Errore durante l'estrazione dei segnali della pagina")
            return None

    async def sanitize_url(
        self, raw_url: str, *, opts: SanitizerOpts
    ) -> tuple[str, str | None]:
        """Pre-processing (schema mancante, mailto/tel) + cache LRU + delega a _sanitize_url_impl."""
        if not raw_url:
            return raw_url, None

        _input_url = raw_url.strip()

        if re.match(r"^(mailto:|tel:)", _input_url, re.IGNORECASE):
            return _input_url, None  # non sono URL HTTP, non ha senso pulirli

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", _input_url):
            _input_url = (
                "https://" + _input_url
            )  # URL senza schema (es. "www.example.com/...")

        # La chiave include le opzioni perché show_title=True produce un risultato diverso
        cache_key = f"{_input_url}|{opts.show_title}|{opts.use_privacy_frontend}"
        if cache_key in self._cache_lru:
            # Cache hit: pop + reinserimento sposta in coda (MRU)
            cached = self._cache_lru.pop(cache_key)
            self._cache_lru[cache_key] = cached
            return cached

        result = await self._sanitize_url_impl(_input_url, opts=opts)

        # Eviction LRU: rimuove il più vecchio finché non rientra nel limite
        while len(self._cache_lru) >= self._cache_maxlen:
            self._cache_lru.popitem(last=False)
        self._cache_lru[cache_key] = result

        return result

    async def _sanitize_url_impl(
        self, _input_url: str, *, opts: SanitizerOpts
    ) -> tuple[str, str | None]:
        """Pipeline completa: redirect → whitelist → pulizia → validazione → frontend alternativo.

        Il frontend alternativo (_with_privacy) è applicato per ULTIMO su ogni return:
        se lo applicassimo prima, la validazione confronterebbe segnali di inv.nadeko.net
        con quelli di youtube.com e non troverebbe mai corrispondenza.
        In caso di errore a qualsiasi step, si restituisce l'URL post-redirect non pulito:
        meglio un link funzionante con tracker che un link rotto.
        """

        # Closure per non ripetere la condizione use_privacy_frontend su ogni return
        def _with_privacy(url: str) -> str:
            return self.TRADUCI_URL.translate(url) if opts.use_privacy_frontend else url

        try:
            signals_post_redirect = await self.do_redirect(_input_url, opts)
        except Exception as error:
            logger.info("Catena dei redirect fallita: %s", error)
            signals_post_redirect = None

        if signals_post_redirect:
            final_title = signals_post_redirect.title
            post_redirect_url = signals_post_redirect.final_url
        else:
            # Redirect fallito (rete irraggiungibile): puliamo comunque l'URL input
            final_title = None
            post_redirect_url = _input_url

        # Interstitial di consenso GDPR (es. consent.google.com): aiohttp si ferma
        # sulla pagina di consenso anziché seguire il redirect verso la destinazione reale.
        # Estraiamo l'URL reale dal parametro continue= e ri-seguiamo il redirect per
        # ottenere segnali corretti e poter pulire la URL di destinazione.
        consent_target = _extract_consent_continue(post_redirect_url)
        if consent_target:
            logger.debug(
                "Interstitial di consenso rilevato su %s — ri-seguo per la destinazione",
                urlsplit(post_redirect_url).netloc,
            )
            try:
                signals_real = await self.do_redirect(consent_target, opts)
                if signals_real:
                    signals_post_redirect = signals_real
                    final_title = signals_real.title
                    post_redirect_url = signals_real.final_url
            except Exception:
                post_redirect_url = (
                    consent_target  # fallback: usiamo l'URL estratto senza segnali
                )

        # I fragment non vengono mai inviati al server HTTP: aiohttp li rimuove prima della
        # richiesta. Se il redirect non ha cambiato host+path (stesso documento), ripristiniamo
        # il fragment originale così che _strip_tracking_params possa decidere se tenerlo o no.
        _orig_parts = urlsplit(_input_url)
        if _orig_parts.fragment:
            _redir_parts = urlsplit(post_redirect_url)
            if (not _redir_parts.fragment and
                    (_orig_parts.scheme, _orig_parts.netloc, _orig_parts.path) ==
                    (_redir_parts.scheme, _redir_parts.netloc, _redir_parts.path)):
                post_redirect_url = urlunsplit(_redir_parts._replace(fragment=_orig_parts.fragment))

        try:
            # re.sub su netloc gestisce anche netloc con porta (es. "www.example.com:8080")
            domain_no_www = re.sub(
                r"^www\.", "", urlsplit(post_redirect_url).netloc, flags=re.IGNORECASE
            ).lower()

            # Dominio in whitelist: l'utente vuole i link intatti, usciamo senza toccare nulla
            if domain_no_www in self.DOMAIN_WHITELIST:
                return _with_privacy(post_redirect_url), final_title

            # ClearURLs prima (parametri per-dominio), poi generici: l'ordine conta perché
            # ClearURLs può modificare l'URL in modo che il secondo step trovi parametri diversi
            cleaned_url = self._strip_tracking_params(
                self._clean_with_clearurls(post_redirect_url)
            )

            # Validazione disabilitata in config: usiamo l'URL pulito senza verificarlo
            if not self.conf.valida_link_post_pulizia:
                return _with_privacy(cleaned_url), final_title

            # URL originale non raggiungibile: non abbiamo segnali con cui confrontare
            if signals_post_redirect and not signals_post_redirect.is_url_ok():
                return _with_privacy(post_redirect_url), final_title

            # La pulizia non ha cambiato nulla: evitiamo una richiesta HTTP inutile
            if cleaned_url == post_redirect_url:
                return _with_privacy(post_redirect_url), final_title

            # Richiesta leggera all'URL pulito per raccogliere i segnali e confrontarli
            # con quelli dell'URL originale raccolti da do_redirect sopra
            try:
                signals_cleaned = await PageSignals._fetch_signals(
                    cleaned_url, self, opts
                )
                if signals_cleaned and signals_cleaned.title:
                    final_title = (
                        signals_cleaned.title
                    )  # titolo dall'URL pulito, più accurato
            except Exception:
                signals_cleaned = None

            # check_url=True: usa il path come segnale di fallback se ETag/hash/canonical mancano.
            # is_url_ok() obbligatorio: se il pulito dà 400/404, il path combacia lo stesso (stessa
            # domain+path, query diversa) e check_url=True fallirebbe la protezione.
            if (
                signals_cleaned
                and signals_post_redirect
                and signals_cleaned.is_url_ok()
                and signals_cleaned.equivalent_to(signals_post_redirect, True)
            ):
                return _with_privacy(cleaned_url), final_title

            # Segnali diversi: i parametri rimossi cambiavano il contenuto (es. ?page=2, ?lang=it)
            logger.info(
                "Validazione fallita per l'URL pulito, restituisco l'URL post-redirect"
            )
            return _with_privacy(post_redirect_url), final_title

        except Exception:
            logger.exception(
                "Errore durante la sanificazione dettagliata: restituisco l'URL grezzo post-redirect"
            )
            return _with_privacy(post_redirect_url), final_title

    async def sanitize_batch(
        self, opts: SanitizerOpts, links: list[str]
    ) -> list[tuple[str, str | None]]:
        """Sanifica più URL in parallelo con deduplicazione e rispetto del limite di concorrenza.

        url_index_map traccia le posizioni di ogni URL nella lista originale:
        se lo stesso URL appare in posizione 0 e 2, viene elaborato una sola volta
        e il risultato copiato in entrambe le posizioni dell'output.
        """
        normalized_inputs = [(url or "").strip() for url in links]

        # Esempio: ["a.com", "b.com", "a.com"] → {"a.com": [0, 2], "b.com": [1]}
        url_index_map: OrderedDict[str, list[int]] = OrderedDict()
        for index, url in enumerate(normalized_inputs):
            if url:
                url_index_map.setdefault(url, []).append(index)

        if not url_index_map:
            return [("", None) for _ in normalized_inputs]

        async def process_one_url(input_url: str) -> tuple[str, str | None]:
            # Il semaforo blocca qui le task in eccesso finché un'altra non termina
            async with self._semaforo:
                try:
                    return await self.sanitize_url(input_url, opts=opts)
                except Exception:
                    return (input_url, None)

        # create_task lancia tutte le task "insieme" sull'event loop;
        # il semaforo dentro process_one_url limita quante fanno richieste HTTP contemporaneamente
        tasks_by_url = {
            dedup_url: asyncio.create_task(process_one_url(dedup_url))
            for dedup_url in url_index_map
        }

        # return_exceptions=True: se una task lancia eccezione, le altre continuano
        task_results = await asyncio.gather(
            *tasks_by_url.values(), return_exceptions=True
        )

        cleaned_by_url: dict[str, tuple[str, str | None]] = {
            url: ((url, None) if isinstance(result, Exception) else result)
            for url, result in zip(tasks_by_url.keys(), task_results)
        }

        # Ricostruisce l'output nell'ordine originale, duplicando i risultati degli URL ripetuti
        output_list: list[tuple[str, str | None]] = [
            ("", None) for _ in normalized_inputs
        ]
        for input_url, original_indexes in url_index_map.items():
            for idx in original_indexes:
                output_list[idx] = cleaned_by_url[input_url]

        return output_list
