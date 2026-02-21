from __future__ import annotations
from UrlTranslator import UrlTranslator
from chat_prefs import SanitizerOpts

# Modulo: sanitizer.py
# Scopo: pulire URL (rimozione parametri di tracciamento), seguire redirect e
#        opzionalmente estrarre il titolo della pagina finale.

from utils import logger
from collections import OrderedDict

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

from app_config import AppConfig


@dataclass
class PageSignals:
    final_url: str
    url_path: str
    status: int
    content_type: str
    etag: Optional[str]
    lastmod: Optional[str]
    canonical: Optional[str]
    og_url: Optional[str]
    title: Optional[str]
    chunk_hash: Optional[str]

    @staticmethod
    def _ok(status) -> bool:
        return 200 <= status < 300 or 300 <= status < 400 or status in (401, 403)

    def is_url_ok(self) -> bool:
        return self._ok(self.status) and self.final_url.startswith(
            ("http://", "https://")
        )

    @staticmethod
    def _norm_etag(et: str | None) -> str | None:
        if not et:
            return None
        et = et.strip()
        if et.startswith("W/"):
            et = et[2:].strip()
        if len(et) >= 2 and ((et[0] == et[-1] == '"') or (et[0] == et[-1] == "'")):
            et = et[1:-1]
        return et or None

    @staticmethod
    def _same_html_type(a: str | None, b: str | None) -> bool:
        if not a or not b:
            return True
        a = a.lower().split(";")[0].strip()
        b = b.lower().split(";")[0].strip()
        htmlish = ("text/html", "application/xhtml+xml")
        return (a in htmlish and b in htmlish) or (a == b)

    @staticmethod
    def _normalize_url_path(url: str | None) -> str | None:
        if not url:
            return None
        parsato = urlparse(url)
        scheme = (parsato.scheme or "http").lower()
        host = (parsato.hostname or "").lower()
        port = parsato.port or ""
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = ""
        netloc = host if not port else f"{host}:{port}"
        path = parsato.path or "/"
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        return urlunparse((scheme, netloc, path, "", "", ""))

    def equivalent_to(
        self, other: Optional["PageSignals"], check_url: bool = False
    ) -> bool:
        """Ritorna True se i due insiemi di segnali indicano la *stessa pagina*."""
        if not self or not other:
            return False

        a_et, b_et = PageSignals._norm_etag(self.etag), PageSignals._norm_etag(
            other.etag
        )
        if a_et and b_et and a_et == b_et:
            return True

        if (
            self.lastmod
            and other.lastmod
            and self.lastmod == other.lastmod
            and PageSignals._normalize_url_path(self.url_path)
            == PageSignals._normalize_url_path(other.url_path)
        ):
            return True

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
        if not raw:
            return None
        t = html.unescape(raw.strip())
        t = re.sub(r"[\u200B-\u200D\uFEFF]", "", t)
        t = t.replace("\u00a0", " ")
        t = re.sub(r"\s+", " ", t).strip()
        return t or None

    @staticmethod
    def _pick_charset(raw_ct_header: str | None) -> str:
        if raw_ct_header:
            parts = raw_ct_header.lower().split(";")
            for p in parts[1:]:
                p = p.strip()
                if p.startswith("charset="):
                    return p.split("=", 1)[1].strip().strip('"').strip("'")
        return "utf-8"

    @staticmethod
    async def _fetch_signals(
        url: str, sanita: Sanitizer, opts: SanitizerOpts
    ) -> PageSignals | None:
        MAX_BYTES = 512 * 1024

        canonical_url: Optional[str] = None
        og_url: Optional[str] = None
        titolo_pagina: Optional[str] = None

        headers = dict(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/126.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
            }
        )

        if opts.show_title:
            max_bytes = 1_048_576
            chunk_size = 16_384
        else:
            headers["Range"] = "bytes=0-131071"
            max_bytes = 131_072
            chunk_size = 8_192

        _RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
        _RE_CANONICAL_TXT = re.compile(
            r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        _RE_OGURL_TXT = re.compile(
            r'<meta[^>]+property=["\']og:url["\'][^>]+content=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        _RE_OGTITLE_TXT = re.compile(
            r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        _RE_TWTITLE_TXT = re.compile(
            r'<meta[^>]+name=["\']twitter:title["\'][^>]+content=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )

        _RE_HEAD_CLOSE_B = re.compile(rb"</head\b[^>]*>", re.IGNORECASE)
        _RE_TITLE_CLOSE_B = re.compile(rb"</title\s*>", re.IGNORECASE)
        _META_CHARSET_B = re.compile(
            rb'<meta[^>]+charset=["\']?\s*([a-zA-Z0-9_\-]+)\s*["\'>]', re.IGNORECASE
        )

        try:
            session = await sanita._get_session()
            async with session.get(
                url,
                headers=headers,
                timeout=sanita.conf.timeout_sec,
            ) as resp:
                raw_cl = resp.headers.get("Content-Length")
                raw_ct = resp.headers.get("Content-Type")
                content_type = (raw_ct or "").split(";")[0].strip().lower()

                if not (200 <= resp.status < 300):
                    return PageSignals(
                        final_url=str(resp.url),
                        url_path=PageSignals._normalize_url_path(str(resp.url)),
                        status=resp.status,
                        content_type=content_type,
                        etag=resp.headers.get("ETag"),
                        lastmod=resp.headers.get("Last-Modified"),
                        canonical=None,
                        og_url=None,
                        title=None,
                        chunk_hash=None,
                    )

                elif raw_cl:
                    try:
                        if int(raw_cl) > MAX_BYTES:
                            return PageSignals(
                                final_url=str(resp.url),
                                url_path=PageSignals._normalize_url_path(str(resp.url)),
                                status=resp.status,
                                content_type=content_type,
                                etag=resp.headers.get("ETag"),
                                lastmod=resp.headers.get("Last-Modified"),
                                canonical=None,
                                og_url=None,
                                title=None,
                                chunk_hash=None,
                            )
                    except (ValueError, TypeError):
                        pass

                primo_chunk = b""

                async for blocco in resp.content.iter_chunked(chunk_size):
                    primo_chunk += blocco

                    if not content_type:
                        low2k = primo_chunk[:2048].lower()
                        if b"<!doctype html" in low2k or b"<html" in low2k:
                            content_type = "text/html"

                    if opts.show_title:
                        if (
                            _RE_TITLE_CLOSE_B.search(primo_chunk)
                            or len(primo_chunk) >= max_bytes
                        ):
                            break
                    else:
                        if (
                            _RE_HEAD_CLOSE_B.search(primo_chunk)
                            or len(primo_chunk) >= max_bytes
                        ):
                            break

                charset = PageSignals._pick_charset(raw_ct)
                if "html" in content_type and primo_chunk:
                    META_CHAR = _META_CHARSET_B.search(primo_chunk[:8192])
                    if META_CHAR:
                        try:
                            cand = META_CHAR.group(1).decode("ascii", "ignore").lower()
                            if cand:
                                charset = cand
                        except Exception:
                            pass

                    try:
                        head_text = primo_chunk.decode(charset, errors="strict")
                    except Exception:
                        try:
                            head_text = primo_chunk.decode("utf-8", errors="ignore")
                        except Exception:
                            head_text = primo_chunk.decode("latin-1", errors="ignore")

                    m = _RE_CANONICAL_TXT.search(head_text)
                    if m:
                        canonical_url = urljoin(str(resp.url), m.group(1).strip())
                    m = _RE_OGURL_TXT.search(head_text)
                    if m:
                        og_url = urljoin(str(resp.url), m.group(1).strip())

                    m = _RE_TITLE.search(head_text)
                    if m:
                        titolo_pagina = PageSignals._normalize_title(m.group(1))
                    if not titolo_pagina:
                        m = _RE_OGTITLE_TXT.search(head_text)
                        if m:
                            titolo_pagina = PageSignals._normalize_title(m.group(1))
                    if not titolo_pagina:
                        m = _RE_TWTITLE_TXT.search(head_text)
                        if m:
                            titolo_pagina = PageSignals._normalize_title(m.group(1))

                if resp.status >= 400:
                    titolo_pagina = None

                return PageSignals(
                    final_url=str(resp.url),
                    url_path=PageSignals._normalize_url_path(str(resp.url)),
                    status=resp.status,
                    content_type=content_type,
                    etag=resp.headers.get("ETag"),
                    lastmod=resp.headers.get("Last-Modified"),
                    canonical=canonical_url,
                    og_url=og_url,
                    title=titolo_pagina,
                    chunk_hash=(
                        hashlib.sha256(primo_chunk).hexdigest() if primo_chunk else None
                    ),
                )
        except Exception as e:
            return None


class Sanitizer:
    """Gestisce la pulizia degli URL e opzionalmente estrae il titolo della pagina.

    - Rimuove parametri di tracciamento secondo liste configurabili.
    - Segue redirect HTTP/meta refresh/JS fino a un limite.
    - Valida l'URL finale (opzionale) con una richiesta leggera.
    """

    def __init__(
        self,
        *,
        exact_keys: set[str],
        prefix_keys: tuple[str, ...],
        ends_with: tuple[str, ...],
        frag_keys: tuple[str, ...],
        domain_whitelist: list[str] | None = None,
        conf: AppConfig,
    ) -> None:
        logger.debug("Sanitizer initialized with rule sets and domain whitelist")
        self.EXACT_KEYS = set(map(str.lower, exact_keys or set()))
        self.PREFIX_KEYS = tuple(k.lower() for k in (prefix_keys or ()))
        self.ENDS_WITH = tuple(k.lower() for k in (ends_with or ()))
        self.FRAG_KEYS = tuple(k.lower() for k in (frag_keys or ()))
        self.DOMAIN_WHITELIST = domain_whitelist or []
        self.conf = conf

        self._session: aiohttp.ClientSession | None = None
        self._ssl_ctx: ssl.SSLContext | None = None

        # FIX 5: semaforo persistente, creato una volta sola
        self._semaforo = asyncio.Semaphore(conf.max_concurrency)

        self.META_REFRESH_RE = re.compile(
            r'<meta\s+http-equiv=["\']refresh["\']\s+content=["\']\s*\d+\s*;\s*url\s*=\s*([^"\']+)["\']',
            re.IGNORECASE,
        )

        self.PATTERNS_JS_REDIRECT = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\.replace\(\s*["\']([^"\']+)["\']\s*\)',
            r'location\.assign\(\s*["\']([^"\']+)["\']\s*\)',
        ]
        self.TRADUCI_URL = UrlTranslator()

    async def _get_session(self) -> aiohttp.ClientSession:
        """Crea (se serve) una sessione HTTP condivisa con timeout e limiti sensati."""
        if self._session is None or self._session.closed:
            if self._ssl_ctx is None:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.load_verify_locations(cafile=certifi.where())
                extra = os.getenv("EXTRA_CA_BUNDLE")
                if extra and os.path.exists(extra):
                    ctx.load_verify_locations(cafile=extra)
                self._ssl_ctx = ctx

            logger.debug(
                "Creating aiohttp ClientSession (timeout_total=%ss, connect_timeout=%ss, limit_per_host=%s, ttl_dns_cache=%ss)",
                self.conf.timeout_sec,
                self.conf.timeout_sec / 3,
                (
                    self.conf.connections_per_host
                    if self.conf.connections_per_host > 0
                    else None
                ),
                self.conf.ttl_dns_cache,
            )

            connector = aiohttp.TCPConnector(
                limit_per_host=(
                    self.conf.connections_per_host
                    if self.conf.connections_per_host > 0
                    else None
                ),
                ssl=self._ssl_ctx,
                ttl_dns_cache=self.conf.ttl_dns_cache,
            )

            timeout_config = aiohttp.ClientTimeout(
                total=self.conf.timeout_sec,
                connect=self.conf.timeout_sec / 3,
            )
            self._session = aiohttp.ClientSession(
                timeout=timeout_config, connector=connector
            )
        return self._session

    async def close(self) -> None:
        """Chiude la sessione HTTP se ancora aperta per liberare risorse."""
        if self._session and not self._session.closed:
            logger.debug("Closing HTTP session and releasing resources")
            await self._session.close()
            self._session = None

    def is_key_to_remove(self, key: str) -> bool:
        """Decide se un parametro di query va rimosso (match esatto, prefisso o suffisso)."""
        lowered_key = (key or "").lower()
        should_remove = (
            lowered_key in self.EXACT_KEYS
            or any(lowered_key.startswith(prefix) for prefix in self.PREFIX_KEYS)
            or any(lowered_key.endswith(suffix) for suffix in self.ENDS_WITH)
        )
        logger.debug("Parameter '%s' marked for removal: %s", key, should_remove)
        return should_remove

    async def do_redirect(
        self, url_iniziale: str, opts: SanitizerOpts
    ) -> PageSignals | None:

        def meta_refresh_target(html_text: str, base_url: str) -> str | None:
            m = self.META_REFRESH_RE.search(html_text)
            if m and m.group(1):
                return urljoin(base_url, m.group(1).strip())
            return None

        def js_redirect_target(html_text: str, base_url: str) -> str | None:
            for pattern in self.PATTERNS_JS_REDIRECT:
                match_js = re.search(pattern, html_text, re.IGNORECASE)
                if match_js and match_js.group(1):
                    return urljoin(base_url, match_js.group(1).strip())
            return None

        current_url = url_iniziale
        redirect_count = 0

        session = await self._get_session()

        while redirect_count < self.conf.max_redirects:
            try:
                async with session.head(current_url, allow_redirects=False) as response:
                    if response.status in (301, 302, 303, 307, 308):
                        location_header = response.headers.get("Location")
                        if location_header:
                            current_url = urljoin(current_url, location_header)
                            redirect_count += 1
                            continue
            except aiohttp.ClientError:
                logger.debug("HEAD request failed, falling back to GET", exc_info=True)

            try:
                async with session.get(
                    current_url,
                    headers={"Range": "bytes=0-16383"},
                    allow_redirects=False,
                ) as response:
                    if response.status in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location")
                        if location:
                            current_url = urljoin(current_url, location)
                            redirect_count += 1
                            continue

                    if response.status == 416:
                        raise aiohttp.ClientError("Range non supportato")

                    if (
                        response.status == 200
                        and response.content_type
                        and response.content_type.startswith("text/html")
                    ):
                        partial_html = await response.text(errors="ignore")
                        target = meta_refresh_target(
                            partial_html, current_url
                        ) or js_redirect_target(partial_html, current_url)
                        if target:
                            current_url = target
                            redirect_count += 1
                            continue
            except aiohttp.ClientError:
                logger.debug(
                    "Partial GET failed, retrying with full GET", exc_info=True
                )

            try:
                async with session.get(current_url, allow_redirects=False) as response:
                    if response.status in (301, 302, 303, 307, 308):
                        location_header = response.headers.get("Location")
                        if location_header:
                            current_url = urljoin(current_url, location_header)
                            redirect_count += 1
                            continue
                    if (
                        response.status == 200
                        and response.content_type
                        and response.content_type.startswith("text/html")
                    ):
                        full_html = await response.text(errors="ignore")
                        target = meta_refresh_target(
                            full_html, current_url
                        ) or js_redirect_target(full_html, current_url)
                        if target:
                            current_url = target
                            redirect_count += 1
                            continue
            except aiohttp.ClientError:
                logger.debug(
                    "Full GET failed, stopping redirect attempts", exc_info=True
                )
                break

            break

        try:
            return await PageSignals._fetch_signals(current_url, self, opts)
        except Exception:
            logger.exception("Error while extracting page signals")
            return None

    async def sanitize_url(
        self, raw_url: str, *, opts: SanitizerOpts
    ) -> tuple[str, str | None]:
        if not raw_url:
            return raw_url, None

        _input_url = (raw_url or "").strip()

        if re.match(r"^(mailto:|tel:)", _input_url, re.IGNORECASE):
            return _input_url, None

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", _input_url):
            _input_url = "https://" + _input_url

        # FIX 4: una sola fetch iniziale tramite do_redirect (che segue i redirect
        # e poi fa _fetch_signals sull'URL finale). Questo sostituisce sia la vecchia
        # _fetch_signals(_input_url) sia do_redirect, evitando la doppia richiesta.
        try:
            _sig_postredir = await self.do_redirect(_input_url, opts)
        except Exception as error:
            logger.info(
                "Redirect chain failed on %s (%s)", _input_url, error
            )
            _sig_postredir = None

        final_title = (
            _sig_postredir.title if _sig_postredir and _sig_postredir.title else None
        )
        post_redirect_url = _sig_postredir.final_url if _sig_postredir else _input_url

        if opts.translate_url:
            post_redirect_url = self.TRADUCI_URL.translate(post_redirect_url)

        # --- pulizia parametri ---
        try:
            split_parts = urlsplit(post_redirect_url)
            domain_no_www = re.sub(
                r"^www\.", "", split_parts.netloc, flags=re.IGNORECASE
            ).lower()

            if domain_no_www in self.DOMAIN_WHITELIST:
                return post_redirect_url, final_title

            original_query_params = parse_qsl(split_parts.query, keep_blank_values=True)
            filtered_query_params = [
                (param_key, param_value)
                for (param_key, param_value) in original_query_params
                if not self.is_key_to_remove(param_key)
            ]
            new_query_string = urlencode(filtered_query_params, doseq=True)

            new_fragment = split_parts.fragment
            if new_fragment:
                lowered_fragment = new_fragment.lstrip("#").lower()
                if self.FRAG_KEYS and any(
                    lowered_fragment.startswith(prefix) for prefix in self.FRAG_KEYS
                ):
                    new_fragment = ""

            final_url = urlunsplit(
                (
                    split_parts.scheme,
                    split_parts.netloc,
                    split_parts.path,
                    new_query_string,
                    new_fragment,
                )
            )

            # --- validazione post-pulizia ---
            if not self.conf.valida_link_post_pulizia:
                return final_url, final_title

            # FIX 3: logica esplicita senza eccezioni come flow control.
            # Se l'URL originale (post-redirect) non era raggiungibile, restituiscilo così com'è.
            if _sig_postredir and not _sig_postredir.is_url_ok():
                logger.debug("Original URL not reachable, returning post-redirect URL as-is")
                return post_redirect_url, final_title

            # Se la pulizia non ha cambiato nulla, non serve validare.
            if (new_query_string == split_parts.query) and (
                new_fragment == split_parts.fragment
            ):
                return post_redirect_url, final_title

            # Verifica che l'URL pulito porti alla stessa pagina.
            try:
                _sig_clean = await PageSignals._fetch_signals(final_url, self, opts)
                if _sig_clean and _sig_clean.title:
                    final_title = _sig_clean.title
            except Exception:
                _sig_clean = None

            # Confronto: l'URL pulito è equivalente a quello post-redirect?
            if _sig_clean and _sig_postredir and _sig_clean.equivalent_to(_sig_postredir):
                return final_url, final_title

            # Fallback: confronto per URL path
            if _sig_clean and _sig_postredir and _sig_clean.equivalent_to(_sig_postredir, True):
                return final_url, final_title

            # Validazione fallita: torniamo all'URL post-redirect non pulito.
            logger.info("Validation failed for cleaned URL, returning post-redirect URL")
            return post_redirect_url, final_title

        except Exception:
            logger.exception(
                "Error during detailed sanitization: returning raw post-redirect URL"
            )
            return post_redirect_url, final_title

    async def sanitize_batch(
        self, links: list[str], *, opts: SanitizerOpts
    ) -> list[tuple[str, str | None]]:
        normalized_inputs = [(url or "").strip() for url in links]

        url_index_map: OrderedDict[str, list[int]] = OrderedDict()
        for index, url in enumerate(normalized_inputs):
            if url:
                url_index_map.setdefault(url, []).append(index)

        if not url_index_map:
            return [("", None) for _ in normalized_inputs]

        # FIX 5: usa il semaforo persistente dell'istanza
        async def process_one_url(input_url: str) -> tuple[str, str | None]:
            async with self._semaforo:
                try:
                    return await self.sanitize_url(input_url, opts=opts)
                except Exception:
                    return (input_url, None)

        tasks_by_url = {
            u: asyncio.create_task(process_one_url(u)) for u in url_index_map
        }
        task_results = await asyncio.gather(
            *tasks_by_url.values(), return_exceptions=True
        )

        cleaned_by_url: dict[str, tuple[str, str | None]] = {}
        for input_url, task_result in zip(tasks_by_url.keys(), task_results):
            cleaned_by_url[input_url] = (
                (input_url, None) if isinstance(task_result, Exception) else task_result
            )

        output_list: list[tuple[str, str | None]] = [
            ("", None) for _ in normalized_inputs
        ]
        for input_url, original_indexes in url_index_map.items():
            for idx in original_indexes:
                output_list[idx] = cleaned_by_url[input_url]
        return output_list
