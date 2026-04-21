from __future__ import annotations

# utils.py — utilità condivise: logger, caricamento JSON, template HTML, token bot, confronto URL.

import os
import json
import html
import logging
import functools
import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# Regex pre-compilata per il check dello schema; re.I per case-insensitivity
_RE_HAS_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", re.I)

BASE_DIR = (
    os.path.dirname(os.path.abspath(__file__))
    if "__file__"
    in globals()  # __file__ non esiste se il modulo è eseguito via exec() o embedded
    else os.getcwd()
)
PROJECT_ROOT = os.path.dirname(BASE_DIR)
KEYS_PATH = os.path.join(PROJECT_ROOT, "keys.json")
TOKEN_PATH = os.path.join(PROJECT_ROOT, "token.txt")

# Il file viene creato al primo aggiornamento mensile; se mancante il layer ClearURLs è disabilitato
CLEARURLS_PATH = os.path.join(PROJECT_ROOT, "data", "clearurls.json")

_LOGGER_NAME = "Sanitize-Link"


def _bootstrap_logger() -> logging.Logger:
    """Crea il logger condiviso dell'applicazione. Guard su handlers: evita duplicati in caso di re-import."""
    logger = logging.getLogger(_LOGGER_NAME)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = (
            False  # impedisce la propagazione al root logger (eviterebbe log doppi)
        )
    return logger


logger: logging.Logger = _bootstrap_logger()


def set_log_level(level_name: str | None) -> None:
    if not level_name:
        return
    try:
        logger.setLevel(getattr(logging, level_name, logging.INFO))
    except Exception:
        pass


def load_json_file(path: str, *, required: bool = False) -> dict:
    """Carica un file JSON. Se required=True e il file manca, solleva RuntimeError."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        if required:
            logger.error("File di configurazione richiesto non trovato: %s", path)
            raise RuntimeError(f"required file not found: {path}") from err
        logger.info(
            "File di configurazione opzionale non trovato: %s, uso i valori predefiniti",
            path,
        )
        return {}
    except json.JSONDecodeError as err:
        logger.error("JSON non valido nel file %s: %s", path, err)
        raise RuntimeError(f"invalid json in {path}: {err}") from err

    if not isinstance(data, dict):
        logger.error("Il file %s non contiene un oggetto JSON", path)
        raise RuntimeError(f"invalid content in {path}: expected a json object")

    logger.info("Caricato JSON da %s", path)
    logger.debug("Chiavi caricate: %s", list(data.keys()))
    return data


@functools.lru_cache(
    maxsize=32
)  # i template non cambiano a runtime: cache per evitare I/O ripetuti
def _read_template(filename: str) -> str:
    path = os.path.join(PROJECT_ROOT, "templates", filename + ".html")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def render_from_file(filename: str, **ctx) -> str:
    """Carica un template HTML e sostituisce i placeholder con i valori escaped."""
    template = _read_template(filename)
    # Escape di tutti i valori prima dell'inserimento: prevenzione XSS nei messaggi Telegram
    safe_ctx = {ctx_key: html.escape(str(ctx_val)) for ctx_key, ctx_val in ctx.items()}
    return template.format(**safe_ctx)


def get_telegram_token() -> str:
    """Legge il token del bot da TELEGRAM_BOT_TOKEN (env) o da token.txt come fallback."""
    env_value = os.getenv("TELEGRAM_BOT_TOKEN")
    if env_value:
        logger.info("Token di Telegram letto dalla variabile d'ambiente")
        return env_value.strip()
    try:
        with open(TOKEN_PATH, "r", encoding="utf-8") as fh:
            logger.info("Token di Telegram letto dal file token.txt")
            return fh.read().strip()
    except FileNotFoundError as err:
        logger.error(
            "Token di Telegram mancante. Imposta TELEGRAM_BOT_TOKEN o crea token.txt"
        )
        raise RuntimeError("missing TELEGRAM_BOT_TOKEN or token.txt") from err


def urls_are_semantically_equivalent(url1: str | None, url2: str | None) -> bool:
    """True se i due URL puntano alla stessa risorsa, ignorando differenze irrilevanti.
    Normalizza: http↔https, www., porta default, trailing slash, ordine parametri query.
    Usato in handle_group per decidere se il link era già pulito (no messaggio in chat).
    """
    if not url1 and not url2:
        return True
    if not url1 or not url2:
        return False
    if url1 == url2:
        return True  # ottimizzazione: confronto diretto prima di normalizzare

    def _normalize(raw_url: str) -> str:
        raw_url = raw_url.strip()
        if not _RE_HAS_SCHEME.match(raw_url):
            raw_url = "https://" + raw_url  # aggiunge schema se assente

        parsed = urlparse(raw_url)
        scheme = parsed.scheme.lower()
        if scheme == "http":
            scheme = "https"  # http e https trattati come equivalenti

        netloc = parsed.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]  # www. non cambia la risorsa

        if ":" in netloc:
            # Rimuove le porte di default per evitare falsi negativi nel confronto
            host_part, port_part = netloc.rsplit(":", 1)
            if (scheme == "https" and port_part == "443") or (
                scheme == "http" and port_part == "80"
            ):
                netloc = host_part

        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path[:-1]

        query = parsed.query
        if query:
            # Normalizziamo l'encoding e l'ordine dei parametri
            qsl = parse_qsl(query, keep_blank_values=True)
            qsl.sort()
            query = urlencode(qsl, doseq=True)

        # urlunparse è comunque necessario per ricostruire la stringa normalizzata finale
        return urlunparse((scheme, netloc, path, parsed.params, query, parsed.fragment))

    try:
        return _normalize(url1) == _normalize(url2)
    except Exception as exc:
        logger.debug(
            "Confronto semantico degli URL fallito (%s), ritorno all'uguaglianza delle stringhe",
            exc,
        )
        return url1 == url2
