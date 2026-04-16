from __future__ import annotations

# modulo: utils.py
# scopo: utilita condivise per logging, caricamento file json, template html e lettura token

import os
import json
import html
import logging
import functools
import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# base path e nomi file standard
BASE_DIR = (
    os.path.dirname(os.path.abspath(__file__))
    if "__file__" in globals()
    else os.getcwd()
)
PROJECT_ROOT = os.path.dirname(BASE_DIR)
KEYS_PATH = os.path.join(PROJECT_ROOT, "keys.json")
TOKEN_PATH = os.path.join(PROJECT_ROOT, "token.txt")

# logger condiviso
_LOGGER_NAME = "puliscilink"


def _bootstrap_logger() -> logging.Logger:
    """crea e configura il logger condiviso dell applicazione"""
    logger = logging.getLogger(_LOGGER_NAME)
    if not logger.handlers:
        handler = logging.StreamHandler()
        fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


logger: logging.Logger = _bootstrap_logger()


def set_log_level(level_name: str | None) -> None:
    """imposta il livello del logger, se valido"""
    if not level_name:
        return
    try:
        logger.setLevel(getattr(logging, level_name, logging.INFO))
    except Exception:
        # lascia livello di default
        pass


def load_json_file(path: str, *, required: bool = False) -> dict:
    """carica un file json e ritorna un dict

    se required è true e il file manca solleva runtimeerror
    se il contenuto non è un oggetto json solleva runtimeerror
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        if required:
            logger.error("Required configuration file not found: %s", path)
            raise RuntimeError(f"required file not found: {path}") from err
        logger.info("Optional configuration file not found: %s, using defaults", path)
        return {}
    except json.JSONDecodeError as err:
        logger.error("Invalid JSON in file %s: %s", path, err)
        raise RuntimeError(f"invalid json in {path}: {err}") from err

    if not isinstance(data, dict):
        logger.error("File %s does not contain a JSON object", path)
        raise RuntimeError(f"invalid content in {path}: expected a json object")

    logger.debug("Loaded JSON from %s with keys: %s", path, list(data.keys()))
    return data


@functools.lru_cache(maxsize=32)
def _read_template(filename: str) -> str:
    path = os.path.join(PROJECT_ROOT, "templates", filename + ".html")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def render_from_file(filename: str, **ctx) -> str:
    """carica un template html e fa format con escape semplice"""
    template = _read_template(filename)
    safe_ctx = {k: html.escape(str(v)) for k, v in ctx.items()}
    return template.format(**safe_ctx)


def get_telegram_token() -> str:
    """ritorna il token del bot telegram dalla variabile di ambiente o da token.txt"""
    env_value = os.getenv("TELEGRAM_BOT_TOKEN")
    if env_value:
        token = env_value.strip()
        logger.info("Telegram token read from environment variable")
        return token
    try:
        with open(TOKEN_PATH, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
            logger.info("Telegram token read from token.txt file")
            return token
    except FileNotFoundError as err:
        logger.error(
            "Missing Telegram token. Set TELEGRAM_BOT_TOKEN or create token.txt"
        )
        raise RuntimeError("missing TELEGRAM_BOT_TOKEN or token.txt") from err


def urls_are_semantically_equivalent(url1: str | None, url2: str | None) -> bool:
    """Verifica se due URL sono spazialmente uguali
    (ignora differenze minime come http vs https, www., trailing slashes o ordine query)"""
    if not url1 and not url2:
        return True
    if not url1 or not url2:
        return False
    if url1 == url2:
        return True

    def _normalize(u: str) -> str:
        u = u.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", u):
            u = "https://" + u
            
        p = urlparse(u)
        scheme = p.scheme.lower()
        if scheme == "http":
            scheme = "https"
            
        netloc = p.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
            
        if ":" in netloc:
            parts = netloc.split(":")
            if (scheme == "https" and parts[-1] == "443") or (scheme == "http" and parts[-1] == "80"):
                netloc = ":".join(parts[:-1])
                
        path = p.path
        if path == "":
            path = "/"
        elif path != "/" and path.endswith("/"):
            path = path[:-1]
            
        query = p.query
        if query:
            qsl = parse_qsl(query, keep_blank_values=True)
            qsl.sort()
            query = urlencode(qsl, doseq=True)
            
        return urlunparse((scheme, netloc, path, p.params, query, p.fragment))
        
    try:
        is_eq = _normalize(url1) == _normalize(url2)
        if not is_eq:
            logger.debug("Link differs semantically")
        return is_eq
    except Exception as e:
        is_eq = url1 == url2
        if not is_eq:
            logger.debug("Link differs (semantic check failed: %s)", e)
        return is_eq
