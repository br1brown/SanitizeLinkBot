from __future__ import annotations

# modulo: utils.py
# scopo: utilita condivise per logging, caricamento file json, template html e lettura token

import os
import json
import html
import logging
from pathlib import Path

# base path e nomi file standard
BASE_DIR = (
    os.path.dirname(os.path.abspath(__file__))
    if "__file__" in globals()
    else os.getcwd()
)
KEYS_PATH = os.path.join(BASE_DIR, "keys.json")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
TOKEN_PATH = os.path.join(BASE_DIR, "token.txt")

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


def render_from_file(filename: str, **ctx) -> str:
    """carica un template html e fa format con escape semplice"""
    path = os.path.join(BASE_DIR, filename + ".html")
    with open(path, "r", encoding="utf-8") as fh:
        template = fh.read()
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
