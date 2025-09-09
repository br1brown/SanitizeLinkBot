from __future__ import annotations

# Modulo: utils.py
# Scopo: utilità condivise (logger, caricamento file JSON, template HTML, token Telegram).

import os  # gestione percorsi e variabili d'ambiente
import json  # parsing/scrittura JSON
import html  # escaping sicuro
import logging  # logging standard Python
from pathlib import Path  # non strettamente usato ma utile se servisse in futuro

# ---- base path e nomi file standard ----
# BASE_DIR: directory base da cui leggere config, chiavi e template.
BASE_DIR = (
    os.path.dirname(os.path.abspath(__file__))
    if "__file__" in globals()
    else os.getcwd()
)
# Percorso file chiavi (es. liste di parametri da rimuovere).
KEYS_PATH = os.path.join(BASE_DIR, "keys.json")
# Percorso file di configurazione principale dell'app.
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
# Percorso file contenente il token Telegram in chiaro (fallback).
TOKEN_PATH = os.path.join(BASE_DIR, "token.txt")

# ---- logger condiviso ----
_LOGGER_NAME = "puliscilink"  # nome del logger principale


def _bootstrap_logger() -> logging.Logger:
    """Crea e configura il logger condiviso dell'applicazione."""
    # Ottengo (o creo) l'istanza di logger con il nome dedicato.
    logger = logging.getLogger(_LOGGER_NAME)
    # Se non ha handler (prima inizializzazione), imposto uno StreamHandler base.
    if not logger.handlers:
        handler = logging.StreamHandler()
        # Definisco un formato semplice con timestamp, livello, nome e messaggio.
        fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
        # Associo l'handler al logger.
        logger.addHandler(handler)
        # Livello predefinito INFO (può essere alzato a DEBUG da __main__.py tramite config).
        logger.setLevel(logging.INFO)
        # Evito di propagare ad altri logger radice per non duplicare output.
        logger.propagate = False
    # Ritorno il logger configurato.
    return logger


# Istanza di logger condiviso da importare altrove.
logger: logging.Logger = _bootstrap_logger()


def set_log_level(level_name: str | None) -> None:
    """Imposta il livello del logger condiviso, se valido (DEBUG/INFO/... )."""
    # Se non è specificato alcun livello, non faccio nulla.
    if not level_name:
        return
    try:
        # Provo a mappare il nome al livello numerico ed applicarlo.
        logger.setLevel(getattr(logging, level_name, logging.INFO))
    except Exception:
        # In caso di valore non valido, rimango su INFO senza interrompere il flusso.
        pass


def load_json_file(path: str, *, required: bool = False) -> dict:
    """Carica un file JSON e ritorna un dict.

    - Se `required=True` e il file manca → sollevo un RuntimeError con messaggio chiaro.
    - Se il JSON non contiene un oggetto/dict → sollevo un RuntimeError descrittivo.
    """
    try:
        # Apro il file in lettura con encoding UTF‑8.
        with open(path, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)
    except FileNotFoundError as error:
        # Se il file è richiesto, l'assenza è un errore bloccante.
        if required:
            logger.error("File di configurazione richiesto non trovato: %s", path)
            raise RuntimeError(f"File richiesto non trovato: {path}") from error
        # Altrimenti loggo in INFO e ritorno un dict vuoto (valori di default).
        logger.info(
            "File opzionale non trovato: %s (uso valori vuoti/di default)", path
        )
        return {}
    except json.JSONDecodeError as error:
        # Se il contenuto non è JSON valido, sollevo errore con contesto.
        logger.error("Errore nel parsing JSON di %s: %s", path, error)
        raise RuntimeError(f"Errore nel parsing di {path}: {error}") from error

    # Verifico che la radice del JSON sia un oggetto/dict.
    if not isinstance(data, dict):
        logger.error("Il file %s non contiene un oggetto JSON (dict).", path)
        raise RuntimeError(
            f"Contenuto non valido in {path}: atteso un oggetto JSON (dict)"
        )

    # Log di debug con le chiavi caricate.
    logger.debug("Caricato JSON da %s (chiavi: %s)", path, list(data.keys()))
    # Ritorno il dict.
    return data


def render_from_file(filename: str, **ctx) -> str:
    """Carica un file template HTML e applica .format sui placeholder con escape sicuro."""
    # Costruisco il percorso partendo dal nome base e aggiungendo estensione .html.
    path = os.path.join(BASE_DIR, filename + ".html")
    # Apro e leggo il contenuto del template.
    with open(path, "r", encoding="utf-8") as file_handle:
        template_source = file_handle.read()
    # Eseguo escape HTML sui soli valori stringa passati come contesto.
    safe_context = {key: html.escape(str(value)) for key, value in ctx.items()}
    # Applico la formattazione e ritorno il risultato.
    return template_source.format(**safe_context)


def get_telegram_token() -> str:
    """Ritorna il token del bot Telegram: prima da variabile d'ambiente, poi da file di fallback."""
    # Controllo prima la variabile d'ambiente TELEGRAM_BOT_TOKEN.
    env_value = os.getenv("TELEGRAM_BOT_TOKEN")
    if env_value:
        token = env_value.strip()
        logger.info("Token Telegram letto da variabile d'ambiente")
        return token
    try:
        # Se non c'è in ambiente, provo a leggere token.txt.
        with open(TOKEN_PATH, "r", encoding="utf-8") as file_handle:
            token = file_handle.read().strip()
            logger.info("Token Telegram letto da file token.txt")
            return token
    except FileNotFoundError as error:
        # Se manca anche il file, sollevo errore guidando l'utente alla soluzione.
        logger.error(
            "Token mancante. Impostare TELEGRAM_BOT_TOKEN o creare 'token.txt'"
        )
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN o 'token.txt'") from error
