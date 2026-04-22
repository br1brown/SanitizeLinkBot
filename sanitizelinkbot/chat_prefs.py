# chat_prefs.py — preferenze per chat salvate su SQLite, con cache in memoria.
from __future__ import annotations

import asyncio
import os
import sqlite3
from dataclasses import dataclass

from .utils import PROJECT_ROOT, logger

_DATA_DIR = os.path.join(PROJECT_ROOT, "data")
os.makedirs(_DATA_DIR, exist_ok=True)
_DB_PATH = os.path.join(_DATA_DIR, "chat_prefs.db")

PREF_KEYS = frozenset({"show_title", "show_url", "use_privacy_frontend", "group_auto"})
_VALID_KEYS = PREF_KEYS

# mappa nome attributo Python → nome colonna DB (solo dove divergono)
_ATTR_TO_COL: dict[str, str] = {"use_privacy_frontend": "translate_url"}


@dataclass
class SanitizerOpts:
    """Opzioni di sanitizzazione attive per una singola richiesta. Costruita da ChatPrefs.build_opts()."""

    show_url: bool
    show_title: bool
    use_privacy_frontend: (
        bool  # True = reindirizza verso frontend alternativi (Invidious, xcancel, ecc.)
    )


@dataclass
class PrefsEntry:
    """Preferenze memorizzate per una chat."""

    show_title: bool
    show_url: bool
    use_privacy_frontend: bool
    group_auto: bool

    @classmethod
    def from_defaults(cls) -> PrefsEntry:
        return cls(
            show_title=True, show_url=True, use_privacy_frontend=False, group_auto=False
        )


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = (
        sqlite3.Row
    )  # accesso ai campi per nome (row["col"]) invece che per indice
    return conn


def _row_to_entry(row: sqlite3.Row) -> PrefsEntry:
    return PrefsEntry(
        show_title=bool(row["show_title"]),
        show_url=bool(row["show_url"]),
        use_privacy_frontend=bool(row["translate_url"]),
        group_auto=bool(row["group_auto"]),
    )


def _init_db() -> None:
    with _connect() as conn:
        conn.execute(
            "PRAGMA journal_mode=WAL"
        )  # WAL: letture e scritture non si bloccano a vicenda
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_prefs (
                chat_id       INTEGER PRIMARY KEY,
                show_title    INTEGER NOT NULL DEFAULT 1,
                show_url      INTEGER NOT NULL DEFAULT 1,
                translate_url INTEGER NOT NULL DEFAULT 0,
                group_auto    INTEGER NOT NULL DEFAULT 0
            )
        """)
    logger.info("Database SQLite pronto in %s", _DB_PATH)


def _get_sync(chat_id: int) -> PrefsEntry:
    with _connect() as conn:
        row = conn.execute(
            "SELECT show_title, show_url, translate_url, group_auto FROM chat_prefs WHERE chat_id = ?",
            (chat_id,),
        ).fetchone()
    return _row_to_entry(row) if row else PrefsEntry.from_defaults()


def _set_sync(chat_id: int, key: str, value: bool) -> PrefsEntry:
    col = _ATTR_TO_COL.get(key, key)  # traduce nome attributo → colonna DB se necessario
    val_int = int(value)
    with _connect() as conn:
        conn.execute(
            f"INSERT INTO chat_prefs (chat_id, {col}) VALUES (?, ?) "
            f"ON CONFLICT(chat_id) DO UPDATE SET {col} = excluded.{col}",
            (chat_id, val_int),
        )
        row = conn.execute(
            "SELECT show_title, show_url, translate_url, group_auto FROM chat_prefs WHERE chat_id = ?",
            (chat_id,),
        ).fetchone()
    return _row_to_entry(row)


class ChatPrefs:
    """API pubblica per le preferenze chat. Cache in memoria per evitare query SQLite ad ogni messaggio."""

    _cache: dict[int, PrefsEntry] = {}

    @classmethod
    def load(cls) -> None:
        """Inizializza il DB SQLite. Chiamare una volta all'avvio."""
        _init_db()

    @classmethod
    def get(cls, chat_id: int) -> PrefsEntry:
        """Lettura dalla cache; SQLite solo se la chat non è ancora in cache."""
        if chat_id in cls._cache:
            return cls._cache[chat_id]
        entry = _get_sync(chat_id)
        cls._cache[chat_id] = entry
        return entry

    @classmethod
    async def set(cls, chat_id: int, key: str, value: bool) -> PrefsEntry:
        """Scrittura asincrona via asyncio.to_thread: il DB I/O blocca, non va fatto nel loop."""
        if key not in _VALID_KEYS:
            logger.error("Tentativo di chiave preferenza non valida: %s", key)
            raise KeyError(f"Invalid preference key: {key}")
        result = await asyncio.to_thread(_set_sync, chat_id, key, value)
        cls._cache[chat_id] = result  # aggiorna la cache con il valore scritto
        logger.info(
            "Aggiornata la preferenza per la chat %s: %s=%s", chat_id, key, value
        )
        return result

    @classmethod
    def build_opts(cls, chat_id: int) -> SanitizerOpts:
        """Costruisce SanitizerOpts dalle preferenze della chat."""
        prf = cls.get(chat_id)
        logger.debug(
            "Costruzione SanitizerOpts per la chat %s (show_url=%s, show_title=%s, use_privacy_frontend=%s)",
            chat_id,
            prf.show_url,
            prf.show_title,
            prf.use_privacy_frontend,
        )
        return SanitizerOpts(
            show_url=prf.show_url,
            show_title=prf.show_title,
            use_privacy_frontend=prf.use_privacy_frontend,
        )
