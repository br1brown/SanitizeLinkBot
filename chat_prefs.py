# chat_prefs.py
from __future__ import annotations

import asyncio
import os
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict

from utils import BASE_DIR, logger

_DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(_DATA_DIR, exist_ok=True)
_DB_PATH = os.path.join(_DATA_DIR, "chat_prefs.db")
PREF_KEYS = frozenset({"show_title", "show_url", "translate_url", "group_auto"})
_VALID_KEYS = PREF_KEYS


@dataclass
class SanitizerOpts:
    show_url: bool
    show_title: bool
    translate_url: bool


@dataclass
class PrefsEntry:
    show_title: bool
    show_url: bool
    translate_url: bool
    group_auto: bool  # True = pulisce tutti i link nel gruppo; False = solo se triggerato

    @classmethod
    def from_defaults(cls) -> PrefsEntry:
        return cls(
            show_title=True,
            show_url=True,
            translate_url=False,
            group_auto=False,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "show_title": self.show_title,
            "show_url": self.show_url,
            "translate_url": self.translate_url,
            "group_auto": self.group_auto,
        }


# ---------------------------------------------------------------------------
# helpers SQLite (funzioni pure, niente stato globale)
# ---------------------------------------------------------------------------

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_entry(row: sqlite3.Row) -> PrefsEntry:
    return PrefsEntry(
        show_title=bool(row["show_title"]),
        show_url=bool(row["show_url"]),
        translate_url=bool(row["translate_url"]),
        group_auto=bool(row["group_auto"]),
    )


def _init_db() -> None:
    with _connect() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_prefs (
                chat_id       INTEGER PRIMARY KEY,
                show_title    INTEGER NOT NULL DEFAULT 1,
                show_url      INTEGER NOT NULL DEFAULT 1,
                translate_url INTEGER NOT NULL DEFAULT 0,
                group_auto    INTEGER NOT NULL DEFAULT 0
            )
        """)
    logger.info("SQLite database ready at %s", _DB_PATH)


def _get_sync(chat_id: int) -> PrefsEntry:
    with _connect() as conn:
        row = conn.execute(
            "SELECT show_title, show_url, translate_url, group_auto "
            "FROM chat_prefs WHERE chat_id = ?",
            (chat_id,),
        ).fetchone()
    return _row_to_entry(row) if row else PrefsEntry.from_defaults()


def _set_sync(chat_id: int, key: str, value: bool) -> PrefsEntry:
    val_int = int(value)
    with _connect() as conn:
        # Upsert atomico: inserisce con i default se manca, oppure aggiorna solo la chiave specifica
        sql = f"""
            INSERT INTO chat_prefs (chat_id, {key}) VALUES (?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET {key} = excluded.{key}
        """
        conn.execute(sql, (chat_id, val_int))
        row = conn.execute(
            "SELECT show_title, show_url, translate_url, group_auto "
            "FROM chat_prefs WHERE chat_id = ?",
            (chat_id,),
        ).fetchone()
    return _row_to_entry(row)


# ---------------------------------------------------------------------------
# API pubblica — stessa interfaccia di prima, zero breaking changes
# ---------------------------------------------------------------------------

class ChatPrefs:
    @classmethod
    def load(cls) -> None:
        """Inizializza il DB SQLite. Chiamare una volta all'avvio."""
        _init_db()

    @classmethod
    def get(cls, chat_id: int) -> PrefsEntry:
        """Lettura sincrona. SQLite è abbastanza veloce da non bloccare l'event loop."""
        return _get_sync(chat_id)

    @classmethod
    async def set(cls, chat_id: int, key: str, value: bool) -> PrefsEntry:
        """Scrittura asincrona via thread pool per non bloccare l'event loop."""
        if key not in _VALID_KEYS:
            logger.error("Invalid preference key attempted: %s", key)
            raise KeyError(f"Invalid preference key: {key}")
        result = await asyncio.to_thread(_set_sync, chat_id, key, value)
        logger.info("Updated preference for chat %s: %s=%s", chat_id, key, value)
        return result

    @classmethod
    def build_opts(cls, chat_id: int) -> SanitizerOpts:
        p = cls.get(chat_id)
        logger.debug(
            "Building SanitizerOpts for chat %s (show_url=%s, show_title=%s, translate_url=%s)",
            chat_id, p.show_url, p.show_title, p.translate_url,
        )
        return SanitizerOpts(
            show_url=p.show_url,
            show_title=p.show_title,
            translate_url=p.translate_url)