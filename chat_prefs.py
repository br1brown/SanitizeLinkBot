# chat_prefs.py
from __future__ import annotations
import json, os, tempfile
from dataclasses import dataclass
from typing import Dict, Any
from utils import logger, CHAT_PREFS_PATH

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

    @classmethod
    def from_defaults(cls) -> PrefsEntry:
        return cls(
            show_title=True,
            show_url=True,
            translate_url=False,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "show_title": self.show_title,
            "show_url": self.show_url,
            "translate_url": self.translate_url,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> PrefsEntry:
        base = cls.from_defaults().to_dict()
        base.update({k: bool(d.get(k, base[k])) for k in base.keys()})
        return cls(**base)


class ChatPrefs:
    _path: str | None = None
    _store: Dict[int, PrefsEntry] = {}

    @classmethod
    def load(cls) -> None:
        cls._path = os.path.join(os.path.dirname(__file__), CHAT_PREFS_PATH)
        try:
            with open(cls._path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                cls._store = {
                    int(k): PrefsEntry.from_dict(v if isinstance(v, dict) else {})
                    for k, v in raw.items()
                }
            logger.info(
                "Loaded chat preferences from %s with %d entries",
                cls._path,
                len(cls._store),
            )
        except FileNotFoundError:
            cls._store = {}
            logger.info(
                "No chat preferences file found at %s, starting with defaults",
                cls._path,
            )
        except Exception as e:
            cls._store = {}
            logger.error("Failed to load chat preferences from %s: %s", cls._path, e)

    @classmethod
    def save(cls) -> None:
        if not cls._path:
            return
        data = {str(k): v.to_dict() for k, v in cls._store.items()}
        payload = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        dirpath = os.path.dirname(cls._path)

        fd, tmp_path = tempfile.mkstemp(prefix=".prefs.", dir=dirpath)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, cls._path)  # atomico su POSIX/NT
            logger.info(
                "Saved chat preferences to %s (%d entries)", cls._path, len(data)
            )
        except Exception as e:
            logger.error("Failed to save chat preferences to %s: %s", cls._path, e)
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    @classmethod
    def get(cls, chat_id: int) -> PrefsEntry:
        if chat_id not in cls._store:
            cls._store[chat_id] = PrefsEntry.from_defaults()
            logger.debug("Initialized default preferences for chat %s", chat_id)
        return cls._store[chat_id]

    @classmethod
    def set(cls, chat_id: int, key: str, value: bool) -> PrefsEntry:
        entry = cls.get(chat_id)
        if key not in entry.to_dict():
            logger.error("Invalid preference key attempted: %s", key)
            raise KeyError(f"Invalid preference key: {key}")
        setattr(entry, key, bool(value))
        cls._store[chat_id] = entry
        cls.save()
        logger.info("Updated preference for chat %s: %s=%s", chat_id, key, value)
        return entry

    @classmethod
    def build_opts(cls, chat_id: int) -> SanitizerOpts:
        p = cls.get(chat_id)
        logger.debug(
            "Building SanitizerOpts for chat %s (show_url=%s, show_title=%s, translate_url=%s)",
            chat_id,
            p.show_url,
            p.show_title,
            p.translate_url
        )
        return SanitizerOpts(
            show_url=p.show_url,
            show_title=p.show_title,
            translate_url=p.translate_url
        )
