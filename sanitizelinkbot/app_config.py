from __future__ import annotations

# app_config.py — configurazione dell'applicazione caricata da variabili d'ambiente.

import os
import logging
from dataclasses import dataclass

from .utils import logger


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    # Set-lookup O(1); gestisce varianti comuni: "true", "1", "yes", "on"
    return str(raw).strip().lower() in {"1", "true", "t", "yes", "y", "on"}


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"Invalid int for {name}: {raw!r}") from exc


def _normalize_log_level(level_value: str | None) -> str | None:
    if not level_value:
        return None
    if level_value.isdigit():
        # Supporta livelli numerici (es. LOG_LEVEL=10 → "DEBUG")
        name = logging.getLevelName(int(level_value))
        return name if isinstance(name, str) and name.isupper() else "INFO"
    candidate = level_value.strip().upper()
    # Whitelist: fallback a INFO per valori sconosciuti invece di far crashare
    return (
        candidate
        if candidate in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        else "INFO"
    )


@dataclass
class AppConfig:
    max_concurrency: int  # URL elaborati in parallelo in sanitize_batch
    cache_max_size: int  # dimensione della cache LRU degli URL già elaborati
    connections_per_host: int  # connessioni HTTP simultanee verso lo stesso host
    max_redirects: int  # massimo redirect HTTP seguiti (passato ad aiohttp)
    timeout_sec: int  # timeout totale per ogni richiesta HTTP
    ttl_dns_cache: int  # TTL della cache DNS in secondi
    valida_link_post_pulizia: (
        bool  # se True, verifica che l'URL pulito punti alla stessa pagina
    )
    urlscan_api_key: str | None  # Chiave API per urlscan.io (opzionale)
    log_level: str | None

    @classmethod
    def load(cls) -> "AppConfig":
        """Carica la configurazione da variabili d'ambiente con i default documentati nel README."""
        logger.debug("Caricamento della configurazione dalle variabili d'ambiente")
        conf = cls(
            max_concurrency=_get_int("BATCH_MAX_CONCURRENCY", 6),
            cache_max_size=_get_int("CACHE_MAX_SIZE", 100),
            connections_per_host=_get_int("HTTP_CONNECTIONS_PER_HOST", 10),
            max_redirects=_get_int("HTTP_MAX_REDIRECTS", 30),
            timeout_sec=_get_int("HTTP_TIMEOUT_SEC", 30),
            ttl_dns_cache=_get_int("HTTP_TTL_DNS_CACHE", 60),
            valida_link_post_pulizia=_get_bool("HTTP_VALIDA_LINK_POST_PULIZIA", True),
            urlscan_api_key=os.getenv("URLSCAN_API_KEY"),
            log_level=_normalize_log_level(os.getenv("LOG_LEVEL", "INFO")),
        )
        logger.info("Configurazione dell'applicazione caricata da ENV")
        logger.debug("Dettagli configurazione %s", conf)
        return conf

    def __repr__(self) -> str:
        return (
            f"AppConfig(max_concurrency={self.max_concurrency}, cache_max_size={self.cache_max_size}, "
            f"connections_per_host={self.connections_per_host}, max_redirects={self.max_redirects}, "
            f"timeout_sec={self.timeout_sec}, ttl_dns_cache={self.ttl_dns_cache}, "
            f"valida_link_post_pulizia={self.valida_link_post_pulizia}, urlscan_api_key={'***' if self.urlscan_api_key else None}, "
            f"log_level={self.log_level})"
        )
