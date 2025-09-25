from __future__ import annotations
import os
import logging
from dataclasses import dataclass

# usa il tuo logger se esiste, altrimenti quello stdlib
try:
    from utils import logger  # type: ignore
except Exception:  # pragma: no cover
    logger = logging.getLogger(__name__)

def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "t", "yes", "y", "on"}

def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as e:
        raise RuntimeError(f"Invalid int for {name}: {raw!r}") from e

def _normalize_log_level(level_value: str | None) -> str | None:
    if not level_value:
        return None
    if level_value.isdigit():
        name = logging.getLevelName(int(level_value))
        return name if isinstance(name, str) and name.isupper() else "INFO"
    candidate = level_value.strip().upper()
    return candidate if candidate in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"} else "INFO"

@dataclass
class AppConfig:
    # Batch
    max_concurrency: int
    # HTTP
    connections_per_host: int
    max_redirects: int
    timeout_sec: int
    ttl_dns_cache: int
    valida_link_post_pulizia: bool
    # Logging
    log_level: str | None

    @classmethod
    def load(cls) -> "AppConfig":
        """Carica la configurazione da variabili d'ambiente, con default."""
        logger.debug("Loading configuration from environment variables")

        conf = cls(
            # Batch
            max_concurrency=_get_int("BATCH_MAX_CONCURRENCY", 6),

            # HTTP
            connections_per_host=_get_int("HTTP_CONNECTIONS_PER_HOST", 10),
            max_redirects=_get_int("HTTP_MAX_REDIRECTS", 30),
            timeout_sec=_get_int("HTTP_TIMEOUT_SEC", 30),
            ttl_dns_cache=_get_int("HTTP_TTL_DNS_CACHE", 60),
            valida_link_post_pulizia=_get_bool("HTTP_VALIDA_LINK_POST_PULIZIA", True),

            # Logging
            log_level=_normalize_log_level(os.getenv("LOG_LEVEL", "INFO")),
        )

        logger.info("Application configuration loaded from ENV")
        logger.debug("Configuration details %s", conf)
        return conf

    def __repr__(self) -> str:
        return (
            "AppConfig("
            f"show_title={self.show_title}, show_url={self.show_url}, "
            f"max_concurrency={self.max_concurrency}, connections_per_host={self.connections_per_host}, "
            f"max_redirects={self.max_redirects}, timeout_sec={self.timeout_sec}, "
            f"ttl_dns_cache={self.ttl_dns_cache}, valida_link_post_pulizia={self.valida_link_post_pulizia}, "
            f"log_level={self.log_level})"
        )
