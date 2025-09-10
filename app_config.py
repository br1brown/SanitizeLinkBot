from __future__ import annotations

# modulo: app_config.py
# scopo: gestione centralizzata della configurazione dell app

from utils import logger, load_json_file
import logging


class AppConfig:
    """config generale caricata da json con controllo delle chiavi minime"""

    _REQUIRED_KEYS = {
        "Output": {"show_title"},
        "Batch": {"max_concurrency"},
        "HTTP": {
            "connections_per_host",
            "max_redirects",
            "timeout_sec",
            "ttl_dns_cache",
        },
    }

    def __init__(self, raw: dict) -> None:
        output_conf = raw["Output"]
        batch_conf = raw["Batch"]
        http_conf = raw["HTTP"]
        logging_conf = raw.get("Logging", {}) or {}

        # opzioni output
        self.show_title: bool = bool(output_conf["show_title"])

        # opzioni batch
        self.max_concurrency: int = int(batch_conf["max_concurrency"])

        # opzioni http
        self.connections_per_host: int = int(http_conf["connections_per_host"])
        self.ttl_dns_cache: int = int(http_conf["ttl_dns_cache"])
        self.max_redirects: int = int(http_conf["max_redirects"])
        self.timeout_sec: int = int(http_conf["timeout_sec"])
        self.valida_link_post_pulizia: bool = bool(
            http_conf.get("valida_link_post_pulizia", True)
        )

        # logging opzionale
        self.log_level: str | None = self._normalize_log_level(
            logging_conf.get("level")
        )

    @classmethod
    def load(cls, path: str) -> "AppConfig":
        """carica la configurazione e verifica che le sezioni obbligatorie esistano"""
        logger.debug("Loading configuration from %s", path)
        raw = load_json_file(path, required=True)

        missing_items: list[str] = []
        for section, keys in cls._REQUIRED_KEYS.items():
            if section not in raw or not isinstance(raw[section], dict):
                missing_items.append(f"- missing section {section}")
                continue
            missing_keys = [k for k in keys if k not in raw[section]]
            if missing_keys:
                missing_items.append(f"- {section} missing keys {missing_keys}")

        if missing_items:
            message = "incomplete configuration\n" + "\n".join(missing_items)
            logger.error(message)
            raise RuntimeError(message)

        conf = cls(raw)
        logger.info("Application configuration loaded successfully")
        logger.debug("Configuration details %s", conf)
        return conf

    @staticmethod
    def _normalize_log_level(level_value) -> str | None:
        """accetta numero o stringa e restituisce un nome livello valido"""
        if not level_value:
            return None
        if isinstance(level_value, int):
            name = logging.getLevelName(level_value)
            if isinstance(name, str) and name.isupper():
                return name
            logging.warning("Numeric log level not recognized, falling back to INFO")
            return "INFO"
        if isinstance(level_value, str):
            candidate = level_value.strip().upper()
            valid_names = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
            if candidate in valid_names:
                return candidate
            logging.warning("String log level not valid, falling back to INFO")
            return "INFO"
        logging.warning("Unsupported log level type, falling back to INFO")
        return "INFO"

    def __repr__(self) -> str:
        return (
            "AppConfig("
            f"show_title={self.show_title}, "
            f"max_redirects={self.max_redirects}, timeout_sec={self.timeout_sec}, "
            f"max_concurrency={self.max_concurrency}, connections_per_host={self.connections_per_host}, "
            ")"
        )
