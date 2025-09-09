from __future__ import annotations

# Modulo: app_config.py
# Scopo: gestione della configurazione dell'app in maniera semplice e centralizzata.

from utils import logger, load_json_file  # logging e utilità caricamento JSON
import logging  # per validare/normalizzare i livelli di log


class AppConfig:
    """Config generale del bot caricata da JSON con controllo chiavi minime.

    Nota: non fa validazioni complesse sui tipi, ma verifica la presenza delle chiavi richieste.
    """

    # Chiavi minime attese per ogni sezione della configurazione (usate in load()).
    _REQUIRED_KEYS = {
        "Output": {"show_title"},
        "Batch": {"max_concurrency"},
        "HTTP": {"connections_per_host", "max_redirects", "timeout_sec"},
    }

    def __init__(self, raw: dict) -> None:
        # Estraggo le sezioni già validate in load().
        output_conf = raw["Output"]
        batch_conf = raw["Batch"]
        http_conf = raw["HTTP"]
        logging_conf = raw.get("Logging", {}) or {}

        # ---- Opzioni output ----
        self.show_title: bool = bool(output_conf["show_title"])

        # ---- Opzioni batch ----
        self.max_concurrency: int = int(batch_conf["max_concurrency"])

        # ---- Opzioni HTTP di base e sicurezza ----
        self.connections_per_host: int = int(http_conf["connections_per_host"])
        self.ttl_dns_cache: int = int(http_conf["ttl_dns_cache"])
        self.max_redirects: int = int(http_conf["max_redirects"])
        self.timeout_sec: int = int(http_conf["timeout_sec"])
        self.valida_link_post_pulizia: bool = bool(
            http_conf.get("valida_link_post_pulizia", True)
        )

        # ---- Logging (opzionale) ----
        self.log_level: str | None = self._normalize_log_level(
            logging_conf.get("level")
        )

    @classmethod
    def load(cls, path: str) -> "AppConfig":
        """Carica la configurazione da file JSON e verifica che le sezioni obbligatorie esistano.

        In caso di mancanze lancia un errore con indicazioni esplicite per facilitare la correzione.
        """
        logger.debug("caricamento configurazione %s", path)
        # Carico il JSON dal percorso richiesto (se manca e required=True → RuntimeError).
        raw = load_json_file(path, required=True)

        # Colleziono anomalie per un unico messaggio di errore sintetico.
        missing_items: list[str] = []
        # Controllo che ogni sezione abbia le chiavi richieste.
        for section, keys in cls._REQUIRED_KEYS.items():
            if section not in raw or not isinstance(raw[section], dict):
                missing_items.append(f"- sezione mancante {section}")
                continue
            missing_keys = [k for k in keys if k not in raw[section]]
            if missing_keys:
                missing_items.append(f"- {section} chiavi mancanti {missing_keys}")

        # Se ho trovato problemi, costruisco un messaggio chiaro e blocco il flusso.
        if missing_items:
            message = "configurazione incompleta\n" + "\n".join(missing_items)
            logger.error(message)
            raise RuntimeError(message)

        # Istanzio la AppConfig.
        conf = cls(raw)
        logger.info("configurazione applicativa caricata correttamente")
        logger.debug("dettagli configurazione %s", conf)
        return conf

    @staticmethod
    def _normalize_log_level(level_value) -> str | None:
        """Accetta numeri o stringhe e restituisce un nome livello valido per logging.

        Se il valore non è valido, usa 'INFO' come fallback.
        """
        # Se non è impostato alcun livello, ritorno None (nessun override).
        if not level_value:
            return None

        # Caso: valore numerico (es. 10, 20, ...).
        if isinstance(level_value, int):
            name = logging.getLevelName(level_value)
            if isinstance(name, str) and name.isupper():
                return name
            logging.warning("log level numerico non riconosciuto fallback a info")
            return "INFO"

        # Caso: valore stringa (es. "DEBUG").
        if isinstance(level_value, str):
            candidate = level_value.strip().upper()
            valid_names = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
            if candidate in valid_names:
                return candidate
            logging.warning("log level stringa non valido fallback a info")
            return "INFO"

        # Caso: tipo non supportato → fallback "INFO".
        logging.warning("tipo log level non supportato fallback a info")
        return "INFO"

    def __repr__(self) -> str:
        # Rappresentazione breve utile per i log di debug.
        return (
            "AppConfig("
            f"show_title={self.show_title}, "
            f"max_redirects={self.max_redirects}, timeout_sec={self.timeout_sec}, "
            f"max_concurrency={self.max_concurrency}, connections_per_host={self.connections_per_host}, "
            ")"
        )
