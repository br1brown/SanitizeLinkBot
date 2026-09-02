from __future__ import annotations

# debounce_loader.py — carica, compila e aggiorna la lista "debounce" di Brave
# (https://github.com/brave/adblock-lists), un elenco di redirector/bounce-tracker
# complementare a ClearURLs. Stessa architettura di clearurls_loader.py.

import asyncio
import base64
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit
from typing import Optional

import aiohttp

from .utils import logger

DEBOUNCE_RULES_URL = (
    "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/debounce.json"
)


def _compile_safe(pattern: str, flags: int = re.IGNORECASE) -> Optional[re.Pattern]:
    """Compila una regex; restituisce None se invalida per non far crashare il loader su una regola rotta."""
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        logger.debug("Debounce: regex non valida %r — %s", pattern, exc)
        return None


def _glob_to_regex(glob_pattern: str) -> Optional[re.Pattern]:
    """Traduce un pattern glob di Brave (es. "*://*.esempio.com/r?*") in una regex. Solo "*" è wildcard."""
    pieces = glob_pattern.split("*")
    escaped = ".*".join(re.escape(piece) for piece in pieces)
    return _compile_safe(f"^{escaped}$")


def _decode_base64_param(raw_value: str) -> Optional[str]:
    """Decodifica un valore base64 (alfabeto URL-safe o standard, padding ripristinato) da una query string."""
    text = unquote(raw_value)
    padded = text + "=" * (-len(text) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(padded).decode("utf-8", errors="strict")
        except Exception:
            continue
    return None


def _apply_prepend_scheme(candidate: str, scheme: str | None) -> str:
    """Se la regola dichiara prepend_scheme e il candidato non ha già uno schema, lo aggiunge."""
    if scheme and not candidate.startswith(("http://", "https://")):
        return f"{scheme}://{candidate.lstrip('/')}"
    return candidate


@dataclass(frozen=True)
class DebounceRule:
    """Regola compilata per un singolo redirector. frozen=True: immutabile, sicuro da leggere senza lock."""

    include: tuple[re.Pattern, ...]  # URL che questa regola copre
    exclude: tuple[re.Pattern, ...]  # se uno matcha l'URL, la regola non si applica
    action: str  # "redirect" | "base64,redirect" | "regex-path" | "regex-path-template"
    param: str  # nome del query param (redirect/base64,redirect) o regex sul path (le due varianti regex-path)
    param_re: Optional[
        re.Pattern
    ]  # "param" precompilato come regex, solo per le varianti regex-path
    redirect_url_template: Optional[str]  # solo per regex-path-template, es. "https://.../v=$1"
    prepend_scheme: Optional[str]  # es. "https", se il candidato estratto può mancare di schema

    def covers(self, url: str) -> bool:
        return any(pattern.search(url) for pattern in self.include) and not any(
            pattern.search(url) for pattern in self.exclude
        )

    def extract_target(self, url: str) -> Optional[str]:
        """Applica l'azione della regola e restituisce l'URL di destinazione, o None se non estraibile."""
        try:
            if self.action == "redirect":
                candidate = self._extract_query_param(url)
                if candidate:
                    candidate = unquote(candidate)
            elif self.action == "base64,redirect":
                raw = self._extract_query_param(url)
                candidate = _decode_base64_param(raw) if raw else None
            elif self.action in ("regex-path", "regex-path-template"):
                candidate = self._extract_from_path(url)
            else:
                candidate = None  # azione sconosciuta: ignoriamo la regola invece di fallire
        except Exception:
            return None

        if not candidate:
            return None
        candidate = _apply_prepend_scheme(candidate, self.prepend_scheme)
        return candidate if candidate.startswith(("http://", "https://")) else None

    def _extract_query_param(self, url: str) -> Optional[str]:
        """Legge il parametro "param" dalla query grezza, preservando eventuali "+" letterali."""
        query = urlsplit(url).query
        for raw_pair in query.split("&"):
            key, _, val = raw_pair.partition("=")
            if key == self.param and val:
                return val
        return None

    def _extract_from_path(self, url: str) -> Optional[str]:
        if self.param_re is None:
            return None
        match = self.param_re.search(urlsplit(url).path)
        if not match or not match.lastindex:
            return None
        if self.action == "regex-path-template":
            if not self.redirect_url_template:
                return None
            result = self.redirect_url_template  # sostituzione manuale dei placeholder $1, $2, ...
            for group_index in range(1, (match.lastindex or 0) + 1):
                result = result.replace(f"${group_index}", match.group(group_index) or "")
            return result
        return unquote(match.group(1))


_KNOWN_ACTIONS = frozenset({"redirect", "base64,redirect", "regex-path", "regex-path-template"})


def _compile_rule(raw: dict) -> Optional[DebounceRule]:
    """Compila una regola dal JSON Brave. Restituisce None se non ha pattern include utilizzabili o l'azione non è nota."""
    include = tuple(
        pattern
        for pattern in (_glob_to_regex(glob) for glob in raw.get("include", []))
        if pattern is not None
    )
    if not include:
        logger.debug("Debounce: regola scartata, nessun pattern include valido — %r", raw)
        return None

    action = raw.get("action", "")
    if action not in _KNOWN_ACTIONS:
        logger.debug("Debounce: regola scartata, azione %r non riconosciuta — %r", action, raw)
        return None

    exclude = tuple(
        pattern
        for pattern in (_glob_to_regex(glob) for glob in raw.get("exclude", []))
        if pattern is not None
    )

    param = raw.get("param", "")
    param_re = (
        _compile_safe(param) if action in ("regex-path", "regex-path-template") else None
    )

    return DebounceRule(
        include=include,
        exclude=exclude,
        action=action,
        param=param,
        param_re=param_re,
        redirect_url_template=raw.get("redirect_url_template"),
        prepend_scheme=raw.get("prepend_scheme"),
    )


@dataclass
class DebounceIndex:
    """Indice compilato: lista piatta di regole, tutte ancorate a un host specifico nel pattern include."""

    rules: list[DebounceRule] = field(default_factory=list)

    def extract_target(self, url: str) -> Optional[str]:
        """Prima regola che copre l'URL vince."""
        for rule in self.rules:
            if rule.covers(url):
                target = rule.extract_target(url)
                if target:
                    return target
        return None


def _compile_index(data: list) -> DebounceIndex:
    rules: list[DebounceRule] = []
    count_skipped = 0
    for raw in data:
        rule = _compile_rule(raw)
        if rule is None:
            count_skipped += 1
            continue
        rules.append(rule)
    logger.info(
        "Debounce: %d regole caricate (%d saltate)", len(rules), count_skipped
    )
    return DebounceIndex(rules=rules)


class DebounceLoader:
    """Gestisce caricamento, hot-reload e aggiornamento periodico della lista Debounce di Brave. Stessa architettura di ClearUrlsLoader."""

    def __init__(self, rules_path: Path) -> None:
        self._rules_path = rules_path
        self._index: Optional[DebounceIndex] = None
        self._reload_lock = asyncio.Lock()

    def load_sync(self) -> None:
        """Caricamento sincrono all'avvio. Se il file manca, il loader resta non caricato."""
        if not self._rules_path.exists():
            logger.warning(
                "File delle regole Debounce non trovato in %s — layer disabilitato fino al primo download",
                self._rules_path,
            )
            return
        try:
            data = json.loads(self._rules_path.read_text(encoding="utf-8"))
            self._index = _compile_index(data)
            logger.info("Regole Debounce caricate da %s", self._rules_path)
        except Exception as exc:
            logger.error("Caricamento delle regole Debounce dal disco fallito: %s", exc)

    async def reload_async(self) -> bool:
        """Ricarica dal disco in modo asincrono. File I/O in thread pool per non bloccare il loop."""
        async with self._reload_lock:
            try:
                loop = asyncio.get_running_loop()
                text = await loop.run_in_executor(
                    None, lambda: self._rules_path.read_text(encoding="utf-8")
                )
                new_index = _compile_index(json.loads(text))
                self._index = new_index  # swap atomico: le coroutine in corso vedono o vecchio o nuovo, mai intermedio
                logger.info("Regole Debounce ricaricate correttamente")
                return True
            except Exception as exc:
                logger.error("Ricaricamento a caldo delle regole Debounce fallito: %s", exc)
                return False

    async def update_from_remote(self, session: aiohttp.ClientSession) -> bool:
        """Scarica regole aggiornate e fa hot-reload. Scrittura atomica: .tmp → os.replace()."""
        tmp_path = self._rules_path.with_suffix(".tmp")
        try:
            logger.info("Debounce: recupero delle regole da %s", DEBOUNCE_RULES_URL)
            async with session.get(
                DEBOUNCE_RULES_URL, timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                if resp.status != 200:
                    logger.warning(
                        "Il server remoto di Debounce ha restituito HTTP %d", resp.status
                    )
                    return False
                raw_bytes = await resp.read()

            data = json.loads(raw_bytes)
            if not isinstance(data, list):
                logger.error(
                    "Debounce: JSON remoto non è una lista di regole — annullo l'aggiornamento"
                )
                return False

            tmp_path.write_bytes(raw_bytes)
            os.replace(tmp_path, self._rules_path)
            logger.info(
                "File delle regole Debounce aggiornato (%d byte, %d regole)",
                len(raw_bytes),
                len(data),
            )
            return await self.reload_async()

        except Exception as exc:
            logger.error("Aggiornamento remoto di Debounce fallito: %s", exc)
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            return False

    async def run_periodic_updater(self, session: aiohttp.ClientSession) -> None:
        """Task di background: aggiorna ogni 5 giorni, stesso intervallo di ClearURLs."""
        INTERVAL_SEC = 5 * 24 * 3600

        if self.is_loaded:
            logger.info("Debounce: regole già presenti, prossimo aggiornamento tra ~5 giorni")
            await asyncio.sleep(INTERVAL_SEC)
        else:
            logger.info("Debounce: regole mancanti, primo download tra ~1 minuto")
            await asyncio.sleep(60)

        while True:
            await self.update_from_remote(session)
            logger.info("Debounce: prossimo aggiornamento pianificato tra ~5 giorni")
            await asyncio.sleep(INTERVAL_SEC)

    @property
    def is_loaded(self) -> bool:
        return self._index is not None

    def extract_target(self, url: str) -> Optional[str]:
        """Restituisce l'URL di destinazione se url è coperto da una regola, altrimenti None."""
        if self._index is None:
            return None
        return self._index.extract_target(url)
