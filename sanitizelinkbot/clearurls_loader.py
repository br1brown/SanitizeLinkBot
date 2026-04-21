from __future__ import annotations

# clearurls_loader.py — carica, compila e aggiorna il database ClearURLs.
#
# ClearURLs (https://clearurls.xyz) pubblica un JSON con "provider" (Amazon, YouTube, ecc.)
# che descrivono: quali URL coprono, quali parametri rimuovere, come estrarre l'URL vero
# da link wrapper. Questo modulo compila quel JSON in strutture ottimizzate per lookup rapido.

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit, parse_qsl, urlencode, urlunsplit
from typing import Optional

import aiohttp

from .utils import logger

CLEARURLS_RULES_URL = "https://rules2.clearurls.xyz/data.minify.json"


@dataclass(frozen=True)
class ProviderRules:
    """Regole compilate per un singolo provider ClearURLs. frozen=True: immutabile, sicuro da leggere senza lock."""

    name: str  # es. "AmazonAds" — usato solo nei log
    url_pattern: re.Pattern  # regex che identifica gli URL di questo provider
    complete_provider: bool  # se True il provider è un tracker completo; noi non blocchiamo, lo saltiamo
    exceptions: tuple[
        re.Pattern, ...
    ]  # se uno matcha l'URL, questo provider non si applica
    redirections: tuple[
        re.Pattern, ...
    ]  # gruppo 1 contiene l'URL nascosto nel wrapper (URL-encoded)
    rules: tuple[
        re.Pattern, ...
    ]  # regex ancorate ^...$  sul NOME del parametro query da rimuovere
    referral_marketing: tuple[
        re.Pattern, ...
    ]  # come rules, categoria diversa ma stessa logica
    raw_rules: tuple[
        re.Pattern, ...
    ]  # regex sull'URL completo: rimuovono porzioni intere (es. tutto il query string)
    # Alternanza precompilata di rules + referral_marketing: un singolo passaggio del motore
    # regex invece di N match separati. None se il provider non ha regole parametro.
    combined_param_rule: Optional[re.Pattern]


@dataclass
class ClearUrlsIndex:
    """Indice compilato: lista piatta di provider ordinati specifici → universali.

    "Specifici": urlPattern ancora su un dominio reale (contiene \\. nel pattern).
    "Universali": pattern senza ancoraggio di dominio (es. globalRules con .*).

    urlPattern è il piano di verità: find_providers non usa euristiche sui nomi dei parametri
    o sul formato del pattern. La scan di ~200 regex compilate costa < 1ms per URL — irrilevante
    per un bot Telegram e immunizza il codice da future variazioni di formato di ClearURLs.
    """

    providers: list[ProviderRules] = field(default_factory=list)

    def find_providers(self, url: str) -> list[ProviderRules]:
        """urlPattern.search() è l'unico arbitro: nessuna euristica, nessun parsing di regex."""
        return [p for p in self.providers if p.url_pattern.search(url)]


def _compile_safe(pattern: str, flags: int = re.IGNORECASE) -> Optional[re.Pattern]:
    """Compila una regex; restituisce None se invalida per non far crashare il loader su un provider rotto."""
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        logger.debug("ClearURLs: regex non valida %r — %s", pattern, exc)
        return None


def _compile_param_rule(rule: str) -> Optional[re.Pattern]:
    """Ancora la regex ClearURLs con ^(?:...)$ per fare full-match sul NOME del parametro.
    Senza ancore, "id" matcherebbe anche "video_id", "user_id", ecc. — troppi falsi positivi.
    """
    return _compile_safe(f"^(?:{rule})$")


def _compile_provider(name: str, raw: dict) -> Optional[ProviderRules]:
    """Compila un provider dal JSON ClearURLs. Restituisce None se urlPattern è invalido (provider inutilizzabile)."""
    url_pat = _compile_safe(raw.get("urlPattern", ""), re.IGNORECASE)
    if url_pat is None:
        logger.warning(
            "ClearURLs: il provider %r ha un urlPattern non valido — lo salto", name
        )
        return None

    def compile_list(key: str, compiler=_compile_safe) -> tuple[re.Pattern, ...]:
        """Compila una lista di stringhe regex, scartando silenziosamente quelle invalide."""
        compiled = []
        for pattern_str in raw.get(key, []):
            pat = compiler(pattern_str)
            if pat is not None:
                compiled.append(pat)
        return tuple(compiled)

    # Raccogliamo i pattern raw per costruire la regex combinata prima di compilarli
    # singolarmente: _compile_param_rule avvolge ogni pattern in ^(?:...)$ e non
    # espone più il testo originale, quindi dobbiamo lavorare sui raw.
    raw_param_patterns = raw.get("rules", []) + raw.get("referralMarketing", [])
    combined_param_rule: Optional[re.Pattern] = None
    if raw_param_patterns:
        combined_param_rule = _compile_safe(f"^(?:{'|'.join(raw_param_patterns)})$")

    return ProviderRules(
        name=name,
        url_pattern=url_pat,
        complete_provider=bool(raw.get("completeProvider", False)),
        exceptions=compile_list("exceptions"),
        redirections=compile_list("redirections"),
        # rules e referralMarketing usano ancore ^...$: vedi _compile_param_rule
        rules=compile_list("rules", _compile_param_rule),
        referral_marketing=compile_list("referralMarketing", _compile_param_rule),
        raw_rules=compile_list("rawRules"),
        combined_param_rule=combined_param_rule,
    )


def _compile_index(data: dict) -> ClearUrlsIndex:
    """Compila il JSON ClearURLs in un ClearUrlsIndex.

    I provider vengono separati in due gruppi:
      - specifici  (urlPattern con \\. → ancora su dominio reale): testati prima
      - universali (urlPattern senza \\. → pattern generico come .*): testati dopo

    L'ordinamento garantisce che regole dominio-specifiche abbiano priorità su quelle globali
    (es. le regole Amazon devono essere applicate prima di globalRules).
    La classificazione usa una semplice ricerca di stringa sul pattern compilato:
    nessun parsing di regex, nessuna euristica fragile.
    """
    specific: list[ProviderRules] = []
    universal: list[ProviderRules] = []
    count_skipped = 0

    for name, raw in data.get("providers", {}).items():
        provider = _compile_provider(name, raw)
        if provider is None:
            count_skipped += 1
            continue
        # \\. nel pattern compilato = separatore backslash-dot → dominio specifico.
        # Senza \\. il pattern non ancora su un dominio (es. ".*" di globalRules).
        if "\\." in provider.url_pattern.pattern:
            specific.append(provider)
        else:
            universal.append(provider)

    providers = specific + universal
    logger.info(
        "ClearURLs: %d provider caricati (%d specifici, %d universali, %d saltati)",
        len(providers),
        len(specific),
        len(universal),
        count_skipped,
    )
    return ClearUrlsIndex(providers=providers)


class ClearUrlsLoader:
    """Gestisce caricamento, hot-reload e aggiornamento mensile delle regole ClearURLs.

    Thread-safety: le letture di _index non richiedono lock (assegnazione Python è atomica grazie al GIL).
    I reload usano asyncio.Lock per evitare due aggiornamenti concorrenti.
    """

    def __init__(self, rules_path: Path) -> None:
        self._rules_path = rules_path
        self._index: Optional[ClearUrlsIndex] = None  # None finché non è caricato
        # Lock solo per il reload: evita due download/compilazioni sovrapposti
        self._reload_lock = asyncio.Lock()

    def load_sync(self) -> None:
        """Caricamento sincrono all'avvio, prima che il loop asyncio sia attivo.
        Se il file manca, il loader resta non caricato: il bot parte con solo keys.json.
        """
        if not self._rules_path.exists():
            logger.warning(
                "File delle regole ClearURLs non trovato in %s — layer disabilitato fino al primo download",
                self._rules_path,
            )
            return
        try:
            data = json.loads(self._rules_path.read_text(encoding="utf-8"))
            self._index = _compile_index(data)
            logger.info("Regole ClearURLs caricate da %s", self._rules_path)
        except Exception as exc:
            logger.error(
                "Caricamento delle regole ClearURLs dal disco fallito: %s", exc
            )

    async def reload_async(self) -> bool:
        """Ricarica dal disco in modo asincrono. File I/O in thread pool per non bloccare il loop.
        Lo swap self._index = new_index è atomico (singola assegnazione Python).
        """
        async with self._reload_lock:
            try:
                loop = asyncio.get_running_loop()
                # run_in_executor: il file I/O blocca, non va fatto direttamente nel loop asyncio
                text = await loop.run_in_executor(
                    None,
                    lambda: self._rules_path.read_text(encoding="utf-8"),
                )
                new_index = _compile_index(json.loads(text))
                self._index = new_index  # swap atomico: le coroutine in corso vedono o vecchio o nuovo, mai intermedio
                logger.info("Regole ClearURLs ricaricate correttamente")
                return True
            except Exception as exc:
                logger.error(
                    "Ricaricamento a caldo delle regole ClearURLs fallito: %s", exc
                )
                return False

    async def update_from_remote(self, session: aiohttp.ClientSession) -> bool:
        """Scarica regole aggiornate e fa hot-reload. Scrittura atomica: .tmp → os.replace().
        Se qualsiasi step fallisce, il file originale e l'indice in memoria restano invariati.
        """
        tmp_path = self._rules_path.with_suffix(".tmp")
        try:
            logger.info("ClearURLs: recupero delle regole da %s", CLEARURLS_RULES_URL)
            async with session.get(
                CLEARURLS_RULES_URL, timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                if resp.status != 200:
                    logger.warning(
                        "Il server remoto di ClearURLs ha restituito HTTP %d",
                        resp.status,
                    )
                    return False
                raw_bytes = await resp.read()

            data = json.loads(raw_bytes)
            if "providers" not in data or not isinstance(data["providers"], dict):
                logger.error(
                    "ClearURLs: JSON remoto privo della chiave 'providers' — annullo l'aggiornamento"
                )
                return False

            n_providers = len(data["providers"])
            # Scrittura atomica: scriviamo su .tmp e poi os.replace() (operazione atomica sul filesystem)
            tmp_path.write_bytes(raw_bytes)
            os.replace(tmp_path, self._rules_path)
            logger.info(
                "File delle regole ClearURLs aggiornato (%d byte, %d provider)",
                len(raw_bytes),
                n_providers,
            )
            return await self.reload_async()

        except Exception as exc:
            logger.error("Aggiornamento remoto di ClearURLs fallito: %s", exc)
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            return False

    async def run_periodic_updater(self, session: aiohttp.ClientSession) -> None:
        """Task di background: aggiorna ogni 5 giorni (120 ore).
        Se le regole sono già caricate, aspetta il primo intervallo prima di scaricare.
        Se mancano, aspetta 5 minuti per lasciar stabilizzare il bot prima del primo download.
        """
        INTERVAL_SEC = 5 * 24 * 3600
        
        if self.is_loaded:
            logger.info("ClearURLs: regole già presenti, prossimo aggiornamento tra ~5 giorni")
            await asyncio.sleep(INTERVAL_SEC)
        else:
            logger.info("ClearURLs: regole mancanti, primo download tra ~5 minuti")
            await asyncio.sleep(300)
            
        while True:
            await self.update_from_remote(session)
            logger.info("ClearURLs: prossimo aggiornamento pianificato tra ~5 giorni")
            await asyncio.sleep(INTERVAL_SEC)

    @property
    def is_loaded(self) -> bool:
        return self._index is not None

    def find_providers(self, url: str) -> list[ProviderRules]:
        """Restituisce i provider applicabili all'URL. urlPattern è il piano di verità."""
        if self._index is None:
            return []
        return self._index.find_providers(url)

    def apply_redirections(
        self, url: str, providers: list[ProviderRules]
    ) -> Optional[str]:
        """Estrae l'URL vero da un link wrapper senza richieste HTTP.
        Restituisce None se nessuna redirection matcha.
        """
        for provider in providers:
            if any(exc.search(url) for exc in provider.exceptions):
                continue
            for redir_pattern in provider.redirections:
                mtc = redir_pattern.search(url)
                # Il gruppo 1 deve esistere: è lì che ClearURLs mette l'URL destinazione
                if mtc and mtc.lastindex and mtc.lastindex >= 1:
                    target = unquote(
                        mtc.group(1)
                    )  # l'URL target è spesso URL-encoded (es. https%3A%2F%2F...)
                    if target.startswith(("http://", "https://")):
                        logger.debug("Applicato redirect di ClearURLs")
                        return target
        return None

    def apply_cleaning(self, url: str, providers: list[ProviderRules]) -> str:
        """Applica le regole di pulizia ClearURLs: exceptions → raw_rules → rules + referralMarketing."""
        result_url = url
        for provider in providers:
            if any(exc.search(result_url) for exc in provider.exceptions):
                continue
            if provider.complete_provider:
                continue  # tracker completo: ClearURLs bloccherebbe la nav, noi lo saltiamo
            for raw_rule in provider.raw_rules:
                result_url = raw_rule.sub(
                    "", result_url
                )  # rimuove porzioni raw (es. tutto il query string)
            if not provider.rules and not provider.referral_marketing:
                continue
            try:
                parts = urlsplit(result_url)
                params = parse_qsl(parts.query, keep_blank_values=True)
                if provider.combined_param_rule:
                    # Regex precompilata: un solo passaggio del motore per tutti i pattern
                    match_fn = provider.combined_param_rule.match
                    filtered = [
                        (param_name, param_val)
                        for param_name, param_val in params
                        if not match_fn(param_name)
                    ]
                else:
                    all_param_rules = list(provider.rules) + list(
                        provider.referral_marketing
                    )
                    filtered = [
                        (param_name, param_val)
                        for param_name, param_val in params
                        if not any(rule.match(param_name) for rule in all_param_rules)
                    ]
                if len(filtered) != len(params):
                    # Ricostruiamo l'URL solo se qualcosa è cambiato: evita allocazioni inutili
                    result_url = urlunsplit(
                        parts._replace(query=urlencode(filtered, doseq=True))
                    )
            except Exception as exc:
                logger.debug(
                    "Pulizia dei parametri ClearURLs fallita per il provider %s: %s",
                    provider.name,
                    exc,
                )
        return result_url
