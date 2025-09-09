from __future__ import annotations

# Modulo: sanitizer.py
# Scopo: pulire URL (rimozione parametri di tracciamento), seguire redirect e
#        opzionalmente estrarre il titolo della pagina finale.
# Note: nomi di variabile parlanti e commenti puntuali su ogni passaggio.

from utils import logger  # logger condiviso per debug
from collections import OrderedDict  # per deduplicare preservando ordine

import re  # regex per estrazioni/parsing semplici
import html  # per unescape e normalizzazione testo HTML
import asyncio  # per concorrenza asincrona
from urllib.parse import (  # utilità per scomporre/ricomporre URL
    urlsplit,
    urlunsplit,
    parse_qsl,
    urlencode,
    urljoin,
)
import aiohttp  # client HTTP asincrono

from app_config import AppConfig  # configurazione applicativa


class Sanitizer:
    """Gestisce la pulizia degli URL e opzionalmente estrae il titolo della pagina.

    - Rimuove parametri di tracciamento secondo liste configurabili.
    - Segue redirect HTTP/meta refresh/JS fino a un limite.
    - Valida l'URL finale (opzionale) con una richiesta leggera.
    """

    def __init__(
        self,
        *,
        exact_keys: set[str],
        prefix_keys: tuple[str, ...],
        ends_with: tuple[str, ...],
        frag_keys: tuple[str, ...],
        domain_whitelist: dict[str, dict] | None = None,
        conf: AppConfig,
    ) -> None:
        # Log di inizializzazione per trasparenza su regole caricate.
        logger.debug("inizializzazione sanitizer con set di regole e whitelist domini")
        # Normalizzo tutte le chiavi per confronti case-insensitive.
        self.EXACT_KEYS = set(map(str.lower, exact_keys or set()))
        self.PREFIX_KEYS = tuple(k.lower() for k in (prefix_keys or ()))
        self.ENDS_WITH = tuple(k.lower() for k in (ends_with or ()))
        self.FRAG_KEYS = tuple(k.lower() for k in (frag_keys or ()))
        # Creo la whitelist dei domini su cui NON applicare la pulizia parametri.
        self.DOMAIN_WHITELIST = {
            (domain or "").lower(): rules
            for domain, rules in (domain_whitelist or {}).items()
        }
        # Conservo un riferimento alla configurazione runtime.
        self.conf = conf
        # Sessione HTTP aiohttp condivisa (creata lazy al primo uso).
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Crea (se serve) una sessione HTTP condivisa con timeout e limiti sensati."""
        # Se non esiste una sessione oppure è stata chiusa, la creo.
        if self._session is None or self._session.closed:
            logger.debug(
                "creazione di aiohttp clientsession con timeout e limit per host"
            )
            # Connettore con limiti per host e TTL della cache DNS.
            connector = aiohttp.TCPConnector(
                limit_per_host=(
                    self.conf.connections_per_host
                    if self.conf.connections_per_host > 0
                    else None
                ),
                ttl_dns_cache=self.conf.ttl_dns_cache,
            )
            # Timeout totale e di connessione (prudenziale).
            timeout_config = aiohttp.ClientTimeout(
                total=self.conf.timeout_sec,
                connect=self.conf.timeout_sec / 3,
            )
            # Creo la sessione vera e propria.
            self._session = aiohttp.ClientSession(
                timeout=timeout_config, connector=connector
            )
        # Ritorno la sessione pronta all'uso.
        return self._session

    async def close(self) -> None:
        """Chiude la sessione HTTP se ancora aperta per liberare risorse."""
        # Se la sessione c'è ed è ancora attiva, la chiudo e azzero il riferimento.
        if self._session and not self._session.closed:
            logger.debug("chiusura sessione http")
            await self._session.close()
            self._session = None

    async def _check_url_ok(self, url: str) -> bool:
        """Verifica che un URL risponda con codice 'accettabile' (esistenza).

        - Considera validi: 2xx, 3xx
        - Tollerati: 401/403 (alcuni siti bloccheranno bot ma l'URL esiste)
        """
        try:
            # Ottengo la sessione HTTP.
            session = await self._get_session()
            # Richiesta GET molto leggera grazie all'header Range (solo il primo byte).
            async with session.get(
                url,
                headers={"Range": "bytes=0-0"},
                allow_redirects=True,
                max_redirects=self.conf.max_redirects,
            ) as response:
                # Valuto lo status 2xx/3xx come valido.
                if 200 <= response.status < 300 or 300 <= response.status < 400:
                    return True
                # Accetto 401/403 come "esiste ma protetto", purché schema http/https.
                if response.status in (401, 403) and url.startswith(
                    ("http://", "https://")
                ):
                    return True
                # Altri codici → non valido.
                return False
        except asyncio.TimeoutError:
            # Timeout: segnalo con warning e considero non valido.
            logger.warning("Timeout verificando %s", url)
            return False
        except aiohttp.ClientError as error:
            # Errori lato client HTTP: loggo e considero non valido.
            logger.warning("Errore HTTP verificando %s: %s", url, error)
            return False
        except Exception as error:
            # Qualunque altro errore inatteso: loggo dettagli e considero non valido.
            logger.error(
                "Errore inatteso verificando %s: %s", url, error, exc_info=True
            )
            return False

    def is_parametro_da_rimuovere(self, key: str) -> bool:
        """Decide se un parametro di query va rimosso (match esatto, prefisso o suffisso)."""
        # Porto la chiave a minuscolo con fallback su stringa vuota.
        lowered_key = (key or "").lower()
        # Verifico regole: esatto / inizia con uno dei prefissi / termina con uno dei suffissi.
        should_remove = (
            lowered_key in self.EXACT_KEYS
            or any(lowered_key.startswith(prefix) for prefix in self.PREFIX_KEYS)
            or any(lowered_key.endswith(suffix) for suffix in self.ENDS_WITH)
        )
        # Loggo la decisione (utile per audit).
        logger.debug("parametro %s marcato per rimozione %s", key, should_remove)
        # Ritorno la decisione finale.
        return should_remove

    def _estrai_titolo(self, html_text: str) -> str | None:
        """Estrae il contenuto del tag <title> e normalizza gli spazi/entità HTML."""
        # Cerco il blocco <title>...</title> anche su più righe.
        match_title = re.search(
            r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL
        )
        # Se non c'è titolo, ritorno None.
        if not match_title:
            return None
        # Prendo il contenuto grezzo del titolo.
        raw_title = match_title.group(1).strip()
        # Se è vuoto, ritorno None.
        if not raw_title:
            return None
        # Converto le entità HTML (es. &amp; → &).
        unescaped_title = html.unescape(raw_title)
        # Rimuovo caratteri invisibili zero-width.
        unescaped_title = re.sub(r"[\u200B-\u200D\uFEFF]", "", unescaped_title)
        # Sostituisco NBSP con spazio normale.
        unescaped_title = unescaped_title.replace("\u00a0", " ")
        # Collasso spazi multipli e strip finale.
        normalized_title = re.sub(r"\s+", " ", unescaped_title).strip()
        # Ritorno il titolo normalizzato o None se vuoto.
        return normalized_title or None

    async def segui_redirect(self, url_iniziale: str):
        """Segue redirect HTTP, meta refresh e redirect JS fino al limite configurato.

        Ritorna una tupla (url_finale, eventuale_titolo).
        """

        def meta_refresh_target(html_text: str, base_url: str) -> str | None:
            """Individua target da meta http-equiv=refresh e lo risolve rispetto alla base."""
            match_meta = re.search(
                r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\']\s*\d+\s*;\s*url\s*=\s*([^"\']+)["\']',
                html_text,
                re.IGNORECASE,
            )
            return (
                urljoin(base_url, match_meta.group(1).strip()) if match_meta else None
            )

        def js_redirect_target(html_text: str, base_url: str) -> str | None:
            """Cerca pattern comuni di redirect JavaScript e li risolve rispetto alla base."""
            patterns = [
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
                r'location\.replace\(\s*["\']([^"\']+)["\']\s*\)',
                r'location\.assign\(\s*["\']([^"\']+)["\']\s*\)',
            ]
            for pattern in patterns:
                match_js = re.search(pattern, html_text, re.IGNORECASE)
                if match_js and match_js.group(1):
                    return urljoin(base_url, match_js.group(1).strip())
            return None

        # Imposto l'URL corrente al valore iniziale.
        current_url = url_iniziale
        # Contatore dei redirect seguiti finora.
        redirect_count = 0
        # Titolo normalizzato (se lo estrarrò).
        normalized_title = None

        # Ottengo la sessione HTTP da riutilizzare.
        session = await self._get_session()

        # Entro in un ciclo finché non supero il numero massimo di redirect.
        while redirect_count < self.conf.max_redirects:
            try:
                # 1) Tentativo veloce: HEAD per leggere Location senza scaricare il corpo.
                async with session.head(current_url, allow_redirects=False) as response:
                    if response.status in (301, 302, 303, 307, 308):
                        location_header = response.headers.get("Location")
                        if location_header:
                            current_url = urljoin(current_url, location_header)
                            redirect_count += 1
                            continue
            except aiohttp.ClientError:
                # Se HEAD fallisce, proseguo con gli altri tentativi.
                break

            try:
                # 2) GET parziale (Range) per cercare meta refresh o redirect via script.
                async with session.get(
                    current_url,
                    headers={"Range": "bytes=0-16383"},
                    allow_redirects=False,
                ) as response:
                    if response.status in (301, 302, 303, 307, 308):
                        location_header = response.headers.get("Location")
                        if location_header:
                            current_url = urljoin(current_url, location_header)
                            redirect_count += 1
                            continue
                    if (
                        response.status == 200
                        and response.content_type
                        and response.content_type.startswith("text/html")
                    ):
                        partial_html = await response.text(errors="ignore")
                        target = meta_refresh_target(
                            partial_html, current_url
                        ) or js_redirect_target(partial_html, current_url)
                        if target:
                            current_url = target
                            redirect_count += 1
                            continue
            except aiohttp.ClientError:
                # Se GET parziale fallisce, proverò l'ultimo tentativo completo.
                break

            # Provo a leggere l'host (utile in alcuni casi per log o regole specifiche).
            try:
                host = urlsplit(current_url).netloc.lower()
                _ = host  # uso dummy per evitare warning di variabile inutilizzata nei linter
            except Exception:
                # In caso di URL non parseable, ignoro.
                pass

            try:
                # 3) Ultimo tentativo: GET completa (alcuni shortener la richiedono).
                async with session.get(current_url, allow_redirects=False) as response:
                    if response.status in (301, 302, 303, 307, 308):
                        location_header = response.headers.get("Location")
                        if location_header:
                            current_url = urljoin(current_url, location_header)
                            redirect_count += 1
                            continue
                    if (
                        response.status == 200
                        and response.content_type
                        and response.content_type.startswith("text/html")
                    ):
                        full_html = await response.text(errors="ignore")
                        target = meta_refresh_target(
                            full_html, current_url
                        ) or js_redirect_target(full_html, current_url)
                        if target:
                            current_url = target
                            redirect_count += 1
                            continue
            except aiohttp.ClientError:
                # Anche qui se fallisce, esco dal ciclo.
                break

            # Se non ho più redirect da seguire, esco dal ciclo.
            break

        # Se la configurazione richiede di mostrare il titolo, lo scarico ora.
        if self.conf.show_title:
            try:
                async with session.get(current_url) as response:
                    if (
                        response.status == 200
                        and response.content_type
                        and response.content_type.startswith("text/html")
                    ):
                        html_text = await response.text(errors="ignore")
                        normalized_title = self._estrai_titolo(html_text)

            except Exception as error:
                logger.error(
                    "errore durante la sanificazione ritorno url grezzo %s", error
                )

        # Rimuovo eventuale punteggiatura finale eccessiva (lasciando parentesi bilanciate).
        while current_url and current_url[-1] in ".,;:!?)”»’'\"" + "\u00a0":
            if current_url.endswith(")") and current_url.count("(") < current_url.count(
                ")"
            ):
                break
            current_url = current_url[:-1]

        # Ritorno la coppia (URL finale, eventuale titolo normalizzato).
        return current_url, normalized_title

    async def sanifica_url(self, raw_url: str) -> tuple[str, str | None]:
        """Pulisce un singolo URL: schema, redirect, query, frammenti, validazione."""
        # Se l'input è vuoto, non elaboro e ritorno input come output con titolo None.
        if not raw_url:
            logger.debug("sanifica url url vuoto")
            return raw_url, None

        # Normalizzo spazi ai bordi.
        current_input_url = raw_url.strip()
        # Valori di fallback in caso di eccezioni.
        final_url = current_input_url
        final_title: str | None = ""

        # Se lo schema è mailto: o tel:, restituisco subito senza modifiche.
        if re.match(r"^(mailto:|tel:)", current_input_url, re.IGNORECASE):
            logger.debug("protocollo non web restituzione invariata")
            return current_input_url, None

        # Se manca lo schema (es. dominio.com), premetto https://.
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", current_input_url):
            logger.debug("schema mancante aggiungo https")
            current_input_url = "https://" + current_input_url

        try:
            # Seguo i redirect e ottengo l'URL finale (e un eventuale titolo preliminare).
            post_redirect_url, extracted_title = await self.segui_redirect(
                current_input_url
            )
            # Se show_title è attivo memorizzo il titolo, altrimenti None.
            final_title = "" if not self.conf.show_title else (extracted_title or None)  # type: ignore[assignment]
        except Exception as error:
            # In caso di errori durante i redirect, tengo l'URL "grezzo" come fallback.
            logger.info(
                f"head fallita su {current_input_url} eseguo fallback get {error}"
            )
            post_redirect_url, extracted_title = current_input_url, None

        try:
            # Scompongo l'URL per lavorare su dominio, path, query, frammento.
            split_parts = urlsplit(post_redirect_url)
            domain_no_www = re.sub(
                r"^www\.", "", split_parts.netloc, flags=re.IGNORECASE
            ).lower()
            logger.debug(
                "parsing url finale domain %s path %s query %s fragment %s",
                domain_no_www,
                split_parts.path,
                split_parts.query,
                split_parts.fragment,
            )

            # Se il dominio è in whitelist, NON tocco i parametri → ritorno subito.
            if domain_no_www in self.DOMAIN_WHITELIST:
                return post_redirect_url, final_title

            # Converto la query string in lista di (chiave, valore) mantenendo chiavi vuote.
            original_query_params = parse_qsl(split_parts.query, keep_blank_values=True)
            # Filtro i parametri in base alle regole di rimozione.
            filtered_query_params = [
                (param_key, param_value)
                for (param_key, param_value) in original_query_params
                if not self.is_parametro_da_rimuovere(param_key)
            ]
            # Ricostruisco la nuova query string (doseq=True gestisce liste di valori).
            new_query_string = urlencode(filtered_query_params, doseq=True)

            # Gestione del frammento (parte dopo #): posso rimuoverne alcuni per prefisso.
            new_fragment = split_parts.fragment
            if new_fragment:
                lowered_fragment = new_fragment.lstrip("#").lower()
                if self.FRAG_KEYS and any(
                    lowered_fragment.startswith(prefix) for prefix in self.FRAG_KEYS
                ):
                    new_fragment = ""

            # Ricompongo l'URL con schema, host, path, nuova query e nuovo frammento.
            final_url = urlunsplit(
                (
                    split_parts.scheme,
                    split_parts.netloc,
                    split_parts.path,
                    new_query_string,
                    new_fragment,
                )
            )

            # Se configurato, valido l'URL "pulito"; se non risponde, mantengo l'URL post-redirect.
            if self.conf.valida_link_post_pulizia and final_url != post_redirect_url:
                is_ok = await self._check_url_ok(final_url)
                if not is_ok:
                    logger.info(
                        "validazione fallita per url pulito restituisco url finale originale"
                    )
                    return post_redirect_url, final_title

            # Se arrivo qui, ho un URL pulito valido → lo ritorno con l'eventuale titolo.
            logger.debug("url pulito prodotto")
            return final_url, final_title
        except Exception as error:
            # Qualunque errore nella sanificazione di dettaglio → ritorno l'URL post-redirect.
            logger.error(
                "errore durante la sanificazione dettagliata ritorno url grezzo %s",
                error,
            )

        # Fallback finale.
        return post_redirect_url, final_title

    async def sanifica_in_batch(self, links: list[str]) -> list[tuple[str, str | None]]:
        """Pulisce una lista di URL con deduplica e limite di concorrenza."""
        # Normalizzo ciascun input rimuovendo spazi di contorno.
        normalized_inputs = [(url or "").strip() for url in links]

        # Deduplica preservando gli indici originali (OrderedDict: url -> lista indici).
        url_index_map: "OrderedDict[str, list[int]]" = OrderedDict()
        for index, url in enumerate(normalized_inputs):
            if url:
                url_index_map.setdefault(url, []).append(index)

        # Se non c'è nessun URL valido, ritorno una lista di placeholder vuoti.
        if not url_index_map:
            return [("", None) for _ in normalized_inputs]

        # Creo (o riuso) un semaforo per limitare la concorrenza.
        concurrency_semaphore = getattr(
            self, "_semaforo", asyncio.Semaphore(self.conf.max_concurrency)
        )

        async def process_one_url(input_url: str) -> tuple[str, str | None]:
            """Elabora un singolo URL all'interno del semaforo."""
            async with concurrency_semaphore:
                try:
                    return await self.sanifica_url(input_url)
                except Exception:
                    # In caso di errore, ritorno l'URL originale senza titolo.
                    return (input_url, None)

        # Avvio i task per ciascun URL unico.
        tasks_by_url = {
            input_url: asyncio.create_task(process_one_url(input_url))
            for input_url in url_index_map
        }
        # Attendo il completamento di tutti i task, conservando eventuali eccezioni.
        task_results = await asyncio.gather(
            *tasks_by_url.values(), return_exceptions=True
        )

        # Ricompongo un dizionario url -> (url_pulito, titolo) gestendo eccezioni per singolo task.
        cleaned_by_url: dict[str, tuple[str, str | None]] = {}
        for input_url, task_result in zip(tasks_by_url.keys(), task_results):
            if isinstance(task_result, Exception):
                cleaned_by_url[input_url] = (input_url, None)
            else:
                cleaned_by_url[input_url] = task_result

        # Preparo l'output nella stessa lunghezza/posizione della lista iniziale.
        output_list: list[tuple[str, str | None]] = [
            ("", None) for _ in normalized_inputs
        ]
        for input_url, original_indexes in url_index_map.items():
            for idx in original_indexes:
                output_list[idx] = cleaned_by_url[input_url]

        # Ritorno la lista finale di risultati (url_pulito, eventuale_titolo).
        return output_list
