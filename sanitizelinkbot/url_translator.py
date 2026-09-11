from urllib.parse import urlparse, parse_qs, urlencode, ParseResult
from typing import Optional, Sequence, List, Type
import re

# UrlTranslator.py — traduce URL verso frontend alternativi privacy-friendly.
# Ogni sito supportato ha il proprio adapter; UrlTranslator li prova in ordine.
# Gli adapter disabilitati (Reddit, Instagram, ecc.) sono listati in fondo come commento:
# i loro frontend erano offline al momento della disabilitazione.


class BaseAdapter:
    """Classe base per tutti gli adapter. Fornisce helper condivisi.

    service_name, frontend_name e frontend_url descrivono l'adapter per l'utente
    (usati da UrlTranslator.list_frontends, mostrato dal comando /alternative):
    ogni adapter attivo li deve valorizzare.
    """

    supported_hosts: tuple[str, ...] = ()
    service_name: str = ""
    frontend_name: str = ""
    frontend_url: str = ""

    def match_host(self, host: str) -> bool:
        return host in self.supported_hosts

    def translate(self, parsed: ParseResult) -> Optional[str]:
        raise NotImplementedError

    @staticmethod
    def _norm_host(netloc: str) -> str:
        """Lowercase + rimozione www. per confronti host uniformi."""
        host_lower = netloc.lower()
        return host_lower[4:] if host_lower.startswith("www.") else host_lower

    @staticmethod
    def _split_path(path: str) -> list[str]:
        """Segmenti di path non vuoti: '/a//b/' → ['a', 'b']."""
        return [seg for seg in path.split("/") if seg]

    @staticmethod
    def _filter_query(qs: dict, keep: Sequence[str]) -> dict:
        # parse_qs restituisce liste ({"t": ["120"]}): prendiamo solo il primo valore
        return {key: qs[key][0] for key in keep if key in qs}


class YouTubeAdapter(BaseAdapter):
    supported_hosts = ("youtube.com", "m.youtube.com", "youtu.be")
    BASE = "https://inv.nadeko.net"
    service_name = "YouTube"
    frontend_name = "Invidious"
    frontend_url = BASE
    # Parametri temporali da preservare: rimuoverli cambierebbe il punto di inizio video
    _TIME_PARAMS = ("t", "time_continue", "start")

    def translate(self, parsed: ParseResult) -> Optional[str]:
        host = self._norm_host(parsed.netloc)
        parts = self._split_path(parsed.path)
        query = parse_qs(parsed.query)

        # youtu.be/<id> — il primo segmento del path è l'ID video
        if host == "youtu.be" and parts:
            keep = self._filter_query(query, self._TIME_PARAMS)
            return f"{self.BASE}/watch?{urlencode({'v': parts[0], **keep})}"

        if parsed.path == "/watch":
            vid = query.get("v", [None])[0]
            if vid:
                keep = self._filter_query(query, self._TIME_PARAMS)
                return f"{self.BASE}/watch?{urlencode({'v': vid, **keep})}"

        # /shorts/<id> → video normale su Invidious (non ha una route /shorts)
        if len(parts) >= 2 and parts[0] == "shorts":
            keep = self._filter_query(query, self._TIME_PARAMS)
            return f"{self.BASE}/watch?{urlencode({'v': parts[1], **keep})}"

        if parts:
            if parts[0].startswith("@"):
                return f"{self.BASE}/{parts[0]}"  # handle canale (@username)
            if len(parts) >= 2 and parts[0] in {"channel", "c"}:
                return f"{self.BASE}/{parts[0]}/{parts[1]}"  # /channel/<id> o /c/<name>

        if parsed.path == "/playlist" or (parts and parts[0] == "playlist"):
            list_id = query.get("list", [None])[0]
            if list_id:
                return f"{self.BASE}/playlist?{urlencode({'list': list_id})}"

        if parsed.path == "/results":
            search_query = query.get("search_query", [None])[0]
            if search_query:
                return f"{self.BASE}/search?{urlencode({'q': search_query})}"

        return None


class YouTubeMusicAdapter(YouTubeAdapter):
    # music.youtube.com usa la stessa struttura URL di youtube.com:
    # eredita tutta la logica di YouTubeAdapter, sovrascrivendo solo i domini supportati
    supported_hosts = ("music.youtube.com",)
    service_name = "YouTube Music"


class TwitterAdapter(BaseAdapter):
    supported_hosts = ("twitter.com", "x.com", "mobile.twitter.com")
    BASE = "https://xcancel.com"
    service_name = "Twitter/X"
    frontend_name = "xcancel"
    frontend_url = BASE

    def translate(self, parsed: ParseResult) -> Optional[str]:
        parts = self._split_path(parsed.path)
        # /<user>/status/<id> — tweet specifico
        if len(parts) >= 3 and parts[1] == "status":
            return f"{self.BASE}/{parts[0]}/status/{parts[2]}"
        if parts:
            return f"{self.BASE}/{parts[0]}"  # profilo utente
        return None


class GoogleSearchAdapter(BaseAdapter):
    supported_hosts = ("google.com",)
    BASE = "https://duckduckgo.com"
    service_name = "Google Search"
    frontend_name = "DuckDuckGo"
    frontend_url = BASE

    def translate(self, parsed: ParseResult) -> Optional[str]:
        if parsed.path != "/search":
            return (
                None  # altri path di google.com (Maps, Drive, ecc.) non vanno toccati
            )
        query = parse_qs(parsed.query)
        if "q" not in query:
            return None
        return f"{self.BASE}/?{urlencode({'q': query['q'][0]})}"


class GoogleMapsAdapter(BaseAdapter):
    supported_hosts = ("maps.google.com",)
    BASE = "https://www.openstreetmap.org"
    service_name = "Google Maps"
    frontend_name = "OpenStreetMap"
    frontend_url = BASE

    def translate(self, parsed: ParseResult) -> Optional[str]:
        query = parse_qs(parsed.query)
        if "q" in query:
            return f"{self.BASE}/search?{urlencode({'query': query['q'][0]})}"
        return f"{self.BASE}/"  # fallback: homepage OSM se non c'è query


class GeniusAdapter(BaseAdapter):
    supported_hosts = ("genius.com",)
    BASE = "https://lyrics.leemoon.network"
    service_name = "Genius"
    frontend_name = "Dumb"
    frontend_url = BASE

    def translate(self, parsed: ParseResult) -> Optional[str]:
        parts = self._split_path(parsed.path)
        return f"{self.BASE}/{'/'.join(parts)}" if parts else None


class FandomAdapter(BaseAdapter):
    # I wiki Fandom vivono su sottodomini (zelda.fandom.com, ecc.): non elencabili in
    # supported_hosts, quindi sovrascriviamo match_host come per Wikipedia
    supported_hosts = ()
    BASE = "https://antifandom.com"
    service_name = "Fandom"
    frontend_name = "BreezeWiki"
    frontend_url = BASE
    _HOST_RE = re.compile(r"^([a-z0-9-]+)\.fandom\.com$")

    def match_host(self, host: str) -> bool:
        return bool(self._HOST_RE.match(host))

    def translate(self, parsed: ParseResult) -> Optional[str]:
        match_sub = self._HOST_RE.match(self._norm_host(parsed.netloc))
        if not match_sub:
            return None
        subdomain = match_sub.group(1)
        parts = self._split_path(parsed.path)
        path = "/".join(parts)
        return f"{self.BASE}/{subdomain}/{path}" if path else f"{self.BASE}/{subdomain}/"


# ---------------------------------------------------------------------------
# Adapter disabilitati — frontend offline al momento della disabilitazione
# ---------------------------------------------------------------------------
# RedditAdapter        → teddit.net offline; anche Redlib (erede di Libreddit) è vivo ma
#                        ogni istanza pubblica trovata mostra una verifica anti-bot
#                        (Cloudflare/DDOS-Guard): un bot senza browser reale riceve solo
#                        quella pagina, non il contenuto
# InstagramAdapter     → pixwox.com offline, nessun sostituto affidabile
# TumblrAdapter        → tb.opnxng.com (Priviblur) offline
# GoodreadsAdapter     → biblioreads.eu.org offline, nessun sostituto affidabile
# TikTokAdapter        → proxitok.pufe.org offline; tutte le istanze pubbliche ProxiTok
#                        verificate (pabloferreiro.es, pussthecat.org, lunar.icu, r4fo.com,
#                        belloworld.it, wpme.pl, ecc.) risultano offline o irraggiungibili
# WikipediaAdapter     → wl.vern.cc (Wikiless) offline; il progetto upstream risulta
#                        abbandonato e le istanze note (esmailelbob.xyz, northboot.xyz)
#                        sono irraggiungibili
# ImdbAdapter          → Libremdb: le istanze verificate rispondono ma danno errore 500
#                        sulle pagine di un titolo (iket.me) o sono bloccate/irraggiungibili
#                        (pussthecat.org, esmailelbob.xyz)
# StackOverflowAdapter → AnonymousOverflow: risponde ma StackExchange blocca l'IP del
#                        proxy (errore 403 su ogni domanda provata)
# ImgurAdapter         → Rimgo (bcow.xyz): la pagina carica solo i metadati (data,
#                        visualizzazioni), l'immagine vera e propria non viene servita
#                        — Imgur blocca gli IP dei data center usati dai proxy pubblici
# GoogleTranslateAdapter → Lingva (lingva.ml): risponde ma traduce nella lingua sbagliata
#                        (es. richiesta it→en, risposta in croato) indipendentemente dal
#                        testo — bug riproducibile, non un problema di rete


class UrlTranslator:
    """Prova ogni adapter in ordine e restituisce il primo URL tradotto, o l'originale."""

    def __init__(self, adapters: Optional[List[Type[BaseAdapter]]] = None):
        classes = adapters or [
            YouTubeAdapter,
            YouTubeMusicAdapter,
            TwitterAdapter,
            GoogleSearchAdapter,
            GoogleMapsAdapter,
            GeniusAdapter,
            FandomAdapter,
        ]
        self.adapters = [cls() for cls in classes]

    def list_frontends(self) -> list[tuple[str, str, str]]:
        """Servizio, frontend e URL per ogni adapter attivo, nell'ordine con cui vengono provati.
        Usato dal comando /alternative: aggiungere un adapter alla lista in __init__
        lo fa comparire qui automaticamente, senza toccare la documentazione a mano.
        """
        return [
            (adapter.service_name, adapter.frontend_name, adapter.frontend_url)
            for adapter in self.adapters
        ]

    def translate(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            host = BaseAdapter._norm_host(parsed.netloc)
            if not host:
                return url
            for adapter in self.adapters:
                if adapter.match_host(host):
                    new_url = adapter.translate(parsed)
                    if new_url:
                        return new_url
            return url
        except Exception:
            return url  # URL malformato: restituiamo invariato
