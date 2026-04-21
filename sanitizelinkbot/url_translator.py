from urllib.parse import urlparse, parse_qs, urlencode, ParseResult
from typing import Optional, Sequence, List, Type
import re

# UrlTranslator.py — traduce URL verso frontend alternativi privacy-friendly.
# Ogni sito supportato ha il proprio adapter; UrlTranslator li prova in ordine.
# Gli adapter disabilitati (Reddit, Instagram, ecc.) sono listati in fondo come commento:
# i loro frontend erano offline al momento della disabilitazione.


class BaseAdapter:
    """Classe base per tutti gli adapter. Fornisce helper condivisi."""

    supported_hosts: tuple[str, ...] = ()

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


class TwitterAdapter(BaseAdapter):
    supported_hosts = ("twitter.com", "x.com", "mobile.twitter.com")
    BASE = "https://xcancel.com"

    def translate(self, parsed: ParseResult) -> Optional[str]:
        parts = self._split_path(parsed.path)
        # /<user>/status/<id> — tweet specifico
        if len(parts) >= 3 and parts[1] == "status":
            return f"{self.BASE}/{parts[0]}/status/{parts[2]}"
        if parts:
            return f"{self.BASE}/{parts[0]}"  # profilo utente
        return None


class TikTokAdapter(BaseAdapter):
    supported_hosts = ("tiktok.com", "vm.tiktok.com")
    BASE = "https://proxitok.pufe.org"

    def translate(self, parsed: ParseResult) -> Optional[str]:
        # vm.tiktok.com sono short-link: richiedono un redirect server-side per risolversi.
        # ProxiTok non li supporta, quindi lasciamo questi URL invariati (None = nessuna traduzione)
        if self._norm_host(parsed.netloc) == "vm.tiktok.com":
            return None
        parts = self._split_path(parsed.path)
        return f"{self.BASE}/{'/'.join(parts)}" if parts else self.BASE


class WikipediaAdapter(BaseAdapter):
    # Wikipedia ha sottodomini per lingua (it.wikipedia.org, en.wikipedia.org, ecc.):
    # non possiamo elencarli tutti in supported_hosts, quindi sovrascriviamo match_host
    supported_hosts = ()
    _HOST_RE = re.compile(
        r"^([a-z-]+)\.wikipedia\.org$"
    )  # cattura il codice lingua (es. "it", "en")

    def match_host(self, host: str) -> bool:
        return host == "wikipedia.org" or host.endswith(".wikipedia.org")

    def translate(self, parsed: ParseResult) -> Optional[str]:
        match_lang = self._HOST_RE.match(self._norm_host(parsed.netloc))
        if not match_lang:
            return None
        lang = match_lang.group(1)
        parts = self._split_path(parsed.path)
        frag = f"#{parsed.fragment}" if parsed.fragment else ""
        base = (
            f"https://wl.vern.cc/{lang}/{'/'.join(parts)}"
            if parts
            else f"https://wl.vern.cc/{lang}/"
        )
        return base + frag


class GoogleSearchAdapter(BaseAdapter):
    supported_hosts = ("google.com",)

    def translate(self, parsed: ParseResult) -> Optional[str]:
        if parsed.path != "/search":
            return (
                None  # altri path di google.com (Maps, Drive, ecc.) non vanno toccati
            )
        query = parse_qs(parsed.query)
        if "q" not in query:
            return None
        return f"https://duckduckgo.com/?{urlencode({'q': query['q'][0]})}"


class GoogleMapsAdapter(BaseAdapter):
    supported_hosts = ("maps.google.com",)

    def translate(self, parsed: ParseResult) -> Optional[str]:
        query = parse_qs(parsed.query)
        if "q" in query:
            return f"https://www.openstreetmap.org/search?{urlencode({'query': query['q'][0]})}"
        return (
            "https://www.openstreetmap.org/"  # fallback: homepage OSM se non c'è query
        )


# ---------------------------------------------------------------------------
# Adapter disabilitati — frontend offline al momento della disabilitazione
# ---------------------------------------------------------------------------
# RedditAdapter     → teddit.net offline
# InstagramAdapter  → pixwox.com offline, nessun sostituto affidabile
# TumblrAdapter     → tb.opnxng.com (Priviblur) offline
# GeniusAdapter     → intellectual.insprill.net offline
# GoodreadsAdapter  → biblioreads.eu.org offline, nessun sostituto affidabile


class UrlTranslator:
    """Prova ogni adapter in ordine e restituisce il primo URL tradotto, o l'originale."""

    def __init__(self, adapters: Optional[List[Type[BaseAdapter]]] = None):
        classes = adapters or [
            YouTubeAdapter,
            YouTubeMusicAdapter,
            TwitterAdapter,
            TikTokAdapter,
            WikipediaAdapter,
            GoogleSearchAdapter,
            GoogleMapsAdapter,
        ]
        self.adapters = [cls() for cls in classes]

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
