from urllib.parse import urlparse, parse_qs, urlencode, ParseResult
from typing import Optional, Sequence, List, Type
import re

# ---------------- Base ----------------

class BaseAdapter:
    supported_hosts: tuple[str, ...] = ()  # host corporate supportati

    def match_host(self, host: str) -> bool:
        return host in self.supported_hosts

    def translate(self, u: ParseResult) -> Optional[str]:
        raise NotImplementedError

    # Utility: keep query subset
    @staticmethod
    def filter_query(qs, keep: Sequence[str]) -> dict:
        return {k: qs[k][0] for k in keep if k in qs}

# ---------------- Adapters ----------------

class YouTubeAdapter(BaseAdapter):
    supported_hosts = ("youtube.com", "m.youtube.com", "youtu.be")

    def translate(self, u: ParseResult) -> Optional[str]:
        host = u.netloc.lower().removeprefix("www.")
        parts = [p for p in u.path.split("/") if p]
        q = parse_qs(u.query)

        base = "https://www.yewtu.be"

        if host == "youtu.be" and parts:
            vid = parts[0]
            return f"{base}/watch?{urlencode({'v': vid})}"

        if u.path == "/watch":
            vid = q.get("v", [None])[0]
            if vid:
                keep = self.filter_query(q, ("t", "time_continue", "start"))
                return f"{base}/watch?{urlencode({'v': vid, **keep})}"

        if len(parts) >= 2 and parts[0] == "shorts":
            return f"{base}/watch?{urlencode({'v': parts[1]})}"

        if parts and parts[0].startswith("@"):
            return f"{base}/{parts[0]}"

        if len(parts) >= 2 and parts[0] in {"channel", "c"}:
            return f"{base}/{'/'.join(parts[:2])}"

        if parts and parts[0] in {"playlist"}:
            list_id = q.get("list", [None])[0]
            if list_id:
                return f"{base}/playlist?{urlencode({'list': list_id})}"

        return None


class YouTubeMusicAdapter(BaseAdapter):
    supported_hosts = ("music.youtube.com",)

    def translate(self, u: ParseResult) -> Optional[str]:
        base = "https://www.yewtu.be"
        q = parse_qs(u.query)
        parts = [p for p in u.path.split("/") if p]
        if u.path == "/watch":
            vid = q.get("v", [None])[0]
            if vid:
                keep = self.filter_query(q, ("t", "time_continue", "start"))
                return f"{base}/watch?{urlencode({'v': vid, **keep})}"
        if parts and parts[0] == "playlist":
            lid = q.get("list", [None])[0]
            if lid:
                return f"{base}/playlist?{urlencode({'list': lid})}"
        return None


class TwitterAdapter(BaseAdapter):
    supported_hosts = ("twitter.com", "x.com", "mobile.twitter.com")

    def translate(self, u: ParseResult) -> Optional[str]:
        parts = [p for p in u.path.split("/") if p]
        base = "https://nitter.net"  # in alternativa: vxtwitter
        if len(parts) >= 3 and parts[1] == "status":
            return f"{base}/{parts[0]}/status/{parts[2]}"
        if parts:
            return f"{base}/{parts[0]}"
        return None


class RedditAdapter(BaseAdapter):
    supported_hosts = ("reddit.com", "old.reddit.com")

    def translate(self, u: ParseResult) -> Optional[str]:
        parts = [p for p in u.path.split("/") if p]
        base = "https://teddit.net"
        if parts:
            return f"{base}/{'/'.join(parts)}" + (f"?{u.query}" if u.query else "")
        return f"{base}/"


class TumblrAdapter(BaseAdapter):
    supported_hosts = ("tumblr.com",)

    def translate(self, u: ParseResult) -> Optional[str]:
        # Priviblur mapping: https://tb.opnxng.com/u/<blog>[/post/...]
        parts = [p for p in u.path.split("/") if p]
        if len(parts) >= 1:
            blog = parts[0]
            rest = "/".join(parts[1:])
            base = f"https://tb.opnxng.com/u/{blog}"
            return f"{base}/{rest}" if rest else base
        return None


class TikTokAdapter(BaseAdapter):
    supported_hosts = ("tiktok.com", "vm.tiktok.com")

    def translate(self, u: ParseResult) -> Optional[str]:
        # ProxiTok accetta path tipo /@user/video/<id>
        base = "https://proxitok.pufe.org"
        host = u.netloc.lower().removeprefix("www.")
        parts = [p for p in u.path.split("/") if p]

        # I link "vm.tiktok.com" sono short-link che richiedono una risoluzione server-side (non possibile qui)
        if host == "vm.tiktok.com":
            return None

        if parts:
            # Mantiene il path così com'è; ProxiTok gestisce i percorsi standard
            return f"{base}/{'/'.join(parts)}"
        return base


class InstagramAdapter(BaseAdapter):
    supported_hosts = ("instagram.com",)

    def translate(self, u: ParseResult) -> Optional[str]:
        base = "https://www.pixwox.com"
        parts = [p for p in u.path.split("/") if p]
        if parts:
            return f"{base}/{'/'.join(parts)}"
        return None


class GeniusAdapter(BaseAdapter):
    supported_hosts = ("genius.com",)

    def translate(self, u: ParseResult) -> Optional[str]:
        base = "https://intellectual.insprill.net"
        parts = [p for p in u.path.split("/") if p]
        if parts:
            return f"{base}/{'/'.join(parts)}"
        return None


class GoodreadsAdapter(BaseAdapter):
    supported_hosts = ("goodreads.com",)

    def translate(self, u: ParseResult) -> Optional[str]:
        base = "https://biblioreads.eu.org"
        parts = [p for p in u.path.split("/") if p]
        if parts:
            return f"{base}/{'/'.join(parts)}" + (f"?{u.query}" if u.query else "")
        return base


class WikipediaAdapter(BaseAdapter):
    supported_hosts = ("wikipedia.org",)

    def translate(self, u: ParseResult) -> Optional[str]:
        # https://<lang>.wikipedia.org/wiki/Title -> https://wikiless.org/<lang>/wiki/Title
        host = u.netloc.lower()
        m = re.match(r"^([a-z-]+)\.wikipedia\.org$", host.removeprefix("www."))
        if not m:
            return None
        lang = m.group(1)
        parts = [p for p in u.path.split("/") if p]
        return f"https://wikiless.org/{lang}/{'/'.join(parts)}" if parts else f"https://wikiless.org/{lang}/"


class GoogleSearchAdapter(BaseAdapter):
    supported_hosts = ("google.com",)

    def translate(self, u: ParseResult) -> Optional[str]:
        # gestiamo solo /search con parametro q
        if u.path != "/search":
            return None
        q = parse_qs(u.query)
        if "q" not in q:
            return None
        params = {"q": q["q"][0]}
        # Redirect Google searches to DuckDuckGo
        return f"https://duckduckgo.com/?{urlencode(params)}"


class GoogleMapsAdapter(BaseAdapter):
    # Restringiamo a maps.google.com per evitare collisione con GoogleSearchAdapter
    supported_hosts = ("maps.google.com",)

    def translate(self, u: ParseResult) -> Optional[str]:
        q = parse_qs(u.query)
        if "q" in q:
            return f"https://www.openstreetmap.org/search?{urlencode({'query': q['q'][0]})}"
        return "https://www.openstreetmap.org/"


class UrlTranslator:
    def __init__(self, adapters: Optional[List[Type[BaseAdapter]]] = None):
        classes = adapters or [
            YouTubeAdapter,
            YouTubeMusicAdapter,
            TwitterAdapter,
            RedditAdapter,
            TumblrAdapter,
            TikTokAdapter,
            InstagramAdapter,
            GeniusAdapter,
            GoodreadsAdapter,
            WikipediaAdapter,
            GoogleSearchAdapter,
            GoogleMapsAdapter,
        ]
        self.adapters = [cls() for cls in classes]

    @staticmethod
    def _norm_host(netloc: str) -> str:
        h = netloc.lower()
        return h[4:] if h.startswith("www.") else h

    def translate(self, url: str) -> str:
        try:
            u = urlparse(url)
            host = self._norm_host(u.netloc)
            if not host:
                return url
            for adapter in self.adapters:
                if adapter.match_host(host):
                    new_url = adapter.translate(u)
                    if new_url:
                        return new_url
            return url
        except Exception:
            return url
