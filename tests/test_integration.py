"""Test di integrazione con rete reale.

Testano l'intera pipeline sanitize_url con valida_link_post_pulizia=True:
  URL sporco → redirect → pulizia → validazione PageSignals → URL finale

Richiedono connessione internet: vengono eseguiti normalmente nel workflow CI
(GitHub Actions ha accesso alla rete) e localmente con: pytest tests/test_integration.py -v
"""

import pytest
from sanitizelinkbot.sanitizer import Sanitizer
from sanitizelinkbot.chat_prefs import SanitizerOpts
from sanitizelinkbot.app_config import AppConfig
from sanitizelinkbot.utils import load_json_file, KEYS_PATH


def _make_sanitizer() -> Sanitizer:
    """Sanitizer con le regole reali di keys.json e validazione attiva."""
    conf = AppConfig(
        max_concurrency=2,
        cache_max_size=20,
        connections_per_host=2,
        max_redirects=10,
        timeout_sec=20,
        ttl_dns_cache=60,
        valida_link_post_pulizia=True,
        log_level="INFO",
    )
    keys = load_json_file(KEYS_PATH, required=True)
    return Sanitizer(
        exact_keys=set(keys.get("EXACT_KEYS", [])),
        prefix_keys=tuple(keys.get("PREFIX_KEYS", [])),
        ends_with=tuple(keys.get("ENDS_WITH", [])),
        frag_keys=tuple(keys.get("FRAG_KEYS", [])),
        domain_whitelist=keys.get("DOMAIN_WHITELIST", []),
        conf=conf,
        clearurls=None,
    )


OPTS = SanitizerOpts(show_url=True, show_title=False, use_privacy_frontend=False)


# ---------------------------------------------------------------------------
# Test 1: Wikipedia con tracker fittizi → tracker rimossi, URL stabile
# ---------------------------------------------------------------------------


async def test_wikipedia_strips_fake_trackers():
    """Wikipedia: fbclid e utm_source aggiunti artificialmente devono sparire.

    Wikipedia ha ETag stabile e canonical dichiarato: la validazione PageSignals
    deve riconoscere che la pagina è la stessa con o senza i tracker fittizi.
    """
    sanitizer = _make_sanitizer()
    try:
        dirty = (
            "https://it.wikipedia.org/wiki/Python"
            "?utm_source=newsletter&fbclid=fake123abc"
        )
        clean, _ = await sanitizer.sanitize_url(dirty, opts=OPTS)

        assert "utm_source" not in clean, "utm_source non rimosso"
        assert "fbclid" not in clean, "fbclid non rimosso"
        assert "wikipedia.org" in clean
        assert "Python" in clean
    finally:
        await sanitizer.close()


# ---------------------------------------------------------------------------
# Test 2: Python.org con tracker fittizi → stessa logica, sito diverso
# ---------------------------------------------------------------------------


async def test_python_org_strips_fake_trackers():
    """python.org: i parametri utm_ devono essere rimossi.

    python.org risponde con canonical consistente e titolo stabile:
    la validazione deve passare e restituire l'URL pulito.
    """
    sanitizer = _make_sanitizer()
    try:
        dirty = (
            "https://www.python.org/about/"
            "?utm_medium=email&utm_campaign=spring2025&fbclid=xyz789"
        )
        clean, _ = await sanitizer.sanitize_url(dirty, opts=OPTS)

        assert "utm_medium" not in clean, "utm_medium non rimosso"
        assert "utm_campaign" not in clean, "utm_campaign non rimosso"
        assert "fbclid" not in clean, "fbclid non rimosso"
        assert "python.org" in clean
    finally:
        await sanitizer.close()


# ---------------------------------------------------------------------------
# Test 3: Google Search — il caso che la vecchia versione rompeva
#
# keys.json rimuove: oq, gs_*, sourceid, ei, ved, ... da Google.
# La vecchia versione restituiva un URL menomato o rotto.
# La nuova versione, con valida_link_post_pulizia=True, confronta i PageSignals:
#   - se il contenuto cambia → restituisce l'URL originale intatto
#   - se è uguale → restituisce l'URL pulito
# In entrambi i casi il parametro "q" (la vera ricerca) DEVE essere presente.
# ---------------------------------------------------------------------------


async def test_google_search_preserves_query():
    """Google Search: il termine di ricerca q= non deve mai sparire.

    Questo URL mandava in crash la vecchia versione del bot perché venivano
    rimossi parametri che Google usa per servire la risposta corretta.
    La validazione PageSignals deve proteggere l'utente da un URL rotto.
    """
    sanitizer = _make_sanitizer()
    try:
        google_url = (
            "https://www.google.com/search"
            "?q=test"
            "&oq=test"
            "&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQRRg7MgYIAhBFGDsyBggD"
            "&client=ms-android-google"
            "&sourceid=chrome-mobile"
            "&ie=UTF-8"
        )
        clean, _ = await sanitizer.sanitize_url(google_url, opts=OPTS)

        # L'URL restituito deve essere sempre un URL Google funzionante
        assert "google.com" in clean, "Perso il dominio google.com"

        # Il parametro della ricerca reale non deve mai sparire
        assert "q=test" in clean, (
            f"Parametro q= rimosso! URL restituito: {clean!r}\n"
            "Questo romperebbe la ricerca Google per l'utente."
        )
    finally:
        await sanitizer.close()


# ---------------------------------------------------------------------------
# Test 4: Google Search con URL come query — encoding non deve rompere il link
# ---------------------------------------------------------------------------


async def test_google_search_with_url_as_query():
    """Google Search con un URL come valore di q=: _strip_tracking_params re-codifica
    i caratteri (://) ma il link deve rimanere funzionante.

    Bug storico: parse_qsl decodifica %3F/%3D e urlencode li ri-codifica in forma
    diversa dall'originale; il link finale deve comunque essere raggiungibile.
    """
    sanitizer = _make_sanitizer()
    try:
        google_url = (
            "https://www.google.com/search"
            "?q=https://www.comune.roma.it/web/it/scheda-servizi.page%3FcontentId%3DINF40030"
        )
        clean, _ = await sanitizer.sanitize_url(google_url, opts=OPTS)

        # Il bot NON deve estrarre il valore di q= e restituire il link interno:
        # la ClearURLs redirection di Google matcha solo /url?q=..., non /search?q=...
        # ma se il pattern cambiasse potrebbe estrarre comune.roma.it direttamente.
        assert "google.com" in clean, (
            f"Il bot ha perso il dominio google.com: {clean!r}\n"
            "Probabile causa: apply_redirections ha estratto il valore di q= invece di "
            "restituire la URL della ricerca."
        )
        # Il valore di q= (comune.roma.it) deve restare DENTRO la URL come parametro,
        # non diventare la URL restituita.
        assert clean.startswith("https://www.google.com/") or clean.startswith(
            "https://google.com/"
        ), f"URL restituita non è google.com: {clean!r}"
        assert "comune.roma.it" in clean, f"Perso il contenuto di q=: {clean!r}"
    finally:
        await sanitizer.close()


# ---------------------------------------------------------------------------
# Test 5: maps.app.goo.gl — short link Maps, redirect HTTP seguito correttamente
# ---------------------------------------------------------------------------


async def test_maps_goo_gl_short_link_resolves():
    """maps.app.goo.gl è uno short link di Google Maps: il redirect deve essere
    seguito e l'URL risultante restituito funzionante (non il short link rotto).

    Bug storico: il bot restituiva il short link con parametri rimossi (URL rotto)
    invece di seguire il redirect e restituire il link Maps reale.
    """
    sanitizer = _make_sanitizer()
    try:
        short_url = "https://maps.app.goo.gl/EyQDiQHJMM5CUqEt5"
        clean, _ = await sanitizer.sanitize_url(short_url, opts=OPTS)

        assert (
            "goo.gl" not in clean
            or "google.com/maps" in clean
            or "maps.google.com" in clean
        ), f"Short link non risolto: {clean!r}"
        assert clean.startswith("http"), f"URL non valido restituito: {clean!r}"
    finally:
        await sanitizer.close()
