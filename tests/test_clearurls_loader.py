"""Test per ClearUrlsLoader: caricamento, merge con le regole custom del progetto."""

import json
from pathlib import Path

from sanitizelinkbot.clearurls_loader import ClearUrlsLoader
from sanitizelinkbot.utils import CUSTOM_PROVIDERS_PATH


def _loader_with_only_custom(tmp_path) -> ClearUrlsLoader:
    """ClearUrlsLoader senza regole ClearURLs scaricate (file inesistente): deve comunque
    caricarsi usando solo custom_providers.json, il file vero del progetto.
    """
    missing_rules_path = tmp_path / "clearurls_non_scaricato.json"
    loader = ClearUrlsLoader(
        missing_rules_path, custom_providers_path=Path(CUSTOM_PROVIDERS_PATH)
    )
    loader.load_sync()
    return loader


class TestCustomProvidersWithoutDownloadedRules:
    def test_is_loaded_even_without_clearurls_file(self, tmp_path):
        # Prima del primo download periodico (o se fallisce) il layer non deve restare
        # spento: le regole custom del progetto devono funzionare comunque.
        loader = _loader_with_only_custom(tmp_path)
        assert loader.is_loaded

    def test_google_share_params_removed(self, tmp_path):
        loader = _loader_with_only_custom(tmp_path)
        url = (
            "https://www.google.com/search"
            "?kgmid=%2Fm%2F01pj5q&q=Joe+Pesci"
            "&shem=dlvs1%2Cepsd1%2Crimspwuoe&shndl=17&kgs=75d808c3ae92a8e5"
        )
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "shem" not in cleaned
        assert "shndl" not in cleaned
        assert "kgs=" not in cleaned
        assert "kgmid=" not in cleaned
        assert "q=Joe" in cleaned

    def test_google_client_identifier_params_removed(self, tmp_path):
        loader = _loader_with_only_custom(tmp_path)
        url = (
            "https://www.google.com/search"
            "?q=test&client=ms-android-samsung-rvo1&sclient=gws-wiz-serp&oe=utf-8"
        )
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "client=" not in cleaned
        assert "sclient" not in cleaned
        assert "oe=" not in cleaned
        assert "q=test" in cleaned

    def test_youtube_is_share_id_removed(self, tmp_path):
        loader = _loader_with_only_custom(tmp_path)
        url = "https://youtu.be/dQw4w9WgXcQ?si=abc123&is=def456"
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        # "si" non è coperto dal nostro custom provider (è già gestito da ClearURLs
        # ufficiale per youtube.com/youtu.be, qui non scaricato): controlliamo solo "is".
        assert "is=" not in cleaned

    def test_youtube_ab_channel_and_feature_removed(self, tmp_path):
        loader = _loader_with_only_custom(tmp_path)
        url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ&feature=share&ab_channel=RickAstley"
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "feature=" not in cleaned
        assert "ab_channel=" not in cleaned
        assert "v=dQw4w9WgXcQ" in cleaned

    def test_is_scoped_to_youtube_not_global(self, tmp_path):
        # Il punto di avere le regole per dominio: "is" NON deve sparire da un URL
        # che non è YouTube, a differenza di quanto sarebbe successo con una chiave
        # globale in keys.json (vedi il caso Discord CDN "ex/is/hm").
        loader = _loader_with_only_custom(tmp_path)
        url = (
            "https://cdn.discordapp.com/attachments/123456789/987654321/foto.png"
            "?ex=66f1a2b3&is=66f0517c&hm=deadbeefcafebabe0123456789abcdef"
        )
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "is=66f0517c" in cleaned
        assert "ex=" in cleaned
        assert "hm=" in cleaned

    def test_instagram_share_tokens_removed(self, tmp_path):
        loader = _loader_with_only_custom(tmp_path)
        url = "https://www.instagram.com/reel/XYZ/?igsh=abc123&igsi=def456&stkn=ghi789"
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "igsh=" not in cleaned
        assert "igsi=" not in cleaned
        assert "stkn=" not in cleaned

    def test_facebook_messenger_mibextid_removed(self, tmp_path):
        loader = _loader_with_only_custom(tmp_path)
        url = "https://www.facebook.com/share/p/abc123/?mibextid=WC7FNe"
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "mibextid" not in cleaned

    def test_threads_xmt_removed(self, tmp_path):
        loader = _loader_with_only_custom(tmp_path)
        url = "https://www.threads.net/@user/post/abc123?xmt=AQGz"
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "xmt=" not in cleaned

    def test_alibaba_spm_removed(self, tmp_path):
        loader = _loader_with_only_custom(tmp_path)
        for domain in ("taobao.com", "tmall.com", "aliexpress.com", "1688.com"):
            url = f"https://www.{domain}/item/123.html?spm=a1z10.1"
            providers = loader.find_providers(url)
            cleaned = loader.apply_cleaning(url, providers)
            assert "spm=" not in cleaned, f"'spm' non rimosso su {domain}"

    def test_tiktok_device_params_removed(self, tmp_path):
        loader = _loader_with_only_custom(tmp_path)
        url = "https://www.tiktok.com/@user/video/123?is_from_webapp=1&sender_device=pc"
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "is_from_webapp" not in cleaned
        assert "sender_device" not in cleaned

    def test_pinterest_pin_params_removed(self, tmp_path):
        loader = _loader_with_only_custom(tmp_path)
        url = "https://www.pinterest.com/pin/123/?pin_id=123&pin_tag=456&source_pin_id=789"
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "pin_id=" not in cleaned
        assert "pin_tag=" not in cleaned
        assert "source_pin_id=" not in cleaned

    def test_pinterest_pin_prefix_covers_unlisted_variants(self, tmp_path):
        # La regola "pin_.*" è un match di prefisso, non un elenco chiuso: copre anche
        # varianti future non ancora viste (es. "pin_sig"), senza doverle aggiungere a mano.
        loader = _loader_with_only_custom(tmp_path)
        url = "https://www.pinterest.com/pin/123/?pin_sig=abc123"
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "pin_sig=" not in cleaned

    def test_snapchat_snapid_removed(self, tmp_path):
        loader = _loader_with_only_custom(tmp_path)
        url = "https://www.snapchat.com/add/user?snapid=abc123"
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "snapid=" not in cleaned

    def test_linkedin_lipi_removed(self, tmp_path):
        loader = _loader_with_only_custom(tmp_path)
        url = "https://www.linkedin.com/posts/user_abc-activity-123?lipi=urn%3Ali%3Apage"
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "lipi=" not in cleaned


class TestSameNameProviderDoesNotShadowOfficialRules:
    def test_custom_provider_merges_instead_of_overwriting(self, tmp_path):
        # Un provider custom con lo stesso nome di uno ufficiale scaricato non deve
        # sostituirlo: entrambi i set di regole devono restare attivi.
        rules_path = tmp_path / "clearurls.json"
        rules_path.write_text(
            json.dumps(
                {
                    "providers": {
                        "google": {
                            "urlPattern": "^https?:\\/\\/(?:[a-z0-9-]+\\.)*?google\\.com",
                            "rules": ["official_only_param"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        custom_path = tmp_path / "custom_providers.json"
        custom_path.write_text(
            json.dumps(
                {
                    "providers": {
                        "google": {
                            "urlPattern": "^https?:\\/\\/(?:[a-z0-9-]+\\.)*?google\\.com",
                            "rules": ["custom_only_param"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        loader = ClearUrlsLoader(rules_path, custom_providers_path=custom_path)
        loader.load_sync()

        url = "https://www.google.com/search?q=test&official_only_param=1&custom_only_param=2"
        providers = loader.find_providers(url)
        cleaned = loader.apply_cleaning(url, providers)
        assert "official_only_param" not in cleaned
        assert "custom_only_param" not in cleaned
        assert "q=test" in cleaned


class TestLinkedinTrkAndLiFatIdKeptGlobal:
    def test_linkedin_trk_and_li_fat_id_kept_global(self, tmp_path):
        # "trk" e "li_fat_id" NON sono nel provider LinkedIn: vengono attaccati anche ai
        # link ESTERNI (link shim / ads di LinkedIn), quindi devono restare nella lista
        # globale keys.json e continuare a essere rimossi ovunque, non solo su linkedin.com.
        from sanitizelinkbot.utils import load_json_file, KEYS_PATH

        keys = load_json_file(KEYS_PATH, required=True)
        exact = [k.lower() for k in keys.get("EXACT_KEYS", [])]
        assert "trk" in exact
        assert "li_fat_id" in exact
