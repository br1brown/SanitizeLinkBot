import pytest
from sanitizelinkbot.app_config import AppConfig
from sanitizelinkbot.sanitizer import Sanitizer


@pytest.fixture
def conf():
    return AppConfig(
        max_concurrency=4,
        cache_max_size=10,
        connections_per_host=2,
        max_redirects=5,
        timeout_sec=10,
        ttl_dns_cache=60,
        valida_link_post_pulizia=False,
        log_level="DEBUG",
    )


@pytest.fixture
def sanitizer(conf):
    return Sanitizer(
        exact_keys={"utm_source", "utm_medium", "fbclid", "ref"},
        prefix_keys=("utm_",),
        ends_with=("_tracking",),
        frag_keys=("utm_",),
        domain_whitelist=["trusted.com"],
        conf=conf,
        clearurls=None,
    )
