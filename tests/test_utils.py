import pytest
from sanitizelinkbot.utils import urls_are_semantically_equivalent

def test_identical_urls():
    assert urls_are_semantically_equivalent(
        "https://example.com/test",
        "https://example.com/test"
    )

def test_http_vs_https():
    assert urls_are_semantically_equivalent(
        "http://example.com/test",
        "https://example.com/test"
    )

def test_www_prefix():
    assert urls_are_semantically_equivalent(
        "https://www.example.com/",
        "https://example.com/"
    )

def test_trailing_slash():
    assert urls_are_semantically_equivalent(
        "https://example.com/test/",
        "https://example.com/test"
    )
    assert urls_are_semantically_equivalent(
        "https://example.com",
        "https://example.com/"
    )

def test_query_parameter_ordering():
    assert urls_are_semantically_equivalent(
        "https://example.com/?b=2&a=1",
        "https://example.com/?a=1&b=2"
    )

def test_query_escaping():
    assert urls_are_semantically_equivalent(
        "https://example.com/?q=hello%20world",
        "https://example.com/?q=hello+world"
    )

def test_different_urls():
    assert not urls_are_semantically_equivalent(
        "https://example.com/test",
        "https://example.com/other"
    )
    assert not urls_are_semantically_equivalent(
        "https://example.com/test",
        "https://another.com/test"
    )

def test_different_query_values():
    assert not urls_are_semantically_equivalent(
        "https://example.com/?v=123",
        "https://example.com/?v=456"
    )

def test_missing_scheme():
    assert urls_are_semantically_equivalent(
        "example.com/test",
        "https://example.com/test"
    )
