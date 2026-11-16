import pytest

from rfc3986.api import is_valid_uri
from rfc3986.api import normalize_uri
from rfc3986.api import uri_reference
from rfc3986.api import URIReference


def test_uri_reference():
    assert isinstance(uri_reference("http://example.com"), URIReference)


def test_is_valid_uri():
    assert is_valid_uri("http://example.com") is True


def test_normalize_uri():
    assert normalize_uri("HTTP://EXAMPLE.COM") == "http://example.com"


def test_is_valid_uri_public_api_does_not_warn_about_deprecated_methods():
    import warnings

    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always", DeprecationWarning)
        for _ in range(20):
            assert is_valid_uri("http://example.com/a") is True
            assert is_valid_uri(".://") is False
    assert not [
        w for w in observed if issubclass(w.category, DeprecationWarning)
    ]


def test_direct_legacy_is_valid_warns_only_once_per_call():
    import warnings

    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always", DeprecationWarning)
        assert uri_reference("http://example.com/a").is_valid() is True
        assert uri_reference(".://").is_valid() is False
    assert (
        len(
            [w for w in observed if issubclass(w.category, DeprecationWarning)]
        )
        == 2
    )


@pytest.mark.parametrize(
    "uri, required, valid",
    [
        ("http://example.com", {}, True),
        ("http://example.com", {"require_scheme": True}, True),
        ("http://example.com", {"require_path": True}, False),
        ("http://example.com/path", {"require_path": True}, True),
        ("/path", {"require_scheme": True}, False),
        ("/path", {}, True),
        ("file:///home", {"require_authority": True}, True),
        (".://", {}, False),
        ("http://]", {}, False),
        ("https://example.com/path?x#y", {"require_fragment": True}, True),
    ],
)
def test_is_valid_uri_public_api_retains_existing_required_component_semantics(
    uri, required, valid
):
    assert is_valid_uri(uri, **required) is valid
