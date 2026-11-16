import pytest

from rfc3986.normalizers import encode_component
from rfc3986.normalizers import normalize_host
from rfc3986.normalizers import normalize_percent_characters
from rfc3986.normalizers import normalize_scheme
from rfc3986.normalizers import remove_dot_segments
from rfc3986.uri import URIReference


def test_normalize_scheme():
    assert "http" == normalize_scheme("htTp")
    assert "http" == normalize_scheme("http")
    assert "http" == normalize_scheme("HTTP")


def test_normalize_percent_characters():
    expected = "%3Athis_should_be_lowercase%DF%ABL"
    assert expected == normalize_percent_characters(
        "%3athis_should_be_lowercase%DF%ab%4c"
    )
    assert expected == normalize_percent_characters(
        "%3Athis_should_be_lowercase%DF%AB%4C"
    )
    assert expected == normalize_percent_characters(
        "%3Athis_should_be_lowercase%DF%aB%4C"
    )


paths = [
    # (Input, expected output)
    ("/foo/bar/.", "/foo/bar/"),
    ("/foo/bar/", "/foo/bar/"),
    ("/foo/bar", "/foo/bar"),
    ("./foo/bar", "foo/bar"),
    ("/./foo/bar", "/foo/bar"),
    ("/foo%20bar/biz%2Abaz", "/foo%20bar/biz%2Abaz"),
    ("../foo/bar", "foo/bar"),
    ("/../foo/bar", "/foo/bar"),
    ("a/./b/../b/%63/%7Bfoo%7D", "a/b/%63/%7Bfoo%7D"),
    ("//a/./b/../b/%63/%7Bfoo%7D", "//a/b/%63/%7Bfoo%7D"),
    ("mid/content=5/../6", "mid/6"),
    ("/a/b/c/./../../g", "/a/g"),
]


@pytest.fixture(params=paths)
def path_fixture(request):
    return request.param


@pytest.fixture(params=paths)
def uris(request):
    to_norm, normalized = request.param
    return (
        URIReference(None, None, to_norm, None, None),
        URIReference(None, None, normalized, None, None),
    )


def test_remove_dot_segments(path_fixture):
    to_normalize, expected = path_fixture
    assert expected == remove_dot_segments(to_normalize)


def test_normalized_equality(uris):
    assert uris[0] == uris[1]


def test_hostname_normalization():
    assert URIReference(None, "EXAMPLE.COM", None, None, None) == URIReference(
        None, "example.com", None, None, None
    )


@pytest.mark.parametrize(
    ["authority", "expected_authority"],
    [
        ("user%2aName@EXAMPLE.COM", "user%2AName@example.com"),
        ("[::1%eth0]", "[::1%25eth0]"),
    ],
)
def test_authority_normalization(authority, expected_authority):
    uri = URIReference(None, authority, None, None, None).normalize()
    assert uri.authority == expected_authority


def test_fragment_normalization():
    uri = URIReference(None, "example.com", None, None, "fiz%DF").normalize()
    assert uri.fragment == "fiz%DF"


@pytest.mark.parametrize(
    ["component", "encoded_component"],
    [
        ("/%", "/%25"),
        ("/~", "/~"),
        ("/%a", "/%25a"),
        ("/%ag", "/%25ag"),
        ("/%af", "/%af"),
        ("/%20/%", "/%2520/%25"),
        ("/%20%25", "/%20%25"),
        ("/%21%22%23%ah%12%ff", "/%2521%2522%2523%25ah%2512%25ff"),
    ],
)
def test_detect_percent_encoded_component(component, encoded_component):
    assert encode_component(component, "utf-8") == encoded_component


@pytest.mark.parametrize(
    ["host", "normalized_host"],
    [
        ("LOCALHOST", "localhost"),
        ("[::1%eth0]", "[::1%25eth0]"),
        ("[::1%25]", "[::1%2525]"),
        ("[::1%%25]", "[::1%25%25]"),
        ("[::1%25%25]", "[::1%25%25]"),
        ("[::Af%Ff]", "[::af%25Ff]"),
        ("[::Af%%Ff]", "[::af%25%Ff]"),
        ("[::Af%25Ff]", "[::af%25Ff]"),
    ],
)
def test_normalize_host(host, normalized_host):
    assert normalize_host(host) == normalized_host


@pytest.mark.parametrize(
    "source, expected",
    [
        ("foo/../baz", "/baz"),
        ("foo/../../baz", "/baz"),
        ("foo/bar/../../baz", "/baz"),
        ("foo/../", "/"),
        ("foo/..", "/"),
        ("/a/../../", "/"),
        ("/../", "/"),
    ],
)
def test_remove_dot_segments_keeps_slash_at_root(source, expected):
    """RFC 3986 §5.2.4 preserves the slash when '..' removes a segment."""
    assert remove_dot_segments(source) == expected


@pytest.mark.parametrize(
    "source, expected",
    [
        ("%7e%41%30%2D%2e%5F", "~A0-._"),
        ("%21%2F%3F%23%25%40%3A", "%21%2F%3F%23%25%40%3A"),
        ("%c3%a9", "%C3%A9"),
        ("user%7e%2fname", "user~%2Fname"),
        ("%7Bfoo%7D", "%7Bfoo%7D"),
    ],
)
def test_unreserved_percent_decoding_preserves_reserved_escapes(
    source, expected
):
    """RFC 3986 §2.3 and §6.2.2.2 decode only unreserved octets."""
    assert normalize_percent_characters(source) == expected


def test_reserved_exclamation_is_not_unreserved():
    from rfc3986 import misc

    assert "!" not in misc.UNRESERVED_CHARS
    assert "!" in misc.RESERVED_CHARS


@pytest.mark.parametrize(
    "encoded, decoded",
    [
        ("http://example.com/%7Euser", "http://example.com/~user"),
        ("http://example.com/%41", "http://example.com/A"),
        ("http://example.com/?a=%7e", "http://example.com/?a=~"),
        ("http://example.com/#%41", "http://example.com/#A"),
        ("http://EXa%6Dple.com/path", "http://example.com/path"),
        ("http://user%7e@EXAMPLE.COM/path", "http://user~@example.com/path"),
        ("http://example.com/a/%2e%2e/b", "http://example.com/b"),
    ],
)
def test_uri_normalization_decodes_pct_unreserved_equivalences(
    encoded, decoded
):
    from rfc3986 import uri_reference

    a = uri_reference(encoded)
    b = uri_reference(decoded)
    assert a.normalize().unsplit() == b.normalize().unsplit()
    assert a == b


@pytest.mark.parametrize(
    "encoded, plain",
    [
        ("http://example.com/%2F", "http://example.com//"),
        ("http://example.com/%3F", "http://example.com/?"),
        ("http://example.com/?a=%26", "http://example.com/?a=&"),
        ("http://example.com/#%23", "http://example.com/##"),
        ("http://example.com/%21", "http://example.com/!"),
    ],
)
def test_reserved_percent_encoding_remains_distinct(encoded, plain):
    from rfc3986 import uri_reference

    assert uri_reference(encoded) != uri_reference(plain)
