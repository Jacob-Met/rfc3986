import pytest

import rfc3986
from rfc3986.exceptions import InvalidAuthority

try:
    import idna
except ImportError:
    idna = None


requires_idna = pytest.mark.skipif(
    idna is None, reason="This test requires the 'idna' module"
)
iri_to_uri = pytest.mark.parametrize(
    ["iri", "uri"],
    [
        ("http://Bücher.de", "http://xn--bcher-kva.de"),
        ("http://faß.de", "http://xn--fa-hia.de"),
        (
            "http://βόλος.com/β/ό?λ#ος",
            "http://xn--nxasmm1c.com/%CE%B2/%CF%8C?%CE%BB#%CE%BF%CF%82",
        ),
        ("http://ශ්\u200dරී.com", "http://xn--10cl1a0b660p.com"),
        ("http://نامه\u200cای.com", "http://xn--mgba3gch31f060k.com"),
        ("http://Bü:ẞ@gOoGle.com", "http://B%C3%BC:%E1%BA%9E@gOoGle.com"),
        ("http://ẞ.com:443", "http://xn--zca.com:443"),
        ("http://ẞ.foo.com", "http://xn--zca.foo.com"),
        ("http://Bẞ.com", "http://xn--b-qfa.com"),
        (
            "http+unix://%2Ftmp%2FTEST.sock/get",
            "http+unix://%2Ftmp%2FTEST.sock/get",
        ),
    ],
)


@requires_idna
@iri_to_uri
def test_encode_iri(iri, uri):
    assert rfc3986.iri_reference(iri).encode().unsplit() == uri


@iri_to_uri
def test_iri_equality(iri, uri):
    assert rfc3986.iri_reference(iri) == iri


def test_iri_equality_special_cases():
    assert rfc3986.iri_reference("http://Bü:ẞ@βόλος.com/β/ό?λ#ος") == (
        "http",
        "Bü:ẞ@βόλος.com",
        "/%CE%B2/%CF%8C",
        "%CE%BB",
        "%CE%BF%CF%82",
    )

    with pytest.raises(TypeError):
        rfc3986.iri_reference("http://ẞ.com") == 1


@requires_idna
@pytest.mark.parametrize(
    "iri",
    [
        "http://♥.net",
        "http://\u0378.net",
        "http://㛼.com",
    ],
)
def test_encode_invalid_iri(iri):
    iri_ref = rfc3986.iri_reference(iri)
    with pytest.raises(InvalidAuthority):
        iri_ref.encode()


@pytest.mark.parametrize("reference", ["file:///home", "foo://", "//"])
def test_iri_with_empty_authority_roundtrips(reference):
    parsed = rfc3986.iri_reference(reference)
    assert parsed.authority == ""
    assert parsed.unsplit() == reference
    assert parsed.encode().unsplit() == reference


@pytest.mark.parametrize(
    "source, expected",
    [
        ("https://example.com/a", "https://example.com/a"),
        ("https://USER@Example.COM/p", "https://USER@Example.COM/p"),
        (
            "http+unix://%2Ftmp%2FTEST.sock/get",
            "http+unix://%2Ftmp%2FTEST.sock/get",
        ),
        (
            "https://user:päss@host.example/a",
            "https://user:p%C3%A4ss@host.example/a",
        ),
        ("http://[::1]/path", "http://[::1]/path"),
    ],
)
def test_encoding_ascii_iri_authority_needs_no_optional_idna(
    monkeypatch, source, expected
):
    import rfc3986.iri as iri_module

    monkeypatch.setattr(iri_module, "idna", None)
    assert rfc3986.iri_reference(source).encode().unsplit() == expected


@pytest.mark.parametrize(
    "source",
    [
        "http://bad host/path",
        "http://foo]bar/path",
        "http://foo:999999oops/a",
        "https://user@@host/a",
    ],
)
def test_encoding_invalid_authority_cannot_erase_destination(
    monkeypatch, source
):
    import rfc3986.iri as iri_module

    monkeypatch.setattr(iri_module, "idna", None)
    with pytest.raises(InvalidAuthority):
        rfc3986.iri_reference(source).encode()


def test_encoding_unicode_hostname_requires_idna_when_unavailable(monkeypatch):
    import rfc3986.iri as iri_module
    from rfc3986.exceptions import MissingDependencyError

    monkeypatch.setattr(iri_module, "idna", None)
    with pytest.raises(MissingDependencyError):
        rfc3986.iri_reference("https://bücher.de/a").encode()


def test_encoding_iri_preserves_syntactically_valid_large_port():
    """IRI encoding should not silently discard a valid URI destination."""
    source = "custom://host:1234567890/resource"
    assert rfc3986.iri_reference(source).encode().unsplit() == source
