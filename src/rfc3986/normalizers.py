# Copyright (c) 2014 Rackspace
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Module with functions to normalize components."""

import re
import typing as t
from urllib.parse import quote as urlquote

from . import compat
from . import misc


def normalize_scheme(scheme: str) -> str:
    """Normalize the scheme component."""
    return scheme.lower()


def normalize_authority(
    authority: t.Tuple[t.Optional[str], t.Optional[str], t.Optional[str]],
) -> str:
    """Normalize an authority tuple to a string."""
    userinfo, host, port = authority
    result = ""
    if userinfo:
        result += normalize_percent_characters(userinfo) + "@"
    if host:
        result += normalize_host(host)
    if port:
        result += ":" + port
    return result


def normalize_username(username: str) -> str:
    """Normalize a username to make it safe to include in userinfo."""
    return urlquote(username)


def normalize_password(password: str) -> str:
    """Normalize a password to make safe for userinfo."""
    return urlquote(password)


def normalize_host(host: str) -> str:
    """Normalize a host string."""
    if misc.IPv6_MATCHER.match(host):
        percent = host.find("%")
        if percent != -1:
            percent_25 = host.find("%25")

            # Replace RFC 4007 IPv6 Zone ID delimiter '%' with '%25'
            # from RFC 6874. If the host is '[<IPv6 addr>%25]' then we
            # assume RFC 4007 and normalize to '[<IPV6 addr>%2525]'
            if (
                percent_25 == -1
                or percent < percent_25
                or (percent == percent_25 and percent_25 == len(host) - 4)
            ):
                host = host.replace("%", "%25", 1)

            # Don't normalize the casing of the Zone ID
            return host[:percent].lower() + host[percent:]

    if "%" not in host:
        return host.lower()
    # Hostnames are case-insensitive, but percent triplet hex digits must
    # remain upper-case; decode unreserved escapes before lower-casing.
    return normalize_percent_characters(
        normalize_percent_characters(host).lower()
    )


def normalize_path(path: str, authority_present: bool = True) -> str:
    """Normalize a path without inventing an authority component."""
    if not path:
        return path

    path = normalize_percent_characters(path)
    normalized = remove_dot_segments(path)
    if not authority_present and normalized.startswith("//"):
        # RFC 3986 Section 3.3 forbids // at the start of a path without
        # authority: re-parsing would interpret the path as an authority.
        # A dot segment keeps the path absolute or relative as it was.
        return ("/." if path.startswith("/") else "./") + normalized
    return normalized


@t.overload
def normalize_query(query: str) -> str:  # noqa: D103
    ...


@t.overload
def normalize_query(query: None) -> None:  # noqa: D103
    ...


def normalize_query(query: t.Optional[str]) -> t.Optional[str]:
    """Normalize the query string."""
    if not query:
        return query
    return normalize_percent_characters(query)


@t.overload
def normalize_fragment(fragment: str) -> str:  # noqa: D103
    ...


@t.overload
def normalize_fragment(fragment: None) -> None:  # noqa: D103
    ...


def normalize_fragment(fragment: t.Optional[str]) -> t.Optional[str]:
    """Normalize the fragment string."""
    if not fragment:
        return fragment
    return normalize_percent_characters(fragment)


PERCENT_MATCHER = re.compile("%[A-Fa-f0-9]{2}")


def normalize_percent_characters(s: str) -> str:
    """Decode unreserved escapes and uppercase reserved escapes (RFC 3986).

    Decoding an encoded reserved character changes URI syntax and is unsafe;
    only ALPHA, DIGIT, hyphen, dot, underscore and tilde may be decoded.
    """

    def replace(match: "re.Match[str]") -> str:
        escape = match.group(0)
        char = chr(int(escape[1:], 16))
        if char in misc.UNRESERVED_CHARS:
            return char
        return escape.upper()

    return PERCENT_MATCHER.sub(replace, s)


def remove_dot_segments(s: str) -> str:
    """Remove dot segments using RFC 3986 Section 5.2.4's buffer algorithm."""
    input_buffer = s
    output_buffer = ""
    while input_buffer:
        if input_buffer.startswith("../"):
            input_buffer = input_buffer[3:]
        elif input_buffer.startswith("./"):
            input_buffer = input_buffer[2:]
        elif input_buffer.startswith("/./"):
            input_buffer = input_buffer[2:]
        elif input_buffer == "/.":
            input_buffer = "/"
        elif input_buffer.startswith("/../"):
            input_buffer = input_buffer[3:]
            output_buffer = (
                output_buffer.rsplit("/", 1)[0] if "/" in output_buffer else ""
            )
        elif input_buffer == "/..":
            input_buffer = "/"
            output_buffer = (
                output_buffer.rsplit("/", 1)[0] if "/" in output_buffer else ""
            )
        elif input_buffer in (".", ".."):
            input_buffer = ""
        else:
            # Step 2E: move the first segment (and its leading slash) to output.
            segment_end = input_buffer.find(
                "/", 1 if input_buffer.startswith("/") else 0
            )
            if segment_end == -1:
                segment_end = len(input_buffer)
            output_buffer += input_buffer[:segment_end]
            input_buffer = input_buffer[segment_end:]
    return output_buffer


@t.overload
def encode_component(uri_component: None, encoding: str) -> None:  # noqa: D103
    ...


@t.overload
def encode_component(uri_component: str, encoding: str) -> str:  # noqa: D103
    ...


def encode_component(
    uri_component: t.Optional[str],
    encoding: str,
) -> t.Optional[str]:
    """Encode the specific component in the provided encoding."""
    if uri_component is None:
        return uri_component

    # Try to see if the component we're encoding is already percent-encoded
    # so we can skip all '%' characters but still encode all others.
    percent_encodings = len(
        PERCENT_MATCHER.findall(compat.to_str(uri_component, encoding))
    )

    uri_bytes = compat.to_bytes(uri_component, encoding)
    is_percent_encoded = percent_encodings == uri_bytes.count(b"%")

    encoded_uri = bytearray()

    for i in range(0, len(uri_bytes)):
        # Will return a single character bytestring on both Python 2 & 3
        byte = uri_bytes[i : i + 1]
        byte_ord = ord(byte)
        if (is_percent_encoded and byte == b"%") or (
            byte_ord < 128 and byte.decode() in misc.NON_PCT_ENCODED
        ):
            encoded_uri.extend(byte)
            continue
        encoded_uri.extend(f"%{byte_ord:02x}".encode().upper())

    return encoded_uri.decode(encoding)
