# -*- coding: utf-8 -*-
# Copyright (c) 2015 Ian Cordasco
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
from collections import namedtuple

from . import compat
from . import exceptions
from . import normalizers
from . import uri

__all__ = ('ParseResult', 'ParseResultBytes')

PARSED_COMPONENTS = ('scheme', 'userinfo', 'host', 'port', 'path', 'query',
                     'fragment')


class ParseResultMixin(object):
    def _generate_authority(self, attributes):
        # I swear I did not align the comparisons below. That's just how they
        # happened to align based on pep8 and attribute lengths.
        userinfo, host, port = (attributes[p]
                                for p in ('userinfo', 'host', 'port'))
        if (self.userinfo != userinfo or
                self.host != host or
                self.port != port):
            if port:
                port = '{0}'.format(port)
            return normalizers.normalize_authority(
                (userinfo, host, port)
            )
        return self.authority

    def geturl(self):
        """Standard library shim to the unsplit method."""
        return self.unsplit()

    @property
    def hostname(self):
        """Standard library shim for the host portion of the URI."""
        return self.host

    @property
    def netloc(self):
        """Standard library shim for the authority portion of the URI."""
        return self.authority

    @property
    def params(self):
        """Standard library shim for the query portion of the URI."""
        return self.query


class ParseResult(namedtuple('ParseResult', PARSED_COMPONENTS),
                  ParseResultMixin):
    slots = ()

    def __new__(cls, scheme, userinfo, host, port, path, query, fragment,
                uri_ref, encoding='utf-8'):
        parse_result = super(ParseResult, cls).__new__(
            cls,
            scheme or None,
            userinfo or None,
            host or None,
            port,
            path or None,
            query or None,
            fragment or None)
        parse_result.encoding = encoding
        parse_result.reference = uri_ref
        return parse_result

    @classmethod
    def from_string(cls, uri_string, encoding='utf-8', strict=True):
        """Parse a URI from the given unicode URI string.

        :param str uri_string: Unicode URI to be parsed into a reference.
        :param str encoding: The encoding of the string provided
        :param bool strict: Parse strictly according to :rfc:`3986` if True.
            If False, parse similarly to the standard library's urlparse
            function.
        :returns: :class:`ParseResult` or subclass thereof
        """
        reference = uri.URIReference.from_string(uri_string, encoding)
        try:
            subauthority = reference.authority_info()
        except exceptions.InvalidAuthority:
            if strict:
                raise
            userinfo, host, port = split_authority(reference.authority)
        else:
            # Thanks to Richard Barrell for this idea:
            # https://twitter.com/0x2ba22e11/status/617338811975139328
            userinfo, host, port = (subauthority.get(p)
                                    for p in ('userinfo', 'host', 'port'))

        if port:
            try:
                port = int(port)
            except ValueError:
                raise exceptions.InvalidPort(port)

        return cls(scheme=reference.scheme,
                   userinfo=userinfo,
                   host=host,
                   port=port,
                   path=reference.path,
                   query=reference.query,
                   fragment=reference.fragment,
                   uri_ref=reference,
                   encoding=encoding)

    @property
    def authority(self):
        """Normalized authority generated from the subauthority parts."""
        return self.reference.authority

    def copy_with(self, scheme=None, userinfo=None, host=None, port=None,
                  path=None, query=None, fragment=None):
        """Create a copy of this instance replacing the specified parts.

        :returns: A new ParseResult instance
        """
        attributes = {
            'scheme': scheme or self.scheme,
            'userinfo': userinfo or self.userinfo,
            'host': host or self.host,
            'port': port or self.port,
            'path': path or self.path,
            'query': query or self.query,
            'fragment': fragment or self.fragment,
        }

        # Generate a new authority
        authority = self._generate_authority(attributes)

        # Use the reference's _replace method to create a new reference with
        # the updated authority
        reference = self.reference._replace(
            scheme=attributes['scheme'],
            authority=authority,
            path=attributes['path'],
            query=attributes['query'],
            fragment=attributes['fragment']
        )

        return ParseResult(
            scheme=attributes['scheme'],
            userinfo=attributes['userinfo'],
            host=attributes['host'],
            port=attributes['port'],
            path=attributes['path'],
            query=attributes['query'],
            fragment=attributes['fragment'],
            uri_ref=reference,
            encoding=self.encoding
        )

    def encode(self, encoding=None):
        encoding = encoding or self.encoding
        attrs = dict(
            zip(PARSED_COMPONENTS,
                (attr.encode(encoding) if hasattr(attr, 'encode') and attr is not None else attr
                 for attr in self)))
        return ParseResultBytes(
            uri_ref=self.reference,
            encoding=encoding,
            **attrs
        )

    def unsplit(self, use_idna=False):
        """Create a URI string from the components.

        :returns: The parsed URI reconstituted as a string.
        :rtype: str
        """
        return self.reference.unsplit()


class ParseResultBytes(namedtuple('ParseResultBytes', PARSED_COMPONENTS),
                       ParseResultMixin):
    def __new__(cls, scheme, userinfo, host, port, path, query, fragment,
                uri_ref, encoding='utf-8'):
        parse_result = super(ParseResultBytes, cls).__new__(
            cls,
            scheme or None,
            userinfo or None,
            host or None,
            port,
            path or None,
            query or None,
            fragment or None)
        parse_result.encoding = encoding
        parse_result.reference = uri_ref
        return parse_result

    @classmethod
    def from_string(cls, uri_string, encoding='utf-8', strict=True):
        """Parse a URI from the given unicode URI string.

        :param str uri_string: Unicode URI to be parsed into a reference.
        :param str encoding: The encoding of the string provided
        :param bool strict: Parse strictly according to :rfc:`3986` if True.
            If False, parse similarly to the standard library's urlparse
            function.
        :returns: :class:`ParseResultBytes` or subclass thereof
        """
        reference = uri.URIReference.from_string(uri_string, encoding)
        try:
            subauthority = reference.authority_info()
        except exceptions.InvalidAuthority:
            if strict:
                raise
            userinfo, host, port = split_authority(reference.authority)
        else:
            # Thanks to Richard Barrell for this idea:
            # https://twitter.com/0x2ba22e11/status/617338811975139328
            userinfo, host, port = (subauthority.get(p)
                                    for p in ('userinfo', 'host', 'port'))

        if port:
            try:
                port = int(port)
            except ValueError:
                raise exceptions.InvalidPort(port)

        to_bytes = compat.to_bytes
        return cls(scheme=to_bytes(reference.scheme, encoding) if reference.scheme else None,
                   userinfo=to_bytes(userinfo, encoding) if userinfo else None,
                   host=to_bytes(host, encoding) if host else None,
                   port=port,
                   path=to_bytes(reference.path, encoding) if reference.path else None,
                   query=to_bytes(reference.query, encoding) if reference.query else None,
                   fragment=to_bytes(reference.fragment, encoding) if reference.fragment else None,
                   uri_ref=reference,
                   encoding=encoding)

    @property
    def authority(self):
        """Normalized authority generated from the subauthority parts."""
        if not self.host:
            return None

        authority_parts = []
        if self.userinfo:
            authority_parts.extend([self.userinfo, b'@'])
        authority_parts.append(self.host)
        if self.port:
            authority_parts.extend([b':', str(self.port).encode(self.encoding)])

        return b''.join(authority_parts)

    def copy_with(self, scheme=None, userinfo=None, host=None, port=None,
                  path=None, query=None, fragment=None):
        """Create a copy of this instance replacing the specified parts.

        :returns: A new ParseResultBytes instance
        """
        attributes = {
            'scheme': scheme or self.scheme,
            'userinfo': userinfo or self.userinfo,
            'host': host or self.host,
            'port': port or self.port,
            'path': path or self.path,
            'query': query or self.query,
            'fragment': fragment or self.fragment,
        }

        # For bytes objects we need to make sure we're working with bytes
        # Convert any string arguments to bytes using our encoding
        for key, value in attributes.items():
            if value is not None and isinstance(value, str):
                attributes[key] = value.encode(self.encoding)

        return ParseResultBytes(
            scheme=attributes['scheme'],
            userinfo=attributes['userinfo'],
            host=attributes['host'],
            port=attributes['port'],
            path=attributes['path'],
            query=attributes['query'],
            fragment=attributes['fragment'],
            uri_ref=self.reference,
            encoding=self.encoding
        )

    def unsplit(self, use_idna=False):
        """Create a URI bytes object from the components.

        :param bool use_idna: Use IDNA encoding for the domain name
        :rtype: bytes
        """
        result_list = []
        if self.scheme:
            result_list.extend([self.scheme, b':'])

        # Authority component (userinfo, host, port)
        if self.host:
            result_list.append(b'//')
            if self.userinfo:
                result_list.extend([self.userinfo, b'@'])

            # Handle IDNA encoding for internationalized domain names
            if use_idna:
                host = self.host
                try:
                    # Check if this looks like a non-ASCII hostname
                    host_str = host.decode(self.encoding)
                    if any(ord(c) > 127 for c in host_str):
                        # Try to use the idna codec to encode the hostname
                        import codecs
                        host = codecs.encode(host_str, 'idna')
                except (UnicodeError, ImportError, AttributeError):
                    # If anything fails, use the original host
                    pass
                result_list.append(host)
            else:
                result_list.append(self.host)

            if self.port:
                result_list.extend([b':', str(self.port).encode(self.encoding)])

        # Path component
        if self.path:
            result_list.append(self.path)

        # Query component
        if self.query:
            result_list.extend([b'?', self.query])

        # Fragment component
        if self.fragment:
            result_list.extend([b'#', self.fragment])

        return b''.join(result_list)


def split_authority(authority):
    # Initialize our expected return values
    userinfo = host = port = None
    # Initialize an extra var we may need to use
    extra_host = None
    # Set-up rest in case there is no userinfo portion
    rest = authority

    if authority and '@' in authority:
        userinfo, rest = authority.rsplit('@', 1)

    # Handle IPv6 host addresses
    if rest and rest.startswith('['):
        host, rest = rest.split(']', 1)
        host += ']'

    if rest and ':' in rest:
        extra_host, port = rest.split(':', 1)
    elif not host and rest:
        host = rest

    if extra_host and not host:
        host = extra_host

    return userinfo, host, port
