# -*- coding: utf-8 -*-
# Copyright (c) 2014 Rackspace
# Copyright (c) 2015 Ian Cordasco
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# See the License for the specific language governing permissions and
# limitations under the License.
from collections import namedtuple

from .compat import to_str
from .exceptions import InvalidAuthority, ResolutionError
from .misc import (
    ABSOLUTE_URI_MATCHER, FRAGMENT_MATCHER, IPv4_MATCHER, PATH_MATCHER,
    QUERY_MATCHER, SCHEME_MATCHER, SUBAUTHORITY_MATCHER, URI_MATCHER,
    URI_COMPONENTS, merge_paths
    )
from .normalizers import (
    encode_component, normalize_scheme, normalize_authority, normalize_path,
    normalize_query, normalize_fragment
    )


class URIReference(namedtuple('URIReference', URI_COMPONENTS)):
    slots = ()

    def __new__(cls, scheme, authority, path, query, fragment,
                encoding='utf-8'):
        ref = super(URIReference, cls).__new__(
            cls,
            scheme or None,
            authority or None,
            path or None,
            query or None,
            fragment or None)
        ref.encoding = encoding
        return ref

    def __eq__(self, other):
        other_ref = None
        if isinstance(other, URIReference):
            other_ref = other
        elif isinstance(other, tuple):
            other_ref = URIReference(*other)
        elif isinstance(other, str):
            other_ref = URIReference.from_string(other, encoding=self.encoding)
        else:
            raise TypeError('Unable to compare URIReference() to {}'.format(
                type(other)))

        # Compare components
        return (self.scheme == other_ref.scheme and
                self.authority == other_ref.authority and
                self.path == other_ref.path and
                self.query == other_ref.query and
                self.fragment == other_ref.fragment)

    @classmethod
    def from_string(cls, uri_string, encoding='utf-8'):
        """Parse a URI reference from the given unicode URI string.

        :param str uri_string: Unicode URI to be parsed into a reference.
        :param str encoding: The encoding of the string provided
        :returns: :class:`URIReference` or subclass thereof
        """
        uri_string = to_str(uri_string, encoding)

        split_uri = URI_MATCHER.match(uri_string).groupdict()
        return cls(split_uri['scheme'],
                   split_uri['authority'],
                   encode_component(split_uri['path'], encoding),
                   encode_component(split_uri['query'], encoding),
                   encode_component(split_uri['fragment'], encoding),
                   encoding)

    def authority_info(self):
        """Returns a dictionary with the ``userinfo``, ``host``, and ``port``.

        If the authority is not valid, it will raise a ``InvalidAuthority``
        Exception.

        :returns:
            ``{'userinfo': 'username:password', 'host': 'www.example.com',
            'port': '80'}``
        :rtype: dict
        :raises InvalidAuthority: If the authority is not ``None`` and can not
            be parsed.
        """
        if not self.authority:
            return {'userinfo': None, 'host': None, 'port': None}

        match = SUBAUTHORITY_MATCHER.match(self.authority)

        if match is None:
            # In this case, we have an authority that was parsed from the URI
            # Reference, but it cannot be further parsed by our
            # SUBAUTHORITY_MATCHER. In this case it must not be a valid
            # authority.
            raise InvalidAuthority(self.authority.encode(self.encoding))

        # We had a match, now let's ensure that it is actually a valid host
        # address if it is IPv4
        groupdict = match.groupdict()
        host = groupdict.get('host')

        if host and IPv4_MATCHER.match(host):
            # Verify each byte is valid
            if not valid_ipv4_host_address(host):
                raise InvalidAuthority(self.authority.encode(self.encoding))

        return {
            'userinfo': groupdict.get('userinfo'),
            'host': host,
            'port': groupdict.get('port')
        }

    @property
    def host(self):
        """If present, a string representing the host."""
        try:
            authority = self.authority_info()
        except InvalidAuthority:
            return None
        return authority['host']

    @property
    def port(self):
        """If present, the port (as a string) extracted from the authority."""
        try:
            authority = self.authority_info()
        except InvalidAuthority:
            return None
        return authority['port']

    @property
    def userinfo(self):
        """If present, the userinfo extracted from the authority."""
        try:
            authority = self.authority_info()
        except InvalidAuthority:
            return None
        return authority['userinfo']

    def is_absolute(self):
        """Determine if this URI Reference is an absolute URI.

        See http://tools.ietf.org/html/rfc3986#section-4.3 for explanation.

        :returns: ``True`` if it is an absolute URI, ``False`` otherwise.
        :rtype: bool
        """
        return self.scheme is not None and self.fragment is None

    def is_valid(self, **kwargs):
        """Determines if the URI is valid.

        :param bool require_scheme: Set to ``True`` if you wish to require the
            presence of the scheme component.
        :param bool require_authority: Set to ``True`` if you wish to require
            the presence of the authority component.
        :param bool require_path: Set to ``True`` if you wish to require the
            presence of the path component.
        :param bool require_query: Set to ``True`` if you wish to require the
            presence of the query component.
        :param bool require_fragment: Set to ``True`` if you wish to require
            the presence of the fragment component.
        :returns: ``True`` if the URI is valid. ``False`` otherwise.
        :rtype: bool
        """
        return (self.scheme_is_valid(kwargs.get('require_scheme', False)) and
                self.authority_is_valid(kwargs.get('require_authority', False)) and
                self.path_is_valid(kwargs.get('require_path', False)) and
                self.query_is_valid(kwargs.get('require_query', False)) and
                self.fragment_is_valid(kwargs.get('require_fragment', False)))

    def _is_valid(self, value, matcher, require):
        if require:
            return (value is not None
                    and matcher.match(value))

        # require is False and value is not None
        return value is None or matcher.match(value)

    def authority_is_valid(self, require=False):
        """Determines if the authority component is valid.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the authority is valid. ``False`` otherwise.
        :rtype: bool
        """
        try:
            self.authority_info()
        except InvalidAuthority:
            return False

        is_valid = self._is_valid(self.authority,
                                  SUBAUTHORITY_MATCHER,
                                  require)

        # Ensure that IPv4 addresses have valid bytes
        if is_valid and self.host and IPv4_MATCHER.match(self.host):
            return valid_ipv4_host_address(self.host)

        # Perhaps the host didn't exist or if it did, it wasn't an IPv4-like
        # address. In either case, we want to rely on the `_is_valid` check,
        # so let's return that.
        return is_valid

    def scheme_is_valid(self, require=False):
        """Determines if the scheme component is valid.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the scheme is valid. ``False`` otherwise.
        :rtype: bool
        """
        return self._is_valid(self.scheme, SCHEME_MATCHER, require)

    def path_is_valid(self, require=False):
        """Determines if the path component is valid.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the path is valid. ``False`` otherwise.
        :rtype: bool
        """
        return self._is_valid(self.path, PATH_MATCHER, require)

    def query_is_valid(self, require=False):
        """Determines if the query component is valid.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the query is valid. ``False`` otherwise.
        :rtype: bool
        """
        return self._is_valid(self.query, QUERY_MATCHER, require)

    def fragment_is_valid(self, require=False):
        """Determines if the fragment component is valid.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the fragment is valid. ``False`` otherwise.
        :rtype: bool
        """
        return self._is_valid(self.fragment, FRAGMENT_MATCHER, require)

    def normalize(self):
        """Normalize this reference as described in Section 6.2.2

        This is not an in-place normalization. Instead this creates a new
        URIReference.

        :returns: A new reference object with normalized components.
        :rtype: URIReference
        """
        # See http://tools.ietf.org/html/rfc3986#section-6.2.2 for logic in
        # this method.
        return URIReference(normalize_scheme(self.scheme or ''),
                            normalize_authority(
                                (self.userinfo, self.host, self.port)),
                            normalize_path(self.path or ''),
                            normalize_query(self.query or ''),
                            normalize_fragment(self.fragment or ''))

    def normalized_equality(self, other_ref):
        """Compare this URIReference to another URIReference.

        :param URIReference other_ref: (required), The reference with which
            we're comparing.
        :returns: ``True`` if the references are equal, ``False`` otherwise.
        :rtype: bool
        """
        return self.normalize() == other_ref.normalize()

    def resolve_with(self, base_uri, strict=False):
        """Use an absolute URI Reference to resolve this relative reference.

        Assuming this is a relative reference that you would like to resolve,
        use the provided base URI to resolve it.

        See http://tools.ietf.org/html/rfc3986#section-5 for more information.

        :param base_uri: Either a string or URIReference. It must be an
            absolute URI or it will raise an exception.
        :returns: A new URIReference which is the result of resolving this
            reference using ``base_uri``.
        :rtype: :class:`URIReference`
        :raises ResolutionError: If the ``base_uri`` is not an absolute URI.
        """
        if not isinstance(base_uri, URIReference):
            base_uri = URIReference.from_string(base_uri)

        if not base_uri.is_absolute():
            raise ResolutionError(base_uri)

        # If we have a scheme, then we're already absolute
        if self.scheme is not None:
            return self.__class__(
                self.scheme,
                self.authority,
                normalize_path(self.path or ''),
                self.query,
                self.fragment
            )

        # Otherwise, we inherit from base_uri
        if self.authority is not None:
            return self.__class__(
                base_uri.scheme,
                self.authority,
                normalize_path(self.path or ''),
                self.query,
                self.fragment
            )

        # No authority, resolve path
        if not self.path:
            path = base_uri.path
            query = self.query if self.query is not None else base_uri.query
        else:
            if self.path.startswith('/'):
                path = normalize_path(self.path)
            else:
                path = normalize_path(
                    merge_paths(base_uri.path, self.path)
                )
            query = self.query

        return self.__class__(
            base_uri.scheme,
            base_uri.authority,
            path,
            query,
            self.fragment
        )

    def unsplit(self):
        result_list = []
        if self.scheme:
            result_list.extend([self.scheme, ':'])
        if self.authority:
            result_list.extend(['//', self.authority])
        if self.path:
            result_list.append(self.path)
        if self.query:
            result_list.extend(['?', self.query])
        if self.fragment:
            result_list.extend(['#', self.fragment])
        return ''.join(result_list)

    def copy_with(self, scheme=None, authority=None, path=None, query=None,
                  fragment=None):
        return self.__class__(
            scheme if scheme is not None else self.scheme,
            authority if authority is not None else self.authority,
            path if path is not None else self.path,
            query if query is not None else self.query,
            fragment if fragment is not None else self.fragment,
            self.encoding
        )


def valid_ipv4_host_address(host):
    # Check each byte in the IPv4 address
    if not host:
        return False

    parts = host.split('.')
    if len(parts) != 4:
        return False

    for part in parts:
        try:
            byte_value = int(part)
            if byte_value < 0 or byte_value > 255:
                return False
        except ValueError:
            return False

    return True
