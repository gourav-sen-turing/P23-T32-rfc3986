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
        if isinstance(other, URIReference):
            return tuple(self) == tuple(other)
        elif isinstance(other, tuple):
            return tuple(self) == other
        elif isinstance(other, str):
            return other == self.unsplit()
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return NotImplemented
        return not result

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
                   split_uri['path'],
                   split_uri['query'],
                   split_uri['fragment'],
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
        host = groupdict['host']

        if host and IPv4_MATCHER.match(host):
            if not valid_ipv4_host_address(host):
                raise InvalidAuthority(self.authority.encode(self.encoding))

        return groupdict

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
        require_scheme = kwargs.get('require_scheme', False)
        require_authority = kwargs.get('require_authority', False)
        require_path = kwargs.get('require_path', False)
        require_query = kwargs.get('require_query', False)
        require_fragment = kwargs.get('require_fragment', False)

        valid_scheme = self.scheme_is_valid(require=require_scheme)
        valid_path = self.path_is_valid(require=require_path)
        valid_query = self.query_is_valid(require=require_query)
        valid_fragment = self.fragment_is_valid(require=require_fragment)
        valid_authority = self.authority_is_valid(require=require_authority)

        return all([
            valid_scheme,
            valid_path,
            valid_query,
            valid_fragment,
            valid_authority,
        ])

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
                            normalize_fragment(self.fragment or ''),
                            self.encoding)

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

        # This is optional per
        # http://tools.ietf.org/html/rfc3986#section-5.2.1
        base_uri = base_uri.normalize()

        # The reference we're resolving
        ref = self

        # This is optional per
        # http://tools.ietf.org/html/rfc3986#section-5.2.1
        ref = ref.normalize()

        if ref.scheme is not None and ref.scheme != base_uri.scheme:
            target = ref
        else:
            if ref.authority is not None:
                target_authority = ref.authority
                target_path = ref.path or ''
                target_query = ref.query
            else:
                target_authority = base_uri.authority

                if ref.path is None or ref.path == '':
                    target_path = base_uri.path
                    target_query = ref.query or base_uri.query
                else:
                    if ref.path.startswith('/'):
                        target_path = ref.path
                    else:
                        target_path = merge_paths(base_uri, ref.path)
                    target_query = ref.query

            target = URIReference(base_uri.scheme, target_authority, target_path,
                                 target_query, ref.fragment)

        return target

    def unsplit(self):
        """Create a URI string from the components.

        :returns: The URI Reference reconstituted as a string.
        :rtype: str
        """
        result_list = []
        if self.scheme is not None:
            result_list.extend([self.scheme, ':'])
        if self.authority is not None:
            result_list.extend(['//', self.authority])
        if self.path is not None:
            result_list.append(self.path)
        if self.query is not None:
            result_list.extend(['?', self.query])
        if self.fragment is not None:
            result_list.extend(['#', self.fragment])
        return ''.join(result_list)

    def copy_with(self, scheme=None, authority=None, path=None, query=None,
                  fragment=None):
        """Create a copy of this reference with the new components.

        :returns: New URIReference with the specified components.
        :rtype: URIReference
        """
        return URIReference(
            scheme or self.scheme,
            authority or self.authority,
            path or self.path,
            query or self.query,
            fragment or self.fragment,
            self.encoding
        )


def valid_ipv4_host_address(host):
    """Determine if the given host is a valid IPv4 address.

    :param str host: The host portion of an authority component.
    :returns: ``True`` if the host is valid, ``False`` otherwise.
    :rtype: bool
    """
    # If each segment is in the proper range, the host is valid
    for segment in host.split('.'):
        try:
            segment = int(segment)
        except ValueError:
            return False
        if segment < 0 or segment > 255:
            return False
    return True
