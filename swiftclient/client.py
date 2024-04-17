# Copyright (c) 2010-2012 OpenStack, LLC.
#
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

"""
OpenStack Swift client library used internally
"""
import socket
import re
import logging
from urllib3.exceptions import HTTPError as urllib_http_error

import warnings

from requests.exceptions import RequestException, SSLError
import http.client as http_client
from requests.structures import CaseInsensitiveDict
from urllib.parse import quote, unquote
from urllib.parse import urljoin, urlparse, urlunparse
from time import sleep, time

from swiftclient import version as swiftclient_version
from swiftclient.exceptions import ClientException
from swiftclient.requests_compat import SwiftClientRequestsSession
from swiftclient.utils import (
    iter_wrapper, LengthWrapper, ReadableToIterable, parse_api_response,
    get_body)

# Default is 100, increase to 256
http_client._MAXHEADERS = 256

VERSIONFUL_AUTH_PATH = re.compile(r'v[2-3](?:\.0)?$')
AUTH_VERSIONS_V1 = ('1.0', '1', 1)
AUTH_VERSIONS_V2 = ('2.0', '2', 2)
AUTH_VERSIONS_V3 = ('3.0', '3', 3)
USER_METADATA_TYPE = tuple('x-%s-meta-' % type_ for type_ in
                           ('container', 'account', 'object'))
URI_PATTERN_INFO = re.compile(r'/info')
URI_PATTERN_VERSION = re.compile(r'\/v\d+\.?\d*(\/.*)?')

ksexceptions = ksclient_v2 = ksclient_v3 = ksa_v3 = None
try:
    from keystoneclient import exceptions as ksexceptions
    # prevent keystoneclient warning us that it has no log handlers
    logging.getLogger('keystoneclient').addHandler(logging.NullHandler())
    from keystoneclient.v2_0 import client as ksclient_v2
except ImportError:
    pass
try:
    from keystoneclient.v3 import client as ksclient_v3
    from keystoneauth1.identity import v3 as ksa_v3
    from keystoneauth1 import session as ksa_session
    from keystoneauth1 import exceptions as ksauthexceptions
except ImportError:
    pass

logger = logging.getLogger("swiftclient")
logger.addHandler(logging.NullHandler())

#: Default behaviour is to redact header values known to contain secrets,
#: such as ``X-Auth-Key`` and ``X-Auth-Token``. Up to the first 16 chars
#: may be revealed.
#:
#: To disable, set the value of ``redact_sensitive_headers`` to ``False``.
#:
#: When header redaction is enabled, ``reveal_sensitive_prefix`` configures the
#: maximum length of any sensitive header data sent to the logs. If the header
#: is less than twice this length, only ``int(len(value)/2)`` chars will be
#: logged; if it is less than 15 chars long, even less will be logged.
logger_settings = {
    'redact_sensitive_headers': True,
    'reveal_sensitive_prefix': 16
}
#: A list of sensitive headers to redact in logs. Note that when extending this
#: list, the header names must be added in all lower case.
LOGGER_SENSITIVE_HEADERS = [
    'x-auth-token', 'x-auth-key', 'x-service-token', 'x-storage-token',
    'x-account-meta-temp-url-key', 'x-account-meta-temp-url-key-2',
    'x-container-meta-temp-url-key', 'x-container-meta-temp-url-key-2',
    'set-cookie'
]


def safe_value(name, value):
    """
    Only show up to logger_settings['reveal_sensitive_prefix'] characters
    from a sensitive header.

    :param name: Header name
    :param value: Header value
    :return: Safe header value
    """
    if name.lower() in LOGGER_SENSITIVE_HEADERS:
        prefix_length = logger_settings.get('reveal_sensitive_prefix', 16)
        prefix_length = int(
            min(prefix_length, (len(value) ** 2) / 32, len(value) / 2)
        )
        redacted_value = value[0:prefix_length]
        return redacted_value + '...'
    return value


def scrub_headers(headers):
    """
    Redact header values that can contain sensitive information that
    should not be logged.

    :param headers: Either a dict or an iterable of two-element tuples
    :return: Safe dictionary of headers with sensitive information removed
    """
    if isinstance(headers, dict):
        headers = headers.items()
    headers = [
        (parse_header_string(key), parse_header_string(val))
        for (key, val) in headers
    ]
    if not logger_settings.get('redact_sensitive_headers', True):
        return dict(headers)
    if logger_settings.get('reveal_sensitive_prefix', 16) < 0:
        logger_settings['reveal_sensitive_prefix'] = 16
    return {key: safe_value(key, val) for (key, val) in headers}


def http_log(args, kwargs, resp, body):
    if not logger.isEnabledFor(logging.INFO):
        return

    # create and log equivalent curl command
    string_parts = ['curl -i']
    for element in args:
        if element == 'HEAD':
            string_parts.append(' -I')
        elif element in ('GET', 'POST', 'PUT'):
            string_parts.append(' -X %s' % element)
        else:
            string_parts.append(' %s' % parse_header_string(element))
    if 'headers' in kwargs:
        headers = scrub_headers(kwargs['headers'])
        for element in headers:
            header = ' -H "%s: %s"' % (element, headers[element])
            string_parts.append(header)

    # log response as debug if good, or info if error
    if resp.status < 300:
        log_method = logger.debug
    else:
        log_method = logger.info

    log_method("REQ: %s", "".join(string_parts))
    log_method("RESP STATUS: %s %s", resp.status, resp.reason)
    log_method("RESP HEADERS: %s", scrub_headers(resp.getheaders()))
    if body:
        resp_headers = resp_header_dict(resp)
        nbody = get_body(resp_headers, body)
        log_method("RESP BODY: %s", nbody)


def parse_header_string(data):
    if not isinstance(data, (str, bytes)):
        data = str(data)
    if isinstance(data, bytes):
        # Under Python3 requests only returns text_type and tosses (!) the
        # rest of the headers. If that ever changes, this should be a sane
        # approach.
        try:
            data = data.decode('ascii')
        except UnicodeDecodeError:
            data = quote(data)
    try:
        unquoted = unquote(data, errors='strict')
    except UnicodeDecodeError:
        return data
    return unquoted


def encode_utf8(value):
    if type(value) in (int, float, bool):
        # As of requests 2.11.0, headers must be byte- or unicode-strings.
        # Convert some known-good types as a convenience for developers.
        # Note that we *don't* convert subclasses, as they may have overriddden
        # __str__ or __repr__.
        # See https://github.com/kennethreitz/requests/pull/3366 for more info
        value = str(value)
    if isinstance(value, str):
        value = value.encode('utf8')
    return value


def encode_meta_headers(headers):
    """Only encode metadata headers keys"""
    ret = {}
    for header, value in headers.items():
        value = encode_utf8(value)
        header = header.lower()

        if (isinstance(header, str) and
                header.startswith(USER_METADATA_TYPE)):
            header = encode_utf8(header)

        ret[header] = value
    return ret


class LowerKeyCaseInsensitiveDict(CaseInsensitiveDict):
    """
    CaseInsensitiveDict returning lower case keys for items()
    """

    def __iter__(self):
        return iter(self._store.keys())


class _ObjectBody:
    """
    Readable and iterable object body response wrapper.
    """

    def __init__(self, resp, chunk_size, conn_to_close):
        """
        Wrap the underlying response

        :param resp: the response to wrap
        :param chunk_size: number of bytes to return each iteration/next call
        """
        self.resp = resp
        self.chunk_size = chunk_size
        self.conn_to_close = conn_to_close

    def read(self, length=None):
        buf = self.resp.read(length)
        if length != 0 and not buf:
            self.close()
        return buf

    def __iter__(self):
        return self

    def next(self):
        buf = self.read(self.chunk_size)
        if not buf:
            raise StopIteration()
        return buf

    def __next__(self):
        return self.next()

    def close(self):
        self.resp.close()
        if self.conn_to_close:
            self.conn_to_close.close()


class _RetryBody(_ObjectBody):
    """
    Wrapper for object body response which triggers a retry
    (from offset) if the connection is dropped after partially
    downloading the object.
    """
    def __init__(self, resp, connection, container, obj,
                 resp_chunk_size=None, query_string=None, response_dict=None,
                 headers=None):
        """
        Wrap the underlying response

        :param resp: the response to wrap
        :param connection: Connection class instance
        :param container: the name of the container the object is in
        :param obj: the name of object we are downloading
        :param resp_chunk_size: if defined, chunk size of data to read
        :param query_string: if set will be appended with '?' to generated path
        :param response_dict: an optional dictionary into which to place
                         the response - status, reason and headers
        :param headers: an optional dictionary with additional headers to
                         include in the request
        """
        super(_RetryBody, self).__init__(resp, resp_chunk_size, None)
        self.expected_length = int(self.resp.getheader('Content-Length'))
        self.conn = connection
        self.container = container
        self.obj = obj
        self.query_string = query_string
        self.response_dict = response_dict
        self.headers = dict(headers) if headers is not None else {}
        self.bytes_read = 0

    def read(self, length=None):
        buf = None
        try:
            buf = self.resp.read(length)
            self.bytes_read += len(buf)
        except (socket.error, urllib_http_error, RequestException):
            if self.conn.attempts > self.conn.retries:
                raise
        if (not buf and self.bytes_read < self.expected_length and
                self.conn.attempts <= self.conn.retries):
            self.headers['Range'] = 'bytes=%d-' % self.bytes_read
            self.headers['If-Match'] = self.resp.getheader('ETag')
            hdrs, body = self.conn._retry(None, get_object,
                                          self.container, self.obj,
                                          resp_chunk_size=self.chunk_size,
                                          query_string=self.query_string,
                                          response_dict=self.response_dict,
                                          headers=self.headers,
                                          attempts=self.conn.attempts)
            expected_range = 'bytes %d-%d/%d' % (
                self.bytes_read,
                self.expected_length - 1,
                self.expected_length)
            if 'content-range' not in hdrs:
                # Server didn't respond with partial content; manually seek
                logger.warning('Received 200 while retrying %s/%s; seeking...',
                               self.container, self.obj)
                to_read = self.bytes_read
                while to_read > 0:
                    buf = body.resp.read(min(to_read, self.chunk_size))
                    to_read -= len(buf)
            elif hdrs['content-range'] != expected_range:
                msg = ('Expected range "%s" while retrying %s/%s '
                       'but got "%s"' % (expected_range, self.container,
                                         self.obj, hdrs['content-range']))
                raise ClientException(msg)
            self.resp = body.resp
            buf = self.read(length)
        return buf


class HTTPConnection:
    def __init__(self, url, proxy=None, cacert=None, insecure=False,
                 cert=None, cert_key=None, ssl_compression=False,
                 default_user_agent=None, timeout=None):
        """
        Make an HTTPConnection or HTTPSConnection

        :param url: url to connect to
        :param proxy: proxy to connect through, if any; None by default; str
                      of the format 'http://127.0.0.1:8888' to set one
        :param cacert: A CA bundle file to use in verifying a TLS server
                       certificate.
        :param insecure: Allow to access servers without checking SSL certs.
                         The server's certificate will not be verified.
        :param cert: Client certificate file to connect on SSL server
                            requiring SSL client certificate.
        :param cert_key: Client certificate private key file.
        :param ssl_compression: SSL compression should be disabled by default
                                and this setting is not usable as of now. The
                                parameter is kept for backward compatibility.
        :param default_user_agent: Set the User-Agent header on every request.
                                   If set to None (default), the user agent
                                   will be "python-swiftclient-<version>". This
                                   may be overridden on a per-request basis by
                                   explicitly setting the user-agent header on
                                   a call to request().
        :param timeout: socket read timeout value, passed directly to
                        the requests library.
        :raises ClientException: Unable to handle protocol scheme
        """
        self.url = url
        self.parsed_url = urlparse(url)
        self.host = self.parsed_url.netloc
        self.port = self.parsed_url.port
        self.requests_args = {}
        self.request_session = SwiftClientRequestsSession()
        # Don't use requests's default headers
        self.request_session.headers = None
        self.resp = None
        if self.parsed_url.scheme not in ('http', 'https'):
            raise ClientException('Unsupported scheme "%s" in url "%s"'
                                  % (self.parsed_url.scheme, url))
        self.requests_args['verify'] = not insecure
        if cacert and not insecure:
            # verify requests parameter is used to pass the CA_BUNDLE file
            # see: http://docs.python-requests.org/en/latest/user/advanced/
            self.requests_args['verify'] = cacert
        if cert:
            # NOTE(cbrandily): cert requests parameter is used to pass client
            # cert path or  a tuple with client certificate/key paths.
            if cert_key:
                self.requests_args['cert'] = cert, cert_key
            else:
                self.requests_args['cert'] = cert

        if proxy:
            proxy_parsed = urlparse(proxy)
            if not proxy_parsed.scheme:
                raise ClientException("Proxy's missing scheme")
            self.requests_args['proxies'] = {
                proxy_parsed.scheme: '%s://%s' % (
                    proxy_parsed.scheme, proxy_parsed.netloc
                )
            }
        self.requests_args['stream'] = True
        if default_user_agent is None:
            default_user_agent = \
                'python-swiftclient-%s' % swiftclient_version.version_string
        self.default_user_agent = default_user_agent
        if timeout:
            self.requests_args['timeout'] = timeout

    def _request(self, *arg, **kwarg):
        """Final wrapper before requests call, to be patched in tests"""
        return self.request_session.request(*arg, **kwarg)

    def request(self, method, full_path, data=None, headers=None, files=None):
        """Encode url and header, then call requests.request"""
        if headers is None:
            headers = {}
        else:
            headers = encode_meta_headers(headers)

        # set a default User-Agent header if it wasn't passed in
        if 'user-agent' not in headers:
            headers['user-agent'] = self.default_user_agent
        url = "%s://%s%s" % (
            self.parsed_url.scheme,
            self.parsed_url.netloc,
            full_path)
        self.resp = self._request(method, url, headers=headers, data=data,
                                  files=files, **self.requests_args)
        return self.resp

    def putrequest(self, full_path, data=None, headers=None, files=None):
        """
        Use python-requests files upload

        :param data: Use data generator for chunked-transfer
        :param files: Use files for default transfer
        """
        return self.request('PUT', full_path, data, headers, files)

    def getresponse(self):
        """Adapt requests response to httplib interface"""
        self.resp.status = self.resp.status_code
        old_getheader = self.resp.raw.getheader

        def _decode_header(string):
            if string is None:
                return string
            return string.encode('iso-8859-1').decode('utf-8')

        def _encode_header(string):
            if string is None:
                return string
            return string.encode('utf-8').decode('iso-8859-1')

        def getheaders():
            return [(_decode_header(k), _decode_header(v))
                    for k, v in self.resp.headers.items()]

        def getheader(k, v=None):
            return _decode_header(old_getheader(
                _encode_header(k.lower()), _encode_header(v)))

        def releasing_read(*args, **kwargs):
            chunk = self.resp.raw.read(*args, **kwargs)
            if not chunk:
                # NOTE(sigmavirus24): Release the connection back to the
                # urllib3's connection pool. This will reduce the number of
                # log messages seen in bug #1341777. This does not actually
                # close a socket. It will also prevent people from being
                # misled as to the cause of a bug as in bug #1424732.
                self.resp.close()
            return chunk

        self.resp.getheaders = getheaders
        self.resp.getheader = getheader
        self.resp.read = releasing_read

        return self.resp

    def close(self):
        if self.resp:
            self.resp.close()
        self.request_session.close()


def http_connection(*arg, **kwarg):
    """:returns: tuple of (parsed url, connection object)"""
    conn = HTTPConnection(*arg, **kwarg)
    return conn.parsed_url, conn


def get_auth_1_0(url, user, key, snet, **kwargs):
    cacert = kwargs.get('cacert', None)
    insecure = kwargs.get('insecure', False)
    cert = kwargs.get('cert')
    cert_key = kwargs.get('cert_key')
    timeout = kwargs.get('timeout', None)
    parsed, conn = http_connection(url, cacert=cacert, insecure=insecure,
                                   cert=cert, cert_key=cert_key,
                                   timeout=timeout)
    method = 'GET'
    headers = {'X-Auth-User': user, 'X-Auth-Key': key}
    conn.request(method, parsed.path, '', headers)
    resp = conn.getresponse()
    body = resp.read()
    resp.close()
    conn.close()
    http_log((url, method,), headers, resp, body)
    url = resp.getheader('x-storage-url')

    # There is a side-effect on current Rackspace 1.0 server where a
    # bad URL would get you that document page and a 200. We error out
    # if we don't have a x-storage-url header and if we get a body.
    if resp.status < 200 or resp.status >= 300 or (body and not url):
        raise ClientException.from_response(resp, 'Auth GET failed', body)
    if snet:
        parsed = list(urlparse(url))
        # Second item in the list is the netloc
        netloc = parsed[1]
        parsed[1] = 'snet-' + netloc
        url = urlunparse(parsed)

    token = resp.getheader('x-storage-token', resp.getheader('x-auth-token'))
    return url, token


def get_keystoneclient_2_0(auth_url, user, key, os_options, **kwargs):
    # this function is only here to preserve the historic 'public'
    # interface of this module
    kwargs.update({'auth_version': '2.0'})
    return get_auth_keystone(auth_url, user, key, os_options, **kwargs)


def get_auth_keystone(auth_url, user, key, os_options, **kwargs):
    """
    Authenticate against a keystone server.

    We are using the keystoneclient library for authentication.
    """

    insecure = kwargs.get('insecure', False)
    timeout = kwargs.get('timeout', None)
    auth_version = kwargs.get('auth_version', None)
    debug = logger.isEnabledFor(logging.DEBUG)

    # Add the version suffix in case of versionless Keystone endpoints. If
    # auth_version is also unset it is likely that it is v3
    if not VERSIONFUL_AUTH_PATH.match(
            urlparse(auth_url).path.rstrip('/').rsplit('/', 1)[-1]):
        # Normalize auth_url to end in a slash because urljoin
        auth_url = auth_url.rstrip('/') + '/'
        if auth_version and auth_version in AUTH_VERSIONS_V2:
            auth_url = urljoin(auth_url, "v2.0")
        else:
            auth_url = urljoin(auth_url, "v3")
            auth_version = '3'
        logger.debug("Versionless auth_url - using %s as endpoint" % auth_url)

    # Legacy default if not set
    if auth_version is None:
        auth_version = '2'

    ksclient = None
    if auth_version in AUTH_VERSIONS_V3:
        if ksclient_v3 is not None:
            ksclient = ksclient_v3
    else:
        if ksclient_v2 is not None:
            ksclient = ksclient_v2

    if ksclient is None:
        raise ClientException('''
Auth versions 2.0 and 3 require python-keystoneclient, install it or use Auth
version 1.0 which requires ST_AUTH, ST_USER, and ST_KEY environment
variables to be set or overridden with -A, -U, or -K.''')

    filter_kwargs = {}
    service_type = os_options.get('service_type') or 'object-store'
    endpoint_type = os_options.get('endpoint_type') or 'publicURL'
    if os_options.get('region_name'):
        filter_kwargs['attr'] = 'region'
        filter_kwargs['filter_value'] = os_options['region_name']

    if os_options.get('auth_type') and os_options['auth_type'] not in (
            'password', 'v2password', 'v3password',
            'v3applicationcredential'):
        raise ClientException(
            'Swiftclient currently only supports v3applicationcredential '
            'for auth_type')
    elif os_options.get('auth_type') == 'v3applicationcredential':
        if ksa_v3 is None:
            raise ClientException('Auth v3applicationcredential requires '
                                  'keystoneauth1 package; consider upgrading '
                                  'to python-keystoneclient>=2.0.0')

        try:
            auth = ksa_v3.ApplicationCredential(
                auth_url=auth_url,
                application_credential_secret=os_options.get(
                    'application_credential_secret'),
                application_credential_id=os_options.get(
                    'application_credential_id'))
            sess = ksa_session.Session(auth=auth)
            token = sess.get_token()
        except ksauthexceptions.Unauthorized:
            msg = 'Unauthorized. Check application credential id and secret.'
            raise ClientException(msg)
        except ksauthexceptions.AuthorizationFailure as err:
            raise ClientException('Authorization Failure. %s' % err)

        try:
            endpoint = sess.get_endpoint_data(service_type=service_type,
                                              endpoint_type=endpoint_type,
                                              **filter_kwargs)

            return endpoint.catalog_url, token
        except ksauthexceptions.EndpointNotFound:
            raise ClientException(
                'Endpoint for %s not found - '
                'have you specified a region?' % service_type)

    try:
        _ksclient = ksclient.Client(
            username=user,
            password=key,
            token=os_options.get('auth_token'),
            tenant_name=os_options.get('tenant_name'),
            tenant_id=os_options.get('tenant_id'),
            user_id=os_options.get('user_id'),
            user_domain_name=os_options.get('user_domain_name'),
            user_domain_id=os_options.get('user_domain_id'),
            project_name=os_options.get('project_name'),
            project_id=os_options.get('project_id'),
            project_domain_name=os_options.get('project_domain_name'),
            project_domain_id=os_options.get('project_domain_id'),
            debug=debug,
            cacert=kwargs.get('cacert'),
            cert=kwargs.get('cert'),
            key=kwargs.get('cert_key'),
            auth_url=auth_url, insecure=insecure, timeout=timeout)
    except ksexceptions.Unauthorized:
        msg = 'Unauthorized. Check username, password and tenant name/id.'
        if auth_version in AUTH_VERSIONS_V3:
            msg = ('Unauthorized. Check username/id, password, '
                   'tenant name/id and user/tenant domain name/id.')
        raise ClientException(msg)
    except ksexceptions.AuthorizationFailure as err:
        raise ClientException('Authorization Failure. %s' % err)

    try:
        endpoint = _ksclient.service_catalog.url_for(
            service_type=service_type,
            endpoint_type=endpoint_type,
            **filter_kwargs)
    except ksexceptions.EndpointNotFound:
        raise ClientException('Endpoint for %s not found - '
                              'have you specified a region?' % service_type)
    return endpoint, _ksclient.auth_token


def get_auth(auth_url, user, key, **kwargs):
    """
    Get authentication/authorization credentials.

    :kwarg auth_version: the api version of the supplied auth params
    :kwarg os_options: a dict, the openstack identity service options

    :returns: a tuple, (storage_url, token)

    N.B. if the optional os_options parameter includes a non-empty
    'object_storage_url' key it will override the default storage url returned
    by the auth service.

    The snet parameter is used for Rackspace's ServiceNet internal network
    implementation. In this function, it simply adds *snet-* to the beginning
    of the host name for the returned storage URL. With Rackspace Cloud Files,
    use of this network path causes no bandwidth charges but requires the
    client to be running on Rackspace's ServiceNet network.
    """
    session = kwargs.get('session', None)
    auth_version = kwargs.get('auth_version', '1')
    os_options = kwargs.get('os_options', {})

    cacert = kwargs.get('cacert', None)
    insecure = kwargs.get('insecure', False)
    cert = kwargs.get('cert')
    cert_key = kwargs.get('cert_key')
    timeout = kwargs.get('timeout', None)

    if session:
        service_type = os_options.get('service_type', 'object-store')
        interface = os_options.get('endpoint_type', 'public')
        region_name = os_options.get('region_name')
        storage_url = session.get_endpoint(service_type=service_type,
                                           interface=interface,
                                           region_name=region_name)
        token = session.get_token()
    elif auth_version in AUTH_VERSIONS_V1:
        storage_url, token = get_auth_1_0(auth_url,
                                          user,
                                          key,
                                          kwargs.get('snet'),
                                          cacert=cacert,
                                          insecure=insecure,
                                          cert=cert,
                                          cert_key=cert_key,
                                          timeout=timeout)
    elif auth_version in AUTH_VERSIONS_V2 + AUTH_VERSIONS_V3:
        # We are handling a special use case here where the user argument
        # specifies both the user name and tenant name in the form tenant:user
        if user and not kwargs.get('tenant_name') and ':' in user:
            os_options['tenant_name'], user = user.split(':')

        # We are allowing to have a tenant_name argument in get_auth
        # directly without having os_options
        if kwargs.get('tenant_name'):
            os_options['tenant_name'] = kwargs['tenant_name']

        if os_options.get('auth_type') == 'v3applicationcredential':
            pass
        elif not (os_options.get('tenant_name') or
                  os_options.get('tenant_id') or
                  os_options.get('project_name') or
                  os_options.get('project_id')):
            if auth_version in AUTH_VERSIONS_V2:
                raise ClientException('No tenant specified')
            raise ClientException('No project name or project id specified.')

        storage_url, token = get_auth_keystone(auth_url, user,
                                               key, os_options,
                                               cacert=cacert,
                                               insecure=insecure,
                                               cert=cert,
                                               cert_key=cert_key,
                                               timeout=timeout,
                                               auth_version=auth_version)
    else:
        raise ClientException('Unknown auth_version %s specified and no '
                              'session found.' % auth_version)

    # Override storage url, if necessary
    if os_options.get('object_storage_url'):
        return os_options['object_storage_url'], token
    else:
        return storage_url, token


def resp_header_dict(resp):
    resp_headers = LowerKeyCaseInsensitiveDict()
    for header, value in resp.getheaders():
        header = parse_header_string(header)
        resp_headers[header] = parse_header_string(value)
    return resp_headers


def store_response(resp, response_dict):
    """
    store information about an operation into a dict

    :param resp: an http response object containing the response
                 headers
    :param response_dict: a dict into which are placed the
       status, reason and a dict of lower-cased headers
    """
    if response_dict is not None:
        response_dict['status'] = resp.status
        response_dict['reason'] = resp.reason
        response_dict['headers'] = resp_header_dict(resp)


def get_account(url, token, marker=None, limit=None, prefix=None,
                end_marker=None, http_conn=None, full_listing=False,
                service_token=None, headers=None, delimiter=None):
    """
    Get a listing of containers for the account.

    :param url: storage URL
    :param token: auth token
    :param marker: marker query
    :param limit: limit query
    :param prefix: prefix query
    :param end_marker: end_marker query
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object)
    :param full_listing: if True, return a full listing, else returns a max
                         of 10000 listings
    :param service_token: service auth token
    :param headers: additional headers to include in the request
    :param delimiter: delimiter query
    :returns: a tuple of (response headers, a list of containers) The response
              headers will be a dict and all header names will be lowercase.
    :raises ClientException: HTTP GET request failed
    """
    req_headers = {'X-Auth-Token': token, 'Accept-Encoding': 'gzip'}
    if service_token:
        req_headers['X-Service-Token'] = service_token
    if headers:
        req_headers.update(headers)

    close_conn = False
    if not http_conn:
        http_conn = http_connection(url)
        close_conn = True
    if full_listing:
        rv = get_account(url, token, marker, limit, prefix, end_marker,
                         http_conn, headers=req_headers, delimiter=delimiter)
        listing = rv[1]
        while listing:
            marker = listing[-1]['name']
            listing = get_account(url, token, marker, limit, prefix,
                                  end_marker, http_conn, headers=req_headers,
                                  delimiter=delimiter)[1]
            if listing:
                rv[1].extend(listing)
        return rv
    parsed, conn = http_conn
    qs = 'format=json'
    if marker:
        qs += '&marker=%s' % quote(marker)
    if limit:
        qs += '&limit=%d' % limit
    if prefix:
        qs += '&prefix=%s' % quote(prefix)
    if delimiter:
        qs += '&delimiter=%s' % quote(delimiter)
    if end_marker:
        qs += '&end_marker=%s' % quote(end_marker)
    full_path = '%s?%s' % (parsed.path, qs)
    method = 'GET'
    conn.request(method, full_path, '', req_headers)
    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()
    http_log(("%s?%s" % (url, qs), method,), {'headers': req_headers},
             resp, body)

    resp_headers = resp_header_dict(resp)
    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(resp, 'Account GET failed', body)
    if resp.status == 204:
        return resp_headers, []
    return resp_headers, parse_api_response(resp_headers, body)


def head_account(url, token, http_conn=None, headers=None,
                 service_token=None):
    """
    Get account stats.

    :param url: storage URL
    :param token: auth token
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object)
    :param headers: additional headers to include in the request
    :param service_token: service auth token
    :returns: a dict containing the response's headers (all header names will
              be lowercase)
    :raises ClientException: HTTP HEAD request failed
    """
    close_conn = False
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
        close_conn = True
    method = "HEAD"
    req_headers = {'X-Auth-Token': token}
    if service_token:
        req_headers['X-Service-Token'] = service_token
    if headers:
        req_headers.update(headers)

    conn.request(method, parsed.path, '', req_headers)
    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()
    http_log((url, method,), {'headers': req_headers}, resp, body)
    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(resp, 'Account HEAD failed', body)
    resp_headers = resp_header_dict(resp)
    return resp_headers


def post_account(url, token, headers, http_conn=None, response_dict=None,
                 service_token=None, query_string=None, data=None):
    """
    Update an account's metadata.

    :param url: storage URL
    :param token: auth token
    :param headers: additional headers to include in the request
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object)
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :param query_string: if set will be appended with '?' to generated path
    :param data: an optional message body for the request
    :raises ClientException: HTTP POST request failed
    :returns: resp_headers, body
    """
    close_conn = False
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
        close_conn = True
    method = 'POST'
    path = parsed.path
    if query_string:
        path += '?' + query_string
    req_headers = {'X-Auth-Token': token}
    if service_token:
        req_headers['X-Service-Token'] = service_token
    if headers:
        req_headers.update(headers)
    conn.request(method, path, data, req_headers)
    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()
    http_log((url, method,), {'headers': req_headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(resp, 'Account POST failed', body)
    resp_headers = {}
    for header, value in resp.getheaders():
        resp_headers[header.lower()] = value
    return resp_headers, body


def get_container(url, token, container, marker=None, limit=None,
                  prefix=None, delimiter=None, end_marker=None,
                  version_marker=None, path=None, http_conn=None,
                  full_listing=False, service_token=None, headers=None,
                  query_string=None):
    """
    Get a listing of objects for the container.

    :param url: storage URL
    :param token: auth token
    :param container: container name to get a listing for
    :param marker: marker query
    :param limit: limit query
    :param prefix: prefix query
    :param delimiter: string to delimit the queries on
    :param end_marker: marker query
    :param version_marker: version marker query
    :param path: path query (equivalent: "delimiter=/" and "prefix=path/")
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object)
    :param full_listing: if True, return a full listing, else returns a max
                         of 10000 listings
    :param service_token: service auth token
    :param headers: additional headers to include in the request
    :param query_string: if set will be appended with '?' to generated path
    :returns: a tuple of (response headers, a list of objects) The response
              headers will be a dict and all header names will be lowercase.
    :raises ClientException: HTTP GET request failed
    """
    close_conn = False
    if not http_conn:
        http_conn = http_connection(url)
        close_conn = True
    if full_listing:
        rv = get_container(url, token, container, marker, limit, prefix,
                           delimiter, end_marker, version_marker, path=path,
                           http_conn=http_conn, service_token=service_token,
                           headers=headers)
        listing = rv[1]
        while listing:
            if not delimiter:
                marker = listing[-1]['name']
            else:
                marker = listing[-1].get('name', listing[-1].get('subdir'))
            version_marker = listing[-1].get('version_id')
            listing = get_container(url, token, container, marker, limit,
                                    prefix, delimiter, end_marker,
                                    version_marker, path, http_conn,
                                    service_token=service_token,
                                    headers=headers)[1]
            if listing:
                rv[1].extend(listing)
        return rv
    parsed, conn = http_conn
    cont_path = '%s/%s' % (parsed.path, quote(container))
    qs = 'format=json'
    if marker:
        qs += '&marker=%s' % quote(marker)
    if limit:
        qs += '&limit=%d' % limit
    if prefix:
        qs += '&prefix=%s' % quote(prefix)
    if delimiter:
        qs += '&delimiter=%s' % quote(delimiter)
    if end_marker:
        qs += '&end_marker=%s' % quote(end_marker)
    if version_marker:
        qs += '&version_marker=%s' % quote(version_marker)
    if path:
        qs += '&path=%s' % quote(path)
    if query_string:
        qs += '&%s' % query_string.lstrip('?')
    req_headers = {'X-Auth-Token': token, 'Accept-Encoding': 'gzip'}
    if service_token:
        req_headers['X-Service-Token'] = service_token
    if headers:
        req_headers.update(headers)
    method = 'GET'
    conn.request(method, '%s?%s' % (cont_path, qs), '', req_headers)
    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()
    http_log(('%(url)s%(cont_path)s?%(qs)s' %
              {'url': url.replace(parsed.path, ''),
               'cont_path': cont_path,
               'qs': qs}, method,),
             {'headers': req_headers}, resp, body)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(resp, 'Container GET failed', body)
    resp_headers = resp_header_dict(resp)
    if resp.status == 204:
        return resp_headers, []
    return resp_headers, parse_api_response(resp_headers, body)


def head_container(url, token, container, http_conn=None, headers=None,
                   service_token=None):
    """
    Get container stats.

    :param url: storage URL
    :param token: auth token
    :param container: container name to get stats for
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object)
    :param headers: additional headers to include in the request
    :param service_token: service auth token
    :returns: a dict containing the response's headers (all header names will
              be lowercase)
    :raises ClientException: HTTP HEAD request failed
    """
    close_conn = False
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
        close_conn = True
    path = '%s/%s' % (parsed.path, quote(container))
    method = 'HEAD'
    req_headers = {'X-Auth-Token': token}
    if service_token:
        req_headers['X-Service-Token'] = service_token
    if headers:
        req_headers.update(headers)
    conn.request(method, path, '', req_headers)
    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
             {'headers': req_headers}, resp, body)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(
            resp, 'Container HEAD failed', body)
    resp_headers = resp_header_dict(resp)
    return resp_headers


def put_container(url, token, container, headers=None, http_conn=None,
                  response_dict=None, service_token=None, query_string=None):
    """
    Create a container

    :param url: storage URL
    :param token: auth token
    :param container: container name to create
    :param headers: additional headers to include in the request
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object)
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :param query_string: if set will be appended with '?' to generated path
    :raises ClientException: HTTP PUT request failed
    """
    close_conn = False
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
        close_conn = True
    path = '%s/%s' % (parsed.path, quote(container))
    method = 'PUT'
    req_headers = {'X-Auth-Token': token}
    if service_token:
        req_headers['X-Service-Token'] = service_token
    if headers:
        req_headers.update(headers)
    if 'content-length' not in (k.lower() for k in req_headers):
        req_headers['Content-Length'] = '0'
    if query_string:
        path += '?' + query_string.lstrip('?')
    conn.request(method, path, '', req_headers)
    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()

    store_response(resp, response_dict)

    http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
             {'headers': req_headers}, resp, body)
    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(resp, 'Container PUT failed', body)


def post_container(url, token, container, headers, http_conn=None,
                   response_dict=None, service_token=None):
    """
    Update a container's metadata.

    :param url: storage URL
    :param token: auth token
    :param container: container name to update
    :param headers: additional headers to include in the request
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object)
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :raises ClientException: HTTP POST request failed
    """
    close_conn = False
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
        close_conn = True
    path = '%s/%s' % (parsed.path, quote(container))
    method = 'POST'
    req_headers = {'X-Auth-Token': token}
    if service_token:
        req_headers['X-Service-Token'] = service_token
    if headers:
        req_headers.update(headers)
    if 'content-length' not in (k.lower() for k in headers):
        req_headers['Content-Length'] = '0'
    conn.request(method, path, '', req_headers)
    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
             {'headers': req_headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(
            resp, 'Container POST failed', body)


def delete_container(url, token, container, http_conn=None,
                     response_dict=None, service_token=None,
                     query_string=None, headers=None):
    """
    Delete a container

    :param url: storage URL
    :param token: auth token
    :param container: container name to delete
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object)
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :param query_string: if set will be appended with '?' to generated path
    :param headers: additional headers to include in the request
    :raises ClientException: HTTP DELETE request failed
    """
    close_conn = False
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
        close_conn = True
    path = '%s/%s' % (parsed.path, quote(container))
    if headers:
        headers = dict(headers)
    else:
        headers = {}

    headers['X-Auth-Token'] = token
    if service_token:
        headers['X-Service-Token'] = service_token
    if query_string:
        path += '?' + query_string.lstrip('?')
    method = 'DELETE'
    conn.request(method, path, '', headers)
    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
             {'headers': headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(
            resp, 'Container DELETE failed', body)


def get_object(url, token, container, name, http_conn=None,
               resp_chunk_size=None, query_string=None,
               response_dict=None, headers=None, service_token=None):
    """
    Get an object

    :param url: storage URL
    :param token: auth token
    :param container: container name that the object is in
    :param name: object name to get
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object and close it
                      after all content is read)
    :param resp_chunk_size: if defined, chunk size of data to read. NOTE: If
                            you specify a resp_chunk_size you must fully read
                            the object's contents before making another
                            request.
    :param query_string: if set will be appended with '?' to generated path
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param headers: an optional dictionary with additional headers to include
                    in the request
    :param service_token: service auth token
    :returns: a tuple of (response headers, the object's contents) The response
              headers will be a dict and all header names will be lowercase.
    :raises ClientException: HTTP GET request failed
    """
    close_conn = False
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
        close_conn = True
    path = '%s/%s/%s' % (parsed.path, quote(container), quote(name))
    if query_string:
        path += '?' + query_string
    method = 'GET'
    headers = headers.copy() if headers else {}
    headers['X-Auth-Token'] = token
    if service_token:
        headers['X-Service-Token'] = service_token
    conn.request(method, path, '', headers)
    resp = conn.getresponse()

    parsed_response = {}
    store_response(resp, parsed_response)
    if response_dict is not None:
        response_dict.update(parsed_response)

    if resp.status < 200 or resp.status >= 300:
        body = resp.read()
        http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
                 {'headers': headers}, resp, body)
        raise ClientException.from_response(resp, 'Object GET failed', body)
    if resp_chunk_size:
        object_body = _ObjectBody(resp, resp_chunk_size,
                                  conn_to_close=conn if close_conn else None)
    else:
        object_body = resp.read()
        if close_conn:
            conn.close()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
             {'headers': headers}, resp, None)

    return parsed_response['headers'], object_body


def head_object(url, token, container, name, http_conn=None,
                service_token=None, headers=None, query_string=None):
    """
    Get object info

    :param url: storage URL
    :param token: auth token
    :param container: container name that the object is in
    :param name: object name to get info for
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object)
    :param service_token: service auth token
    :param headers: additional headers to include in the request
    :returns: a dict containing the response's headers (all header names will
              be lowercase)
    :raises ClientException: HTTP HEAD request failed
    """
    close_conn = False
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
        close_conn = True
    path = '%s/%s/%s' % (parsed.path, quote(container), quote(name))
    if query_string:
        path += '?' + query_string
    if headers:
        headers = dict(headers)
    else:
        headers = {}
    headers['X-Auth-Token'] = token
    method = 'HEAD'
    if service_token:
        headers['X-Service-Token'] = service_token
    conn.request(method, path, '', headers)
    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
             {'headers': headers}, resp, body)
    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(resp, 'Object HEAD failed', body)
    resp_headers = resp_header_dict(resp)
    return resp_headers


def put_object(url, token=None, container=None, name=None, contents=None,
               content_length=None, etag=None, chunk_size=None,
               content_type=None, headers=None, http_conn=None, proxy=None,
               query_string=None, response_dict=None, service_token=None):
    """
    Put an object

    :param url: storage URL
    :param token: auth token; if None, no token will be sent
    :param container: container name that the object is in; if None, the
                      container name is expected to be part of the url
    :param name: object name to put; if None, the object name is expected to be
                 part of the url
    :param contents: a string, a file-like object or an iterable
                     to read object data from;
                     if None, a zero-byte put will be done
    :param content_length: value to send as content-length header; also limits
                           the amount read from contents; if None, it will be
                           computed via the contents or chunked transfer
                           encoding will be used
    :param etag: etag of contents; if None, no etag will be sent
    :param chunk_size: chunk size of data to write; it defaults to 65536;
                       used only if the contents object has a 'read'
                       method, e.g. file-like objects, ignored otherwise

    :param content_type: value to send as content-type header, overriding any
                       value included in the headers param; if None and no
                       value is found in the headers param, an empty string
                       value will be sent
    :param headers: additional headers to include in the request, if any
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object)
    :param proxy: proxy to connect through, if any; None by default; str of the
                  format 'http://127.0.0.1:8888' to set one
    :param query_string: if set will be appended with '?' to generated path
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :returns: etag
    :raises ClientException: HTTP PUT request failed
    """
    close_conn = False
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url, proxy=proxy)
        close_conn = True
    path = parsed.path
    if container:
        path = '%s/%s' % (path.rstrip('/'), quote(container))
    if name:
        path = '%s/%s' % (path.rstrip('/'), quote(name))
    if query_string:
        path += '?' + query_string
    if headers:
        headers = dict(headers)
    else:
        headers = {}
    if token:
        headers['X-Auth-Token'] = token
    if service_token:
        headers['X-Service-Token'] = service_token
    if etag:
        headers['ETag'] = etag.strip('"')
    if content_length is not None:
        headers['Content-Length'] = str(content_length)
    else:
        for n, v in headers.items():
            if n.lower() == 'content-length':
                content_length = int(v)
    if content_type is not None:
        headers['Content-Type'] = content_type
    if not contents:
        headers['Content-Length'] = '0'

    if isinstance(contents, (ReadableToIterable, LengthWrapper)):
        conn.putrequest(path, headers=headers, data=contents)
    elif hasattr(contents, 'read'):
        if chunk_size is None:
            chunk_size = 65536

        if content_length is None:
            data = ReadableToIterable(contents, chunk_size, md5=False)
        else:
            data = LengthWrapper(contents, content_length, md5=False)

        conn.putrequest(path, headers=headers, data=data)
    else:
        if chunk_size is not None:
            warn_msg = ('%s object has no "read" method, ignoring chunk_size'
                        % type(contents).__name__)
            warnings.warn(warn_msg, stacklevel=2)
        # Match requests's is_stream test
        if hasattr(contents, '__iter__') and not isinstance(contents, (
                str, bytes, list, tuple, dict)):
            contents = iter_wrapper(contents)
        conn.request('PUT', path, contents, headers)

    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), 'PUT',),
             {'headers': headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(resp, 'Object PUT failed', body)

    etag = resp.getheader('etag', '').strip('"')
    return etag


def post_object(url, token, container, name, headers, http_conn=None,
                response_dict=None, service_token=None):
    """
    Update object metadata

    :param url: storage URL
    :param token: auth token
    :param container: container name that the object is in
    :param name: name of the object to update
    :param headers: additional headers to include in the request
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object)
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :raises ClientException: HTTP POST request failed
    """
    close_conn = False
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
        close_conn = True
    path = '%s/%s/%s' % (parsed.path, quote(container), quote(name))
    req_headers = {'X-Auth-Token': token}
    if service_token:
        req_headers['X-Service-Token'] = service_token
    if headers:
        req_headers.update(headers)
    conn.request('POST', path, '', req_headers)
    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), 'POST',),
             {'headers': req_headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(resp, 'Object POST failed', body)


def copy_object(url, token, container, name, destination=None,
                headers=None, fresh_metadata=None, http_conn=None,
                response_dict=None, service_token=None):
    """
    Copy object

    :param url: storage URL
    :param token: auth token; if None, no token will be sent
    :param container: container name that the source object is in
    :param name: source object name
    :param destination: The container and object name of the destination object
                        in the form of /container/object; if None, the copy
                        will use the source as the destination.
    :param headers: additional headers to include in the request
    :param fresh_metadata: Enables object creation that omits existing user
                           metadata, default None
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :raises ClientException: HTTP COPY request failed
    """
    close_conn = False
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
        close_conn = True

    path = parsed.path
    container = quote(container)
    name = quote(name)
    path = '%s/%s/%s' % (path.rstrip('/'), container, name)

    headers = dict(headers) if headers else {}

    if destination is not None:
        headers['Destination'] = quote(destination)
    elif container and name:
        headers['Destination'] = '/%s/%s' % (container, name)

    if token is not None:
        headers['X-Auth-Token'] = token
    if service_token is not None:
        headers['X-Service-Token'] = service_token

    if fresh_metadata is not None:
        # remove potential fresh metadata headers
        for fresh_hdr in [hdr for hdr in headers.keys()
                          if hdr.lower() == 'x-fresh-metadata']:
            headers.pop(fresh_hdr)
        headers['X-Fresh-Metadata'] = 'true' if fresh_metadata else 'false'

    conn.request('COPY', path, '', headers)
    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), 'COPY',),
             {'headers': headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(resp, 'Object COPY failed', body)


def delete_object(url, token=None, container=None, name=None, http_conn=None,
                  headers=None, proxy=None, query_string=None,
                  response_dict=None, service_token=None):
    """
    Delete object

    :param url: storage URL
    :param token: auth token; if None, no token will be sent
    :param container: container name that the object is in; if None, the
                      container name is expected to be part of the url
    :param name: object name to delete; if None, the object name is expected to
                 be part of the url
    :param http_conn: a tuple of (parsed url, HTTPConnection object),
                      (If None, it will create the conn object)
    :param headers: additional headers to include in the request
    :param proxy: proxy to connect through, if any; None by default; str of the
                  format 'http://127.0.0.1:8888' to set one
    :param query_string: if set will be appended with '?' to generated path
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :raises ClientException: HTTP DELETE request failed
    """
    close_conn = False
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url, proxy=proxy)
        close_conn = True
    path = parsed.path
    if container:
        path = '%s/%s' % (path.rstrip('/'), quote(container))
    if name:
        path = '%s/%s' % (path.rstrip('/'), quote(name))
    if query_string:
        path += '?' + query_string
    if headers:
        headers = dict(headers)
    else:
        headers = {}
    if token:
        headers['X-Auth-Token'] = token
    if service_token:
        headers['X-Service-Token'] = service_token
    conn.request('DELETE', path, '', headers)
    resp = conn.getresponse()
    body = resp.read()
    if close_conn:
        conn.close()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), 'DELETE',),
             {'headers': headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(resp, 'Object DELETE failed', body)


def get_capabilities(http_conn):
    """
    Get cluster capability infos.

    :param http_conn: a tuple of (parsed url, HTTPConnection object)
    :returns: a dict containing the cluster capabilities
    :raises ClientException: HTTP Capabilities GET failed
    """
    parsed, conn = http_conn
    headers = {'Accept-Encoding': 'gzip'}
    conn.request('GET', parsed.path, '', headers)
    resp = conn.getresponse()
    body = resp.read()
    http_log((parsed.geturl(), 'GET',), {'headers': headers}, resp, body)
    if resp.status < 200 or resp.status >= 300:
        raise ClientException.from_response(
            resp, 'Capabilities GET failed', body)
    resp_headers = resp_header_dict(resp)
    return parse_api_response(resp_headers, body)


class Connection:

    """
    Convenience class to make requests that will also retry the request

    Requests will have an X-Auth-Token header whose value is either
    the preauthtoken or a token obtained from the auth service using
    the user credentials provided as args to the constructor. If
    os_options includes a service_username then requests will also have
    an X-Service-Token header whose value is a token obtained from the
    auth service using the service credentials. In this case the request
    url will be set to the storage_url obtained from the auth service
    for the service user, unless this is overridden by a preauthurl.
    """

    def __init__(self, authurl=None, user=None, key=None, retries=5,
                 preauthurl=None, preauthtoken=None, snet=False,
                 starting_backoff=1, max_backoff=64, tenant_name=None,
                 os_options=None, auth_version="1", cacert=None,
                 insecure=False, cert=None, cert_key=None,
                 ssl_compression=True, retry_on_ratelimit=True,
                 timeout=None, session=None, force_auth_retry=False):
        """
        :param authurl: authentication URL
        :param user: user name to authenticate as
        :param key: key/password to authenticate with
        :param retries: Number of times to retry the request before failing
        :param preauthurl: storage URL (if you have already authenticated)
        :param preauthtoken: authentication token (if you have already
                             authenticated) note authurl/user/key/tenant_name
                             are not required when specifying preauthtoken
        :param snet: use SERVICENET internal network default is False
        :param starting_backoff: initial delay between retries (seconds)
        :param max_backoff: maximum delay between retries (seconds)
        :param auth_version: OpenStack auth version, default is 1.0
        :param tenant_name: The tenant/account name, required when connecting
                            to an auth 2.0 system.
        :param os_options: The OpenStack options which can have tenant_id,
                           auth_token, service_type, endpoint_type,
                           tenant_name, object_storage_url, region_name,
                           service_username, service_project_name, service_key
        :param insecure: Allow to access servers without checking SSL certs.
                         The server's certificate will not be verified.
        :param cert: Client certificate file to connect on SSL server
                            requiring SSL client certificate.
        :param cert_key: Client certificate private key file.
        :param ssl_compression: Whether to enable compression at the SSL layer.
                                If set to 'False' and the pyOpenSSL library is
                                present an attempt to disable SSL compression
                                will be made. This may provide a performance
                                increase for https upload/download operations.
        :param retry_on_ratelimit: by default, a ratelimited connection will
                                   retry after a backoff. Setting this
                                   parameter to False will cause an exception
                                   to be raised to the caller.
        :param timeout: The connect timeout for the HTTP connection.
        :param session: A keystoneauth session object.
        :param force_auth_retry: reset auth info even if client got unexpected
                                 error except 401 Unauthorized.
        """
        self.session = session
        self.authurl = authurl
        self.user = user
        self.key = key
        self.retries = retries
        self.http_conn = None
        self.attempts = 0
        self.snet = snet
        self.starting_backoff = starting_backoff
        self.max_backoff = max_backoff
        self.auth_version = auth_version
        self.os_options = dict(os_options or {})
        if tenant_name:
            self.os_options['tenant_name'] = tenant_name
        if preauthurl:
            self.os_options['object_storage_url'] = preauthurl
        self.url = preauthurl or self.os_options.get('object_storage_url')
        self.token = preauthtoken or self.os_options.get('auth_token')
        if self.os_options.get('service_username', None):
            self.service_auth = True
        else:
            self.service_auth = False
        self.service_token = None
        self.cacert = cacert
        self.insecure = insecure
        self.cert = cert
        self.cert_key = cert_key
        self.ssl_compression = ssl_compression
        self.auth_end_time = 0
        self.retry_on_ratelimit = retry_on_ratelimit
        self.timeout = timeout
        self.force_auth_retry = force_auth_retry

    def close(self):
        if (self.http_conn and isinstance(self.http_conn, tuple) and
                len(self.http_conn) > 1):
            conn = self.http_conn[1]
            conn.close()
            self.http_conn = None

    def get_auth(self):
        self.url, self.token = get_auth(self.authurl, self.user, self.key,
                                        session=self.session, snet=self.snet,
                                        auth_version=self.auth_version,
                                        os_options=self.os_options,
                                        cacert=self.cacert,
                                        insecure=self.insecure,
                                        cert=self.cert,
                                        cert_key=self.cert_key,
                                        timeout=self.timeout)
        return self.url, self.token

    def get_service_auth(self):
        opts = self.os_options
        service_options = {}
        service_options['tenant_name'] = opts.get('service_project_name', None)
        service_options['region_name'] = opts.get('region_name', None)
        service_options['object_storage_url'] = opts.get('object_storage_url',
                                                         None)
        service_user = opts.get('service_username', None)
        service_key = opts.get('service_key', None)
        return get_auth(self.authurl, service_user, service_key,
                        session=self.session,
                        snet=self.snet,
                        auth_version=self.auth_version,
                        os_options=service_options,
                        cacert=self.cacert,
                        insecure=self.insecure,
                        timeout=self.timeout)

    def http_connection(self, url=None):
        return http_connection(url if url else self.url,
                               cacert=self.cacert,
                               insecure=self.insecure,
                               cert=self.cert,
                               cert_key=self.cert_key,
                               ssl_compression=self.ssl_compression,
                               timeout=self.timeout)

    def _add_response_dict(self, target_dict, kwargs):
        if target_dict is not None and 'response_dict' in kwargs:
            response_dict = kwargs['response_dict']
            if 'response_dicts' in target_dict:
                target_dict['response_dicts'].append(response_dict)
            else:
                target_dict['response_dicts'] = [response_dict]
            target_dict.update(response_dict)

    def _retry(self, reset_func, func, *args, **kwargs):
        retried_auth = False
        backoff = self.starting_backoff
        caller_response_dict = kwargs.pop('response_dict', None)
        self.attempts = kwargs.pop('attempts', 0)
        while self.attempts <= self.retries or retried_auth:
            self.attempts += 1
            try:
                if not self.url or not self.token:
                    self.url, self.token = self.get_auth()
                    self.close()
                if self.service_auth and not self.service_token:
                    self.url, self.service_token = self.get_service_auth()
                    self.close()
                self.auth_end_time = time()
                if not self.http_conn:
                    self.http_conn = self.http_connection()
                kwargs['http_conn'] = self.http_conn
                if caller_response_dict is not None:
                    kwargs['response_dict'] = {}
                rv = func(self.url, self.token, *args,
                          service_token=self.service_token, **kwargs)
                self._add_response_dict(caller_response_dict, kwargs)
                return rv
            except SSLError as e:
                self._add_response_dict(caller_response_dict, kwargs)
                if ('certificate verify' in str(e)) or \
                        ('hostname' in str(e)) or \
                        self.attempts > self.retries:
                    raise
                self.http_conn = None
            except (socket.error, RequestException):
                self._add_response_dict(caller_response_dict, kwargs)
                if self.attempts > self.retries:
                    raise
                self.http_conn = None
            except ClientException as err:
                self._add_response_dict(caller_response_dict, kwargs)
                if err.http_status == 401:
                    if self.session:
                        should_retry = self.session.invalidate()
                    else:
                        # Without a proper session, just check for auth creds
                        should_retry = all((self.authurl, self.user, self.key))

                    self.url = self.token = self.service_token = None

                    if retried_auth or not should_retry:
                        raise
                    retried_auth = True
                elif self.attempts > self.retries or err.http_status is None:
                    raise
                elif err.http_status in (408, 499):
                    # Server hit a timeout, so HTTP request/response framing
                    # are likely in a bad state; trash the connection
                    self.http_conn = None
                elif 500 <= err.http_status <= 599:
                    pass
                elif self.retry_on_ratelimit and err.http_status in (498, 429):
                    pass
                else:
                    raise

            if self.force_auth_retry:
                self.url = self.token = self.service_token = None

            sleep(backoff)
            backoff = min(backoff * 2, self.max_backoff)
            if reset_func:
                reset_func(func, *args, **kwargs)

    def head_account(self, headers=None):
        """Wrapper for :func:`head_account`"""
        return self._retry(None, head_account, headers=headers)

    def get_account(self, marker=None, limit=None, prefix=None,
                    end_marker=None, full_listing=False, headers=None,
                    delimiter=None):
        """Wrapper for :func:`get_account`"""
        # TODO(unknown): With full_listing=True this will restart the entire
        # listing with each retry. Need to make a better version that just
        # retries where it left off.
        return self._retry(None, get_account, marker=marker, limit=limit,
                           prefix=prefix, end_marker=end_marker,
                           full_listing=full_listing, headers=headers,
                           delimiter=delimiter)

    def post_account(self, headers, response_dict=None,
                     query_string=None, data=None):
        """Wrapper for :func:`post_account`"""
        return self._retry(None, post_account, headers,
                           query_string=query_string, data=data,
                           response_dict=response_dict)

    def head_container(self, container, headers=None):
        """Wrapper for :func:`head_container`"""
        return self._retry(None, head_container, container, headers=headers)

    def get_container(self, container, marker=None, limit=None, prefix=None,
                      delimiter=None, end_marker=None, version_marker=None,
                      path=None, full_listing=False, headers=None,
                      query_string=None):
        """Wrapper for :func:`get_container`"""
        # TODO(unknown): With full_listing=True this will restart the entire
        # listing with each retry. Need to make a better version that just
        # retries where it left off.
        return self._retry(None, get_container, container, marker=marker,
                           limit=limit, prefix=prefix, delimiter=delimiter,
                           end_marker=end_marker,
                           version_marker=version_marker, path=path,
                           full_listing=full_listing, headers=headers,
                           query_string=query_string)

    def put_container(self, container, headers=None, response_dict=None,
                      query_string=None):
        """Wrapper for :func:`put_container`"""
        return self._retry(None, put_container, container, headers=headers,
                           response_dict=response_dict,
                           query_string=query_string)

    def post_container(self, container, headers, response_dict=None):
        """Wrapper for :func:`post_container`"""
        return self._retry(None, post_container, container, headers,
                           response_dict=response_dict)

    def delete_container(self, container, response_dict=None,
                         query_string=None, headers={}):
        """Wrapper for :func:`delete_container`"""
        return self._retry(None, delete_container, container,
                           response_dict=response_dict,
                           query_string=query_string,
                           headers=headers)

    def head_object(self, container, obj, headers=None, query_string=None):
        """Wrapper for :func:`head_object`"""
        return self._retry(None, head_object, container, obj, headers=headers,
                           query_string=query_string)

    def get_object(self, container, obj, resp_chunk_size=None,
                   query_string=None, response_dict=None, headers=None):
        """Wrapper for :func:`get_object`"""
        rheaders, body = self._retry(None, get_object, container, obj,
                                     resp_chunk_size=resp_chunk_size,
                                     query_string=query_string,
                                     response_dict=response_dict,
                                     headers=headers)
        is_not_range_request = (
            not headers or 'range' not in (k.lower() for k in headers))
        retry_is_possible = (
            is_not_range_request and resp_chunk_size and
            self.attempts <= self.retries and
            rheaders.get('transfer-encoding') is None)

        if retry_is_possible:
            body = _RetryBody(body.resp, self, container, obj,
                              resp_chunk_size=resp_chunk_size,
                              query_string=query_string,
                              response_dict=response_dict,
                              headers=headers)
        return rheaders, body

    def put_object(self, container, obj, contents, content_length=None,
                   etag=None, chunk_size=None, content_type=None,
                   headers=None, query_string=None, response_dict=None):
        """Wrapper for :func:`put_object`"""

        def _default_reset(*args, **kwargs):
            raise ClientException('put_object(%r, %r, ...) failure and no '
                                  'ability to reset contents for reupload.'
                                  % (container, obj))

        if isinstance(contents, str) or not contents:
            # if its a str or None then you can retry as much as you want
            reset_func = None
        else:
            reset_func = _default_reset
            if self.retries > 0:
                tell = getattr(contents, 'tell', None)
                seek = getattr(contents, 'seek', None)
                reset = getattr(contents, 'reset', None)
                if tell and seek:
                    orig_pos = tell()

                    def reset_func(*a, **kw):
                        seek(orig_pos)
                elif reset:
                    reset_func = reset
        return self._retry(reset_func, put_object, container, obj, contents,
                           content_length=content_length, etag=etag,
                           chunk_size=chunk_size, content_type=content_type,
                           headers=headers, query_string=query_string,
                           response_dict=response_dict)

    def post_object(self, container, obj, headers, response_dict=None):
        """Wrapper for :func:`post_object`"""
        return self._retry(None, post_object, container, obj, headers,
                           response_dict=response_dict)

    def copy_object(self, container, obj, destination=None, headers=None,
                    fresh_metadata=None, response_dict=None):
        """Wrapper for :func:`copy_object`"""
        return self._retry(None, copy_object, container, obj, destination,
                           headers, fresh_metadata,
                           response_dict=response_dict)

    def delete_object(self, container, obj, query_string=None,
                      response_dict=None, headers=None):
        """Wrapper for :func:`delete_object`"""
        return self._retry(None, delete_object, container, obj,
                           query_string=query_string,
                           response_dict=response_dict,
                           headers=headers)

    def _map_url(self, url):
        url = url or self.url
        if not url:
            url, _ = self.get_auth()
        scheme, netloc, path, params, query, fragment = urlparse(url)
        if URI_PATTERN_VERSION.search(path):
            path = URI_PATTERN_VERSION.sub('/info', path)
        elif not URI_PATTERN_INFO.search(path):
            if path.endswith('/'):
                path += 'info'
            else:
                path += '/info'
        return urlunparse((scheme, netloc, path, params, query, fragment))

    def get_capabilities(self, url=None):
        parsed = urlparse(self._map_url(url))
        if not self.http_conn:
            self.http_conn = self.http_connection(url)
        return get_capabilities((parsed, self.http_conn[1]))
