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
import requests
import logging
import warnings

from distutils.version import StrictVersion
from requests.exceptions import RequestException, SSLError
from six.moves import http_client
from six.moves.urllib.parse import quote as _quote
from six.moves.urllib.parse import urlparse, urlunparse
from time import sleep, time
import six

from swiftclient import version as swiftclient_version
from swiftclient.exceptions import ClientException
from swiftclient.utils import (
    LengthWrapper, ReadableToIterable, parse_api_response)

# Defautl is 100, increase to 256
http_client._MAXHEADERS = 256

AUTH_VERSIONS_V1 = ('1.0', '1', 1)
AUTH_VERSIONS_V2 = ('2.0', '2', 2)
AUTH_VERSIONS_V3 = ('3.0', '3', 3)
USER_METADATA_TYPE = tuple('x-%s-meta-' % type_ for type_ in
                           ('container', 'account', 'object'))

try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def handle(self, record):
            pass

        def emit(self, record):
            pass

        def createLock(self):
            self.lock = None

# requests version 1.2.3 try to encode headers in ascii, preventing
# utf-8 encoded header to be 'prepared'
if StrictVersion(requests.__version__) < StrictVersion('2.0.0'):
    from requests.structures import CaseInsensitiveDict

    def prepare_unicode_headers(self, headers):
        if headers:
            self.headers = CaseInsensitiveDict(headers)
        else:
            self.headers = CaseInsensitiveDict()
    requests.models.PreparedRequest.prepare_headers = prepare_unicode_headers

logger = logging.getLogger("swiftclient")
logger.addHandler(NullHandler())


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
            string_parts.append(' %s' % element)
    if 'headers' in kwargs:
        for element in kwargs['headers']:
            header = ' -H "%s: %s"' % (element, kwargs['headers'][element])
            string_parts.append(header)

    # log response as debug if good, or info if error
    if resp.status < 300:
        log_method = logger.debug
    else:
        log_method = logger.info

    log_method("REQ: %s", "".join(string_parts))
    log_method("RESP STATUS: %s %s", resp.status, resp.reason)
    log_method("RESP HEADERS: %s", resp.getheaders())
    if body:
        log_method("RESP BODY: %s", body)


def quote(value, safe='/'):
    """
    Patched version of urllib.quote that encodes utf8 strings before quoting.
    On Python 3, call directly urllib.parse.quote().
    """
    if six.PY3:
        return _quote(value, safe=safe)
    value = encode_utf8(value)
    if isinstance(value, bytes):
        return _quote(value, safe)
    else:
        return value


def encode_utf8(value):
    if isinstance(value, six.text_type):
        value = value.encode('utf8')
    return value


def encode_meta_headers(headers):
    """Only encode metadata headers keys"""
    ret = {}
    for header, value in headers.items():
        value = encode_utf8(value)
        header = header.lower()

        if (isinstance(header, six.string_types)
                and header.startswith(USER_METADATA_TYPE)):
            header = encode_utf8(header)

        ret[header] = value
    return ret


class _ObjectBody(object):
    """
    Readable and iterable object body response wrapper.
    """

    def __init__(self, resp, chunk_size):
        """
        Wrap the underlying response

        :param resp: the response to wrap
        :param chunk_size: number of bytes to return each iteration/next call
        """
        self.resp = resp
        self.chunk_size = chunk_size

    def read(self, length=None):
        return self.resp.read(length)

    def __iter__(self):
        return self

    def next(self):
        buf = self.resp.read(self.chunk_size)
        if not buf:
            raise StopIteration()
        return buf

    def __next__(self):
        return self.next()


class HTTPConnection(object):
    def __init__(self, url, proxy=None, cacert=None, insecure=False,
                 ssl_compression=False, default_user_agent=None, timeout=None):
        """
        Make an HTTPConnection or HTTPSConnection

        :param url: url to connect to
        :param proxy: proxy to connect through, if any; None by default; str
                      of the format 'http://127.0.0.1:8888' to set one
        :param cacert: A CA bundle file to use in verifying a TLS server
                       certificate.
        :param insecure: Allow to access servers without checking SSL certs.
                         The server's certificate will not be verified.
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
        self.request_session = requests.Session()
        # Don't use requests's default headers
        self.request_session.headers = None
        if self.parsed_url.scheme not in ('http', 'https'):
            raise ClientException('Unsupported scheme "%s" in url "%s"'
                                  % (self.parsed_url.scheme, url))
        self.requests_args['verify'] = not insecure
        if cacert and not insecure:
            # verify requests parameter is used to pass the CA_BUNDLE file
            # see: http://docs.python-requests.org/en/latest/user/advanced/
            self.requests_args['verify'] = cacert
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
        """ Final wrapper before requests call, to be patched in tests """
        return self.request_session.request(*arg, **kwarg)

    def request(self, method, full_path, data=None, headers=None, files=None):
        """ Encode url and header, then call requests.request """
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
        """ Adapt requests response to httplib interface """
        self.resp.status = self.resp.status_code
        old_getheader = self.resp.raw.getheader

        def getheaders():
            return self.resp.headers.items()

        def getheader(k, v=None):
            return old_getheader(k.lower(), v)

        def releasing_read(*args, **kwargs):
            chunk = self.resp.raw.read(*args, **kwargs)
            if not chunk:
                # NOTE(sigmavirus24): Release the connection back to the
                # urllib3's connection pool. This will reduce the number of
                # log messages seen in bug #1341777. This does not actually
                # close a socket. It will also prevent people from being
                # mislead as to the cause of a bug as in bug #1424732.
                self.resp.close()
            return chunk

        self.resp.getheaders = getheaders
        self.resp.getheader = getheader
        self.resp.read = releasing_read

        return self.resp


def http_connection(*arg, **kwarg):
    """ :returns: tuple of (parsed url, connection object) """
    conn = HTTPConnection(*arg, **kwarg)
    return conn.parsed_url, conn


def get_auth_1_0(url, user, key, snet, **kwargs):
    cacert = kwargs.get('cacert', None)
    insecure = kwargs.get('insecure', False)
    timeout = kwargs.get('timeout', None)
    parsed, conn = http_connection(url, cacert=cacert, insecure=insecure,
                                   timeout=timeout)
    method = 'GET'
    conn.request(method, parsed.path, '',
                 {'X-Auth-User': user, 'X-Auth-Key': key})
    resp = conn.getresponse()
    body = resp.read()
    http_log((url, method,), {}, resp, body)
    url = resp.getheader('x-storage-url')

    # There is a side-effect on current Rackspace 1.0 server where a
    # bad URL would get you that document page and a 200. We error out
    # if we don't have a x-storage-url header and if we get a body.
    if resp.status < 200 or resp.status >= 300 or (body and not url):
        raise ClientException('Auth GET failed', http_scheme=parsed.scheme,
                              http_host=conn.host, http_path=parsed.path,
                              http_status=resp.status, http_reason=resp.reason)
    if snet:
        parsed = list(urlparse(url))
        # Second item in the list is the netloc
        netloc = parsed[1]
        parsed[1] = 'snet-' + netloc
        url = urlunparse(parsed)
    return url, resp.getheader('x-storage-token',
                               resp.getheader('x-auth-token'))


def get_keystoneclient_2_0(auth_url, user, key, os_options, **kwargs):
    # this function is only here to preserve the historic 'public'
    # interface of this module
    kwargs.update({'auth_version': '2.0'})
    return get_auth_keystone(auth_url, user, key, os_options, **kwargs)


def _import_keystone_client(auth_version):
    # the attempted imports are encapsulated in this function to allow
    # mocking for tests
    try:
        if auth_version in AUTH_VERSIONS_V3:
            from keystoneclient.v3 import client as ksclient
        else:
            from keystoneclient.v2_0 import client as ksclient
        from keystoneclient import exceptions
        # prevent keystoneclient warning us that it has no log handlers
        logging.getLogger('keystoneclient').addHandler(NullHandler())
        return ksclient, exceptions
    except ImportError:
        raise ClientException('''
Auth versions 2.0 and 3 require python-keystoneclient, install it or use Auth
version 1.0 which requires ST_AUTH, ST_USER, and ST_KEY environment
variables to be set or overridden with -A, -U, or -K.''')


def get_auth_keystone(auth_url, user, key, os_options, **kwargs):
    """
    Authenticate against a keystone server.

    We are using the keystoneclient library for authentication.
    """

    insecure = kwargs.get('insecure', False)
    timeout = kwargs.get('timeout', None)
    auth_version = kwargs.get('auth_version', '2.0')
    debug = logger.isEnabledFor(logging.DEBUG) and True or False

    ksclient, exceptions = _import_keystone_client(auth_version)

    try:
        _ksclient = ksclient.Client(
            username=user,
            password=key,
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
            auth_url=auth_url, insecure=insecure, timeout=timeout)
    except exceptions.Unauthorized:
        msg = 'Unauthorized. Check username, password and tenant name/id.'
        if auth_version in AUTH_VERSIONS_V3:
            msg = ('Unauthorized. Check username/id, password, '
                   'tenant name/id and user/tenant domain name/id.')
        raise ClientException(msg)
    except exceptions.AuthorizationFailure as err:
        raise ClientException('Authorization Failure. %s' % err)
    service_type = os_options.get('service_type') or 'object-store'
    endpoint_type = os_options.get('endpoint_type') or 'publicURL'
    try:
        endpoint = _ksclient.service_catalog.url_for(
            attr='region',
            filter_value=os_options.get('region_name'),
            service_type=service_type,
            endpoint_type=endpoint_type)
    except exceptions.EndpointNotFound:
        raise ClientException('Endpoint for %s not found - '
                              'have you specified a region?' % service_type)
    return endpoint, _ksclient.auth_token


def get_auth(auth_url, user, key, **kwargs):
    """
    Get authentication/authorization credentials.

    :kwarg auth_version: the api version of the supplied auth params
    :kwarg os_options: a dict, the openstack idenity service options

    :returns: a tuple, (storage_url, token)

    N.B. if the optional os_options paramater includes an non-empty
    'object_storage_url' key it will override the the default storage url
    returned by the auth service.

    The snet parameter is used for Rackspace's ServiceNet internal network
    implementation. In this function, it simply adds *snet-* to the beginning
    of the host name for the returned storage URL. With Rackspace Cloud Files,
    use of this network path causes no bandwidth charges but requires the
    client to be running on Rackspace's ServiceNet network.
    """
    auth_version = kwargs.get('auth_version', '1')
    os_options = kwargs.get('os_options', {})

    storage_url, token = None, None
    cacert = kwargs.get('cacert', None)
    insecure = kwargs.get('insecure', False)
    timeout = kwargs.get('timeout', None)
    if auth_version in AUTH_VERSIONS_V1:
        storage_url, token = get_auth_1_0(auth_url,
                                          user,
                                          key,
                                          kwargs.get('snet'),
                                          cacert=cacert,
                                          insecure=insecure,
                                          timeout=timeout)
    elif auth_version in AUTH_VERSIONS_V2 + AUTH_VERSIONS_V3:
        # We are handling a special use case here where the user argument
        # specifies both the user name and tenant name in the form tenant:user
        if user and not kwargs.get('tenant_name') and ':' in user:
            os_options['tenant_name'], user = user.split(':')

        # We are allowing to have an tenant_name argument in get_auth
        # directly without having os_options
        if kwargs.get('tenant_name'):
            os_options['tenant_name'] = kwargs['tenant_name']

        if not (os_options.get('tenant_name') or os_options.get('tenant_id')
                or os_options.get('project_name')
                or os_options.get('project_id')):
            if auth_version in AUTH_VERSIONS_V2:
                raise ClientException('No tenant specified')
            raise ClientException('No project name or project id specified.')

        storage_url, token = get_auth_keystone(auth_url, user,
                                               key, os_options,
                                               cacert=cacert,
                                               insecure=insecure,
                                               timeout=timeout,
                                               auth_version=auth_version)
    else:
        raise ClientException('Unknown auth_version %s specified.'
                              % auth_version)

    # Override storage url, if necessary
    if os_options.get('object_storage_url'):
        return os_options['object_storage_url'], token
    else:
        return storage_url, token


def store_response(resp, response_dict):
    """
    store information about an operation into a dict

    :param resp: an http response object containing the response
                 headers
    :param response_dict: a dict into which are placed the
       status, reason and a dict of lower-cased headers
    """
    if response_dict is not None:
        resp_headers = {}
        for header, value in resp.getheaders():
            resp_headers[header.lower()] = value

        response_dict['status'] = resp.status
        response_dict['reason'] = resp.reason
        response_dict['headers'] = resp_headers


def get_account(url, token, marker=None, limit=None, prefix=None,
                end_marker=None, http_conn=None, full_listing=False,
                service_token=None):
    """
    Get a listing of containers for the account.

    :param url: storage URL
    :param token: auth token
    :param marker: marker query
    :param limit: limit query
    :param prefix: prefix query
    :param end_marker: end_marker query
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param full_listing: if True, return a full listing, else returns a max
                         of 10000 listings
    :param service_token: service auth token
    :returns: a tuple of (response headers, a list of containers) The response
              headers will be a dict and all header names will be lowercase.
    :raises ClientException: HTTP GET request failed
    """
    if not http_conn:
        http_conn = http_connection(url)
    if full_listing:
        rv = get_account(url, token, marker, limit, prefix,
                         end_marker, http_conn)
        listing = rv[1]
        while listing:
            marker = listing[-1]['name']
            listing = get_account(url, token, marker, limit, prefix,
                                  end_marker, http_conn)[1]
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
    if end_marker:
        qs += '&end_marker=%s' % quote(end_marker)
    full_path = '%s?%s' % (parsed.path, qs)
    headers = {'X-Auth-Token': token}
    if service_token:
        headers['X-Service-Token'] = service_token
    method = 'GET'
    conn.request(method, full_path, '', headers)
    resp = conn.getresponse()
    body = resp.read()
    http_log(("%s?%s" % (url, qs), method,), {'headers': headers}, resp, body)

    resp_headers = {}
    for header, value in resp.getheaders():
        resp_headers[header.lower()] = value
    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Account GET failed', http_scheme=parsed.scheme,
                              http_host=conn.host, http_path=parsed.path,
                              http_query=qs, http_status=resp.status,
                              http_reason=resp.reason,
                              http_response_content=body)
    if resp.status == 204:
        return resp_headers, []
    return resp_headers, parse_api_response(resp_headers, body)


def head_account(url, token, http_conn=None, service_token=None):
    """
    Get account stats.

    :param url: storage URL
    :param token: auth token
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param service_token: service auth token
    :returns: a dict containing the response's headers (all header names will
              be lowercase)
    :raises ClientException: HTTP HEAD request failed
    """
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
    method = "HEAD"
    headers = {'X-Auth-Token': token}
    if service_token:
        headers['X-Service-Token'] = service_token
    conn.request(method, parsed.path, '', headers)
    resp = conn.getresponse()
    body = resp.read()
    http_log((url, method,), {'headers': headers}, resp, body)
    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Account HEAD failed', http_scheme=parsed.scheme,
                              http_host=conn.host, http_path=parsed.path,
                              http_status=resp.status, http_reason=resp.reason,
                              http_response_content=body)
    resp_headers = {}
    for header, value in resp.getheaders():
        resp_headers[header.lower()] = value
    return resp_headers


def post_account(url, token, headers, http_conn=None, response_dict=None,
                 service_token=None):
    """
    Update an account's metadata.

    :param url: storage URL
    :param token: auth token
    :param headers: additional headers to include in the request
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :raises ClientException: HTTP POST request failed
    """
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
    method = 'POST'
    headers['X-Auth-Token'] = token
    if service_token:
        headers['X-Service-Token'] = service_token
    conn.request(method, parsed.path, '', headers)
    resp = conn.getresponse()
    body = resp.read()
    http_log((url, method,), {'headers': headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Account POST failed',
                              http_scheme=parsed.scheme,
                              http_host=conn.host,
                              http_path=parsed.path,
                              http_status=resp.status,
                              http_reason=resp.reason,
                              http_response_content=body)


def get_container(url, token, container, marker=None, limit=None,
                  prefix=None, delimiter=None, end_marker=None,
                  path=None, http_conn=None,
                  full_listing=False, service_token=None, headers=None):
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
    :param path: path query (equivalent: "delimiter=/" and "prefix=path/")
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param full_listing: if True, return a full listing, else returns a max
                         of 10000 listings
    :param service_token: service auth token
    :returns: a tuple of (response headers, a list of objects) The response
              headers will be a dict and all header names will be lowercase.
    :raises ClientException: HTTP GET request failed
    """
    if not http_conn:
        http_conn = http_connection(url)
    if headers:
        headers = dict(headers)
    else:
        headers = {}
    headers['X-Auth-Token'] = token
    if full_listing:
        rv = get_container(url, token, container, marker, limit, prefix,
                           delimiter, end_marker, path, http_conn,
                           service_token, headers=headers)
        listing = rv[1]
        while listing:
            if not delimiter:
                marker = listing[-1]['name']
            else:
                marker = listing[-1].get('name', listing[-1].get('subdir'))
            listing = get_container(url, token, container, marker, limit,
                                    prefix, delimiter, end_marker, path,
                                    http_conn, service_token,
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
    if path:
        qs += '&path=%s' % quote(path)
    if service_token:
        headers['X-Service-Token'] = service_token
    method = 'GET'
    conn.request(method, '%s?%s' % (cont_path, qs), '', headers)
    resp = conn.getresponse()
    body = resp.read()
    http_log(('%(url)s%(cont_path)s?%(qs)s' %
              {'url': url.replace(parsed.path, ''),
               'cont_path': cont_path,
               'qs': qs}, method,),
             {'headers': headers}, resp, body)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Container GET failed',
                              http_scheme=parsed.scheme, http_host=conn.host,
                              http_path=cont_path, http_query=qs,
                              http_status=resp.status, http_reason=resp.reason,
                              http_response_content=body)
    resp_headers = {}
    for header, value in resp.getheaders():
        resp_headers[header.lower()] = value
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
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param service_token: service auth token
    :returns: a dict containing the response's headers (all header names will
              be lowercase)
    :raises ClientException: HTTP HEAD request failed
    """
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
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
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
             {'headers': req_headers}, resp, body)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Container HEAD failed',
                              http_scheme=parsed.scheme, http_host=conn.host,
                              http_path=path, http_status=resp.status,
                              http_reason=resp.reason,
                              http_response_content=body)
    resp_headers = {}
    for header, value in resp.getheaders():
        resp_headers[header.lower()] = value
    return resp_headers


def put_container(url, token, container, headers=None, http_conn=None,
                  response_dict=None, service_token=None):
    """
    Create a container

    :param url: storage URL
    :param token: auth token
    :param container: container name to create
    :param headers: additional headers to include in the request
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :raises ClientException: HTTP PUT request failed
    """
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
    path = '%s/%s' % (parsed.path, quote(container))
    method = 'PUT'
    if not headers:
        headers = {}
    headers['X-Auth-Token'] = token
    if service_token:
        headers['X-Service-Token'] = service_token
    if 'content-length' not in (k.lower() for k in headers):
        headers['Content-Length'] = '0'
    conn.request(method, path, '', headers)
    resp = conn.getresponse()
    body = resp.read()

    store_response(resp, response_dict)

    http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
             {'headers': headers}, resp, body)
    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Container PUT failed',
                              http_scheme=parsed.scheme, http_host=conn.host,
                              http_path=path, http_status=resp.status,
                              http_reason=resp.reason,
                              http_response_content=body)


def post_container(url, token, container, headers, http_conn=None,
                   response_dict=None, service_token=None):
    """
    Update a container's metadata.

    :param url: storage URL
    :param token: auth token
    :param container: container name to update
    :param headers: additional headers to include in the request
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :raises ClientException: HTTP POST request failed
    """
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
    path = '%s/%s' % (parsed.path, quote(container))
    method = 'POST'
    headers['X-Auth-Token'] = token
    if service_token:
        headers['X-Service-Token'] = service_token
    if 'content-length' not in (k.lower() for k in headers):
        headers['Content-Length'] = '0'
    conn.request(method, path, '', headers)
    resp = conn.getresponse()
    body = resp.read()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
             {'headers': headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Container POST failed',
                              http_scheme=parsed.scheme, http_host=conn.host,
                              http_path=path, http_status=resp.status,
                              http_reason=resp.reason,
                              http_response_content=body)


def delete_container(url, token, container, http_conn=None,
                     response_dict=None, service_token=None):
    """
    Delete a container

    :param url: storage URL
    :param token: auth token
    :param container: container name to delete
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :raises ClientException: HTTP DELETE request failed
    """
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
    path = '%s/%s' % (parsed.path, quote(container))
    headers = {'X-Auth-Token': token}
    if service_token:
        headers['X-Service-Token'] = service_token
    method = 'DELETE'
    conn.request(method, path, '', headers)
    resp = conn.getresponse()
    body = resp.read()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
             {'headers': headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Container DELETE failed',
                              http_scheme=parsed.scheme, http_host=conn.host,
                              http_path=path, http_status=resp.status,
                              http_reason=resp.reason,
                              http_response_content=body)


def get_object(url, token, container, name, http_conn=None,
               resp_chunk_size=None, query_string=None,
               response_dict=None, headers=None, service_token=None):
    """
    Get an object

    :param url: storage URL
    :param token: auth token
    :param container: container name that the object is in
    :param name: object name to get
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
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
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
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
        raise ClientException('Object GET failed', http_scheme=parsed.scheme,
                              http_host=conn.host, http_path=path,
                              http_status=resp.status,
                              http_reason=resp.reason,
                              http_response_content=body)
    if resp_chunk_size:
        object_body = _ObjectBody(resp, resp_chunk_size)
    else:
        object_body = resp.read()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
             {'headers': headers}, resp, None)

    return parsed_response['headers'], object_body


def head_object(url, token, container, name, http_conn=None,
                service_token=None, headers=None):
    """
    Get object info

    :param url: storage URL
    :param token: auth token
    :param container: container name that the object is in
    :param name: object name to get info for
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param service_token: service auth token
    :returns: a dict containing the response's headers (all header names will
              be lowercase)
    :raises ClientException: HTTP HEAD request failed
    """
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
    path = '%s/%s/%s' % (parsed.path, quote(container), quote(name))
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
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), method,),
             {'headers': headers}, resp, body)
    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Object HEAD failed', http_scheme=parsed.scheme,
                              http_host=conn.host, http_path=path,
                              http_status=resp.status, http_reason=resp.reason,
                              http_response_content=body)
    resp_headers = {}
    for header, value in resp.getheaders():
        resp_headers[header.lower()] = value
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
    :param contents: a string, a file like object or an iterable
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
    :param content_type: value to send as content-type header; if None, an
                         empty string value will be sent
    :param headers: additional headers to include in the request, if any
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param proxy: proxy to connect through, if any; None by default; str of the
                  format 'http://127.0.0.1:8888' to set one
    :param query_string: if set will be appended with '?' to generated path
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :returns: etag
    :raises ClientException: HTTP PUT request failed
    """
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url, proxy=proxy)
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
    elif 'Content-Type' not in headers:  # python-requests sets application/x-www-form-urlencoded otherwise
        headers['Content-Type'] = ''
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
        conn.request('PUT', path, contents, headers)

    resp = conn.getresponse()
    body = resp.read()
    headers = {'X-Auth-Token': token}
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), 'PUT',),
             {'headers': headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Object PUT failed', http_scheme=parsed.scheme,
                              http_host=conn.host, http_path=path,
                              http_status=resp.status, http_reason=resp.reason,
                              http_response_content=body)

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
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :raises ClientException: HTTP POST request failed
    """
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url)
    path = '%s/%s/%s' % (parsed.path, quote(container), quote(name))
    headers['X-Auth-Token'] = token
    if service_token:
        headers['X-Service-Token'] = service_token
    conn.request('POST', path, '', headers)
    resp = conn.getresponse()
    body = resp.read()
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), 'POST',),
             {'headers': headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Object POST failed', http_scheme=parsed.scheme,
                              http_host=conn.host, http_path=path,
                              http_status=resp.status, http_reason=resp.reason,
                              http_response_content=body)


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
    :param http_conn: HTTP connection object (If None, it will create the
                      conn object)
    :param headers: additional headers to include in the request
    :param proxy: proxy to connect through, if any; None by default; str of the
                  format 'http://127.0.0.1:8888' to set one
    :param query_string: if set will be appended with '?' to generated path
    :param response_dict: an optional dictionary into which to place
                     the response - status, reason and headers
    :param service_token: service auth token
    :raises ClientException: HTTP DELETE request failed
    """
    if http_conn:
        parsed, conn = http_conn
    else:
        parsed, conn = http_connection(url, proxy=proxy)
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
    http_log(('%s%s' % (url.replace(parsed.path, ''), path), 'DELETE',),
             {'headers': headers}, resp, body)

    store_response(resp, response_dict)

    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Object DELETE failed',
                              http_scheme=parsed.scheme, http_host=conn.host,
                              http_path=path, http_status=resp.status,
                              http_reason=resp.reason,
                              http_response_content=body)


def get_capabilities(http_conn):
    """
    Get cluster capability infos.

    :param http_conn: HTTP connection
    :returns: a dict containing the cluster capabilities
    :raises ClientException: HTTP Capabilities GET failed
    """
    parsed, conn = http_conn
    conn.request('GET', parsed.path, '')
    resp = conn.getresponse()
    body = resp.read()
    http_log((parsed.geturl(), 'GET',), {'headers': {}}, resp, body)
    if resp.status < 200 or resp.status >= 300:
        raise ClientException('Capabilities GET failed',
                              http_scheme=parsed.scheme,
                              http_host=conn.host, http_path=parsed.path,
                              http_status=resp.status, http_reason=resp.reason,
                              http_response_content=body)
    resp_headers = {}
    for header, value in resp.getheaders():
        resp_headers[header.lower()] = value
    return parse_api_response(resp_headers, body)


class Connection(object):

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
                 insecure=False, ssl_compression=True,
                 retry_on_ratelimit=False, timeout=None):
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
        :param ssl_compression: Whether to enable compression at the SSL layer.
                                If set to 'False' and the pyOpenSSL library is
                                present an attempt to disable SSL compression
                                will be made. This may provide a performance
                                increase for https upload/download operations.
        :param retry_on_ratelimit: by default, a ratelimited connection will
                                   raise an exception to the caller. Setting
                                   this parameter to True will cause a retry
                                   after a backoff.
        :param timeout: The connect timeout for the HTTP connection.
        """
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
        self.ssl_compression = ssl_compression
        self.auth_end_time = 0
        self.retry_on_ratelimit = retry_on_ratelimit
        self.timeout = timeout

    def close(self):
        if (self.http_conn and isinstance(self.http_conn, tuple)
                and len(self.http_conn) > 1):
            conn = self.http_conn[1]
            if hasattr(conn, 'close') and callable(conn.close):
                # XXX: Our HTTPConnection object has no close, should be
                # trying to close the requests.Session here?
                conn.close()
                self.http_conn = None

    def get_auth(self):
        self.url, self.token = get_auth(self.authurl, self.user, self.key,
                                        snet=self.snet,
                                        auth_version=self.auth_version,
                                        os_options=self.os_options,
                                        cacert=self.cacert,
                                        insecure=self.insecure,
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
        return get_auth(self.authurl, service_user,
                        service_key,
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
        self.attempts = 0
        retried_auth = False
        backoff = self.starting_backoff
        caller_response_dict = kwargs.pop('response_dict', None)
        while self.attempts <= self.retries:
            self.attempts += 1
            try:
                if not self.url or not self.token:
                    self.url, self.token = self.get_auth()
                    self.http_conn = None
                if self.service_auth and not self.service_token:
                    self.url, self.service_token = self.get_service_auth()
                    self.http_conn = None
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
            except SSLError:
                raise
            except (socket.error, RequestException) as e:
                self._add_response_dict(caller_response_dict, kwargs)
                if self.attempts > self.retries:
                    logger.exception(e)
                    raise
                self.http_conn = None
            except ClientException as err:
                self._add_response_dict(caller_response_dict, kwargs)
                if self.attempts > self.retries or err.http_status is None:
                    logger.exception(err)
                    raise
                if err.http_status == 401:
                    self.url = self.token = self.service_token = None
                    if retried_auth or not all((self.authurl,
                                                self.user,
                                                self.key)):
                        logger.exception(err)
                        raise
                    retried_auth = True
                elif err.http_status == 408:
                    self.http_conn = None
                elif 500 <= err.http_status <= 599:
                    pass
                elif self.retry_on_ratelimit and err.http_status == 498:
                    pass
                else:
                    logger.exception(err)
                    raise
            sleep(backoff)
            backoff = min(backoff * 2, self.max_backoff)
            if reset_func:
                reset_func(func, *args, **kwargs)

    def head_account(self):
        """Wrapper for :func:`head_account`"""
        return self._retry(None, head_account)

    def get_account(self, marker=None, limit=None, prefix=None,
                    end_marker=None, full_listing=False):
        """Wrapper for :func:`get_account`"""
        # TODO(unknown): With full_listing=True this will restart the entire
        # listing with each retry. Need to make a better version that just
        # retries where it left off.
        return self._retry(None, get_account, marker=marker, limit=limit,
                           prefix=prefix, end_marker=end_marker,
                           full_listing=full_listing)

    def post_account(self, headers, response_dict=None):
        """Wrapper for :func:`post_account`"""
        return self._retry(None, post_account, headers,
                           response_dict=response_dict)

    def head_container(self, container):
        """Wrapper for :func:`head_container`"""
        return self._retry(None, head_container, container)

    def get_container(self, container, marker=None, limit=None, prefix=None,
                      delimiter=None, end_marker=None, path=None,
                      full_listing=False, headers=None):
        """Wrapper for :func:`get_container`"""
        # TODO(unknown): With full_listing=True this will restart the entire
        # listing with each retry. Need to make a better version that just
        # retries where it left off.
        return self._retry(None, get_container, container, marker=marker,
                           limit=limit, prefix=prefix, delimiter=delimiter,
                           end_marker=end_marker, path=path,
                           full_listing=full_listing, headers=headers)

    def put_container(self, container, headers=None, response_dict=None):
        """Wrapper for :func:`put_container`"""
        return self._retry(None, put_container, container, headers=headers,
                           response_dict=response_dict)

    def post_container(self, container, headers, response_dict=None):
        """Wrapper for :func:`post_container`"""
        return self._retry(None, post_container, container, headers,
                           response_dict=response_dict)

    def delete_container(self, container, response_dict=None):
        """Wrapper for :func:`delete_container`"""
        return self._retry(None, delete_container, container,
                           response_dict=response_dict)

    def head_object(self, container, obj):
        """Wrapper for :func:`head_object`"""
        return self._retry(None, head_object, container, obj)

    def get_object(self, container, obj, resp_chunk_size=None,
                   query_string=None, response_dict=None, headers=None):
        """Wrapper for :func:`get_object`"""
        return self._retry(None, get_object, container, obj,
                           resp_chunk_size=resp_chunk_size,
                           query_string=query_string,
                           response_dict=response_dict, headers=headers)

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
                if tell and seek:
                    orig_pos = tell()
                    reset_func = lambda *a, **k: seek(orig_pos)

        return self._retry(reset_func, put_object, container, obj, contents,
                           content_length=content_length, etag=etag,
                           chunk_size=chunk_size, content_type=content_type,
                           headers=headers, query_string=query_string,
                           response_dict=response_dict)

    def post_object(self, container, obj, headers, response_dict=None):
        """Wrapper for :func:`post_object`"""
        return self._retry(None, post_object, container, obj, headers,
                           response_dict=response_dict)

    def delete_object(self, container, obj, query_string=None,
                      response_dict=None):
        """Wrapper for :func:`delete_object`"""
        return self._retry(None, delete_object, container, obj,
                           query_string=query_string,
                           response_dict=response_dict)

    def get_capabilities(self, url=None):
        url = url or self.url
        if not url:
            url, _ = self.get_auth()
        scheme = urlparse(url).scheme
        netloc = urlparse(url).netloc
        url = scheme + '://' + netloc + '/info'
        http_conn = self.http_connection(url)
        return get_capabilities(http_conn)
