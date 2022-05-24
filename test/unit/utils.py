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

import functools
import io
import importlib
import os
import sys
from time import sleep
import unittest
from unittest import mock

from requests import RequestException
from requests.structures import CaseInsensitiveDict
from urllib.parse import urlparse, ParseResult
from swiftclient import client as c
from swiftclient import shell as s
from swiftclient.utils import EMPTY_ETAG


def fake_get_auth_keystone(expected_os_options=None, exc=None,
                           storage_url='http://url/', token='token',
                           **kwargs):
    def fake_get_auth_keystone(auth_url,
                               user,
                               key,
                               actual_os_options, **actual_kwargs):
        if exc:
            raise exc('test')
        # TODO: some way to require auth_url, user and key?
        if expected_os_options:
            for key, value in actual_os_options.items():
                if value and value != expected_os_options.get(key):
                    return "", None
        if 'required_kwargs' in kwargs:
            for k, v in kwargs['required_kwargs'].items():
                if v != actual_kwargs.get(k):
                    return "", None

        if auth_url.startswith("https") and \
           auth_url.endswith("invalid-certificate") and \
           not actual_kwargs['insecure']:
            from swiftclient import client as c
            raise c.ClientException("invalid-certificate")
        if auth_url.startswith("https") and \
           auth_url.endswith("self-signed-certificate") and \
           not actual_kwargs['insecure'] and \
           actual_kwargs['cacert'] is None:
            from swiftclient import client as c
            raise c.ClientException("unverified-certificate")
        if auth_url.startswith("https") and \
           auth_url.endswith("client-certificate") and \
           not (actual_kwargs['cert'] and actual_kwargs['cert_key']):
            from swiftclient import client as c
            raise c.ClientException("noclient-certificate")

        return storage_url, token
    return fake_get_auth_keystone


class StubResponse(object):
    """
    Placeholder structure for use with fake_http_connect's code_iter to modify
    response attributes (status, body, headers) on a per-request basis.
    """

    def __init__(self, status=200, body='', headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {}

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.status,
                                   self.body, self.headers)


def fake_http_connect(*code_iter, **kwargs):
    """
    Generate a callable which yields a series of stubbed responses.  Because
    swiftclient will reuse an HTTP connection across pipelined requests it is
    not always the case that this fake is used strictly for mocking an HTTP
    connection, but rather each HTTP response (i.e. each call to requests
    get_response).
    """

    class FakeConn(object):

        def __init__(self, status, etag=None, body='', timestamp='1',
                     headers=None):
            self.status_code = self.status = status
            self.reason = 'Fake'
            self.scheme = 'http'
            self.host = '1.2.3.4'
            self.port = '1234'
            self.sent = 0
            self.received = 0
            self.etag = etag
            self.content = self.body = body
            self.timestamp = timestamp
            self.headers = headers or {}
            self.request = None
            self._closed = False

        def getresponse(self):
            if kwargs.get('raise_exc'):
                raise Exception('test')
            return self

        def getheaders(self):
            if self.headers:
                return self.headers.items()
            headers = {'content-length': str(len(self.body)),
                       'content-type': 'x-application/test',
                       'x-timestamp': self.timestamp,
                       'last-modified': self.timestamp,
                       'x-object-meta-test': 'testing',
                       'etag':
                       self.etag or '"%s"' % EMPTY_ETAG,
                       'x-works': 'yes',
                       'x-account-container-count': '12345'}
            if not self.timestamp:
                del headers['x-timestamp']
            try:
                if next(container_ts_iter) is False:
                    headers['x-container-timestamp'] = '1'
            except StopIteration:
                pass
            if 'slow' in kwargs:
                headers['content-length'] = '4'
            if 'headers' in kwargs:
                headers.update(kwargs['headers'])
            if 'auth_v1' in kwargs:
                headers.update(
                    {'x-storage-url': 'storageURL',
                     'x-auth-token': 'someauthtoken'})
            return headers.items()

        def read(self, amt=None):
            if 'slow' in kwargs:
                if self.sent < 4:
                    self.sent += 1
                    sleep(0.1)
                    return ' '
            rv = self.body[:amt]
            if amt is not None:
                self.body = self.body[amt:]
            else:
                self.body = ''
            return rv

        def send(self, amt=None):
            if 'slow' in kwargs:
                if self.received < 4:
                    self.received += 1
                    sleep(0.1)

        def getheader(self, name, default=None):
            return dict(self.getheaders()).get(name.lower(), default)

        def close(self):
            self._closed = True

    timestamps_iter = iter(kwargs.get('timestamps') or ['1'] * len(code_iter))
    etag_iter = iter(kwargs.get('etags') or [None] * len(code_iter))
    x = kwargs.get('missing_container', [False] * len(code_iter))
    if not isinstance(x, (tuple, list)):
        x = [x] * len(code_iter)
    container_ts_iter = iter(x)
    code_iter = iter(code_iter)

    def connect(*args, **ckwargs):
        if 'give_content_type' in kwargs:
            if len(args) >= 7 and 'Content-Type' in args[6]:
                kwargs['give_content_type'](args[6]['Content-Type'])
            else:
                kwargs['give_content_type']('')
        if 'give_connect' in kwargs:
            kwargs['give_connect'](*args, **ckwargs)
        status = next(code_iter)
        if isinstance(status, StubResponse):
            fake_conn = FakeConn(status.status, body=status.body,
                                 headers=status.headers)
        else:
            etag = next(etag_iter)
            timestamp = next(timestamps_iter)
            fake_conn = FakeConn(status, etag, body=kwargs.get('body', ''),
                                 timestamp=timestamp)
        if fake_conn.status <= 0:
            raise RequestException()
        return fake_conn

    connect.code_iter = code_iter
    return connect


class MockHttpTest(unittest.TestCase):

    def setUp(self):
        super(MockHttpTest, self).setUp()
        self.fake_connect = None
        self.request_log = []

        # Capture output, since the test-runner stdout/stderr monkey-patching
        # won't cover the references to sys.stdout/sys.stderr in
        # swiftclient.multithreading
        self.capture_output = CaptureOutput()
        if 'SWIFTCLIENT_DEBUG' not in os.environ:
            self.capture_output.__enter__()
            self.addCleanup(self.capture_output.__exit__)

            # since we're going to steal all stderr output globally; we should
            # give the developer an escape hatch or risk scorn
            def blowup_but_with_the_helpful(*args, **kwargs):
                raise Exception(
                    "You tried to enter a debugger while stderr is "
                    "patched, you need to set SWIFTCLIENT_DEBUG=1 "
                    "and try again")
            import pdb
            pdb.set_trace = blowup_but_with_the_helpful

        def fake_http_connection(*args, **kwargs):
            self.validateMockedRequestsConsumed()
            self.request_log = []
            self.fake_connect = fake_http_connect(*args, **kwargs)
            _orig_http_connection = c.http_connection
            query_string = kwargs.get('query_string')
            storage_url = kwargs.get('storage_url')
            auth_token = kwargs.get('auth_token')
            exc = kwargs.get('exc')
            on_request = kwargs.get('on_request')

            def wrapper(url, proxy=None, cacert=None, insecure=False,
                        cert=None, cert_key=None,
                        ssl_compression=True, timeout=None):
                if storage_url:
                    self.assertEqual(storage_url, url)

                parsed, _conn = _orig_http_connection(url, proxy=proxy)

                class RequestsWrapper(object):
                    def close(self):
                        if hasattr(self, 'resp'):
                            self.resp.close()
                conn = RequestsWrapper()

                def request(method, path, *args, **kwargs):
                    try:
                        conn.resp = self.fake_connect()
                    except StopIteration:
                        self.fail('Unexpected %s request for %s' % (
                            method, path))
                    self.request_log.append((parsed, method, path, args,
                                             kwargs, conn.resp))
                    conn.host = conn.resp.host
                    conn.resp.request = RequestsWrapper()
                    conn.resp.request.url = '%s://%s%s' % (
                        conn.resp.scheme, conn.resp.host, path)
                    conn.resp.has_been_read = False
                    _orig_read = conn.resp.read

                    def read(*args, **kwargs):
                        conn.resp.has_been_read = True
                        return _orig_read(*args, **kwargs)
                    conn.resp.read = read
                    if on_request:
                        status = on_request(method, path, *args, **kwargs)
                        conn.resp.status = status
                    if auth_token:
                        headers = args[1]
                        self.assertEqual(auth_token,
                                         headers.get('X-Auth-Token'))
                    if query_string:
                        self.assertTrue(path.endswith('?' + query_string))
                    if path.endswith('invalid_cert') and not insecure:
                        from swiftclient import client as c
                        raise c.ClientException("invalid_certificate")
                    if exc:
                        raise exc
                    return conn.resp

                def putrequest(path, data=None, headers=None, **kwargs):
                    request('PUT', path, data, headers, **kwargs)

                conn.request = request
                conn.putrequest = putrequest

                def getresponse():
                    return conn.resp
                conn.getresponse = getresponse

                return parsed, conn
            return wrapper
        self.fake_http_connection = fake_http_connection

    def iter_request_log(self):
        for parsed, method, path, args, kwargs, resp in self.request_log:
            parts = parsed._asdict()
            parts['path'] = path
            full_path = ParseResult(**parts).geturl()
            args = list(args)
            log = dict(zip(('body', 'headers'), args))
            log.update({
                'method': method,
                'full_path': full_path,
                'parsed_path': urlparse(full_path),
                'path': path,
                'headers': CaseInsensitiveDict(log.get('headers')),
                'resp': resp,
                'status': resp.status,
            })
            yield log

    orig_assertEqual = unittest.TestCase.assertEqual

    def assert_request_equal(self, expected, real_request):
        method, path = expected[:2]
        if urlparse(path).scheme:
            match_path = real_request['full_path']
        else:
            match_path = real_request['path']
        self.assertEqual((method, path), (real_request['method'],
                                          match_path))
        if len(expected) > 2:
            body = expected[2]
            real_request['expected'] = body
            err_msg = 'Body mismatch for %(method)s %(path)s, ' \
                'expected %(expected)r, and got %(body)r' % real_request
            self.orig_assertEqual(body, real_request['body'], err_msg)

        if len(expected) > 3:
            headers = CaseInsensitiveDict(expected[3])
            for key, value in headers.items():
                real_request['key'] = key
                real_request['expected_value'] = value
                real_request['value'] = real_request['headers'].get(key)
                err_msg = (
                    'Header mismatch on %(key)r, '
                    'expected %(expected_value)r and got %(value)r '
                    'for %(method)s %(path)s %(headers)r' % real_request)
                self.orig_assertEqual(value, real_request['value'],
                                      err_msg)
            real_request['extra_headers'] = dict(
                (key, value) for key, value in real_request['headers'].items()
                if key not in headers)
            if real_request['extra_headers']:
                self.fail('Received unexpected headers for %(method)s '
                          '%(path)s, got %(extra_headers)r' % real_request)

    def assertRequests(self, expected_requests):
        """
        Make sure some requests were made like you expected, provide a list of
        expected requests, typically in the form of [(method, path), ...]
        or [(method, path, body, headers), ...]
        """
        real_requests = self.iter_request_log()
        for expected in expected_requests:
            real_request = next(real_requests)
            self.assert_request_equal(expected, real_request)
        try:
            real_request = next(real_requests)
        except StopIteration:
            pass
        else:
            self.fail('At least one extra request received: %r' %
                      real_request)

    def assert_request(self, expected_request):
        """
        Make sure a request was made as expected. Provide the
        expected request in the form of [(method, path), ...]
        """
        real_requests = self.iter_request_log()
        for real_request in real_requests:
            try:
                self.assert_request_equal(expected_request, real_request)
                break
            except AssertionError:
                pass
        else:
            raise AssertionError(
                "Expected request %s not found in actual requests %s"
                % (expected_request, self.request_log)
            )

    def validateMockedRequestsConsumed(self):
        if not self.fake_connect:
            return
        unused_responses = list(self.fake_connect.code_iter)
        if unused_responses:
            self.fail('Unused responses %r' % (unused_responses,))

    def tearDown(self):
        self.validateMockedRequestsConsumed()
        super(MockHttpTest, self).tearDown()
        # TODO: this nuke from orbit clean up seems to be encouraging
        # un-hygienic mocking on the swiftclient.client module; which may lead
        # to some unfortunate test order dependency bugs by way of the broken
        # window theory if any other modules are similarly patched
        importlib.reload(c)


class CaptureStreamPrinter(object):
    """
    CaptureStreamPrinter is used for testing unicode writing for PY3. Anything
    written here is encoded as utf-8 and written to the parent CaptureStream
    """
    def __init__(self, captured_stream):
        self._captured_stream = captured_stream

    def write(self, data):
        # No encoding, just convert the raw bytes into a str for testing
        # The below call also validates that we have a byte string.
        self._captured_stream.write(
            data if isinstance(data, bytes) else data.encode('utf8'))


class CaptureStream(object):

    def __init__(self, stream):
        self.stream = stream
        self._buffer = io.BytesIO()
        self._capture = CaptureStreamPrinter(self._buffer)
        self.streams = [self._capture]

    @property
    def buffer(self):
        return self._buffer

    def flush(self):
        pass

    def write(self, *args, **kwargs):
        for stream in self.streams:
            stream.write(*args, **kwargs)

    def writelines(self, *args, **kwargs):
        for stream in self.streams:
            stream.writelines(*args, **kwargs)

    def getvalue(self):
        return self._buffer.getvalue()

    def clear(self):
        self._buffer.truncate(0)
        self._buffer.seek(0)


class CaptureOutput(object):

    def __init__(self, suppress_systemexit=False):
        self._out = CaptureStream(sys.stdout)
        self._err = CaptureStream(sys.stderr)
        self.patchers = []

        WrappedOutputManager = functools.partial(s.OutputManager,
                                                 print_stream=self._out,
                                                 error_stream=self._err)

        if suppress_systemexit:
            self.patchers += [
                mock.patch('swiftclient.shell.OutputManager.get_error_count',
                           return_value=0)
            ]

        self.patchers += [
            mock.patch('swiftclient.shell.OutputManager',
                       WrappedOutputManager),
            mock.patch('sys.stdout', self._out),
            mock.patch('sys.stderr', self._err),
        ]

    def __enter__(self):
        for patcher in self.patchers:
            patcher.start()
        return self

    def __exit__(self, *args, **kwargs):
        for patcher in self.patchers:
            patcher.stop()

    @property
    def out(self):
        return self._out.getvalue().decode('utf8')

    @property
    def err(self):
        return self._err.getvalue().decode('utf8')

    def clear(self):
        self._out.clear()
        self._err.clear()

    # act like the string captured by stdout

    def __str__(self):
        return self.out

    def __len__(self):
        return len(self.out)

    def __eq__(self, other):
        return self.out == other

    def __ne__(self, other):
        return not self.__eq__(other)

    def __getattr__(self, name):
        return getattr(self.out, name)


class FakeKeystone(object):
    '''
    Fake keystone client module. Returns given endpoint url and auth token.
    '''
    def __init__(self, endpoint, token):
        self.calls = []
        self.auth_version = None
        self.endpoint = endpoint
        self.token = token

    class _Client(object):
        def __init__(self, endpoint, auth_token, **kwargs):
            self.auth_token = auth_token
            self.endpoint = endpoint
            self.service_catalog = self.ServiceCatalog(endpoint)

        class ServiceCatalog(object):
            def __init__(self, endpoint):
                self.calls = []
                self.endpoint_url = endpoint

            def url_for(self, **kwargs):
                self.calls.append(kwargs)
                return self.endpoint_url

    def Client(self, **kwargs):
        self.calls.append(kwargs)
        self.client = self._Client(
            endpoint=self.endpoint, auth_token=self.token, **kwargs)
        return self.client

    class Unauthorized(Exception):
        pass

    class AuthorizationFailure(Exception):
        pass

    class EndpointNotFound(Exception):
        pass


class FakeStream(object):
    def __init__(self, size):
        self.bytes_read = 0
        self.size = size

    def read(self, size=-1):
        if self.bytes_read == self.size:
            return b''

        if size == -1 or size + self.bytes_read > self.size:
            remaining = self.size - self.bytes_read
            self.bytes_read = self.size
            return b'A' * remaining

        self.bytes_read += size
        return b'A' * size

    def __len__(self):
        return self.size
