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

# TODO: More tests
import mock
import logging
import socket
import StringIO
import testtools
import warnings
from urlparse import urlparse

# TODO: mock http connection class with more control over headers
from .utils import fake_http_connect, fake_get_keystoneclient_2_0

from swiftclient import client as c


class TestClientException(testtools.TestCase):

    def test_is_exception(self):
        self.assertTrue(issubclass(c.ClientException, Exception))

    def test_format(self):
        exc = c.ClientException('something failed')
        self.assertTrue('something failed' in str(exc))
        test_kwargs = (
            'scheme',
            'host',
            'port',
            'path',
            'query',
            'status',
            'reason',
            'device',
        )
        for value in test_kwargs:
            kwargs = {
                'http_%s' % value: value,
            }
            exc = c.ClientException('test', **kwargs)
            self.assertTrue(value in str(exc))


class TestJsonImport(testtools.TestCase):

    def tearDown(self):
        try:
            import json
        except ImportError:
            pass
        else:
            reload(json)

        try:
            import simplejson
        except ImportError:
            pass
        else:
            reload(simplejson)
        super(TestJsonImport, self).tearDown()

    def test_any(self):
        self.assertTrue(hasattr(c, 'json_loads'))

    def test_no_simplejson(self):
        # break simplejson
        try:
            import simplejson
        except ImportError:
            # not installed, so we don't have to break it for these tests
            pass
        else:
            delattr(simplejson, 'loads')
            reload(c)

        try:
            from json import loads
        except ImportError:
            # this case is stested in _no_json
            pass
        else:
            self.assertEqual(loads, c.json_loads)


class MockHttpTest(testtools.TestCase):

    def setUp(self):
        super(MockHttpTest, self).setUp()

        def fake_http_connection(*args, **kwargs):
            _orig_http_connection = c.http_connection
            return_read = kwargs.get('return_read')
            query_string = kwargs.get('query_string')
            storage_url = kwargs.get('storage_url')

            def wrapper(url, proxy=None, cacert=None, insecure=False,
                        ssl_compression=True):
                if storage_url:
                    self.assertEqual(storage_url, url)

                parsed, _conn = _orig_http_connection(url, proxy=proxy)
                conn = fake_http_connect(*args, **kwargs)()

                def request(method, url, *args, **kwargs):
                    if query_string:
                        self.assertTrue(url.endswith('?' + query_string))
                    if url.endswith('invalid_cert') and not insecure:
                        from swiftclient import client as c
                        raise c.ClientException("invalid_certificate")
                    return
                conn.request = request

                conn.has_been_read = False
                _orig_read = conn.read

                def read(*args, **kwargs):
                    conn.has_been_read = True
                    return _orig_read(*args, **kwargs)
                conn.read = return_read or read

                return parsed, conn
            return wrapper
        self.fake_http_connection = fake_http_connection

    def tearDown(self):
        super(MockHttpTest, self).tearDown()
        reload(c)


class MockHttpResponse():
    def __init__(self, status=0):
        self.status = status
        self.status_code = status
        self.reason = "OK"
        self.buffer = []

        class Raw:
            def read():
                pass
        self.raw = Raw()

    def read(self):
        return ""

    def getheader(self, name, default):
        return ""

    def getheaders(self):
        return {"key1": "value1", "key2": "value2"}

    def fake_response(self):
        return MockHttpResponse(self.status)

    def _fake_request(self, *arg, **kwarg):
        self.status = 200
        # This simulate previous httplib implementation that would do a
        # putrequest() and then use putheader() to send header.
        for k, v in kwarg['headers'].iteritems():
            self.buffer.append('%s: %s' % (k, v))
        return self.fake_response()


class TestHttpHelpers(MockHttpTest):

    def test_quote(self):
        value = 'standard string'
        self.assertEqual('standard%20string', c.quote(value))
        value = u'\u0075nicode string'
        self.assertEqual('unicode%20string', c.quote(value))

    def test_http_connection(self):
        url = 'http://www.test.com'
        _junk, conn = c.http_connection(url)
        self.assertTrue(isinstance(conn, c.HTTPConnection))
        url = 'https://www.test.com'
        _junk, conn = c.http_connection(url)
        self.assertTrue(isinstance(conn, c.HTTPConnection))
        url = 'ftp://www.test.com'
        self.assertRaises(c.ClientException, c.http_connection, url)

    def test_validate_headers(self):
        headers = {'key': 'value'}
        self.assertEqual(c.validate_headers(headers), None)

        headers = {'key': 'value1\nvalue2'}
        self.assertRaises(c.InvalidHeadersException, c.validate_headers,
                          headers)

        headers = {'key': 'value1\rvalue2'}
        self.assertRaises(c.InvalidHeadersException, c.validate_headers,
                          headers)

    def test_validate_headers_with_other_than_str(self):
        for t in (None, 1, 1.0, 1L, u"A"):
            self.assertEqual(c.validate_headers({'key': t}),
                             None)

# TODO: following tests are placeholders, need more tests, better coverage


class TestGetAuth(MockHttpTest):

    def test_ok(self):
        c.http_connection = self.fake_http_connection(200)
        url, token = c.get_auth('http://www.test.com', 'asdf', 'asdf')
        self.assertEqual(url, None)
        self.assertEqual(token, None)

    def test_invalid_auth(self):
        c.http_connection = self.fake_http_connection(200)
        self.assertRaises(c.ClientException, c.get_auth,
                          'http://www.tests.com', 'asdf', 'asdf',
                          auth_version="foo")

    def test_auth_v1(self):
        c.http_connection = self.fake_http_connection(200, auth_v1=True)
        url, token = c.get_auth('http://www.test.com', 'asdf', 'asdf',
                                auth_version="1.0")
        self.assertEqual(url, 'storageURL')
        self.assertEqual(token, 'someauthtoken')

    def test_auth_v1_insecure(self):
        c.http_connection = self.fake_http_connection(200, auth_v1=True)
        url, token = c.get_auth('http://www.test.com/invalid_cert',
                                'asdf', 'asdf',
                                auth_version='1.0',
                                insecure=True)
        self.assertEqual(url, 'storageURL')
        self.assertEqual(token, 'someauthtoken')

        self.assertRaises(c.ClientException, c.get_auth,
                          'http://www.test.com/invalid_cert',
                          'asdf', 'asdf',
                          auth_version='1.0')

    def test_auth_v2(self):
        os_options = {'tenant_name': 'asdf'}
        c.get_keystoneclient_2_0 = fake_get_keystoneclient_2_0(os_options)
        url, token = c.get_auth('http://www.test.com', 'asdf', 'asdf',
                                os_options=os_options,
                                auth_version="2.0")
        self.assertTrue(url.startswith("http"))
        self.assertTrue(token)

    def test_auth_v2_no_tenant_name(self):
        c.get_keystoneclient_2_0 = fake_get_keystoneclient_2_0({})
        self.assertRaises(c.ClientException, c.get_auth,
                          'http://www.tests.com', 'asdf', 'asdf',
                          os_options={},
                          auth_version='2.0')

    def test_auth_v2_with_tenant_user_in_user(self):
        tenant_option = {'tenant_name': 'foo'}
        c.get_keystoneclient_2_0 = fake_get_keystoneclient_2_0(tenant_option)
        url, token = c.get_auth('http://www.test.com', 'foo:bar', 'asdf',
                                os_options={},
                                auth_version="2.0")
        self.assertTrue(url.startswith("http"))
        self.assertTrue(token)

    def test_auth_v2_tenant_name_no_os_options(self):
        tenant_option = {'tenant_name': 'asdf'}
        c.get_keystoneclient_2_0 = fake_get_keystoneclient_2_0(tenant_option)
        url, token = c.get_auth('http://www.test.com', 'asdf', 'asdf',
                                tenant_name='asdf',
                                os_options={},
                                auth_version="2.0")
        self.assertTrue(url.startswith("http"))
        self.assertTrue(token)

    def test_auth_v2_with_os_options(self):
        os_options = {'service_type': 'object-store',
                      'endpoint_type': 'internalURL',
                      'tenant_name': 'asdf'}
        c.get_keystoneclient_2_0 = fake_get_keystoneclient_2_0(os_options)
        url, token = c.get_auth('http://www.test.com', 'asdf', 'asdf',
                                os_options=os_options,
                                auth_version="2.0")
        self.assertTrue(url.startswith("http"))
        self.assertTrue(token)

    def test_auth_v2_with_tenant_user_in_user_no_os_options(self):
        tenant_option = {'tenant_name': 'foo'}
        c.get_keystoneclient_2_0 = fake_get_keystoneclient_2_0(tenant_option)
        url, token = c.get_auth('http://www.test.com', 'foo:bar', 'asdf',
                                auth_version="2.0")
        self.assertTrue(url.startswith("http"))
        self.assertTrue(token)

    def test_auth_v2_with_os_region_name(self):
        os_options = {'region_name': 'good-region',
                      'tenant_name': 'asdf'}
        c.get_keystoneclient_2_0 = fake_get_keystoneclient_2_0(os_options)
        url, token = c.get_auth('http://www.test.com', 'asdf', 'asdf',
                                os_options=os_options,
                                auth_version="2.0")
        self.assertTrue(url.startswith("http"))
        self.assertTrue(token)

    def test_auth_v2_no_endpoint(self):
        os_options = {'region_name': 'unknown_region',
                      'tenant_name': 'asdf'}
        c.get_keystoneclient_2_0 = fake_get_keystoneclient_2_0(
            os_options, c.ClientException)
        self.assertRaises(c.ClientException, c.get_auth,
                          'http://www.tests.com', 'asdf', 'asdf',
                          os_options=os_options, auth_version='2.0')

    def test_auth_v2_ks_exception(self):
        c.get_keystoneclient_2_0 = fake_get_keystoneclient_2_0(
            {}, c.ClientException)
        self.assertRaises(c.ClientException, c.get_auth,
                          'http://www.tests.com', 'asdf', 'asdf',
                          os_options={},
                          auth_version='2.0')

    def test_auth_v2_cacert(self):
        os_options = {'tenant_name': 'foo'}
        c.get_keystoneclient_2_0 = fake_get_keystoneclient_2_0(
            os_options, None)

        auth_url_secure = 'https://www.tests.com'
        auth_url_insecure = 'https://www.tests.com/self-signed-certificate'

        url, token = c.get_auth(auth_url_secure, 'asdf', 'asdf',
                                os_options=os_options, auth_version='2.0',
                                insecure=False)
        self.assertTrue(url.startswith("http"))
        self.assertTrue(token)

        url, token = c.get_auth(auth_url_insecure, 'asdf', 'asdf',
                                os_options=os_options, auth_version='2.0',
                                cacert='ca.pem', insecure=False)
        self.assertTrue(url.startswith("http"))
        self.assertTrue(token)

        self.assertRaises(c.ClientException, c.get_auth,
                          auth_url_insecure, 'asdf', 'asdf',
                          os_options=os_options, auth_version='2.0')
        self.assertRaises(c.ClientException, c.get_auth,
                          auth_url_insecure, 'asdf', 'asdf',
                          os_options=os_options, auth_version='2.0',
                          insecure=False)

    def test_auth_v2_insecure(self):
        os_options = {'tenant_name': 'foo'}
        c.get_keystoneclient_2_0 = fake_get_keystoneclient_2_0(
            os_options, None)

        auth_url_secure = 'https://www.tests.com'
        auth_url_insecure = 'https://www.tests.com/invalid-certificate'

        url, token = c.get_auth(auth_url_secure, 'asdf', 'asdf',
                                os_options=os_options, auth_version='2.0')
        self.assertTrue(url.startswith("http"))
        self.assertTrue(token)

        url, token = c.get_auth(auth_url_insecure, 'asdf', 'asdf',
                                os_options=os_options, auth_version='2.0',
                                insecure=True)
        self.assertTrue(url.startswith("http"))
        self.assertTrue(token)

        self.assertRaises(c.ClientException, c.get_auth,
                          auth_url_insecure, 'asdf', 'asdf',
                          os_options=os_options, auth_version='2.0')
        self.assertRaises(c.ClientException, c.get_auth,
                          auth_url_insecure, 'asdf', 'asdf',
                          os_options=os_options, auth_version='2.0',
                          insecure=False)


class TestGetAccount(MockHttpTest):

    def test_no_content(self):
        c.http_connection = self.fake_http_connection(204)
        value = c.get_account('http://www.test.com', 'asdf')[1]
        self.assertEqual(value, [])

    def test_param_marker(self):
        c.http_connection = self.fake_http_connection(
            204,
            query_string="format=json&marker=marker")
        c.get_account('http://www.test.com', 'asdf', marker='marker')

    def test_param_limit(self):
        c.http_connection = self.fake_http_connection(
            204,
            query_string="format=json&limit=10")
        c.get_account('http://www.test.com', 'asdf', limit=10)

    def test_param_prefix(self):
        c.http_connection = self.fake_http_connection(
            204,
            query_string="format=json&prefix=asdf/")
        c.get_account('http://www.test.com', 'asdf', prefix='asdf/')

    def test_param_end_marker(self):
        c.http_connection = self.fake_http_connection(
            204,
            query_string="format=json&end_marker=end_marker")
        c.get_account('http://www.test.com', 'asdf', end_marker='end_marker')


class TestHeadAccount(MockHttpTest):

    def test_ok(self):
        c.http_connection = self.fake_http_connection(200)
        value = c.head_account('http://www.tests.com', 'asdf')
        # TODO: Hmm. This doesn't really test too much as it uses a fake that
        # always returns the same dict. I guess it "exercises" the code, so
        # I'll leave it for now.
        self.assertEqual(type(value), dict)

    def test_server_error(self):
        body = 'c' * 65
        c.http_connection = self.fake_http_connection(500, body=body)
        self.assertRaises(c.ClientException, c.head_account,
                          'http://www.tests.com', 'asdf')
        try:
            c.head_account('http://www.tests.com', 'asdf')
        except c.ClientException as e:
            new_body = "[first 60 chars of response] " + body[0:60]
            self.assertEqual(e.__str__()[-89:], new_body)


class TestGetContainer(MockHttpTest):

    def test_no_content(self):
        c.http_connection = self.fake_http_connection(204)
        value = c.get_container('http://www.test.com', 'asdf', 'asdf')[1]
        self.assertEqual(value, [])

    def test_param_marker(self):
        c.http_connection = self.fake_http_connection(
            204,
            query_string="format=json&marker=marker")
        c.get_container('http://www.test.com', 'asdf', 'asdf', marker='marker')

    def test_param_limit(self):
        c.http_connection = self.fake_http_connection(
            204,
            query_string="format=json&limit=10")
        c.get_container('http://www.test.com', 'asdf', 'asdf', limit=10)

    def test_param_prefix(self):
        c.http_connection = self.fake_http_connection(
            204,
            query_string="format=json&prefix=asdf/")
        c.get_container('http://www.test.com', 'asdf', 'asdf', prefix='asdf/')

    def test_param_delimiter(self):
        c.http_connection = self.fake_http_connection(
            204,
            query_string="format=json&delimiter=/")
        c.get_container('http://www.test.com', 'asdf', 'asdf', delimiter='/')

    def test_param_end_marker(self):
        c.http_connection = self.fake_http_connection(
            204,
            query_string="format=json&end_marker=end_marker")
        c.get_container('http://www.test.com', 'asdf', 'asdf',
                        end_marker='end_marker')

    def test_param_path(self):
        c.http_connection = self.fake_http_connection(
            204,
            query_string="format=json&path=asdf")
        c.get_container('http://www.test.com', 'asdf', 'asdf',
                        path='asdf')


class TestHeadContainer(MockHttpTest):

    def test_server_error(self):
        body = 'c' * 60
        c.http_connection = self.fake_http_connection(500, body=body)
        self.assertRaises(c.ClientException, c.head_container,
                          'http://www.test.com', 'asdf', 'asdf',
                          )
        try:
            c.head_container('http://www.test.com', 'asdf', 'asdf')
        except c.ClientException as e:
            self.assertEqual(e.http_response_content, body)


class TestPutContainer(MockHttpTest):

    def test_ok(self):
        c.http_connection = self.fake_http_connection(200)
        value = c.put_container('http://www.test.com', 'asdf', 'asdf')
        self.assertEqual(value, None)

    def test_server_error(self):
        body = 'c' * 60
        c.http_connection = self.fake_http_connection(500, body=body)
        self.assertRaises(c.ClientException, c.put_container,
                          'http://www.test.com', 'asdf', 'asdf',
                          )
        try:
            c.put_container('http://www.test.com', 'asdf', 'asdf')
        except c.ClientException as e:
            self.assertEqual(e.http_response_content, body)


class TestDeleteContainer(MockHttpTest):

    def test_ok(self):
        c.http_connection = self.fake_http_connection(200)
        value = c.delete_container('http://www.test.com', 'asdf', 'asdf')
        self.assertEqual(value, None)


class TestGetObject(MockHttpTest):

    def test_server_error(self):
        c.http_connection = self.fake_http_connection(500)
        self.assertRaises(c.ClientException, c.get_object,
                          'http://www.test.com', 'asdf', 'asdf', 'asdf')

    def test_query_string(self):
        c.http_connection = self.fake_http_connection(200,
                                                      query_string="hello=20")
        c.get_object('http://www.test.com', 'asdf', 'asdf', 'asdf',
                     query_string="hello=20")

    def test_request_headers(self):
        request_args = {}

        def fake_request(method, url, body=None, headers=None):
            request_args['method'] = method
            request_args['url'] = url
            request_args['body'] = body
            request_args['headers'] = headers
            return
        conn = self.fake_http_connection(200)('http://www.test.com/')
        conn[1].request = fake_request
        headers = {'Range': 'bytes=1-2'}
        c.get_object('url_is_irrelevant', 'TOKEN', 'container', 'object',
                     http_conn=conn, headers=headers)
        self.assertFalse(request_args['headers'] is None,
                         "No headers in the request")
        self.assertTrue('Range' in request_args['headers'],
                        "No Range header in the request")
        self.assertEqual(request_args['headers']['Range'], 'bytes=1-2')


class TestHeadObject(MockHttpTest):

    def test_server_error(self):
        c.http_connection = self.fake_http_connection(500)
        self.assertRaises(c.ClientException, c.head_object,
                          'http://www.test.com', 'asdf', 'asdf', 'asdf')


class TestPutObject(MockHttpTest):

    def test_ok(self):
        c.http_connection = self.fake_http_connection(200)
        args = ('http://www.test.com', 'asdf', 'asdf', 'asdf', 'asdf')
        value = c.put_object(*args)
        self.assertTrue(isinstance(value, basestring))

    def test_unicode_ok(self):
        conn = c.http_connection(u'http://www.test.com/')
        mock_file = StringIO.StringIO(u'\u5929\u7a7a\u4e2d\u7684\u4e4c\u4e91')
        args = (u'\u5929\u7a7a\u4e2d\u7684\u4e4c\u4e91',
                '\u5929\u7a7a\u4e2d\u7684\u4e4c\u4e91',
                u'\u5929\u7a7a\u4e2d\u7684\u4e4c\u4e91',
                u'\u5929\u7a7a\u4e2d\u7684\u4e4c\u4e91',
                mock_file)
        headers = {'X-Header1': u'\u5929\u7a7a\u4e2d\u7684\u4e4c\u4e91',
                   'X-2': 1, 'X-3': {'a': 'b'}, 'a-b': '.x:yz mn:fg:lp'}

        resp = MockHttpResponse()
        conn[1].getresponse = resp.fake_response
        conn[1]._request = resp._fake_request
        value = c.put_object(*args, headers=headers, http_conn=conn)
        self.assertTrue(isinstance(value, basestring))
        # Test for RFC-2616 encoded symbols
        self.assertTrue("a-b: .x:yz mn:fg:lp" in resp.buffer[0],
                        "[a-b: .x:yz mn:fg:lp] header is missing")

    def test_chunk_warning(self):
        conn = c.http_connection('http://www.test.com/')
        mock_file = StringIO.StringIO('asdf')
        args = ('asdf', 'asdf', 'asdf', 'asdf', mock_file)
        resp = MockHttpResponse()
        conn[1].getresponse = resp.fake_response
        conn[1]._request = resp._fake_request
        with warnings.catch_warnings(record=True) as w:
            c.put_object(*args, chunk_size=20, headers={}, http_conn=conn)
            self.assertEqual(len(w), 0)

        body = 'c' * 60
        c.http_connection = self.fake_http_connection(200, body=body)
        args = ('http://www.test.com', 'asdf', 'asdf', 'asdf', 'asdf')
        with warnings.catch_warnings(record=True) as w:
            c.put_object(*args, chunk_size=20)
            self.assertEqual(len(w), 1)
            self.assertTrue(issubclass(w[-1].category, UserWarning))

    def test_server_error(self):
        body = 'c' * 60
        c.http_connection = self.fake_http_connection(500, body=body)
        args = ('http://www.test.com', 'asdf', 'asdf', 'asdf', 'asdf')
        self.assertRaises(c.ClientException, c.put_object, *args)
        try:
            c.put_object(*args)
        except c.ClientException as e:
            self.assertEqual(e.http_response_content, body)

    def test_query_string(self):
        c.http_connection = self.fake_http_connection(200,
                                                      query_string="hello=20")
        c.put_object('http://www.test.com', 'asdf', 'asdf', 'asdf',
                     query_string="hello=20")


class TestPostObject(MockHttpTest):

    def test_ok(self):
        c.http_connection = self.fake_http_connection(200)
        args = ('http://www.test.com', 'asdf', 'asdf', 'asdf', {})
        c.post_object(*args)

    def test_unicode_ok(self):
        conn = c.http_connection(u'http://www.test.com/')
        args = (u'\u5929\u7a7a\u4e2d\u7684\u4e4c\u4e91',
                '\u5929\u7a7a\u4e2d\u7684\u4e4c\u4e91',
                u'\u5929\u7a7a\u4e2d\u7684\u4e4c\u4e91',
                u'\u5929\u7a7a\u4e2d\u7684\u4e4c\u4e91')
        headers = {'X-Header1': u'\u5929\u7a7a\u4e2d\u7684\u4e4c\u4e91',
                   'X-2': '1', 'X-3': {'a': 'b'}, 'a-b': '.x:yz mn:kl:qr'}

        resp = MockHttpResponse()
        conn[1].getresponse = resp.fake_response
        conn[1]._request = resp._fake_request
        c.post_object(*args, headers=headers, http_conn=conn)
        # Test for RFC-2616 encoded symbols
        self.assertTrue("a-b: .x:yz mn:kl:qr" in resp.buffer[0],
                        "[a-b: .x:yz mn:kl:qr] header is missing")

    def test_server_error(self):
        body = 'c' * 60
        c.http_connection = self.fake_http_connection(500, body=body)
        args = ('http://www.test.com', 'asdf', 'asdf', 'asdf', {})
        self.assertRaises(c.ClientException, c.post_object, *args)
        try:
            c.post_object(*args)
        except c.ClientException as e:
            self.assertEqual(e.http_response_content, body)


class TestDeleteObject(MockHttpTest):

    def test_ok(self):
        c.http_connection = self.fake_http_connection(200)
        c.delete_object('http://www.test.com', 'asdf', 'asdf', 'asdf')

    def test_server_error(self):
        c.http_connection = self.fake_http_connection(500)
        self.assertRaises(c.ClientException, c.delete_object,
                          'http://www.test.com', 'asdf', 'asdf', 'asdf')

    def test_query_string(self):
        c.http_connection = self.fake_http_connection(200,
                                                      query_string="hello=20")
        c.delete_object('http://www.test.com', 'asdf', 'asdf', 'asdf',
                        query_string="hello=20")


class TestGetCapabilities(MockHttpTest):

    def test_ok(self):
        conn = self.fake_http_connection(200, body='{}')
        http_conn = conn('http://www.test.com/info')
        self.assertEqual(type(c.get_capabilities(http_conn)), dict)
        self.assertTrue(http_conn[1].has_been_read)

    def test_server_error(self):
        conn = self.fake_http_connection(500)
        http_conn = conn('http://www.test.com/info')
        self.assertRaises(c.ClientException, c.get_capabilities, http_conn)


class TestConnection(MockHttpTest):

    def test_instance(self):
        conn = c.Connection('http://www.test.com', 'asdf', 'asdf')
        self.assertEqual(conn.retries, 5)

    def test_instance_kwargs(self):
        args = {'user': 'ausername',
                'key': 'secretpass',
                'authurl': 'http://www.test.com',
                'tenant_name': 'atenant'}
        conn = c.Connection(**args)
        self.assertEqual(type(conn), c.Connection)

    def test_instance_kwargs_token(self):
        args = {'preauthtoken': 'atoken123',
                'preauthurl': 'http://www.test.com:8080/v1/AUTH_123456'}
        conn = c.Connection(**args)
        self.assertEqual(type(conn), c.Connection)

    def test_storage_url_override(self):
        static_url = 'http://overridden.storage.url'
        c.http_connection = self.fake_http_connection(
            200, body='[]', storage_url=static_url)
        conn = c.Connection('http://auth.url/', 'some_user', 'some_key',
                            os_options={
                                'object_storage_url': static_url})
        method_signatures = (
            (conn.head_account, []),
            (conn.get_account, []),
            (conn.head_container, ('asdf',)),
            (conn.get_container, ('asdf',)),
            (conn.put_container, ('asdf',)),
            (conn.delete_container, ('asdf',)),
            (conn.head_object, ('asdf', 'asdf')),
            (conn.get_object, ('asdf', 'asdf')),
            (conn.put_object, ('asdf', 'asdf', 'asdf')),
            (conn.post_object, ('asdf', 'asdf', {})),
            (conn.delete_object, ('asdf', 'asdf')),
        )

        with mock.patch('swiftclient.client.get_auth_1_0') as mock_get_auth:
            mock_get_auth.return_value = ('http://auth.storage.url', 'tToken')

            for method, args in method_signatures:
                method(*args)

    def test_get_capabilities(self):
        conn = c.Connection()
        with mock.patch('swiftclient.client.get_capabilities') as get_cap:
            conn.get_capabilities('http://storage2.test.com')
            parsed = get_cap.call_args[0][0][0]
            self.assertEqual(parsed.path, '/info')
            self.assertEqual(parsed.netloc, 'storage2.test.com')
            conn.get_auth = lambda: ('http://storage.test.com/v1/AUTH_test',
                                     'token')
            conn.get_capabilities()
            parsed = get_cap.call_args[0][0][0]
            self.assertEqual(parsed.path, '/info')
            self.assertEqual(parsed.netloc, 'storage.test.com')

    def test_retry(self):
        c.http_connection = self.fake_http_connection(500)

        def quick_sleep(*args):
            pass
        c.sleep = quick_sleep
        conn = c.Connection('http://www.test.com', 'asdf', 'asdf')
        self.assertRaises(c.ClientException, conn.head_account)
        self.assertEqual(conn.attempts, conn.retries + 1)

    def test_retry_on_ratelimit(self):
        c.http_connection = self.fake_http_connection(498)

        def quick_sleep(*args):
            pass
        c.sleep = quick_sleep

        # test retries
        conn = c.Connection('http://www.test.com', 'asdf', 'asdf',
                            retry_on_ratelimit=True)
        self.assertRaises(c.ClientException, conn.head_account)
        self.assertEqual(conn.attempts, conn.retries + 1)

        # test default no-retry
        conn = c.Connection('http://www.test.com', 'asdf', 'asdf')
        self.assertRaises(c.ClientException, conn.head_account)
        self.assertEqual(conn.attempts, 1)

    def test_resp_read_on_server_error(self):
        c.http_connection = self.fake_http_connection(500)
        conn = c.Connection('http://www.test.com', 'asdf', 'asdf', retries=0)

        def get_auth(*args, **kwargs):
            return 'http://www.new.com', 'new'
        conn.get_auth = get_auth
        self.url, self.token = conn.get_auth()

        method_signatures = (
            (conn.head_account, []),
            (conn.get_account, []),
            (conn.head_container, ('asdf',)),
            (conn.get_container, ('asdf',)),
            (conn.put_container, ('asdf',)),
            (conn.delete_container, ('asdf',)),
            (conn.head_object, ('asdf', 'asdf')),
            (conn.get_object, ('asdf', 'asdf')),
            (conn.put_object, ('asdf', 'asdf', 'asdf')),
            (conn.post_object, ('asdf', 'asdf', {})),
            (conn.delete_object, ('asdf', 'asdf')),
        )

        for method, args in method_signatures:
            self.assertRaises(c.ClientException, method, *args)
            try:
                self.assertTrue(conn.http_conn[1].has_been_read)
            except AssertionError:
                msg = '%s did not read resp on server error' % method.__name__
                self.fail(msg)
            except Exception as e:
                raise e.__class__("%s - %s" % (method.__name__, e))

    def test_reauth(self):
        c.http_connection = self.fake_http_connection(401)

        def get_auth(*args, **kwargs):
            return 'http://www.new.com', 'new'

        def swap_sleep(*args):
            self.swap_sleep_called = True
            c.get_auth = get_auth
            c.http_connection = self.fake_http_connection(200)
        c.sleep = swap_sleep
        self.swap_sleep_called = False

        conn = c.Connection('http://www.test.com', 'asdf', 'asdf',
                            preauthurl='http://www.old.com',
                            preauthtoken='old',
                            )

        self.assertEqual(conn.attempts, 0)
        self.assertEqual(conn.url, 'http://www.old.com')
        self.assertEqual(conn.token, 'old')

        conn.head_account()

        self.assertTrue(self.swap_sleep_called)
        self.assertEqual(conn.attempts, 2)
        self.assertEqual(conn.url, 'http://www.new.com')
        self.assertEqual(conn.token, 'new')

    def test_reset_stream(self):

        class LocalContents(object):

            def __init__(self, tell_value=0):
                self.already_read = False
                self.seeks = []
                self.tell_value = tell_value

            def tell(self):
                return self.tell_value

            def seek(self, position):
                self.seeks.append(position)
                self.already_read = False

            def read(self, size=-1):
                if self.already_read:
                    return ''
                else:
                    self.already_read = True
                    return 'abcdef'

        class LocalConnection(object):

            def __init__(self, parsed_url=None):
                self.reason = ""
                if parsed_url:
                    self.host = parsed_url.netloc
                    self.port = parsed_url.netloc

            def putrequest(self, *args, **kwargs):
                self.send()

            def putheader(self, *args, **kwargs):
                return

            def endheaders(self, *args, **kwargs):
                return

            def send(self, *args, **kwargs):
                raise socket.error('oops')

            def request(self, *args, **kwargs):
                return

            def getresponse(self, *args, **kwargs):
                self.status = 200
                return self

            def getheader(self, *args, **kwargs):
                return 'header'

            def getheaders(self):
                return {"key1": "value1", "key2": "value2"}

            def read(self, *args, **kwargs):
                return ''

        def local_http_connection(url, proxy=None, cacert=None,
                                  insecure=False, ssl_compression=True):
            parsed = urlparse(url)
            return parsed, LocalConnection()

        orig_conn = c.http_connection
        try:
            c.http_connection = local_http_connection
            conn = c.Connection('http://www.example.com', 'asdf', 'asdf',
                                retries=1, starting_backoff=.0001)

            contents = LocalContents()
            exc = None
            try:
                conn.put_object('c', 'o', contents)
            except socket.error as err:
                exc = err
            self.assertEqual(contents.seeks, [0])
            self.assertEqual(str(exc), 'oops')

            contents = LocalContents(tell_value=123)
            exc = None
            try:
                conn.put_object('c', 'o', contents)
            except socket.error as err:
                exc = err
            self.assertEqual(contents.seeks, [123])
            self.assertEqual(str(exc), 'oops')

            contents = LocalContents()
            contents.tell = None
            exc = None
            try:
                conn.put_object('c', 'o', contents)
            except c.ClientException as err:
                exc = err
            self.assertEqual(contents.seeks, [])
            self.assertEqual(str(exc), "put_object('c', 'o', ...) failure "
                             "and no ability to reset contents for reupload.")
        finally:
            c.http_connection = orig_conn


class TestLogging(MockHttpTest):
    """
    Make sure all the lines in http_log are covered.
    """

    def setUp(self):
        super(TestLogging, self).setUp()
        self.swiftclient_logger = logging.getLogger("swiftclient")
        self.log_level = self.swiftclient_logger.getEffectiveLevel()
        self.swiftclient_logger.setLevel(logging.INFO)

    def tearDown(self):
        self.swiftclient_logger.setLevel(self.log_level)
        super(TestLogging, self).tearDown()

    def test_put_ok(self):
        c.http_connection = self.fake_http_connection(200)
        args = ('http://www.test.com', 'asdf', 'asdf', 'asdf', 'asdf')
        value = c.put_object(*args)
        self.assertTrue(isinstance(value, basestring))

    def test_head_error(self):
        c.http_connection = self.fake_http_connection(500)
        self.assertRaises(c.ClientException, c.head_object,
                          'http://www.test.com', 'asdf', 'asdf', 'asdf')

    def test_get_error(self):
        body = 'c' * 65
        conn = self.fake_http_connection(
            404, body=body)('http://www.test.com/')
        request_args = {}

        def fake_request(method, url, body=None, headers=None):
            request_args['method'] = method
            request_args['url'] = url
            request_args['body'] = body
            request_args['headers'] = headers
            return
        conn[1].request = fake_request
        headers = {'Range': 'bytes=1-2'}
        self.assertRaises(
            c.ClientException,
            c.get_object,
            'url_is_irrelevant', 'TOKEN', 'container', 'object',
            http_conn=conn, headers=headers)


class TestCloseConnection(MockHttpTest):

    def test_close_none(self):
        c.http_connection = self.fake_http_connection(200)
        conn = c.Connection('http://www.test.com', 'asdf', 'asdf')
        self.assertEqual(conn.http_conn, None)
        conn.close()
        self.assertEqual(conn.http_conn, None)

    def test_close_ok(self):
        url = 'http://www.test.com'
        c.http_connection = self.fake_http_connection(200)
        conn = c.Connection(url, 'asdf', 'asdf')
        self.assertEqual(conn.http_conn, None)

        conn.http_conn = c.http_connection(url)
        self.assertEqual(type(conn.http_conn), tuple)
        self.assertEqual(len(conn.http_conn), 2)
        http_conn_obj = conn.http_conn[1]
        self.assertEqual(http_conn_obj.isclosed(), False)
        conn.close()
        self.assertEqual(http_conn_obj.isclosed(), True)
        self.assertEqual(conn.http_conn, None)


if __name__ == '__main__':
    testtools.main()
