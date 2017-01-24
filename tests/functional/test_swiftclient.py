# Copyright (c) 2014 Christian Schwede <christian.schwede@enovance.com>
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

import os
import unittest
import time
from io import BytesIO

from six.moves import configparser

import swiftclient


class TestFunctional(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestFunctional, self).__init__(*args, **kwargs)
        self.skip_tests = False
        self._get_config()

        self.test_data = b'42' * 10
        self.etag = '2704306ec982238d85d4b235c925d58e'

        self.containername = "functional-tests-container-%s" % int(time.time())
        self.containername_2 = self.containername + '_second'
        self.containername_3 = self.containername + '_third'
        self.objectname = "functional-tests-object-%s" % int(time.time())
        self.objectname_2 = self.objectname + '_second'

    def _get_config(self):
        config_file = os.environ.get('SWIFT_TEST_CONFIG_FILE',
                                     '/etc/swift/test.conf')
        config = configparser.ConfigParser({'auth_version': '1'})
        config.read(config_file)
        self.config = config
        if config.has_section('func_test'):
            auth_host = config.get('func_test', 'auth_host')
            auth_port = config.getint('func_test', 'auth_port')
            auth_ssl = config.getboolean('func_test', 'auth_ssl')
            auth_prefix = config.get('func_test', 'auth_prefix')
            self.auth_version = config.get('func_test', 'auth_version')
            try:
                self.account_username = config.get('func_test',
                                                   'account_username')
            except configparser.NoOptionError:
                account = config.get('func_test', 'account')
                username = config.get('func_test', 'username')
                self.account_username = "%s:%s" % (account, username)
            self.password = config.get('func_test', 'password')
            self.auth_url = ""
            if auth_ssl:
                self.auth_url += "https://"
            else:
                self.auth_url += "http://"
            self.auth_url += "%s:%s%s" % (auth_host, auth_port, auth_prefix)
            if self.auth_version == "1":
                self.auth_url += 'v1.0'

        else:
            self.skip_tests = True

    def _get_connection(self):
        """
        Subclasses may override to use different connection setup
        """
        return swiftclient.Connection(
            self.auth_url, self.account_username, self.password,
            auth_version=self.auth_version)

    def setUp(self):
        super(TestFunctional, self).setUp()
        if self.skip_tests:
            self.skipTest('SKIPPING FUNCTIONAL TESTS DUE TO NO CONFIG')

        self.conn = self._get_connection()
        self.conn.put_container(self.containername)
        self.conn.put_container(self.containername_2)
        self.conn.put_object(
            self.containername, self.objectname, self.test_data)
        self.conn.put_object(
            self.containername, self.objectname_2, self.test_data)

    def tearDown(self):
        super(TestFunctional, self).tearDown()
        for obj in [self.objectname, self.objectname_2]:
            try:
                self.conn.delete_object(self.containername, obj)
            except swiftclient.ClientException:
                pass

        for container in [self.containername,
                          self.containername_2,
                          self.containername_3,
                          self.containername + '_segments']:
            try:
                self.conn.delete_container(container)
            except swiftclient.ClientException:
                pass

    def _check_account_headers(self, headers):
        headers_to_check = [
            'content-length',
            'x-account-object-count',
            'x-timestamp',
            'x-trans-id',
            'date',
            'x-account-bytes-used',
            'x-account-container-count',
            'content-type',
            'accept-ranges',
        ]
        for h in headers_to_check:
            self.assertIn(h, headers)
            self.assertTrue(headers[h])

    def test_stat_account(self):
        headers = self.conn.head_account()
        self._check_account_headers(headers)

    def test_list_account(self):
        headers, containers = self.conn.get_account()
        self._check_account_headers(headers)

        self.assertTrue(len(containers))
        test_container = [c
                          for c in containers
                          if c.get('name') == self.containername][0]
        self.assertTrue(test_container.get('bytes') >= 0)
        self.assertTrue(test_container.get('count') >= 0)

        # Check if list limit is working
        headers, containers = self.conn.get_account(limit=1)
        self.assertEqual(1, len(containers))

        # Check full listing
        headers, containers = self.conn.get_account(limit=1, full_listing=True)
        self.assertTrue(len(containers) >= 2)  # there might be more containers

        # Test marker
        headers, containers = self.conn.get_account(marker=self.containername)
        self.assertTrue(len(containers) >= 1)
        self.assertEqual(self.containername_2, containers[0].get('name'))

    def _check_container_headers(self, headers):
        self.assertTrue(headers.get('content-length'))
        self.assertTrue(headers.get('x-container-object-count'))
        self.assertTrue(headers.get('x-timestamp'))
        self.assertTrue(headers.get('x-trans-id'))
        self.assertTrue(headers.get('date'))
        self.assertTrue(headers.get('x-container-bytes-used'))
        self.assertTrue(headers.get('x-container-object-count'))
        self.assertTrue(headers.get('content-type'))
        self.assertTrue(headers.get('accept-ranges'))

    def test_stat_container(self):
        headers = self.conn.head_container(self.containername)
        self._check_container_headers(headers)

    def test_list_container(self):
        headers, objects = self.conn.get_container(self.containername)
        self._check_container_headers(headers)
        self.assertTrue(len(objects))
        test_object = [o
                       for o in objects
                       if o.get('name') == self.objectname][0]
        self.assertEqual(len(self.test_data), test_object.get('bytes'))
        self.assertEqual(self.etag, test_object.get('hash'))
        self.assertEqual('application/octet-stream',
                         test_object.get('content_type'))

        # Check if list limit is working
        headers, objects = self.conn.get_container(self.containername, limit=1)
        self.assertEqual(1, len(objects))

        # Check full listing
        headers, objects = self.conn.get_container(
            self.containername, limit=1, full_listing=True)
        self.assertEqual(2, len(objects))

        # Test marker
        headers, objects = self.conn.get_container(
            self.containername, marker=self.objectname)
        self.assertEqual(1, len(objects))
        self.assertEqual(self.objectname_2, objects[0].get('name'))

    def test_create_container(self):
        self.conn.put_container(self.containername_3)
        self.assertTrue(self.conn.head_container(self.containername_3))

    def test_delete(self):
        self.conn.delete_object(self.containername, self.objectname)
        self.conn.delete_object(self.containername, self.objectname_2)
        self.conn.delete_container(self.containername)

        # Container HEAD will raise an exception if container doesn't exist
        # which is only possible if previous requests succeeded
        self.assertRaises(
            swiftclient.ClientException,
            self.conn.head_container,
            self.containername)

    def test_upload_object(self):
        # Object with content from string
        self.conn.put_object(
            self.containername, self.objectname, contents=self.test_data)
        hdrs = self.conn.head_object(self.containername, self.objectname)
        self.assertEqual(str(len(self.test_data)),
                         hdrs.get('content-length'))
        self.assertEqual(self.etag, hdrs.get('etag'))
        self.assertEqual('application/octet-stream',
                         hdrs.get('content-type'))

        # Same but with content_type
        self.conn.put_object(
            self.containername, self.objectname,
            content_type='text/plain', contents=self.test_data)
        hdrs = self.conn.head_object(self.containername, self.objectname)
        self.assertEqual(str(len(self.test_data)),
                         hdrs.get('content-length'))
        self.assertEqual(self.etag, hdrs.get('etag'))
        self.assertEqual('text/plain',
                         hdrs.get('content-type'))

        # Same but with content-type in headers
        self.conn.put_object(
            self.containername, self.objectname,
            headers={'Content-Type': 'text/plain'}, contents=self.test_data)
        hdrs = self.conn.head_object(self.containername, self.objectname)
        self.assertEqual(str(len(self.test_data)),
                         hdrs.get('content-length'))
        self.assertEqual(self.etag, hdrs.get('etag'))
        self.assertEqual('text/plain',
                         hdrs.get('content-type'))

        # content_type rewrites content-type in headers
        self.conn.put_object(
            self.containername, self.objectname,
            content_type='image/jpeg',
            headers={'Content-Type': 'text/plain'}, contents=self.test_data)
        hdrs = self.conn.head_object(self.containername, self.objectname)
        self.assertEqual(str(len(self.test_data)),
                         hdrs.get('content-length'))
        self.assertEqual(self.etag, hdrs.get('etag'))
        self.assertEqual('image/jpeg',
                         hdrs.get('content-type'))

        # Same but with content-length
        self.conn.put_object(
            self.containername, self.objectname,
            contents=self.test_data, content_length=len(self.test_data))
        hdrs = self.conn.head_object(self.containername, self.objectname)
        self.assertEqual(str(len(self.test_data)),
                         hdrs.get('content-length'))
        self.assertEqual(self.etag, hdrs.get('etag'))
        self.assertEqual('application/octet-stream', hdrs.get('content-type'))

        # Content from File-like object
        fileobj = BytesIO(self.test_data)
        self.conn.put_object(
            self.containername, self.objectname, contents=fileobj)
        hdrs = self.conn.head_object(self.containername, self.objectname)
        self.assertEqual(str(len(self.test_data)),
                         hdrs.get('content-length'))
        self.assertEqual(self.etag, hdrs.get('etag'))
        self.assertEqual('application/octet-stream', hdrs.get('content-type'))

        # Content from File-like object, but read in chunks
        fileobj = BytesIO(self.test_data)
        self.conn.put_object(
            self.containername, self.objectname,
            contents=fileobj, content_length=len(self.test_data),
            chunk_size=10)
        hdrs = self.conn.head_object(self.containername, self.objectname)
        self.assertEqual(str(len(self.test_data)),
                         hdrs.get('content-length'))
        self.assertEqual(self.etag, hdrs.get('etag'))
        self.assertEqual('application/octet-stream', hdrs.get('content-type'))

        # Wrong etag arg, should raise an exception
        self.assertRaises(
            swiftclient.ClientException,
            self.conn.put_object,
            self.containername, self.objectname,
            contents=self.test_data, etag='invalid')

    def test_download_object(self):
        # Download whole object
        hdrs, body = self.conn.get_object(self.containername, self.objectname)
        self.assertEqual(self.test_data, body)

        # Download in chunks, should return a generator
        hdrs, body = self.conn.get_object(
            self.containername, self.objectname,
            resp_chunk_size=10)
        downloaded_contents = b''
        while True:
            try:
                chunk = next(body)
            except StopIteration:
                break
            downloaded_contents += chunk
        self.assertEqual(self.test_data, downloaded_contents)

        # Download in chunks, should also work with read
        hdrs, body = self.conn.get_object(
            self.containername, self.objectname,
            resp_chunk_size=10)
        num_bytes = 5
        downloaded_contents = body.read(num_bytes)
        self.assertEqual(num_bytes, len(downloaded_contents))
        downloaded_contents += body.read()
        self.assertEqual(self.test_data, downloaded_contents)

    def test_put_object_using_generator(self):
        # verify that put using a generator yielding empty strings does not
        # cause connection to be closed
        def data():
            yield b"should"
            yield b""
            yield b" tolerate"
            yield b""
            yield b" empty chunks"

        self.conn.put_object(
            self.containername, self.objectname, data())
        hdrs, body = self.conn.get_object(self.containername, self.objectname)
        self.assertEqual(b"should tolerate empty chunks", body)

    def test_download_object_retry_chunked(self):
        resp_chunk_size = 2
        hdrs, body = self.conn.get_object(self.containername,
                                          self.objectname,
                                          resp_chunk_size=resp_chunk_size)
        data = next(body)
        self.assertEqual(self.test_data[:resp_chunk_size], data)
        self.assertTrue(1, self.conn.attempts)
        for chunk in body.resp:
            # Flush remaining data from underlying response
            # (simulate a dropped connection)
            pass
        # Trigger the retry
        for chunk in body:
            data += chunk
        self.assertEqual(self.test_data, data)
        self.assertEqual(2, self.conn.attempts)

    def test_download_object_retry_chunked_auth_failure(self):
        resp_chunk_size = 2
        self.conn.token = 'invalid'
        hdrs, body = self.conn.get_object(self.containername,
                                          self.objectname,
                                          resp_chunk_size=resp_chunk_size)
        self.assertEqual(2, self.conn.attempts)
        for chunk in body.resp:
            # Flush remaining data from underlying response
            # (simulate a dropped connection)
            pass

        self.conn.token = 'invalid'
        data = next(body)
        self.assertEqual(4, self.conn.attempts)

        for chunk in body:
            data += chunk

        self.assertEqual(self.test_data, data)
        self.assertEqual(4, self.conn.attempts)

    def test_download_object_non_chunked(self):
        hdrs, body = self.conn.get_object(self.containername, self.objectname)
        data = body
        self.assertEqual(self.test_data, data)
        self.assertTrue(1, self.conn.attempts)

        hdrs, body = self.conn.get_object(self.containername, self.objectname,
                                          resp_chunk_size=0)
        data = body
        self.assertEqual(self.test_data, data)
        self.assertTrue(1, self.conn.attempts)

    def test_post_account(self):
        self.conn.post_account({'x-account-meta-data': 'Something'})
        headers = self.conn.head_account()
        self.assertEqual('Something', headers.get('x-account-meta-data'))

    def test_post_container(self):
        self.conn.post_container(
            self.containername, {'x-container-meta-color': 'Something'})

        headers = self.conn.head_container(self.containername)
        self.assertEqual('Something', headers.get('x-container-meta-color'))

    def test_post_object(self):
        self.conn.post_object(self.containername,
                              self.objectname,
                              {'x-object-meta-color': 'Something',
                               'x-object-meta-uni': b'\xd8\xaa'.decode('utf8'),
                               'x-object-meta-int': 123,
                               'x-object-meta-float': 45.67,
                               'x-object-meta-bool': False})

        headers = self.conn.head_object(self.containername, self.objectname)
        self.assertEqual('Something', headers.get('x-object-meta-color'))
        self.assertEqual(b'\xd8\xaa'.decode('utf-8'),
                         headers.get('x-object-meta-uni'))
        self.assertEqual('123', headers.get('x-object-meta-int'))
        self.assertEqual('45.67', headers.get('x-object-meta-float'))
        self.assertEqual('False', headers.get('x-object-meta-bool'))

    def test_copy_object(self):
        self.conn.put_object(
            self.containername, self.objectname, self.test_data)
        self.conn.copy_object(self.containername,
                              self.objectname,
                              headers={'x-object-meta-color': 'Something'})

        headers = self.conn.head_object(self.containername, self.objectname)
        self.assertEqual('Something', headers.get('x-object-meta-color'))

        self.conn.copy_object(self.containername,
                              self.objectname,
                              headers={'x-object-meta-taste': 'Second'})

        headers = self.conn.head_object(self.containername, self.objectname)
        self.assertEqual('Something', headers.get('x-object-meta-color'))
        self.assertEqual('Second', headers.get('x-object-meta-taste'))

        destination = "/%s/%s" % (self.containername, self.objectname_2)
        self.conn.copy_object(self.containername,
                              self.objectname,
                              destination,
                              headers={'x-object-meta-taste': 'Second'})
        headers, data = self.conn.get_object(self.containername,
                                             self.objectname_2)
        self.assertEqual(self.test_data, data)
        self.assertEqual('Something', headers.get('x-object-meta-color'))
        self.assertEqual('Second', headers.get('x-object-meta-taste'))

        destination = "/%s/%s" % (self.containername, self.objectname_2)
        self.conn.copy_object(self.containername,
                              self.objectname,
                              destination,
                              headers={'x-object-meta-color': 'Else'},
                              fresh_metadata=True)

        headers = self.conn.head_object(self.containername, self.objectname_2)
        self.assertEqual('Else', headers.get('x-object-meta-color'))
        self.assertIsNone(headers.get('x-object-meta-taste'))

    def test_get_capabilities(self):
        resp = self.conn.get_capabilities()
        self.assertTrue(resp.get('swift'))


class TestUsingKeystone(TestFunctional):
    """
    Repeat tests using os_options parameter to Connection.
    """

    def _get_connection(self):
        account = username = password = None
        if self.auth_version not in ('2', '3'):
            self.skipTest('SKIPPING KEYSTONE-SPECIFIC FUNCTIONAL TESTS')
        try:
            account = self.config.get('func_test', 'account')
            username = self.config.get('func_test', 'username')
            password = self.config.get('func_test', 'password')
        except Exception:
            self.skipTest('SKIPPING KEYSTONE-SPECIFIC FUNCTIONAL TESTS' +
                          ' - NO CONFIG')
        os_options = {'tenant_name': account}
        return swiftclient.Connection(
            self.auth_url, username, password, auth_version=self.auth_version,
            os_options=os_options)

    def setUp(self):
        super(TestUsingKeystone, self).setUp()


class TestUsingKeystoneV3(TestFunctional):
    """
    Repeat tests using a keystone user with domain specified.
    """

    def _get_connection(self):
        account = username = password = project_domain = user_domain = None
        if self.auth_version != '3':
            self.skipTest('SKIPPING KEYSTONE-V3-SPECIFIC FUNCTIONAL TESTS')
        try:
            account = self.config.get('func_test', 'account4')
            username = self.config.get('func_test', 'username4')
            user_domain = self.config.get('func_test', 'domain4')
            project_domain = self.config.get('func_test', 'domain4')
            password = self.config.get('func_test', 'password4')
        except Exception:
            self.skipTest('SKIPPING KEYSTONE-V3-SPECIFIC FUNCTIONAL TESTS' +
                          ' - NO CONFIG')

        os_options = {'project_name': account,
                      'project_domain_name': project_domain,
                      'user_domain_name': user_domain}
        return swiftclient.Connection(self.auth_url, username, password,
                                      auth_version=self.auth_version,
                                      os_options=os_options)

    def setUp(self):
        super(TestUsingKeystoneV3, self).setUp()
