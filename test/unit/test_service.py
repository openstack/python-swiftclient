# Copyright (c) 2014 OpenStack Foundation
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

import builtins
import contextlib
import io
import os
import tempfile
import unittest
import time
import json
from io import BytesIO
from unittest import mock

from concurrent.futures import Future
from hashlib import md5
from queue import Queue, Empty as QueueEmptyError
from time import sleep

import swiftclient
import swiftclient.utils as utils
from swiftclient.client import Connection, ClientException
from swiftclient.service import (
    SwiftService, SwiftError, SwiftUploadObject, SwiftDeleteObject
)

from test.unit import utils as test_utils


clean_os_environ = {}
environ_prefixes = ('ST_', 'OS_')
for key in os.environ:
    if any(key.startswith(m) for m in environ_prefixes):
        clean_os_environ[key] = ''


class TestSwiftPostObject(unittest.TestCase):

    def setUp(self):
        super(TestSwiftPostObject, self).setUp()
        self.spo = swiftclient.service.SwiftPostObject

    def test_create(self):
        spo = self.spo('obj_name')

        self.assertEqual(spo.object_name, 'obj_name')
        self.assertIsNone(spo.options)

    def test_create_with_invalid_name(self):
        # empty strings are not allowed as names
        self.assertRaises(SwiftError, self.spo, '')

        # names cannot be anything but strings
        self.assertRaises(SwiftError, self.spo, 1)


class TestSwiftCopyObject(unittest.TestCase):

    def setUp(self):
        super(TestSwiftCopyObject, self).setUp()
        self.sco = swiftclient.service.SwiftCopyObject

    def test_create(self):
        sco = self.sco('obj_name')

        self.assertEqual(sco.object_name, 'obj_name')
        self.assertIsNone(sco.destination)
        self.assertFalse(sco.fresh_metadata)

        sco = self.sco('obj_name',
                       {'destination': '/dest', 'fresh_metadata': True})

        self.assertEqual(sco.object_name, 'obj_name')
        self.assertEqual(sco.destination, '/dest/obj_name')
        self.assertTrue(sco.fresh_metadata)

        sco = self.sco('obj_name',
                       {'destination': '/dest/new_obj/a',
                        'fresh_metadata': False})

        self.assertEqual(sco.object_name, 'obj_name')
        self.assertEqual(sco.destination, '/dest/new_obj/a')
        self.assertFalse(sco.fresh_metadata)

    def test_create_with_invalid_name(self):
        # empty strings are not allowed as names
        self.assertRaises(SwiftError, self.sco, '')

        # names cannot be anything but strings
        self.assertRaises(SwiftError, self.sco, 1)


class TestSwiftReader(unittest.TestCase):

    def setUp(self):
        super(TestSwiftReader, self).setUp()
        self.sr = swiftclient.service._SwiftReader
        self.md5_type = type(md5())

    def test_create(self):
        sr = self.sr('path', 'body', {})

        self.assertEqual(sr._path, 'path')
        self.assertEqual(sr._body, 'body')
        self.assertIsNone(sr._content_length)
        self.assertFalse(sr._expected_md5)

        self.assertIsNone(sr._actual_md5)

    def test_create_with_large_object_headers(self):
        # md5 should not be initialized if large object headers are present
        sr = self.sr('path', 'body', {'x-object-manifest': 'test',
                                      'etag': '"%s"' % ('0' * 32)})
        self.assertEqual(sr._path, 'path')
        self.assertEqual(sr._body, 'body')
        self.assertIsNone(sr._content_length)
        self.assertFalse(sr._expected_md5)
        self.assertIsNone(sr._actual_md5)

        sr = self.sr('path', 'body', {'x-static-large-object': 'test',
                                      'etag': '"%s"' % ('0' * 32)})
        self.assertEqual(sr._path, 'path')
        self.assertEqual(sr._body, 'body')
        self.assertIsNone(sr._content_length)
        self.assertFalse(sr._expected_md5)
        self.assertIsNone(sr._actual_md5)

    def test_create_with_content_range_header(self):
        # md5 should not be initialized if large object headers are present
        sr = self.sr('path', 'body', {'content-range': 'bytes 0-3/10',
                                      'etag': '"%s"' % ('0' * 32)})
        self.assertEqual(sr._path, 'path')
        self.assertEqual(sr._body, 'body')
        self.assertIsNone(sr._content_length)
        self.assertFalse(sr._expected_md5)
        self.assertIsNone(sr._actual_md5)

    def test_create_with_ignore_checksum(self):
        # md5 should not be initialized if checksum is False
        sr = self.sr('path', 'body', {}, False)
        self.assertEqual(sr._path, 'path')
        self.assertEqual(sr._body, 'body')
        self.assertIsNone(sr._content_length)
        self.assertFalse(sr._expected_md5)
        self.assertIsNone(sr._actual_md5)

    def test_create_with_content_length(self):
        sr = self.sr('path', 'body', {'content-length': 5})

        self.assertEqual(sr._path, 'path')
        self.assertEqual(sr._body, 'body')
        self.assertEqual(sr._content_length, 5)
        self.assertFalse(sr._expected_md5)

        self.assertIsNone(sr._actual_md5)

        # Check Contentlength raises error if it isn't an integer
        self.assertRaises(SwiftError, self.sr, 'path', 'body',
                          {'content-length': 'notanint'})

    def test_iterator_usage(self):
        def _consume(sr):
            for _ in sr:
                pass

        sr = self.sr('path', BytesIO(b'body'), {})
        _consume(sr)

        # Check error is raised if expected etag doesn't match calculated md5.
        # md5 for a SwiftReader that has done nothing is
        # d41d8cd98f00b204e9800998ecf8427e  i.e md5 of nothing
        sr = self.sr('path', BytesIO(b'body'),
                     {'etag': md5(b'doesntmatch').hexdigest()})
        self.assertRaises(SwiftError, _consume, sr)

        sr = self.sr('path', BytesIO(b'body'),
                     {'etag': md5(b'body').hexdigest()})
        _consume(sr)

        # Should still work if etag was quoted
        sr = self.sr('path', BytesIO(b'body'),
                     {'etag': '"%s"' % md5(b'body').hexdigest()})
        _consume(sr)

        # Check error is raised if SwiftReader doesn't read the same length
        # as the content length it is created with
        sr = self.sr('path', BytesIO(b'body'), {'content-length': 5})
        self.assertRaises(SwiftError, _consume, sr)

        sr = self.sr('path', BytesIO(b'body'), {'content-length': 4})
        _consume(sr)

        # Check that the iterator generates expected length and etag values
        sr = self.sr('path', ['abc'.encode()] * 3,
                     {'content-length': 9,
                      'etag': md5('abc'.encode() * 3).hexdigest()})
        _consume(sr)
        self.assertEqual(sr._actual_read, 9)
        self.assertEqual(sr._actual_md5.hexdigest(),
                         md5('abc'.encode() * 3).hexdigest())


class _TestServiceBase(unittest.TestCase):
    def _get_mock_connection(self, attempts=2):
        m = mock.Mock(spec=Connection)
        type(m).attempts = mock.PropertyMock(return_value=attempts)
        type(m).auth_end_time = mock.PropertyMock(return_value=4)
        return m

    def _get_queue(self, q):
        # Instead of blocking pull items straight from the queue.
        # expects at least one item otherwise the test will fail.
        try:
            return q.get_nowait()
        except QueueEmptyError:
            self.fail('Expected item in queue but found none')

    def _get_expected(self, update=None):
        expected = self.expected.copy()
        if update:
            expected.update(update)

        return expected


class TestServiceDelete(_TestServiceBase):
    def setUp(self):
        super(TestServiceDelete, self).setUp()
        self.opts = {'leave_segments': False, 'yes_all': False}
        self.exc = Exception('test_exc')
        # Base response to be copied and updated to matched the expected
        # response for each test
        self.expected = {
            'action': None,   # Should be string in the form delete_XX
            'container': 'test_c',
            'object': 'test_o',
            'attempts': 2,
            'response_dict': {},
            'success': None   # Should be a bool
        }

    def test_delete_segment(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        expected_r = self._get_expected({
            'action': 'delete_segment',
            'object': 'test_s',
            'success': True,
        })

        r = SwiftService._delete_segment(mock_conn, 'test_c', 'test_s', mock_q)

        mock_conn.delete_object.assert_called_once_with(
            'test_c', 'test_s', response_dict={}
        )
        self.assertEqual(expected_r, r)
        self.assertEqual(expected_r, self._get_queue(mock_q))

    def test_delete_segment_exception(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        mock_conn.delete_object = mock.Mock(side_effect=self.exc)
        expected_r = self._get_expected({
            'action': 'delete_segment',
            'object': 'test_s',
            'success': False,
            'error': self.exc,
            'traceback': mock.ANY,
            'error_timestamp': mock.ANY
        })

        before = time.time()
        r = SwiftService._delete_segment(mock_conn, 'test_c', 'test_s', mock_q)
        after = time.time()

        mock_conn.delete_object.assert_called_once_with(
            'test_c', 'test_s', response_dict={}
        )
        self.assertEqual(expected_r, r)
        self.assertEqual(expected_r, self._get_queue(mock_q))
        self.assertGreaterEqual(r['error_timestamp'], before)
        self.assertLessEqual(r['error_timestamp'], after)
        self.assertIn('Traceback', r['traceback'])

    def test_delete_object(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        mock_conn.head_object = mock.Mock(return_value={})
        expected_r = self._get_expected({
            'action': 'delete_object',
            'success': True
        })

        s = SwiftService()
        r = s._delete_object(mock_conn, 'test_c', 'test_o', self.opts, mock_q)

        mock_conn.head_object.assert_called_once_with(
            'test_c', 'test_o', query_string='symlink=get', headers={})
        mock_conn.delete_object.assert_called_once_with(
            'test_c', 'test_o', query_string='', response_dict={},
            headers={}
        )
        self.assertEqual(expected_r, r)

    @mock.patch('swiftclient.service.Connection')
    def test_delete_object_version(self, mock_connection_class):
        mock_conn = mock_connection_class.return_value
        mock_conn.url = 'http://saio/v1/AUTH_test'
        mock_conn.attempts = 0
        mock_conn.head_object.return_value = {}
        mock_conn.delete_object.return_value = {}
        expected = {
            'action': 'delete_object',
            'attempts': 0,
            'container': 'c',
            'object': 'o',
            'response_dict': {},
            'success': True}
        with SwiftService() as swift:
            delete_results = swift.delete(
                container='c', objects='o', options={
                    'version_id': '234567.8'})
            for delete_result in delete_results:
                self.assertEqual(delete_result, expected)
        self.assertEqual(mock_conn.mock_calls, [
            mock.call.head_object('c', 'o', headers={},
                                  query_string='symlink=get'),
            mock.call.delete_object('c', 'o', headers={},
                                    query_string='version-id=234567.8',
                                    response_dict={}),
        ])

    def test_delete_object_with_headers(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        mock_conn.head_object = mock.Mock(return_value={})
        expected_r = self._get_expected({
            'action': 'delete_object',
            'success': True
        })
        opt_c = self.opts.copy()
        opt_c['header'] = ['Skip-Middleware: Test']

        s = SwiftService()
        r = s._delete_object(mock_conn, 'test_c', 'test_o', opt_c, mock_q)

        mock_conn.head_object.assert_called_once_with(
            'test_c', 'test_o', headers={'Skip-Middleware': 'Test'},
            query_string='symlink=get')
        mock_conn.delete_object.assert_called_once_with(
            'test_c', 'test_o', query_string='', response_dict={},
            headers={'Skip-Middleware': 'Test'}
        )
        self.assertEqual(expected_r, r)

    def test_delete_object_exception(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        mock_conn.delete_object = mock.Mock(side_effect=self.exc)
        expected_r = self._get_expected({
            'action': 'delete_object',
            'success': False,
            'error': self.exc,
            'traceback': mock.ANY,
            'error_timestamp': mock.ANY
        })
        # _delete_object doesn't populate attempts or response dict if it hits
        # an error. This may not be the correct behaviour.
        del expected_r['response_dict'], expected_r['attempts']

        before = time.time()
        s = SwiftService()
        r = s._delete_object(mock_conn, 'test_c', 'test_o', self.opts, mock_q)
        after = time.time()

        mock_conn.head_object.assert_called_once_with(
            'test_c', 'test_o', query_string='symlink=get', headers={})
        mock_conn.delete_object.assert_called_once_with(
            'test_c', 'test_o', query_string='', response_dict={},
            headers={}
        )
        self.assertEqual(expected_r, r)
        self.assertGreaterEqual(r['error_timestamp'], before)
        self.assertLessEqual(r['error_timestamp'], after)
        self.assertIn('Traceback', r['traceback'])

    def test_delete_object_slo_support(self):
        # If SLO headers are present the delete call should include an
        # additional query string to cause the right delete server side
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        mock_conn.head_object = mock.Mock(
            return_value={'x-static-large-object': True}
        )
        expected_r = self._get_expected({
            'action': 'delete_object',
            'success': True
        })

        s = SwiftService()
        r = s._delete_object(mock_conn, 'test_c', 'test_o', self.opts, mock_q)

        mock_conn.head_object.assert_called_once_with(
            'test_c', 'test_o', query_string='symlink=get', headers={})
        mock_conn.delete_object.assert_called_once_with(
            'test_c', 'test_o',
            query_string='multipart-manifest=delete',
            response_dict={},
            headers={}
        )
        self.assertEqual(expected_r, r)

    def test_delete_object_dlo_support(self):
        mock_q = Queue()
        s = SwiftService()
        mock_conn = self._get_mock_connection()
        expected_r = self._get_expected({
            'action': 'delete_object',
            'success': True,
            'dlo_segments_deleted': True
        })
        # A DLO object is determined in _delete_object by heading the object
        # and checking for the existence of a x-object-manifest header.
        # Mock that here.
        mock_conn.head_object = mock.Mock(
            return_value={'x-object-manifest': 'manifest_c/manifest_p'}
        )
        mock_conn.get_container = mock.Mock(
            side_effect=[(None, [{'name': 'test_seg_1'},
                                 {'name': 'test_seg_2'}]),
                         (None, {})]
        )

        def get_mock_list_conn(options):
            return mock_conn

        with mock.patch('swiftclient.service.get_conn', get_mock_list_conn):
            r = s._delete_object(
                mock_conn, 'test_c', 'test_o', self.opts, mock_q
            )

        self.assertEqual(expected_r, r)
        expected = [
            mock.call('test_c', 'test_o', query_string='', response_dict={},
                      headers={}),
            mock.call('manifest_c', 'test_seg_1', response_dict={}),
            mock.call('manifest_c', 'test_seg_2', response_dict={})]
        mock_conn.delete_object.assert_has_calls(expected, any_order=True)

    def test_delete_empty_container(self):
        mock_conn = self._get_mock_connection()
        expected_r = self._get_expected({
            'action': 'delete_container',
            'success': True,
            'object': None
        })

        r = SwiftService._delete_empty_container(mock_conn, 'test_c',
                                                 self.opts)

        mock_conn.delete_container.assert_called_once_with(
            'test_c', response_dict={}, headers={}
        )
        self.assertEqual(expected_r, r)

    def test_delete_empty_container_with_headers(self):
        mock_conn = self._get_mock_connection()
        expected_r = self._get_expected({
            'action': 'delete_container',
            'success': True,
            'object': None
        })
        opt_c = self.opts.copy()
        opt_c['header'] = ['Skip-Middleware: Test']

        r = SwiftService._delete_empty_container(mock_conn, 'test_c', opt_c)

        mock_conn.delete_container.assert_called_once_with(
            'test_c', response_dict={}, headers={'Skip-Middleware': 'Test'}
        )
        self.assertEqual(expected_r, r)

    def test_delete_empty_container_exception(self):
        mock_conn = self._get_mock_connection()
        mock_conn.delete_container = mock.Mock(side_effect=self.exc)
        expected_r = self._get_expected({
            'action': 'delete_container',
            'success': False,
            'object': None,
            'error': self.exc,
            'traceback': mock.ANY,
            'error_timestamp': mock.ANY
        })

        before = time.time()
        s = SwiftService()
        r = s._delete_empty_container(mock_conn, 'test_c', {})
        after = time.time()

        mock_conn.delete_container.assert_called_once_with(
            'test_c', response_dict={}, headers={}
        )
        self.assertEqual(expected_r, r)
        self.assertGreaterEqual(r['error_timestamp'], before)
        self.assertLessEqual(r['error_timestamp'], after)
        self.assertIn('Traceback', r['traceback'])

    @mock.patch.object(swiftclient.service.SwiftService, 'capabilities',
                       lambda *a: {'action': 'capabilities',
                                   'timestamp': time.time(),
                                   'success': True,
                                   'capabilities': {
                                       'bulk_delete':
                                       {'max_deletes_per_request': 10}}
                                   })
    def test_bulk_delete_page_size(self):
        # make a list of 100 objects
        obj_list = ['x%02d' % i for i in range(100)]
        errors = []

        # _bulk_delete_page_size uses 2x the number of threads to determine
        # if if there are "many" object to delete or not

        # format is: [(thread_count, expected result), ...]
        obj_threads_exp = [
            (10, 10),  # something small
            (49, 10),  # just under the bounds
            (50, 1),  # cutover point
            (51, 1),  # just over bounds
            (100, 1),  # something big
        ]
        for thread_count, exp in obj_threads_exp:
            s = SwiftService(options={'object_dd_threads': thread_count})
            res = s._bulk_delete_page_size(obj_list)
            if res != exp:
                msg = 'failed for thread_count %d: got %r expected %r' % \
                    (thread_count, res, exp)
                errors.append(msg)
        if errors:
            self.fail('_bulk_delete_page_size() failed\n' + '\n'.join(errors))

    @mock.patch('swiftclient.service.Connection')
    def test_bulk_delete(self, mock_connection_class):
        mock_conn = mock_connection_class.return_value
        mock_conn.attempts = 0
        mock_conn.get_capabilities.return_value = {
            'bulk_delete': {}}
        stub_headers = {}
        stub_resp = []
        mock_conn.post_account.return_value = (
            stub_headers, json.dumps(stub_resp).encode('utf8'))
        obj_list = ['x%02d' % i for i in range(100)]
        expected = [{
            'action': 'bulk_delete',
            'attempts': 0,
            'container': 'c',
            'objects': list(objs),
            'response_dict': {},
            'result': [],
            'success': True,
        } for objs in zip(*[iter(obj_list)] * 10)]
        found_result = []
        with SwiftService(options={'object_dd_threads': 10}) as swift:
            delete_results = swift.delete(container='c', objects=obj_list)
            for delete_result in delete_results:
                found_result.append(delete_result)
        self.assertEqual(sorted(found_result, key=lambda r: r['objects'][0]),
                         expected)

    @mock.patch('swiftclient.service.Connection')
    def test_bulk_delete_versions(self, mock_connection_class):
        mock_conn = mock_connection_class.return_value
        mock_conn.attempts = 0
        mock_conn.get_capabilities.return_value = {
            'bulk_delete': {}}
        mock_conn.head_object.return_value = {}
        stub_headers = {}
        stub_resp = []
        mock_conn.post_account.return_value = (
            stub_headers, json.dumps(stub_resp))
        obj_list = [SwiftDeleteObject('x%02d' % i, options={'version_id': i})
                    for i in range(100)]
        expected = [{
            'action': 'delete_object',
            'attempts': 0,
            'container': 'c',
            'object': obj.object_name,
            'response_dict': {},
            'success': True,
        } for obj in obj_list]
        found_result = []
        with SwiftService(options={'object_dd_threads': 10}) as swift:
            delete_results = swift.delete(container='c', objects=obj_list)
            for delete_result in delete_results:
                found_result.append(delete_result)
        self.assertEqual(sorted(found_result, key=lambda r: r['object']),
                         expected)


class TestSwiftError(unittest.TestCase):

    def test_is_exception(self):
        se = SwiftError(5)
        self.assertIsInstance(se, Exception)

    def test_empty_swifterror_creation(self):
        se = SwiftError(5)

        self.assertEqual(se.value, 5)
        self.assertIsNone(se.container)
        self.assertIsNone(se.obj)
        self.assertIsNone(se.segment)
        self.assertIsNone(se.exception)

        self.assertEqual(str(se), '5')

    def test_swifterror_creation(self):
        test_exc = Exception('test exc')
        se = SwiftError(5, 'con', 'obj', 'seg', test_exc)

        self.assertEqual(se.value, 5)
        self.assertEqual(se.container, 'con')
        self.assertEqual(se.obj, 'obj')
        self.assertEqual(se.segment, 'seg')
        self.assertEqual(se.exception, test_exc)

        self.assertEqual(str(se), '5 container:con object:obj segment:seg')


class TestServiceUtils(unittest.TestCase):

    def setUp(self):
        super(TestServiceUtils, self).setUp()
        with mock.patch.dict(swiftclient.service.environ, clean_os_environ):
            swiftclient.service._default_global_options = \
                swiftclient.service._build_default_global_options()
        self.opts = swiftclient.service._default_global_options.copy()

    def test_process_options_defaults(self):
        # The only actions that should be taken on default options set is
        # to change the auth version to v2.0 and create the os_options dict
        opt_c = self.opts.copy()

        swiftclient.service.process_options(opt_c)

        self.assertIn('os_options', opt_c)
        del opt_c['os_options']
        self.assertEqual(opt_c['auth_version'], '2.0')
        opt_c['auth_version'] = '1.0'

        self.assertEqual(opt_c, self.opts)

    def test_process_options_auth_version(self):
        # auth_version should be set to 2.0
        # if it isn't already set to 3.0
        # and the v1 command line arguments aren't present
        opt_c = self.opts.copy()

        # Check v3 isn't changed
        opt_c['auth_version'] = '3'
        swiftclient.service.process_options(opt_c)
        self.assertEqual(opt_c['auth_version'], '3')

        # Check v1 isn't changed if user, key and auth are set
        opt_c = self.opts.copy()
        opt_c['auth_version'] = '1'
        opt_c['auth'] = True
        opt_c['user'] = True
        opt_c['key'] = True
        swiftclient.service.process_options(opt_c)
        self.assertEqual(opt_c['auth_version'], '1')

    def test_process_options_new_style_args(self):
        # checks new style args are copied to old style
        # when old style don't exist
        opt_c = self.opts.copy()

        opt_c['auth'] = ''
        opt_c['user'] = ''
        opt_c['key'] = ''
        opt_c['os_auth_url'] = 'os_auth'
        opt_c['os_username'] = 'os_user'
        opt_c['os_password'] = 'os_pass'
        swiftclient.service.process_options(opt_c)
        self.assertEqual(opt_c['auth_version'], '2.0')
        self.assertEqual(opt_c['auth'], 'os_auth')
        self.assertEqual(opt_c['user'], 'os_user')
        self.assertEqual(opt_c['key'], 'os_pass')

        # Check old style args are left alone if they exist
        opt_c = self.opts.copy()
        opt_c['auth'] = 'auth'
        opt_c['user'] = 'user'
        opt_c['key'] = 'key'
        opt_c['os_auth_url'] = 'os_auth'
        opt_c['os_username'] = 'os_user'
        opt_c['os_password'] = 'os_pass'
        swiftclient.service.process_options(opt_c)
        self.assertEqual(opt_c['auth_version'], '1.0')
        self.assertEqual(opt_c['auth'], 'auth')
        self.assertEqual(opt_c['user'], 'user')
        self.assertEqual(opt_c['key'], 'key')

    def test_split_headers(self):
        mock_headers = ['color:blue', 'SIZE: large']
        expected = {'Color': 'blue', 'Size': 'large'}

        actual = swiftclient.service.split_headers(mock_headers)
        self.assertEqual(expected, actual)

    def test_split_headers_prefix(self):
        mock_headers = ['color:blue', 'size:large']
        expected = {'Prefix-Color': 'blue', 'Prefix-Size': 'large'}

        actual = swiftclient.service.split_headers(mock_headers, 'prefix-')
        self.assertEqual(expected, actual)

    def test_split_headers_list_of_tuples(self):
        mock_headers = [('color', 'blue'), ('size', 'large')]
        expected = {'Prefix-Color': 'blue', 'Prefix-Size': 'large'}

        actual = swiftclient.service.split_headers(mock_headers, 'prefix-')
        self.assertEqual(expected, actual)

    def test_split_headers_dict(self):
        expected = {'Color': 'blue', 'Size': 'large'}

        actual = swiftclient.service.split_headers(expected)
        self.assertEqual(expected, actual)

    def test_split_headers_error(self):
        self.assertRaises(SwiftError, swiftclient.service.split_headers,
                          ['notvalid'])
        self.assertRaises(SwiftError, swiftclient.service.split_headers,
                          [('also', 'not', 'valid')])


class TestSwiftUploadObject(unittest.TestCase):

    def setUp(self):
        self.suo = swiftclient.service.SwiftUploadObject
        super(TestSwiftUploadObject, self).setUp()

    def test_create_with_string(self):
        suo = self.suo('source')
        self.assertEqual(suo.source, 'source')
        self.assertEqual(suo.object_name, 'source')
        self.assertIsNone(suo.options)

        suo = self.suo('source', 'obj_name')
        self.assertEqual(suo.source, 'source')
        self.assertEqual(suo.object_name, 'obj_name')
        self.assertIsNone(suo.options)

        suo = self.suo('source', 'obj_name', {'opt': '123'})
        self.assertEqual(suo.source, 'source')
        self.assertEqual(suo.object_name, 'obj_name')
        self.assertEqual(suo.options, {'opt': '123'})

    def test_create_with_file(self):
        with tempfile.TemporaryFile() as mock_file:
            # Check error is raised if no object name is provided with a
            # filelike object
            self.assertRaises(SwiftError, self.suo, mock_file)

            # Check that empty strings are invalid object names
            self.assertRaises(SwiftError, self.suo, mock_file, '')

            suo = self.suo(mock_file, 'obj_name')
            self.assertEqual(suo.source, mock_file)
            self.assertEqual(suo.object_name, 'obj_name')
            self.assertIsNone(suo.options)

            suo = self.suo(mock_file, 'obj_name', {'opt': '123'})
            self.assertEqual(suo.source, mock_file)
            self.assertEqual(suo.object_name, 'obj_name')
            self.assertEqual(suo.options, {'opt': '123'})

    def test_create_with_no_source(self):
        suo = self.suo(None, 'obj_name')
        self.assertIsNone(suo.source)
        self.assertEqual(suo.object_name, 'obj_name')
        self.assertIsNone(suo.options)

        # Check error is raised if source is None without an object name
        self.assertRaises(SwiftError, self.suo, None)

    def test_create_with_invalid_source(self):
        # Source can only be None, string or filelike object,
        # check an error is raised with an invalid type.
        self.assertRaises(SwiftError, self.suo, [])


class TestServiceList(_TestServiceBase):
    def setUp(self):
        super(TestServiceList, self).setUp()
        self.opts = {'prefix': None, 'long': False, 'delimiter': ''}
        self.exc = Exception('test_exc')
        # Base response to be copied and updated to matched the expected
        # response for each test
        self.expected = {
            'action': None,   # Should be list_X_part (account or container)
            'container': None,   # Should be a string when listing a container
            'prefix': None,
            'success': None   # Should be a bool
        }

    def test_list_account(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        get_account_returns = [
            (None, [{'name': 'test_c'}]),
            (None, [])
        ]
        mock_conn.get_account = mock.Mock(side_effect=get_account_returns)

        expected_r = self._get_expected({
            'action': 'list_account_part',
            'success': True,
            'listing': [{'name': 'test_c'}],
            'marker': ''
        })

        SwiftService._list_account_job(
            mock_conn, self.opts, mock_q
        )
        self.assertEqual(expected_r, self._get_queue(mock_q))
        self.assertIsNone(self._get_queue(mock_q))

        long_opts = dict(self.opts, **{'long': True})
        mock_conn.head_container = mock.Mock(return_value={'test_m': '1'})
        get_account_returns = [
            (None, [{'name': 'test_c'}]),
            (None, [])
        ]
        mock_conn.get_account = mock.Mock(side_effect=get_account_returns)

        expected_r_long = self._get_expected({
            'action': 'list_account_part',
            'success': True,
            'listing': [{'name': 'test_c', 'meta': {'test_m': '1'}}],
            'marker': '',
        })

        SwiftService._list_account_job(
            mock_conn, long_opts, mock_q
        )
        self.assertEqual(expected_r_long, self._get_queue(mock_q))
        self.assertIsNone(self._get_queue(mock_q))

    def test_list_account_with_headers(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        get_account_returns = [
            (None, [{'name': 'test_c'}]),
            (None, [])
        ]
        mock_conn.get_account = mock.Mock(side_effect=get_account_returns)

        expected_r = self._get_expected({
            'action': 'list_account_part',
            'success': True,
            'listing': [{'name': 'test_c'}],
            'marker': ''
        })
        opt_c = self.opts.copy()
        opt_c['header'] = ['Skip-Middleware: True']
        SwiftService._list_account_job(
            mock_conn, opt_c, mock_q
        )
        self.assertEqual(expected_r, self._get_queue(mock_q))
        self.assertIsNone(self._get_queue(mock_q))
        self.assertEqual(mock_conn.get_account.mock_calls, [
            mock.call(headers={'Skip-Middleware': 'True'}, marker='',
                      prefix=None),
            mock.call(headers={'Skip-Middleware': 'True'}, marker='test_c',
                      prefix=None)])

    def test_list_account_exception(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        mock_conn.get_account = mock.Mock(side_effect=self.exc)
        expected_r = self._get_expected({
            'action': 'list_account_part',
            'success': False,
            'error': self.exc,
            'marker': '',
            'traceback': mock.ANY,
            'error_timestamp': mock.ANY
        })

        SwiftService._list_account_job(
            mock_conn, self.opts, mock_q)

        mock_conn.get_account.assert_called_once_with(
            marker='', prefix=None, headers={}
        )
        self.assertEqual(expected_r, self._get_queue(mock_q))
        self.assertIsNone(self._get_queue(mock_q))

    def test_list_container(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        get_container_returns = [
            (None, [{'name': 'test_o'}]),
            (None, [])
        ]
        mock_conn.get_container = mock.Mock(side_effect=get_container_returns)

        expected_r = self._get_expected({
            'action': 'list_container_part',
            'container': 'test_c',
            'success': True,
            'listing': [{'name': 'test_o'}],
            'marker': ''
        })

        SwiftService._list_container_job(
            mock_conn, 'test_c', self.opts, mock_q
        )
        self.assertEqual(expected_r, self._get_queue(mock_q))
        self.assertIsNone(self._get_queue(mock_q))

        long_opts = dict(self.opts, **{'long': True})
        mock_conn.head_container = mock.Mock(return_value={'test_m': '1'})
        get_container_returns = [
            (None, [{'name': 'test_o'}]),
            (None, [])
        ]
        mock_conn.get_container = mock.Mock(side_effect=get_container_returns)

        expected_r_long = self._get_expected({
            'action': 'list_container_part',
            'container': 'test_c',
            'success': True,
            'listing': [{'name': 'test_o'}],
            'marker': ''
        })

        SwiftService._list_container_job(
            mock_conn, 'test_c', long_opts, mock_q
        )
        self.assertEqual(expected_r_long, self._get_queue(mock_q))
        self.assertIsNone(self._get_queue(mock_q))

    def test_list_container_marker(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()

        get_container_returns = [
            (None, [{'name': 'b'}, {'name': 'c'}]),
            (None, [])
        ]
        mock_get_cont = mock.Mock(side_effect=get_container_returns)
        mock_conn.get_container = mock_get_cont

        expected_r = self._get_expected({
            'action': 'list_container_part',
            'container': 'test_c',
            'success': True,
            'listing': [{'name': 'b'}, {'name': 'c'}],
            'marker': 'b'
        })

        _opts = self.opts.copy()
        _opts['marker'] = 'b'
        SwiftService._list_container_job(mock_conn, 'test_c', _opts, mock_q)

        # This does not test if the marker is propagated, because we always
        # get the final call to the get_container with the final item 'c',
        # even if marker wasn't set. This test just makes sure the whole
        # stack works in a sane way.
        mock_kw = mock_get_cont.call_args[1]
        self.assertEqual(mock_kw['marker'], 'c')

        # This tests that the lower levels get the marker delivered.
        self.assertEqual(expected_r, self._get_queue(mock_q))

        self.assertIsNone(self._get_queue(mock_q))

    def test_list_container_with_headers(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        get_container_returns = [
            (None, [{'name': 'test_o'}]),
            (None, [])
        ]
        mock_conn.get_container = mock.Mock(side_effect=get_container_returns)

        expected_r = self._get_expected({
            'action': 'list_container_part',
            'container': 'test_c',
            'success': True,
            'listing': [{'name': 'test_o'}],
            'marker': ''
        })

        opt_c = self.opts.copy()
        opt_c['header'] = ['Skip-Middleware: Test']

        SwiftService._list_container_job(
            mock_conn, 'test_c', opt_c, mock_q
        )
        self.assertEqual(expected_r, self._get_queue(mock_q))
        self.assertIsNone(self._get_queue(mock_q))
        self.assertEqual(mock_conn.get_container.mock_calls, [
            mock.call('test_c', headers={'Skip-Middleware': 'Test'},
                      delimiter='', marker='', prefix=None,
                      query_string=None, version_marker=''),
            mock.call('test_c', headers={'Skip-Middleware': 'Test'},
                      delimiter='', marker='test_o', prefix=None,
                      query_string=None, version_marker='')])

    def test_list_container_exception(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        mock_conn.get_container = mock.Mock(side_effect=self.exc)
        expected_r = self._get_expected({
            'action': 'list_container_part',
            'container': 'test_c',
            'success': False,
            'error': self.exc,
            'marker': '',
            'version_marker': '',
            'error_timestamp': mock.ANY,
            'traceback': mock.ANY
        })

        SwiftService._list_container_job(
            mock_conn, 'test_c', self.opts, mock_q
        )

        mock_conn.get_container.assert_called_once_with(
            'test_c', marker='', delimiter='', prefix=None, headers={},
            query_string=None, version_marker='',
        )
        self.assertEqual(expected_r, self._get_queue(mock_q))
        self.assertIsNone(self._get_queue(mock_q))

    @mock.patch('swiftclient.service.Connection')
    def test_list_container_versions(self, mock_connection_class):
        mock_conn = mock_connection_class.return_value
        mock_conn.url = 'http://saio/v1/AUTH_test'
        resp_headers = {}
        items = [{
            "bytes": 9,
            "content_type": "application/octet-stream",
            "hash": "e55cedc11adb39c404b7365f7d6291fa",
            "is_latest": True,
            "last_modified": "2019-11-08T05:00:15.115360",
            "name": "test",
            "version_id": "1573189215.11536"
        }, {
            "bytes": 8,
            "content_type": "application/octet-stream",
            "hash": "70c1db56f301c9e337b0099bd4174b28",
            "is_latest": False,
            "last_modified": "2019-11-08T05:00:14.730240",
            "name": "test",
            "version_id": "1573184903.06720"
        }]
        mock_conn.get_container.side_effect = [
            (resp_headers, items),
            (resp_headers, []),
        ]
        expected = {
            'action': 'list_container_part',
            'container': 'c',
            'listing': items,
            'marker': '',
            'prefix': None,
            'success': True,
        }
        with SwiftService() as swift:
            list_result_gen = swift.list(container='c', options={
                'versions': True})
            self.maxDiff = None
            for result in list_result_gen:
                self.assertEqual(result, expected)
        self.assertEqual(mock_conn.get_container.mock_calls, [
            mock.call('c', delimiter=None, headers={}, marker='',
                      prefix=None, query_string='versions=true',
                      version_marker=''),
            mock.call('c', delimiter=None, headers={}, marker='test',
                      prefix=None, query_string='versions=true',
                      version_marker='1573184903.06720'),
        ])

    @mock.patch('swiftclient.service.get_conn')
    def test_list_queue_size(self, mock_get_conn):
        mock_conn = self._get_mock_connection()
        # Return more results than should fit in the results queue
        get_account_returns = [
            (None, [{'name': 'container1'}]),
            (None, [{'name': 'container2'}]),
            (None, [{'name': 'container3'}]),
            (None, [{'name': 'container4'}]),
            (None, [{'name': 'container5'}]),
            (None, [{'name': 'container6'}]),
            (None, [{'name': 'container7'}]),
            (None, [{'name': 'container8'}]),
            (None, [{'name': 'container9'}]),
            (None, [{'name': 'container10'}]),
            (None, [{'name': 'container11'}]),
            (None, [{'name': 'container12'}]),
            (None, [{'name': 'container13'}]),
            (None, [{'name': 'container14'}]),
            (None, [])
        ]
        mock_conn.get_account = mock.Mock(side_effect=get_account_returns)
        mock_get_conn.return_value = mock_conn

        s = SwiftService(options=self.opts)
        lg = s.list()

        # Start the generator
        first_list_part = next(lg)

        # Wait for the number of calls to get_account to reach our expected
        # value, then let it run some more to make sure the value remains
        # stable
        count = mock_conn.get_account.call_count
        stable = 0
        while mock_conn.get_account.call_count != count or stable < 5:
            if mock_conn.get_account.call_count == count:
                stable += 1
            else:
                count = mock_conn.get_account.call_count
                stable = 0
            # The test requires a small sleep to allow other threads to
            # execute - in this mocked environment we assume that if the call
            # count to get_account has not changed in 0.25s then no more calls
            # will be made.
            sleep(0.05)

        stable_get_account_call_count = mock_conn.get_account.call_count

        # Collect all remaining results from the generator
        list_results = [first_list_part] + list(lg)

        # Make sure the stable call count is correct - this should be 12 calls
        # to get_account;
        #  1 for first_list_part
        #  10 for the values on the queue
        #  1 for the value blocking whilst trying to place onto the queue
        self.assertEqual(12, stable_get_account_call_count)

        # Make sure all the containers were listed and placed onto the queue
        self.assertEqual(15, mock_conn.get_account.call_count)

        # Check the results were all returned
        observed_listing = []
        for lir in list_results:
            observed_listing.append(
                [li['name'] for li in lir['listing']]
            )
        expected_listing = []
        for gar in get_account_returns[:-1]:  # The empty list is not returned
            expected_listing.append(
                [li['name'] for li in gar[1]]
            )
        self.assertEqual(observed_listing, expected_listing)


class TestServiceStat(_TestServiceBase):

    maxDiff = None

    @mock.patch('swiftclient.service.Connection')
    def test_stat_object(self, mock_connection_class):
        mock_conn = mock_connection_class.return_value
        mock_conn.url = 'http://saio/v1/AUTH_test'
        mock_conn.head_object.return_value = {}
        expected = {
            'action': 'stat_object',
            'container': 'c',
            'object': 'o',
            'headers': {},
            'items': [('Account', 'AUTH_test'),
                      ('Container', 'c'),
                      ('Object', 'o'),
                      ('Content Type', None),
                      ('Content Length', '0'),
                      ('Last Modified', None),
                      ('ETag', None),
                      ('Manifest', None)],
            'success': True}
        with SwiftService() as swift:
            stat_results = swift.stat(container='c', objects='o')
            for stat_result in stat_results:
                self.assertEqual(stat_result, expected)
        self.assertEqual(mock_conn.head_object.mock_calls, [
            mock.call('c', 'o', headers={}, query_string=None),
        ])

    @mock.patch('swiftclient.service.Connection')
    def test_stat_versioned_object(self, mock_connection_class):
        mock_conn = mock_connection_class.return_value
        mock_conn.url = 'http://saio/v1/AUTH_test'
        mock_conn.head_object.return_value = {}
        expected = {
            'action': 'stat_object',
            'container': 'c',
            'object': 'o',
            'headers': {},
            'items': [('Account', 'AUTH_test'),
                      ('Container', 'c'),
                      ('Object', 'o'),
                      ('Content Type', None),
                      ('Content Length', '0'),
                      ('Last Modified', None),
                      ('ETag', None),
                      ('Manifest', None)],
            'success': True}
        with SwiftService() as swift:
            stat_results = swift.stat(container='c', objects='o', options={
                'version_id': '234567.8'})
            for stat_result in stat_results:
                self.assertEqual(stat_result, expected)
        self.assertEqual(mock_conn.head_object.mock_calls, [
            mock.call('c', 'o', headers={},
                      query_string='version-id=234567.8'),
        ])


class TestService(unittest.TestCase):

    def test_upload_with_bad_segment_size(self):
        for bad in ('ten', '1234X', '100.3'):
            options = {'segment_size': bad}
            try:
                service = SwiftService(options)
                next(service.upload('c', 'o'))
                self.fail('Expected SwiftError when segment_size=%s' % bad)
            except SwiftError as exc:
                self.assertEqual('Segment size should be an integer value',
                                 exc.value)

    @mock.patch('swiftclient.service.stat')
    @mock.patch('swiftclient.service.getmtime', return_value=1.0)
    @mock.patch('swiftclient.service.getsize', return_value=4)
    def test_upload_with_relative_path(self, *args, **kwargs):
        service = SwiftService({})
        objects = [{'path': "./testobj",
                    'strt_indx': 2},
                   {'path': os.path.join(os.getcwd(), "testobj"),
                    'strt_indx': 1},
                   {'path': ".\\testobj",
                    'strt_indx': 2}]
        for obj in objects:
            with mock.patch('swiftclient.service.Connection') as mock_conn, \
                    mock.patch.object(builtins, 'open') as mock_open:
                mock_open.return_value = io.StringIO('asdf')
                mock_conn.return_value.head_object.side_effect = \
                    ClientException('Not Found', http_status=404)
                mock_conn.return_value.put_object.return_value =\
                    'd41d8cd98f00b204e9800998ecf8427e'
                resp_iter = service.upload(
                    'c', [SwiftUploadObject(obj['path'])])
                responses = [x for x in resp_iter]
                for resp in responses:
                    self.assertIsNone(resp.get('error'))
                    self.assertIs(True, resp['success'])
                self.assertEqual(2, len(responses))
                create_container_resp, upload_obj_resp = responses
                self.assertEqual(create_container_resp['action'],
                                 'create_container')
                self.assertEqual(upload_obj_resp['action'],
                                 'upload_object')
                self.assertEqual(upload_obj_resp['object'],
                                 obj['path'][obj['strt_indx']:])
                self.assertEqual(upload_obj_resp['path'], obj['path'])
                self.assertTrue(mock_open.return_value.closed)

    @mock.patch('swiftclient.service.Connection')
    def test_upload_stream(self, mock_conn):
        service = SwiftService({})

        stream = test_utils.FakeStream(2048)
        segment_etag = md5(b'A' * 1024).hexdigest()

        mock_conn.return_value.head_object.side_effect = \
            ClientException('Not Found', http_status=404)
        mock_conn.return_value.put_object.return_value = \
            segment_etag
        options = {'use_slo': True, 'segment_size': 1024}
        resp_iter = service.upload(
            'container',
            [SwiftUploadObject(stream, object_name='streamed')],
            options)
        responses = [x for x in resp_iter]
        for resp in responses:
            self.assertFalse('error' in resp)
            self.assertTrue(resp['success'])
        self.assertEqual(5, len(responses))
        container_resp, segment_container_resp = responses[0:2]
        segment_response = responses[2:4]
        upload_obj_resp = responses[-1]
        self.assertEqual(container_resp['action'],
                         'create_container')
        self.assertEqual(upload_obj_resp['action'],
                         'upload_object')
        self.assertEqual(upload_obj_resp['object'],
                         'streamed')
        self.assertTrue(upload_obj_resp['path'] is None)
        self.assertTrue(upload_obj_resp['large_object'])
        self.assertIn('manifest_response_dict', upload_obj_resp)
        self.assertEqual(upload_obj_resp['manifest_response_dict'], {})
        for i, resp in enumerate(segment_response):
            self.assertEqual(i, resp['segment_index'])
            self.assertEqual(1024, resp['segment_size'])
            self.assertEqual('d47b127bc2de2d687ddc82dac354c415',
                             resp['segment_etag'])
            self.assertTrue(resp['segment_location'].endswith(
                '/0000000%d' % i))
            self.assertTrue(resp['segment_location'].startswith(
                '/container_segments/streamed'))

    @mock.patch('swiftclient.service.Connection')
    def test_upload_stream_fits_in_one_segment(self, mock_conn):
        service = SwiftService({})

        stream = test_utils.FakeStream(2048)
        whole_etag = md5(b'A' * 2048).hexdigest()

        mock_conn.return_value.head_object.side_effect = \
            ClientException('Not Found', http_status=404)
        mock_conn.return_value.put_object.return_value = \
            whole_etag
        options = {'use_slo': True, 'segment_size': 10240}
        resp_iter = service.upload(
            'container',
            [SwiftUploadObject(stream, object_name='streamed')],
            options)
        responses = [x for x in resp_iter]
        for resp in responses:
            self.assertNotIn('error', resp)
            self.assertTrue(resp['success'])
        self.assertEqual(3, len(responses))
        container_resp, segment_container_resp = responses[0:2]
        upload_obj_resp = responses[-1]
        self.assertEqual(container_resp['action'],
                         'create_container')
        self.assertEqual(upload_obj_resp['action'],
                         'upload_object')
        self.assertEqual(upload_obj_resp['object'],
                         'streamed')
        self.assertTrue(upload_obj_resp['path'] is None)
        self.assertFalse(upload_obj_resp['large_object'])
        self.assertNotIn('manifest_response_dict', upload_obj_resp)


class TestServiceUpload(_TestServiceBase):

    @contextlib.contextmanager
    def assert_open_results_are_closed(self):
        opened_files = []
        builtin_open = builtins.open

        def open_wrapper(*a, **kw):
            opened_files.append((builtin_open(*a, **kw), a, kw))
            return opened_files[-1][0]

        with mock.patch.object(builtins, 'open', open_wrapper):
            yield
        for fp, args, kwargs in opened_files:
            formatted_args = [repr(a) for a in args]
            formatted_args.extend('%s=%r' % kv for kv in kwargs.items())
            formatted_args = ', '.join(formatted_args)
            self.assertTrue(fp.closed,
                            'Failed to close open(%s)' % formatted_args)

    def test_upload_object_job_file_with_unicode_path(self):
        # Uploading a file results in the file object being wrapped in a
        # LengthWrapper. This test sets the options in such a way that much
        # of _upload_object_job is skipped bringing the critical path down
        # to around 60 lines to ease testing.
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 30)
            f.flush()
            expected_r = {
                'action': 'upload_object',
                'attempts': 2,
                'container': 'test_c',
                'headers': {},
                'large_object': True,
                'object': 'テスト/dummy.dat',
                'manifest_response_dict': {},
                'segment_results': [{'action': 'upload_segment',
                                    'success': True}] * 3,
                'status': 'uploaded',
                'success': True,
            }
            expected_mtime = '%f' % os.path.getmtime(f.name)

            mock_conn = mock.Mock()
            mock_conn.put_object.return_value = ''
            type(mock_conn).attempts = mock.PropertyMock(return_value=2)

            s = SwiftService()
            with mock.patch.object(s, '_upload_segment_job') as mock_job:
                mock_job.return_value = {
                    'action': 'upload_segment',
                    'success': True}

                r = s._upload_object_job(conn=mock_conn,
                                         container='test_c',
                                         source=f.name,
                                         obj='テスト/dummy.dat',
                                         options=dict(s._options,
                                                      segment_size=10,
                                                      leave_segments=True))

            mtime = r['headers']['x-object-meta-mtime']
            self.assertEqual(expected_mtime, mtime)
            del r['headers']['x-object-meta-mtime']

            self.assertEqual(
                'test_c_segments/%E3%83%86%E3%82%B9%E3%83%88/dummy.dat/' +
                '%s/30/10/' % mtime, r['headers']['x-object-manifest'])
            del r['headers']['x-object-manifest']

            self.assertEqual(r['path'], f.name)
            del r['path']

            self.assertEqual(r, expected_r)
            self.assertEqual(mock_conn.put_object.call_count, 1)
            mock_conn.put_object.assert_called_with('test_c', 'テスト/dummy.dat',
                                                    '',
                                                    content_length=0,
                                                    headers={},
                                                    response_dict={})

    def test_upload_segment_job(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 10)
            f.write(b'b' * 10)
            f.write(b'c' * 10)
            f.flush()

            # run read() when put_object is called to calculate md5sum
            def _consuming_conn(*a, **kw):
                contents = a[2]
                contents.read()  # Force md5 calculation
                return contents.get_md5sum()

            mock_conn = mock.Mock()
            mock_conn.put_object.side_effect = _consuming_conn
            type(mock_conn).attempts = mock.PropertyMock(return_value=2)
            expected_r = {
                'action': 'upload_segment',
                'for_container': 'test_c',
                'for_object': 'test_o',
                'segment_index': 2,
                'segment_size': 10,
                'segment_location': '/test_c_segments/test_s_1',
                'log_line': 'test_o segment 2',
                'success': True,
                'response_dict': {},
                'segment_etag': md5(b'b' * 10).hexdigest(),
                'attempts': 2,
            }

            s = SwiftService()
            with self.assert_open_results_are_closed():
                r = s._upload_segment_job(conn=mock_conn,
                                          path=f.name,
                                          container='test_c',
                                          segment_name='test_s_1',
                                          segment_start=10,
                                          segment_size=10,
                                          segment_index=2,
                                          obj_name='test_o',
                                          options={'segment_container': None,
                                                   'checksum': True})

            self.assertEqual(r, expected_r)

            self.assertEqual(mock_conn.put_object.call_count, 1)
            mock_conn.put_object.assert_called_with(
                'test_c_segments', 'test_s_1',
                mock.ANY,
                content_length=10,
                content_type='application/swiftclient-segment',
                response_dict={})
            contents = mock_conn.put_object.call_args[0][2]
            self.assertIsInstance(contents, utils.LengthWrapper)
            self.assertEqual(len(contents), 10)

    def test_upload_stream_segment(self):
        common_params = {
            'segment_container': 'segments',
            'segment_name': 'test_stream_2',
            'container': 'test_stream',
            'object': 'stream_object',
        }
        tests = [
            {'test_params': {
                'segment_size': 1024,
                'segment_index': 2,
                'content_size': 1024},
             'put_object_args': {
                'container': 'segments',
                'object': 'test_stream_2'},
             'expected': {
                'complete': False,
                'segment_etag': md5(b'A' * 1024).hexdigest()}},
            {'test_params': {
                'segment_size': 2048,
                'segment_index': 0,
                'content_size': 512},
             'put_object_args': {
                'container': 'test_stream',
                'object': 'stream_object'},
             'expected': {
                'complete': True,
                'segment_etag': md5(b'A' * 512).hexdigest()}},
            # 0-sized segment should not be uploaded
            {'test_params': {
                'segment_size': 1024,
                'segment_index': 1,
                'content_size': 0},
             'put_object_args': {},
             'expected': {
                'complete': True}},
            # 0-sized objects should be uploaded
            {'test_params': {
                'segment_size': 1024,
                'segment_index': 0,
                'content_size': 0},
             'put_object_args': {
                'container': 'test_stream',
                'object': 'stream_object'},
             'expected': {
                'complete': True,
                'segment_etag': md5(b'').hexdigest()}},
            # Test boundary conditions
            {'test_params': {
                'segment_size': 1024,
                'segment_index': 1,
                'content_size': 1023},
             'put_object_args': {
                'container': 'segments',
                'object': 'test_stream_2'},
             'expected': {
                'complete': True,
                'segment_etag': md5(b'A' * 1023).hexdigest()}},
            {'test_params': {
                'segment_size': 2048,
                'segment_index': 0,
                'content_size': 2047},
             'put_object_args': {
                'container': 'test_stream',
                'object': 'stream_object'},
             'expected': {
                'complete': True,
                'segment_etag': md5(b'A' * 2047).hexdigest()}},
            {'test_params': {
                'segment_size': 1024,
                'segment_index': 2,
                'content_size': 1025},
             'put_object_args': {
                'container': 'segments',
                'object': 'test_stream_2'},
             'expected': {
                'complete': False,
                'segment_etag': md5(b'A' * 1024).hexdigest()}},
        ]

        for test_args in tests:
            params = test_args['test_params']
            stream = test_utils.FakeStream(params['content_size'])
            segment_size = params['segment_size']
            segment_index = params['segment_index']

            def _fake_put_object(*args, **kwargs):
                contents = args[2]
                # Consume and compute md5
                return md5(contents).hexdigest()

            mock_conn = mock.Mock()
            mock_conn.put_object.side_effect = _fake_put_object

            s = SwiftService()
            resp = s._upload_stream_segment(
                conn=mock_conn,
                container=common_params['container'],
                object_name=common_params['object'],
                segment_container=common_params['segment_container'],
                segment_name=common_params['segment_name'],
                segment_size=segment_size,
                segment_index=segment_index,
                headers={},
                fd=stream)
            expected_args = test_args['expected']
            put_args = test_args['put_object_args']
            expected_response = {
                'segment_size': min(len(stream), segment_size),
                'complete': expected_args['complete'],
                'success': True,
            }
            if len(stream) or segment_index == 0:
                segment_location = '/%s/%s' % (put_args['container'],
                                               put_args['object'])
                expected_response.update(
                    {'segment_index': segment_index,
                     'segment_location': segment_location,
                     'segment_etag': expected_args['segment_etag'],
                     'for_object': common_params['object']})
                mock_conn.put_object.assert_called_once_with(
                    put_args['container'],
                    put_args['object'],
                    mock.ANY,
                    content_length=min(len(stream), segment_size),
                    headers={'etag': expected_args['segment_etag']},
                    response_dict=mock.ANY)
            else:
                self.assertEqual([], mock_conn.put_object.mock_calls)
                expected_response.update(
                    {'segment_index': None,
                     'segment_location': None,
                     'segment_etag': None})
            self.assertEqual(expected_response, resp)

    def test_etag_mismatch_with_ignore_checksum(self):
        def _consuming_conn(*a, **kw):
            contents = a[2]
            contents.read()  # Force md5 calculation
            return 'badresponseetag'

        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 10)
            f.write(b'b' * 10)
            f.write(b'c' * 10)
            f.flush()

            mock_conn = mock.Mock()
            mock_conn.put_object.side_effect = _consuming_conn
            type(mock_conn).attempts = mock.PropertyMock(return_value=2)

            s = SwiftService()
            r = s._upload_segment_job(conn=mock_conn,
                                      path=f.name,
                                      container='test_c',
                                      segment_name='test_s_1',
                                      segment_start=10,
                                      segment_size=10,
                                      segment_index=2,
                                      obj_name='test_o',
                                      options={'segment_container': None,
                                               'checksum': False})

            self.assertIsNone(r.get('error'))
            self.assertEqual(mock_conn.put_object.call_count, 1)
            mock_conn.put_object.assert_called_with(
                'test_c_segments', 'test_s_1',
                mock.ANY,
                content_length=10,
                content_type='application/swiftclient-segment',
                response_dict={})
            contents = mock_conn.put_object.call_args[0][2]
            # Check that md5sum is not calculated.
            self.assertEqual(contents.get_md5sum(), '')

    def test_upload_segment_job_etag_mismatch(self):
        def _consuming_conn(*a, **kw):
            contents = a[2]
            contents.read()  # Force md5 calculation
            return 'badresponseetag'

        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 10)
            f.write(b'b' * 10)
            f.write(b'c' * 10)
            f.flush()

            mock_conn = mock.Mock()
            mock_conn.put_object.side_effect = _consuming_conn
            type(mock_conn).attempts = mock.PropertyMock(return_value=2)

            s = SwiftService()
            with self.assert_open_results_are_closed():
                r = s._upload_segment_job(conn=mock_conn,
                                          path=f.name,
                                          container='test_c',
                                          segment_name='test_s_1',
                                          segment_start=10,
                                          segment_size=10,
                                          segment_index=2,
                                          obj_name='test_o',
                                          options={'segment_container': None,
                                                   'checksum': True})

            self.assertIn('md5 mismatch', str(r.get('error')))

            self.assertEqual(mock_conn.put_object.call_count, 1)
            mock_conn.put_object.assert_called_with(
                'test_c_segments', 'test_s_1',
                mock.ANY,
                content_length=10,
                content_type='application/swiftclient-segment',
                response_dict={})
            contents = mock_conn.put_object.call_args[0][2]
            self.assertEqual(contents.get_md5sum(), md5(b'b' * 10).hexdigest())

    def test_upload_object_job_file(self):
        # Uploading a file results in the file object being wrapped in a
        # LengthWrapper. This test sets the options in such a way that much
        # of _upload_object_job is skipped bringing the critical path down
        # to around 60 lines to ease testing.
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 30)
            f.flush()
            expected_r = {
                'action': 'upload_object',
                'attempts': 2,
                'container': 'test_c',
                'headers': {},
                'large_object': False,
                'object': 'test_o',
                'response_dict': {},
                'status': 'uploaded',
                'success': True,
            }
            expected_mtime = '%f' % os.path.getmtime(f.name)

            # run read() when put_object is called to calculate md5sum
            # md5sum is verified in _upload_object_job.
            def _consuming_conn(*a, **kw):
                contents = a[2]
                contents.read()  # Force md5 calculation
                return contents.get_md5sum()

            mock_conn = mock.Mock()
            mock_conn.put_object.side_effect = _consuming_conn
            type(mock_conn).attempts = mock.PropertyMock(return_value=2)

            s = SwiftService()
            with self.assert_open_results_are_closed():
                r = s._upload_object_job(conn=mock_conn,
                                         container='test_c',
                                         source=f.name,
                                         obj='test_o',
                                         options=dict(s._options,
                                                      leave_segments=True))

            mtime = r['headers']['x-object-meta-mtime']
            self.assertEqual(expected_mtime, mtime)
            del r['headers']['x-object-meta-mtime']

            self.assertEqual(r['path'], f.name)
            del r['path']

            self.assertEqual(r, expected_r)
            self.assertEqual(mock_conn.put_object.call_count, 1)
            mock_conn.put_object.assert_called_with('test_c', 'test_o',
                                                    mock.ANY,
                                                    content_length=30,
                                                    headers={},
                                                    response_dict={})
            contents = mock_conn.put_object.call_args[0][2]
            self.assertIsInstance(contents, utils.LengthWrapper)
            self.assertEqual(len(contents), 30)

    @mock.patch('swiftclient.service.time', return_value=1400000000)
    def test_upload_object_job_stream(self, time_mock):
        # Streams are wrapped as ReadableToIterable
        with tempfile.TemporaryFile() as f:
            f.write(b'a' * 30)
            f.flush()
            f.seek(0)
            expected_r = {
                'action': 'upload_object',
                'attempts': 2,
                'container': 'test_c',
                'headers': {},
                'large_object': False,
                'object': 'test_o',
                'response_dict': {},
                'status': 'uploaded',
                'success': True,
                'path': None,
            }
            expected_mtime = 1400000000

            mock_conn = mock.Mock()
            mock_conn.put_object.return_value = ''
            type(mock_conn).attempts = mock.PropertyMock(return_value=2)

            s = SwiftService()
            r = s._upload_object_job(conn=mock_conn,
                                     container='test_c',
                                     source=f,
                                     obj='test_o',
                                     options=dict(s._options,
                                                  leave_segments=True))

            mtime = float(r['headers']['x-object-meta-mtime'])
            self.assertEqual(mtime, expected_mtime)
            del r['headers']['x-object-meta-mtime']

            self.assertEqual(r, expected_r)
            self.assertEqual(mock_conn.put_object.call_count, 1)
            mock_conn.put_object.assert_called_with('test_c', 'test_o',
                                                    mock.ANY,
                                                    content_length=None,
                                                    headers={},
                                                    response_dict={})
            contents = mock_conn.put_object.call_args[0][2]
            self.assertIsInstance(contents, utils.ReadableToIterable)
            self.assertEqual(contents.chunk_size, 65536)
            # next retrieves the first chunk of the stream or len(chunk_size)
            # or less, it also forces the md5 to be calculated.
            self.assertEqual(next(contents), b'a' * 30)
            self.assertEqual(contents.get_md5sum(), md5(b'a' * 30).hexdigest())

    def test_upload_object_job_etag_mismatch(self):
        # The etag test for both streams and files use the same code
        # so only one test should be needed.
        def _consuming_conn(*a, **kw):
            contents = a[2]
            contents.read()  # Force md5 calculation
            return 'badresponseetag'

        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 30)
            f.flush()

            mock_conn = mock.Mock()
            mock_conn.put_object.side_effect = _consuming_conn
            type(mock_conn).attempts = mock.PropertyMock(return_value=2)

            s = SwiftService()
            r = s._upload_object_job(conn=mock_conn,
                                     container='test_c',
                                     source=f.name,
                                     obj='test_o',
                                     options=dict(s._options,
                                                  leave_segments=True))

            self.assertIs(r['success'], False)
            self.assertIn('md5 mismatch', str(r.get('error')))

            self.assertEqual(mock_conn.put_object.call_count, 1)
            expected_headers = {'x-object-meta-mtime': mock.ANY}
            mock_conn.put_object.assert_called_with('test_c', 'test_o',
                                                    mock.ANY,
                                                    content_length=30,
                                                    headers=expected_headers,
                                                    response_dict={})

            contents = mock_conn.put_object.call_args[0][2]
            self.assertEqual(contents.get_md5sum(), md5(b'a' * 30).hexdigest())

    def test_upload_object_job_identical_etag(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 30)
            f.flush()

            mock_conn = mock.Mock()
            mock_conn.head_object.return_value = {
                'content-length': 30,
                'etag': md5(b'a' * 30).hexdigest()}
            type(mock_conn).attempts = mock.PropertyMock(return_value=2)

            s = SwiftService()
            r = s._upload_object_job(conn=mock_conn,
                                     container='test_c',
                                     source=f.name,
                                     obj='test_o',
                                     options={'changed': False,
                                              'skip_identical': True,
                                              'leave_segments': True,
                                              'header': '',
                                              'segment_size': 0})

            self.assertIsNone(r.get('error'))
            self.assertIs(True, r['success'])
            self.assertEqual(r.get('status'), 'skipped-identical')
            self.assertEqual(mock_conn.put_object.call_count, 0)
            self.assertEqual(mock_conn.head_object.call_count, 1)
            mock_conn.head_object.assert_called_with('test_c', 'test_o')

    def test_upload_object_job_identical_slo_with_nesting(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 30)
            f.flush()
            seg_etag = md5(b'a' * 10).hexdigest()
            submanifest = "[%s]" % ",".join(
                ['{"bytes":10,"hash":"%s"}' % seg_etag] * 2)
            submanifest_etag = md5(seg_etag.encode('ascii') * 2).hexdigest()
            manifest = "[%s]" % ",".join([
                '{"sub_slo":true,"name":"/test_c_segments/test_sub_slo",'
                '"bytes":20,"hash":"%s"}' % submanifest_etag,
                '{"bytes":10,"hash":"%s"}' % seg_etag])

            mock_conn = mock.Mock()
            mock_conn.head_object.return_value = {
                'x-static-large-object': True,
                'content-length': 30,
                'etag': md5(submanifest_etag.encode('ascii') +
                            seg_etag.encode('ascii')).hexdigest()}
            mock_conn.get_object.side_effect = [
                ({}, manifest.encode('ascii')),
                ({}, submanifest.encode('ascii'))]
            type(mock_conn).attempts = mock.PropertyMock(return_value=2)

            s = SwiftService()
            r = s._upload_object_job(conn=mock_conn,
                                     container='test_c',
                                     source=f.name,
                                     obj='test_o',
                                     options={'changed': False,
                                              'skip_identical': True,
                                              'leave_segments': True,
                                              'header': '',
                                              'segment_size': 10})

            self.assertIsNone(r.get('error'))
            self.assertIs(True, r['success'])
            self.assertEqual('skipped-identical', r.get('status'))
            self.assertEqual(0, mock_conn.put_object.call_count)
            self.assertEqual([mock.call('test_c', 'test_o')],
                             mock_conn.head_object.mock_calls)
            self.assertEqual([
                mock.call('test_c', 'test_o',
                          query_string='multipart-manifest=get'),
                mock.call('test_c_segments', 'test_sub_slo',
                          query_string='multipart-manifest=get'),
            ], mock_conn.get_object.mock_calls)

    def test_upload_object_job_identical_dlo(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 30)
            f.flush()
            segment_etag = md5(b'a' * 10).hexdigest()

            mock_conn = mock.Mock()
            mock_conn.head_object.return_value = {
                'x-object-manifest': 'test_c_segments/test_o/prefix',
                'content-length': 30,
                'etag': md5(segment_etag.encode('ascii') * 3).hexdigest()}
            mock_conn.get_container.side_effect = [
                (None, [{"bytes": 10, "hash": segment_etag,
                         "name": "test_o/prefix/00"},
                        {"bytes": 10, "hash": segment_etag,
                         "name": "test_o/prefix/01"}]),
                (None, [{"bytes": 10, "hash": segment_etag,
                         "name": "test_o/prefix/02"}]),
                (None, {})]
            type(mock_conn).attempts = mock.PropertyMock(return_value=2)

            s = SwiftService()
            with mock.patch('swiftclient.service.get_conn',
                            return_value=mock_conn):
                r = s._upload_object_job(conn=mock_conn,
                                         container='test_c',
                                         source=f.name,
                                         obj='test_o',
                                         options={'changed': False,
                                                  'skip_identical': True,
                                                  'leave_segments': True,
                                                  'header': '',
                                                  'segment_size': 10})

            self.assertIsNone(r.get('error'))
            self.assertIs(True, r['success'])
            self.assertEqual('skipped-identical', r.get('status'))
            self.assertEqual(0, mock_conn.put_object.call_count)
            self.assertEqual(1, mock_conn.head_object.call_count)
            self.assertEqual(3, mock_conn.get_container.call_count)
            mock_conn.head_object.assert_called_with('test_c', 'test_o')
            expected = [
                mock.call('test_c_segments', prefix='test_o/prefix',
                          marker='', delimiter=None, headers={},
                          query_string=None, version_marker=''),
                mock.call('test_c_segments', prefix='test_o/prefix',
                          marker="test_o/prefix/01", delimiter=None,
                          headers={}, query_string=None, version_marker=''),
                mock.call('test_c_segments', prefix='test_o/prefix',
                          marker="test_o/prefix/02", delimiter=None,
                          headers={}, query_string=None, version_marker=''),
            ]
            mock_conn.get_container.assert_has_calls(expected)

    def test_make_upload_objects(self):
        check_names_pseudo_to_expected = {
            (('/absolute/file/path',), ''): ['absolute/file/path'],
            (('relative/file/path',), ''): ['relative/file/path'],
            (('/absolute/file/path',), '/absolute/pseudo/dir'): [
                'absolute/pseudo/dir/absolute/file/path'],
            (('/absolute/file/path',), 'relative/pseudo/dir'): [
                'relative/pseudo/dir/absolute/file/path'],
            (('relative/file/path',), '/absolute/pseudo/dir'): [
                'absolute/pseudo/dir/relative/file/path'],
            (('relative/file/path',), 'relative/pseudo/dir'): [
                'relative/pseudo/dir/relative/file/path'],
        }
        errors = []
        for (filenames, pseudo_folder), expected in \
                check_names_pseudo_to_expected.items():
            actual = SwiftService._make_upload_objects(
                filenames, pseudo_folder=pseudo_folder)
            try:
                self.assertEqual(expected, [o.object_name for o in actual])
            except AssertionError as e:
                msg = 'given (%r, %r) expected %r, got %s' % (
                    filenames, pseudo_folder, expected, e)
                errors.append(msg)
        self.assertFalse(errors, "\nERRORS:\n%s" % '\n'.join(errors))

    def test_create_dir_marker_job_unchanged(self):
        mock_conn = mock.Mock()
        mock_conn.head_object.return_value = {
            'content-type': 'application/directory',
            'content-length': '0',
            'x-object-meta-mtime': '1.234000',
            'etag': md5().hexdigest()}

        s = SwiftService()
        with mock.patch('swiftclient.service.get_conn',
                        return_value=mock_conn):
            with mock.patch('swiftclient.service.getmtime',
                            return_value=1.234):
                r = s._create_dir_marker_job(conn=mock_conn,
                                             container='test_c',
                                             obj='test_o',
                                             path='test',
                                             options={'changed': True,
                                                      'skip_identical': True,
                                                      'leave_segments': True,
                                                      'header': '',
                                                      'segment_size': 10})
        self.assertEqual({
            'action': 'create_dir_marker',
            'container': 'test_c',
            'object': 'test_o',
            'path': 'test',
            'headers': {'x-object-meta-mtime': '1.234000'},
            # NO response dict!
            'success': True,
        }, r)
        self.assertEqual([], mock_conn.put_object.mock_calls)

    def test_create_dir_marker_job_unchanged_old_type(self):
        mock_conn = mock.Mock()
        mock_conn.head_object.return_value = {
            'content-type': 'text/directory',
            'content-length': '0',
            'x-object-meta-mtime': '1.000000',
            'etag': md5().hexdigest()}

        s = SwiftService()
        with mock.patch('swiftclient.service.get_conn',
                        return_value=mock_conn):
            with mock.patch('swiftclient.service.time',
                            return_value=1.234):
                r = s._create_dir_marker_job(conn=mock_conn,
                                             container='test_c',
                                             obj='test_o',
                                             options={'changed': True,
                                                      'skip_identical': True,
                                                      'leave_segments': True,
                                                      'header': '',
                                                      'segment_size': 10})
        self.assertEqual({
            'action': 'create_dir_marker',
            'container': 'test_c',
            'object': 'test_o',
            'path': None,
            'headers': {'x-object-meta-mtime': '1.000000'},
            # NO response dict!
            'success': True,
        }, r)
        self.assertEqual([], mock_conn.put_object.mock_calls)

    def test_create_dir_marker_job_overwrites_bad_type(self):
        mock_conn = mock.Mock()
        mock_conn.head_object.return_value = {
            'content-type': 'text/plain',
            'content-length': '0',
            'x-object-meta-mtime': '1.000000',
            'etag': md5().hexdigest()}

        s = SwiftService()
        with mock.patch('swiftclient.service.get_conn',
                        return_value=mock_conn):
            with mock.patch('swiftclient.service.time',
                            return_value=1.234):
                r = s._create_dir_marker_job(conn=mock_conn,
                                             container='test_c',
                                             obj='test_o',
                                             options={'changed': True,
                                                      'skip_identical': True,
                                                      'leave_segments': True,
                                                      'header': '',
                                                      'segment_size': 10})
        self.assertEqual({
            'action': 'create_dir_marker',
            'container': 'test_c',
            'object': 'test_o',
            'path': None,
            'headers': {'x-object-meta-mtime': '1.000000'},
            'response_dict': {},
            'success': True,
        }, r)
        self.assertEqual([mock.call(
            'test_c', 'test_o', '',
            content_length=0,
            content_type='application/directory',
            headers={'x-object-meta-mtime': '1.000000'},
            response_dict={})], mock_conn.put_object.mock_calls)

    def test_create_dir_marker_job_missing(self):
        mock_conn = mock.Mock()
        mock_conn.head_object.side_effect = \
            ClientException('Not Found', http_status=404)

        s = SwiftService()
        with mock.patch('swiftclient.service.get_conn',
                        return_value=mock_conn):
            with mock.patch('swiftclient.service.time',
                            return_value=1.234):
                r = s._create_dir_marker_job(conn=mock_conn,
                                             container='test_c',
                                             obj='test_o',
                                             options={'changed': True,
                                                      'skip_identical': True,
                                                      'leave_segments': True,
                                                      'header': '',
                                                      'segment_size': 10})
        self.assertEqual({
            'action': 'create_dir_marker',
            'container': 'test_c',
            'object': 'test_o',
            'path': None,
            'headers': {'x-object-meta-mtime': '1.000000'},
            'response_dict': {},
            'success': True,
        }, r)
        self.assertEqual([mock.call(
            'test_c', 'test_o', '',
            content_length=0,
            content_type='application/directory',
            headers={'x-object-meta-mtime': '1.000000'},
            response_dict={})], mock_conn.put_object.mock_calls)


class TestServiceDownload(_TestServiceBase):

    def setUp(self):
        super(TestServiceDownload, self).setUp()
        self.opts = swiftclient.service._default_local_options.copy()
        self.opts['no_download'] = True
        self.obj_content = b'c' * 10
        self.obj_etag = md5(self.obj_content).hexdigest()
        self.obj_len = len(self.obj_content)
        self.exc = Exception('test_exc')
        # Base response to be copied and updated to matched the expected
        # response for each test
        self.expected = {
            'action': 'download_object',   # Should always be download_object
            'container': 'test_c',
            'object': 'test_o',
            'attempts': 2,
            'response_dict': {},
            'path': 'test_o',
            'pseudodir': False,
            'success': None   # Should be a bool
        }

    def _readbody(self):
        yield self.obj_content

    @mock.patch('swiftclient.service.SwiftService.list')
    @mock.patch('swiftclient.service.SwiftService._submit_page_downloads')
    @mock.patch('swiftclient.service.interruptable_as_completed')
    def test_download_container_job(self, as_comp, sub_page, service_list):
        """
        Check that paged downloads work correctly
        """
        obj_count = [0]

        def make_counting_generator(object_to_yield, total_count):
            # maintain a counter of objects yielded
            count = [0]

            def counting_generator():
                while count[0] < 10:
                    yield object_to_yield
                    count[0] += 1
                    total_count[0] += 1
            return counting_generator()

        obj_count_on_sub_page_call = []
        sub_page_call_count = [0]

        def fake_sub_page(*args):
            # keep a record of obj_count when this function is called
            obj_count_on_sub_page_call.append(obj_count[0])
            sub_page_call_count[0] += 1
            if sub_page_call_count[0] < 3:
                return range(0, 10)
            return None

        sub_page.side_effect = fake_sub_page

        r = mock.Mock(spec=Future)
        r.result.return_value = self._get_expected({
            'success': True,
            'start_time': 1,
            'finish_time': 2,
            'headers_receipt': 3,
            'auth_end_time': 4,
            'read_length': len(b'objcontent'),
        })

        as_comp.side_effect = [
            make_counting_generator(r, obj_count),
            make_counting_generator(r, obj_count)
        ]

        s = SwiftService()
        down_gen = s._download_container('test_c', self.opts)
        results = list(down_gen)
        self.assertEqual(20, len(results))
        self.assertEqual(2, as_comp.call_count)
        self.assertEqual(3, sub_page_call_count[0])
        self.assertEqual([0, 7, 17], obj_count_on_sub_page_call)

    @mock.patch('swiftclient.service.SwiftService.list')
    @mock.patch('swiftclient.service.SwiftService._submit_page_downloads')
    @mock.patch('swiftclient.service.interruptable_as_completed')
    def test_download_container_job_error(
            self, as_comp, sub_page, service_list):
        """
        Check that paged downloads work correctly
        """
        class BoomError(Exception):
            def __init__(self, value):
                self.value = value

            def __str__(self):
                return repr(self.value)

        def _make_result():
            r = mock.Mock(spec=Future)
            r.result.return_value = self._get_expected({
                'success': True,
                'start_time': 1,
                'finish_time': 2,
                'headers_receipt': 3,
                'auth_end_time': 4,
                'read_length': len(b'objcontent'),
            })
            return r

        as_comp.side_effect = [

        ]
        # We need Futures here because the error will cause a call to .cancel()
        sub_page_effects = [
            [_make_result() for _ in range(0, 10)],
            BoomError('Go Boom')
        ]
        sub_page.side_effect = sub_page_effects
        # ...but we must also mock the returns to as_completed
        as_comp.side_effect = [
            [_make_result() for _ in range(0, 10)]
        ]

        s = SwiftService()
        self.assertRaises(
            BoomError,
            lambda: list(s._download_container('test_c', self.opts))
        )
        # This was an unknown error, so make sure we attempt to cancel futures
        for spe in sub_page_effects[0]:
            spe.cancel.assert_called_once_with()
        self.assertEqual(1, as_comp.call_count)

        # Now test ClientException
        sub_page_effects = [
            [_make_result() for _ in range(0, 10)],
            ClientException('Go Boom')
        ]
        sub_page.side_effect = sub_page_effects
        as_comp.reset_mock()
        as_comp.side_effect = [
            [_make_result() for _ in range(0, 10)],
        ]
        self.assertRaises(
            ClientException,
            lambda: list(s._download_container('test_c', self.opts))
        )
        # This was a ClientException, so make sure we don't cancel futures
        for spe in sub_page_effects[0]:
            self.assertFalse(spe.cancel.called)
        self.assertEqual(1, as_comp.call_count)

    def test_download_object_job(self):
        mock_conn = self._get_mock_connection()
        objcontent = io.BytesIO(b'objcontent')
        mock_conn.get_object.side_effect = [
            ({'content-type': 'text/plain',
              'etag': '2cbbfe139a744d6abbe695e17f3c1991'},
             objcontent)
        ]
        expected_r = self._get_expected({
            'success': True,
            'start_time': 1,
            'finish_time': 2,
            'headers_receipt': 3,
            'auth_end_time': 4,
            'read_length': len(b'objcontent'),
        })

        with mock.patch.object(builtins, 'open') as mock_open:
            written_content = mock.Mock()
            mock_open.return_value = written_content
            s = SwiftService()
            _opts = self.opts.copy()
            _opts['no_download'] = False
            actual_r = s._download_object_job(
                mock_conn, 'test_c', 'test_o', _opts)
            actual_r = dict(  # Need to override the times we got from the call
                actual_r,
                **{
                    'start_time': 1,
                    'finish_time': 2,
                    'headers_receipt': 3
                }
            )
            mock_open.assert_called_once_with('test_o', 'wb', 65536)
            written_content.write.assert_called_once_with(b'objcontent')

        mock_conn.get_object.assert_called_once_with(
            'test_c', 'test_o', resp_chunk_size=65536, headers={},
            response_dict={}
        )
        self.assertEqual(expected_r, actual_r)

    def test_download_object_job_with_mtime(self):
        mock_conn = self._get_mock_connection()
        objcontent = io.BytesIO(b'objcontent')
        mock_conn.get_object.side_effect = [
            ({'content-type': 'text/plain',
              'etag': '2cbbfe139a744d6abbe695e17f3c1991',
              'x-object-meta-mtime': '1454113727.682512'},
             objcontent)
        ]
        expected_r = self._get_expected({
            'success': True,
            'start_time': 1,
            'finish_time': 2,
            'headers_receipt': 3,
            'auth_end_time': 4,
            'read_length': len(b'objcontent'),
        })

        with mock.patch.object(builtins, 'open') as mock_open, \
                mock.patch('swiftclient.service.utime') as mock_utime:
            written_content = mock.Mock()
            mock_open.return_value = written_content
            s = SwiftService()
            _opts = self.opts.copy()
            _opts['no_download'] = False
            actual_r = s._download_object_job(
                mock_conn, 'test_c', 'test_o', _opts)
            actual_r = dict(  # Need to override the times we got from the call
                actual_r,
                **{
                    'start_time': 1,
                    'finish_time': 2,
                    'headers_receipt': 3
                }
            )
            mock_open.assert_called_once_with('test_o', 'wb', 65536)
            mock_utime.assert_called_once_with(
                'test_o', (1454113727.682512, 1454113727.682512))
            written_content.write.assert_called_once_with(b'objcontent')

        mock_conn.get_object.assert_called_once_with(
            'test_c', 'test_o', resp_chunk_size=65536, headers={},
            response_dict={}
        )
        self.assertEqual(expected_r, actual_r)

    def test_download_object_job_bad_mtime(self):
        mock_conn = self._get_mock_connection()
        objcontent = io.BytesIO(b'objcontent')
        mock_conn.get_object.side_effect = [
            ({'content-type': 'text/plain',
              'etag': '2cbbfe139a744d6abbe695e17f3c1991',
              'x-object-meta-mtime': 'foo'},
             objcontent)
        ]
        expected_r = self._get_expected({
            'success': True,
            'start_time': 1,
            'finish_time': 2,
            'headers_receipt': 3,
            'auth_end_time': 4,
            'read_length': len(b'objcontent'),
        })

        with mock.patch.object(builtins, 'open') as mock_open, \
                mock.patch('swiftclient.service.utime') as mock_utime:
            written_content = mock.Mock()
            mock_open.return_value = written_content
            s = SwiftService()
            _opts = self.opts.copy()
            _opts['no_download'] = False
            actual_r = s._download_object_job(
                mock_conn, 'test_c', 'test_o', _opts)
            actual_r = dict(  # Need to override the times we got from the call
                actual_r,
                **{
                    'start_time': 1,
                    'finish_time': 2,
                    'headers_receipt': 3
                }
            )
            mock_open.assert_called_once_with('test_o', 'wb', 65536)
            self.assertEqual(0, len(mock_utime.mock_calls))
            written_content.write.assert_called_once_with(b'objcontent')

        mock_conn.get_object.assert_called_once_with(
            'test_c', 'test_o', resp_chunk_size=65536, headers={},
            response_dict={}
        )
        self.assertEqual(expected_r, actual_r)

    def test_download_object_job_ignore_mtime(self):
        mock_conn = self._get_mock_connection()
        objcontent = io.BytesIO(b'objcontent')
        mock_conn.get_object.side_effect = [
            ({'content-type': 'text/plain',
              'etag': '2cbbfe139a744d6abbe695e17f3c1991',
              'x-object-meta-mtime': '1454113727.682512'},
             objcontent)
        ]
        expected_r = self._get_expected({
            'success': True,
            'start_time': 1,
            'finish_time': 2,
            'headers_receipt': 3,
            'auth_end_time': 4,
            'read_length': len(b'objcontent'),
        })

        with mock.patch.object(builtins, 'open') as mock_open, \
                mock.patch('swiftclient.service.utime') as mock_utime:
            written_content = mock.Mock()
            mock_open.return_value = written_content
            s = SwiftService()
            _opts = self.opts.copy()
            _opts['no_download'] = False
            _opts['ignore_mtime'] = True
            actual_r = s._download_object_job(
                mock_conn, 'test_c', 'test_o', _opts)
            actual_r = dict(  # Need to override the times we got from the call
                actual_r,
                **{
                    'start_time': 1,
                    'finish_time': 2,
                    'headers_receipt': 3
                }
            )
            mock_open.assert_called_once_with('test_o', 'wb', 65536)
            self.assertEqual([], mock_utime.mock_calls)
            written_content.write.assert_called_once_with(b'objcontent')

        mock_conn.get_object.assert_called_once_with(
            'test_c', 'test_o', resp_chunk_size=65536, headers={},
            response_dict={}
        )
        self.assertEqual(expected_r, actual_r)

    def test_download_object_job_exception(self):
        mock_conn = self._get_mock_connection()
        mock_conn.get_object = mock.Mock(side_effect=self.exc)
        expected_r = self._get_expected({
            'success': False,
            'error': self.exc,
            'error_timestamp': mock.ANY,
            'traceback': mock.ANY
        })

        s = SwiftService()
        actual_r = s._download_object_job(
            mock_conn, 'test_c', 'test_o', self.opts)

        mock_conn.get_object.assert_called_once_with(
            'test_c', 'test_o', resp_chunk_size=65536, headers={},
            response_dict={}
        )
        self.assertEqual(expected_r, actual_r)

    def test_download(self):
        with mock.patch('swiftclient.service.Connection') as mock_conn:
            header = {'content-length': self.obj_len,
                      'etag': self.obj_etag}
            mock_conn.get_object.return_value = header, self._readbody()

            resp = SwiftService()._download_object_job(mock_conn,
                                                       'c',
                                                       'test',
                                                       self.opts)

        self.assertIsNone(resp.get('error'))
        self.assertIs(True, resp['success'])
        self.assertEqual(resp['action'], 'download_object')
        self.assertEqual(resp['object'], 'test')
        self.assertEqual(resp['path'], 'test')

    def test_download_version_id(self):
        self.opts['version_id'] = '23456.7'
        with mock.patch('swiftclient.service.Connection') as mock_conn:
            header = {'content-length': self.obj_len,
                      'etag': self.obj_etag}
            mock_conn.get_object.return_value = header, self._readbody()

            resp = SwiftService()._download_object_job(mock_conn,
                                                       'c',
                                                       'test',
                                                       self.opts)

        self.assertIsNone(resp.get('error'))
        self.assertIs(True, resp['success'])
        self.assertEqual(resp['action'], 'download_object')
        self.assertEqual(resp['object'], 'test')
        self.assertEqual(resp['path'], 'test')
        self.assertEqual(mock_conn.get_object.mock_calls, [
            mock.call(
                'c', 'test', headers={}, query_string='version-id=23456.7',
                resp_chunk_size=65536, response_dict={}),
        ])

    @mock.patch('swiftclient.service.interruptable_as_completed')
    @mock.patch('swiftclient.service.SwiftService._download_container')
    @mock.patch('swiftclient.service.SwiftService._download_object_job')
    def test_download_with_objects_empty(self, mock_down_obj,
                                         mock_down_cont, mock_as_comp):
        fake_future = Future()
        fake_future.set_result(1)
        mock_as_comp.return_value = [fake_future]
        service = SwiftService()
        next(service.download('c', [], self.opts), None)
        mock_down_obj.assert_not_called()
        mock_down_cont.assert_not_called()

        next(service.download('c', options=self.opts), None)
        self.assertTrue(mock_down_cont.called)

    def test_download_with_output_dir(self):
        with mock.patch('swiftclient.service.Connection') as mock_conn:
            header = {'content-length': self.obj_len,
                      'etag': self.obj_etag}
            mock_conn.get_object.return_value = header, self._readbody()

            options = self.opts.copy()
            options['out_directory'] = 'temp_dir'
            resp = SwiftService()._download_object_job(mock_conn,
                                                       'c',
                                                       'example/test',
                                                       options)

        self.assertIsNone(resp.get('error'))
        self.assertIs(True, resp['success'])
        self.assertEqual(resp['action'], 'download_object')
        self.assertEqual(resp['object'], 'example/test')
        self.assertEqual(resp['path'], 'temp_dir/example/test')

    def test_download_with_remove_prefix(self):
        with mock.patch('swiftclient.service.Connection') as mock_conn:
            header = {'content-length': self.obj_len,
                      'etag': self.obj_etag}
            mock_conn.get_object.return_value = header, self._readbody()

            options = self.opts.copy()
            options['prefix'] = 'example/'
            options['remove_prefix'] = True
            resp = SwiftService()._download_object_job(mock_conn,
                                                       'c',
                                                       'example/test',
                                                       options)

        self.assertIsNone(resp.get('error'))
        self.assertIs(True, resp['success'])
        self.assertEqual(resp['action'], 'download_object')
        self.assertEqual(resp['object'], 'example/test')
        self.assertEqual(resp['path'], 'test')

    def test_download_with_remove_prefix_and_remove_slashes(self):
        with mock.patch('swiftclient.service.Connection') as mock_conn:
            header = {'content-length': self.obj_len,
                      'etag': self.obj_etag}
            mock_conn.get_object.return_value = header, self._readbody()

            options = self.opts.copy()
            options['prefix'] = 'example'
            options['remove_prefix'] = True
            resp = SwiftService()._download_object_job(mock_conn,
                                                       'c',
                                                       'example/test',
                                                       options)

        self.assertIsNone(resp.get('error'))
        self.assertIs(True, resp['success'])
        self.assertEqual(resp['action'], 'download_object')
        self.assertEqual(resp['object'], 'example/test')
        self.assertEqual(resp['path'], 'test')

    def test_download_with_output_dir_and_remove_prefix(self):
        with mock.patch('swiftclient.service.Connection') as mock_conn:
            header = {'content-length': self.obj_len,
                      'etag': self.obj_etag}
            mock_conn.get_object.return_value = header, self._readbody()

            options = self.opts.copy()
            options['prefix'] = 'example'
            options['out_directory'] = 'new/dir'
            options['remove_prefix'] = True
            resp = SwiftService()._download_object_job(mock_conn,
                                                       'c',
                                                       'example/test',
                                                       options)

        self.assertIsNone(resp.get('error'))
        self.assertIs(True, resp['success'])
        self.assertEqual(resp['action'], 'download_object')
        self.assertEqual(resp['object'], 'example/test')
        self.assertEqual(resp['path'], 'new/dir/test')

    def test_download_object_job_skip_identical(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 30)
            f.flush()

            err = swiftclient.ClientException('Object GET failed',
                                              http_status=304)

            def fake_get(*args, **kwargs):
                kwargs['response_dict']['headers'] = {}
                raise err

            mock_conn = mock.Mock()
            mock_conn.get_object.side_effect = fake_get
            type(mock_conn).attempts = mock.PropertyMock(return_value=2)
            expected_r = {
                'action': 'download_object',
                'container': 'test_c',
                'object': 'test_o',
                'success': False,
                'error': err,
                'response_dict': {'headers': {}},
                'path': 'test_o',
                'pseudodir': False,
                'attempts': 2,
                'traceback': mock.ANY,
                'error_timestamp': mock.ANY
            }

            s = SwiftService()
            r = s._download_object_job(conn=mock_conn,
                                       container='test_c',
                                       obj='test_o',
                                       options={'out_file': f.name,
                                                'out_directory': None,
                                                'prefix': None,
                                                'remove_prefix': False,
                                                'header': {},
                                                'yes_all': False,
                                                'skip_identical': True})
            self.assertEqual(r, expected_r)

            self.assertEqual(mock_conn.get_object.call_count, 1)
            mock_conn.get_object.assert_called_with(
                'test_c',
                'test_o',
                resp_chunk_size=65536,
                headers={'If-None-Match': md5(b'a' * 30).hexdigest()},
                query_string='multipart-manifest=get',
                response_dict=expected_r['response_dict'])

    def test_download_object_job_skip_identical_dlo(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 30)
            f.flush()
            on_disk_md5 = md5(b'a' * 30).hexdigest()
            segment_md5 = md5(b'a' * 10).hexdigest()

            mock_conn = mock.Mock()
            mock_conn.get_object.return_value = (
                {'x-object-manifest': 'test_c_segments/test_o/prefix'}, [b''])
            mock_conn.get_container.side_effect = [
                (None, [{'name': 'test_o/prefix/1',
                         'bytes': 10, 'hash': segment_md5},
                        {'name': 'test_o/prefix/2',
                         'bytes': 10, 'hash': segment_md5}]),
                (None, [{'name': 'test_o/prefix/3',
                         'bytes': 10, 'hash': segment_md5}]),
                (None, [])]

            type(mock_conn).attempts = mock.PropertyMock(return_value=2)
            expected_r = {
                'action': 'download_object',
                'container': 'test_c',
                'object': 'test_o',
                'success': False,
                'response_dict': {},
                'path': 'test_o',
                'pseudodir': False,
                'attempts': 2,
                'traceback': mock.ANY,
                'error_timestamp': mock.ANY
            }

            s = SwiftService()
            with mock.patch('swiftclient.service.get_conn',
                            return_value=mock_conn):
                r = s._download_object_job(conn=mock_conn,
                                           container='test_c',
                                           obj='test_o',
                                           options={'out_file': f.name,
                                                    'out_directory': None,
                                                    'prefix': None,
                                                    'remove_prefix': False,
                                                    'header': {},
                                                    'yes_all': False,
                                                    'skip_identical': True})

            err = r.pop('error')
            self.assertEqual("Large object is identical", err.msg)
            self.assertEqual(304, err.http_status)

            self.assertEqual(r, expected_r)

            self.assertEqual(mock_conn.get_object.call_count, 1)
            mock_conn.get_object.assert_called_with(
                'test_c',
                'test_o',
                resp_chunk_size=65536,
                headers={'If-None-Match': on_disk_md5},
                query_string='multipart-manifest=get',
                response_dict=expected_r['response_dict'])
            self.assertEqual(mock_conn.get_container.mock_calls, [
                mock.call('test_c_segments',
                          delimiter=None,
                          prefix='test_o/prefix',
                          marker='',
                          headers={}, query_string=None, version_marker=''),
                mock.call('test_c_segments',
                          delimiter=None,
                          prefix='test_o/prefix',
                          marker='test_o/prefix/2',
                          headers={}, query_string=None, version_marker=''),
                mock.call('test_c_segments',
                          delimiter=None,
                          prefix='test_o/prefix',
                          marker='test_o/prefix/3',
                          headers={}, query_string=None, version_marker='')])

    def test_download_object_job_skip_identical_nested_slo(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 30)
            f.flush()
            on_disk_md5 = md5(b'a' * 30).hexdigest()

            seg_etag = md5(b'a' * 10).hexdigest()
            submanifest = "[%s]" % ",".join(
                ['{"bytes":10,"hash":"%s"}' % seg_etag] * 2)
            submanifest_etag = md5(seg_etag.encode('ascii') * 2).hexdigest()
            manifest = "[%s]" % ",".join([
                '{"sub_slo":true,"name":"/test_c_segments/test_sub_slo",'
                '"bytes":20,"hash":"%s"}' % submanifest_etag,
                '{"bytes":10,"hash":"%s"}' % seg_etag])

            mock_conn = mock.Mock()
            mock_conn.get_object.side_effect = [
                ({'x-static-large-object': True,
                  'content-length': 30,
                  'etag': md5(submanifest_etag.encode('ascii') +
                              seg_etag.encode('ascii')).hexdigest()},
                 [manifest.encode('ascii')]),
                ({'x-static-large-object': True,
                  'content-length': 20,
                  'etag': submanifest_etag},
                 submanifest.encode('ascii'))]

            type(mock_conn).attempts = mock.PropertyMock(return_value=2)
            expected_r = {
                'action': 'download_object',
                'container': 'test_c',
                'object': 'test_o',
                'success': False,
                'response_dict': {},
                'path': 'test_o',
                'pseudodir': False,
                'attempts': 2,
                'traceback': mock.ANY,
                'error_timestamp': mock.ANY
            }

            s = SwiftService()
            with mock.patch('swiftclient.service.get_conn',
                            return_value=mock_conn):
                r = s._download_object_job(conn=mock_conn,
                                           container='test_c',
                                           obj='test_o',
                                           options={'out_file': f.name,
                                                    'out_directory': None,
                                                    'prefix': None,
                                                    'remove_prefix': False,
                                                    'header': {},
                                                    'yes_all': False,
                                                    'skip_identical': True})

            err = r.pop('error')
            self.assertEqual("Large object is identical", err.msg)
            self.assertEqual(304, err.http_status)

            self.assertEqual(r, expected_r)
            self.assertEqual(mock_conn.get_object.mock_calls, [
                mock.call('test_c',
                          'test_o',
                          resp_chunk_size=65536,
                          headers={'If-None-Match': on_disk_md5},
                          query_string='multipart-manifest=get',
                          response_dict={}),
                mock.call('test_c_segments',
                          'test_sub_slo',
                          query_string='multipart-manifest=get')])

    def test_download_object_job_skip_identical_diff_dlo(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 30)
            f.write(b'b')
            f.flush()
            on_disk_md5 = md5(b'a' * 30 + b'b').hexdigest()
            segment_md5 = md5(b'a' * 10).hexdigest()

            mock_conn = mock.Mock()
            mock_conn.get_object.side_effect = [
                ({'x-object-manifest': 'test_c_segments/test_o/prefix'},
                 [b'']),
                ({'x-object-manifest': 'test_c_segments/test_o/prefix'},
                 [b'a' * 30])]
            mock_conn.get_container.side_effect = [
                (None, [{'name': 'test_o/prefix/1',
                         'bytes': 10, 'hash': segment_md5},
                        {'name': 'test_o/prefix/2',
                         'bytes': 10, 'hash': segment_md5}]),
                (None, [{'name': 'test_o/prefix/3',
                         'bytes': 10, 'hash': segment_md5}]),
                (None, [])]

            type(mock_conn).attempts = mock.PropertyMock(return_value=2)
            type(mock_conn).auth_end_time = mock.PropertyMock(return_value=14)
            expected_r = {
                'action': 'download_object',
                'container': 'test_c',
                'object': 'test_o',
                'success': True,
                'response_dict': {},
                'path': 'test_o',
                'pseudodir': False,
                'read_length': 30,
                'attempts': 2,
                'start_time': 0,
                'headers_receipt': 1,
                'finish_time': 2,
                'auth_end_time': mock_conn.auth_end_time,
            }

            options = self.opts.copy()
            options['out_file'] = f.name
            options['skip_identical'] = True
            s = SwiftService()
            with mock.patch('swiftclient.service.time', side_effect=range(3)):
                with mock.patch('swiftclient.service.get_conn',
                                return_value=mock_conn):
                    r = s._download_object_job(
                        conn=mock_conn,
                        container='test_c',
                        obj='test_o',
                        options=options)

            self.maxDiff = None
            self.assertEqual(r, expected_r)

            self.assertEqual(mock_conn.get_container.mock_calls, [
                mock.call('test_c_segments',
                          delimiter=None,
                          prefix='test_o/prefix',
                          marker='',
                          headers={}, query_string=None, version_marker=''),
                mock.call('test_c_segments',
                          delimiter=None,
                          prefix='test_o/prefix',
                          marker='test_o/prefix/2',
                          headers={}, query_string=None, version_marker=''),
                mock.call('test_c_segments',
                          delimiter=None,
                          prefix='test_o/prefix',
                          marker='test_o/prefix/3',
                          headers={}, query_string=None, version_marker='')])
            self.assertEqual(mock_conn.get_object.mock_calls, [
                mock.call('test_c',
                          'test_o',
                          resp_chunk_size=65536,
                          headers={'If-None-Match': on_disk_md5},
                          query_string='multipart-manifest=get',
                          response_dict={}),
                mock.call('test_c',
                          'test_o',
                          resp_chunk_size=65536,
                          headers={'If-None-Match': on_disk_md5},
                          response_dict={})])

    def test_download_object_job_skip_identical_diff_nested_slo(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b'a' * 29)
            f.flush()
            on_disk_md5 = md5(b'a' * 29).hexdigest()

            seg_etag = md5(b'a' * 10).hexdigest()
            submanifest = "[%s]" % ",".join(
                ['{"bytes":10,"hash":"%s"}' % seg_etag] * 2)
            submanifest_etag = md5(seg_etag.encode('ascii') * 2).hexdigest()
            manifest = "[%s]" % ",".join([
                '{"sub_slo":true,"name":"/test_c_segments/test_sub_slo",'
                '"bytes":20,"hash":"%s"}' % submanifest_etag,
                '{"bytes":10,"hash":"%s"}' % seg_etag])

            mock_conn = mock.Mock()
            mock_conn.get_object.side_effect = [
                ({'x-static-large-object': True,
                  'content-length': 30,
                  'etag': md5(submanifest_etag.encode('ascii') +
                              seg_etag.encode('ascii')).hexdigest()},
                 [manifest.encode('ascii')]),
                ({'x-static-large-object': True,
                  'content-length': 20,
                  'etag': submanifest_etag},
                 submanifest.encode('ascii')),
                ({'x-static-large-object': True,
                  'content-length': 30,
                  'etag': md5(submanifest_etag.encode('ascii') +
                              seg_etag.encode('ascii')).hexdigest()},
                 [b'a' * 30])]

            type(mock_conn).attempts = mock.PropertyMock(return_value=2)
            type(mock_conn).auth_end_time = mock.PropertyMock(return_value=14)
            expected_r = {
                'action': 'download_object',
                'container': 'test_c',
                'object': 'test_o',
                'success': True,
                'response_dict': {},
                'path': 'test_o',
                'pseudodir': False,
                'read_length': 30,
                'attempts': 2,
                'start_time': 0,
                'headers_receipt': 1,
                'finish_time': 2,
                'auth_end_time': mock_conn.auth_end_time,
            }

            options = self.opts.copy()
            options['out_file'] = f.name
            options['skip_identical'] = True
            s = SwiftService()
            with mock.patch('swiftclient.service.time', side_effect=range(3)):
                with mock.patch('swiftclient.service.get_conn',
                                return_value=mock_conn):
                    r = s._download_object_job(
                        conn=mock_conn,
                        container='test_c',
                        obj='test_o',
                        options=options)

            self.assertEqual(r, expected_r)
            self.assertEqual(mock_conn.get_object.mock_calls, [
                mock.call('test_c',
                          'test_o',
                          resp_chunk_size=65536,
                          headers={'If-None-Match': on_disk_md5},
                          query_string='multipart-manifest=get',
                          response_dict={}),
                mock.call('test_c_segments',
                          'test_sub_slo',
                          query_string='multipart-manifest=get'),
                mock.call('test_c',
                          'test_o',
                          resp_chunk_size=65536,
                          headers={'If-None-Match': on_disk_md5},
                          response_dict={})])


class TestServicePost(_TestServiceBase):

    def setUp(self):
        super(TestServicePost, self).setUp()
        self.opts = swiftclient.service._default_local_options.copy()

    @mock.patch('swiftclient.service.MultiThreadingManager')
    @mock.patch('swiftclient.service.ResultsIterator')
    def test_object_post(self, res_iter, thread_manager):
        """
        Check post method translates strings and objects to _post_object_job
        calls correctly
        """
        tm_instance = mock.Mock()
        thread_manager.return_value = tm_instance

        self.opts.update({'meta': ["meta1:test1"], "header": ["hdr1:test1"]})
        spo = swiftclient.service.SwiftPostObject(
            "test_spo",
            {'meta': ["meta1:test2"], "header": ["hdr1:test2"]})

        SwiftService().post('test_c', ['test_o', spo], self.opts)

        calls = [
            mock.call(
                SwiftService._post_object_job, 'test_c', 'test_o',
                {
                    "X-Object-Meta-Meta1": "test1",
                    "Hdr1": "test1"},
                {}),
            mock.call(
                SwiftService._post_object_job, 'test_c', 'test_spo',
                {
                    "X-Object-Meta-Meta1": "test2",
                    "Hdr1": "test2"},
                {}),
        ]
        tm_instance.object_uu_pool.submit.assert_has_calls(calls)
        self.assertEqual(
            tm_instance.object_uu_pool.submit.call_count, len(calls))

        res_iter.assert_called_with(
            [tm_instance.object_uu_pool.submit()] * len(calls))


class TestServiceCopy(_TestServiceBase):

    def setUp(self):
        super(TestServiceCopy, self).setUp()
        self.opts = swiftclient.service._default_local_options.copy()

    @mock.patch('swiftclient.service.MultiThreadingManager')
    @mock.patch('swiftclient.service.interruptable_as_completed')
    def test_object_copy(self, inter_compl, thread_manager):
        """
        Check copy method translates strings and objects to _copy_object_job
        calls correctly
        """
        tm_instance = mock.Mock()
        thread_manager.return_value = tm_instance

        self.opts.update({'meta': ["meta1:test1"], "header": ["hdr1:test1"]})
        sco = swiftclient.service.SwiftCopyObject(
            "test_sco",
            options={'meta': ["meta1:test2"], "header": ["hdr1:test2"],
                     'destination': "/cont_new/test_sco"})

        res = SwiftService().copy('test_c', ['test_o', sco], self.opts)
        res = list(res)

        calls = [
            mock.call(
                SwiftService._create_container_job, 'cont_new', headers={}),
        ]
        tm_instance.container_pool.submit.assert_has_calls(calls,
                                                           any_order=True)
        self.assertEqual(
            tm_instance.container_pool.submit.call_count, len(calls))

        calls = [
            mock.call(
                SwiftService._copy_object_job, 'test_c', 'test_o',
                None,
                {
                    "X-Object-Meta-Meta1": "test1",
                    "Hdr1": "test1"},
                False),
            mock.call(
                SwiftService._copy_object_job, 'test_c', 'test_sco',
                '/cont_new/test_sco',
                {
                    "X-Object-Meta-Meta1": "test2",
                    "Hdr1": "test2"},
                False),
        ]
        tm_instance.object_uu_pool.submit.assert_has_calls(calls)
        self.assertEqual(
            tm_instance.object_uu_pool.submit.call_count, len(calls))

        inter_compl.assert_called_with(
            [tm_instance.object_uu_pool.submit()] * len(calls))

    def test_object_copy_fail_dest(self):
        """
        Destination in incorrect format and destination with object
        used when multiple objects are copied raises SwiftError
        """
        with self.assertRaises(SwiftError):
            list(SwiftService().copy('test_c', ['test_o'],
                                     {'destination': 'cont'}))
        with self.assertRaises(SwiftError):
            list(SwiftService().copy('test_c', ['test_o', 'test_o2'],
                                     {'destination': '/cont/obj'}))
