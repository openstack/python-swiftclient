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
import mock
import testtools
from mock import Mock, PropertyMock
from six.moves.queue import Queue, Empty as QueueEmptyError
from hashlib import md5

import swiftclient
from swiftclient.service import SwiftService, SwiftError
from swiftclient.client import Connection


class TestSwiftPostObject(testtools.TestCase):

    def setUp(self):
        self.spo = swiftclient.service.SwiftPostObject
        super(TestSwiftPostObject, self).setUp()

    def test_create(self):
        spo = self.spo('obj_name')

        self.assertEqual(spo.object_name, 'obj_name')
        self.assertEqual(spo.options, None)

    def test_create_with_invalid_name(self):
        # empty strings are not allowed as names
        self.assertRaises(SwiftError, self.spo, '')

        # names cannot be anything but strings
        self.assertRaises(SwiftError, self.spo, 1)


class TestSwiftReader(testtools.TestCase):

    def setUp(self):
        self.sr = swiftclient.service._SwiftReader
        super(TestSwiftReader, self).setUp()
        self.md5_type = type(md5())

    def test_create(self):
        sr = self.sr('path', 'body', {})

        self.assertEqual(sr._path, 'path')
        self.assertEqual(sr._body, 'body')
        self.assertEqual(sr._content_length, None)
        self.assertEqual(sr._expected_etag, None)

        self.assertNotEqual(sr._actual_md5, None)
        self.assertTrue(isinstance(sr._actual_md5, self.md5_type))

    def test_create_with_large_object_headers(self):
        # md5 should not be initialized if large object headers are present
        sr = self.sr('path', 'body', {'x-object-manifest': 'test'})
        self.assertEqual(sr._path, 'path')
        self.assertEqual(sr._body, 'body')
        self.assertEqual(sr._content_length, None)
        self.assertEqual(sr._expected_etag, None)
        self.assertEqual(sr._actual_md5, None)

        sr = self.sr('path', 'body', {'x-static-large-object': 'test'})
        self.assertEqual(sr._path, 'path')
        self.assertEqual(sr._body, 'body')
        self.assertEqual(sr._content_length, None)
        self.assertEqual(sr._expected_etag, None)
        self.assertEqual(sr._actual_md5, None)

    def test_create_with_content_length(self):
        sr = self.sr('path', 'body', {'content-length': 5})

        self.assertEqual(sr._path, 'path')
        self.assertEqual(sr._body, 'body')
        self.assertEqual(sr._content_length, 5)
        self.assertEqual(sr._expected_etag, None)

        self.assertNotEqual(sr._actual_md5, None)
        self.assertTrue(isinstance(sr._actual_md5, self.md5_type))

        # Check Contentlength raises error if it isnt an integer
        self.assertRaises(SwiftError, self.sr, 'path', 'body',
                          {'content-length': 'notanint'})

    def test_context_usage(self):
        def _context(sr):
            with sr:
                pass

        sr = self.sr('path', 'body', {})
        _context(sr)

        # Check error is raised if expected etag doesnt match calculated md5.
        # md5 for a SwiftReader that has done nothing is
        # d41d8cd98f00b204e9800998ecf8427e  i.e md5 of nothing
        sr = self.sr('path', 'body', {'etag': 'doesntmatch'})
        self.assertRaises(SwiftError, _context, sr)

        sr = self.sr('path', 'body',
                     {'etag': 'd41d8cd98f00b204e9800998ecf8427e'})
        _context(sr)

        # Check error is raised if SwiftReader doesnt read the same length
        # as the content length it is created with
        sr = self.sr('path', 'body', {'content-length': 5})
        self.assertRaises(SwiftError, _context, sr)

        sr = self.sr('path', 'body', {'content-length': 5})
        sr._actual_read = 5
        _context(sr)

    def test_buffer(self):
        # md5 = 97ac82a5b825239e782d0339e2d7b910
        mock_buffer_content = ['abc'.encode()] * 3

        sr = self.sr('path', mock_buffer_content, {})
        for x in sr.buffer():
            pass

        self.assertEqual(sr._actual_read, 9)
        self.assertEqual(sr._actual_md5.hexdigest(),
                         '97ac82a5b825239e782d0339e2d7b910')


class TestServiceDelete(testtools.TestCase):
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

    def _get_mock_connection(self, attempts=2):
        m = Mock(spec=Connection)
        type(m).attempts = PropertyMock(return_value=attempts)
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

    def _assertDictEqual(self, a, b, m=None):
        # assertDictEqual is not available in py2.6 so use a shallow check
        # instead
        if hasattr(self, 'assertDictEqual'):
            self.assertDictEqual(a, b, m)
        else:
            self.assertTrue(isinstance(a, dict))
            self.assertTrue(isinstance(b, dict))
            self.assertEqual(len(a), len(b), m)
            for k, v in a.items():
                self.assertTrue(k in b, m)
                self.assertEqual(b[k], v, m)

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
        self._assertDictEqual(expected_r, r)
        self._assertDictEqual(expected_r, self._get_queue(mock_q))

    def test_delete_segment_exception(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        mock_conn.delete_object = Mock(side_effect=self.exc)
        expected_r = self._get_expected({
            'action': 'delete_segment',
            'object': 'test_s',
            'success': False,
            'error': self.exc
        })

        r = SwiftService._delete_segment(mock_conn, 'test_c', 'test_s', mock_q)

        mock_conn.delete_object.assert_called_once_with(
            'test_c', 'test_s', response_dict={}
        )
        self._assertDictEqual(expected_r, r)
        self._assertDictEqual(expected_r, self._get_queue(mock_q))

    def test_delete_object(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        mock_conn.head_object = Mock(return_value={})
        expected_r = self._get_expected({
            'action': 'delete_object',
            'success': True
        })

        s = SwiftService()
        r = s._delete_object(mock_conn, 'test_c', 'test_o', self.opts, mock_q)

        mock_conn.head_object.assert_called_once_with('test_c', 'test_o')
        mock_conn.delete_object.assert_called_once_with(
            'test_c', 'test_o', query_string=None, response_dict={}
        )
        self._assertDictEqual(expected_r, r)

    def test_delete_object_exception(self):
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        mock_conn.delete_object = Mock(side_effect=self.exc)
        expected_r = self._get_expected({
            'action': 'delete_object',
            'success': False,
            'error': self.exc
        })
        # _delete_object doesnt populate attempts or response dict if it hits
        # an error. This may not be the correct behaviour.
        del expected_r['response_dict'], expected_r['attempts']

        s = SwiftService()
        r = s._delete_object(mock_conn, 'test_c', 'test_o', self.opts, mock_q)

        mock_conn.head_object.assert_called_once_with('test_c', 'test_o')
        mock_conn.delete_object.assert_called_once_with(
            'test_c', 'test_o', query_string=None, response_dict={}
        )
        self._assertDictEqual(expected_r, r)

    def test_delete_object_slo_support(self):
        # If SLO headers are present the delete call should include an
        # additional query string to cause the right delete server side
        mock_q = Queue()
        mock_conn = self._get_mock_connection()
        mock_conn.head_object = Mock(
            return_value={'x-static-large-object': True}
        )
        expected_r = self._get_expected({
            'action': 'delete_object',
            'success': True
        })

        s = SwiftService()
        r = s._delete_object(mock_conn, 'test_c', 'test_o', self.opts, mock_q)

        mock_conn.head_object.assert_called_once_with('test_c', 'test_o')
        mock_conn.delete_object.assert_called_once_with(
            'test_c', 'test_o',
            query_string='multipart-manifest=delete',
            response_dict={}
        )
        self._assertDictEqual(expected_r, r)

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
        mock_conn.head_object = Mock(
            return_value={'x-object-manifest': 'manifest_c/manifest_p'}
        )
        mock_conn.get_container = Mock(
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

        self._assertDictEqual(expected_r, r)
        expected = [
            mock.call('test_c', 'test_o', query_string=None, response_dict={}),
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

        r = SwiftService._delete_empty_container(mock_conn, 'test_c')

        mock_conn.delete_container.assert_called_once_with(
            'test_c', response_dict={}
        )
        self._assertDictEqual(expected_r, r)

    def test_delete_empty_container_excpetion(self):
        mock_conn = self._get_mock_connection()
        mock_conn.delete_container = Mock(side_effect=self.exc)
        expected_r = self._get_expected({
            'action': 'delete_container',
            'success': False,
            'object': None,
            'error': self.exc
        })

        s = SwiftService()
        r = s._delete_empty_container(mock_conn, 'test_c')

        mock_conn.delete_container.assert_called_once_with(
            'test_c', response_dict={}
        )
        self._assertDictEqual(expected_r, r)


class TestService(testtools.TestCase):

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
