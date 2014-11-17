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

import testtools
from hashlib import md5

from swiftclient.service import SwiftService, SwiftError
import swiftclient


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
        # md5 should not be initalized if large object headers are present
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
