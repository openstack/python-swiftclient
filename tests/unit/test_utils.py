# Copyright (c) 2010-2013 OpenStack, LLC.
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
import mock
import six
import tempfile
from hashlib import md5

from swiftclient import utils as u


class TestConfigTrueValue(testtools.TestCase):

    def test_TRUE_VALUES(self):
        for v in u.TRUE_VALUES:
            self.assertEqual(v, v.lower())

    def test_config_true_value(self):
        orig_trues = u.TRUE_VALUES
        try:
            u.TRUE_VALUES = 'hello world'.split()
            for val in 'hello world HELLO WORLD'.split():
                self.assertTrue(u.config_true_value(val) is True)
            self.assertTrue(u.config_true_value(True) is True)
            self.assertTrue(u.config_true_value('foo') is False)
            self.assertTrue(u.config_true_value(False) is False)
        finally:
            u.TRUE_VALUES = orig_trues


class TestPrtBytes(testtools.TestCase):

    def test_zero_bytes(self):
        bytes_ = 0
        raw = '0'
        human = '0'
        self.assertEqual(raw, u.prt_bytes(bytes_, False).lstrip())
        self.assertEqual(human, u.prt_bytes(bytes_, True).lstrip())

    def test_one_byte(self):
        bytes_ = 1
        raw = '1'
        human = '1'
        self.assertEqual(raw, u.prt_bytes(bytes_, False).lstrip())
        self.assertEqual(human, u.prt_bytes(bytes_, True).lstrip())

    def test_less_than_one_k(self):
        bytes_ = (2 ** 10) - 1
        raw = '1023'
        human = '1023'
        self.assertEqual(raw, u.prt_bytes(bytes_, False).lstrip())
        self.assertEqual(human, u.prt_bytes(bytes_, True).lstrip())

    def test_one_k(self):
        bytes_ = 2 ** 10
        raw = '1024'
        human = '1.0K'
        self.assertEqual(raw, u.prt_bytes(bytes_, False).lstrip())
        self.assertEqual(human, u.prt_bytes(bytes_, True).lstrip())

    def test_a_decimal_k(self):
        bytes_ = (3 * 2 ** 10) + 512
        raw = '3584'
        human = '3.5K'
        self.assertEqual(raw, u.prt_bytes(bytes_, False).lstrip())
        self.assertEqual(human, u.prt_bytes(bytes_, True).lstrip())

    def test_a_bit_less_than_one_meg(self):
        bytes_ = (2 ** 20) - (2 ** 10)
        raw = '1047552'
        human = '1023K'
        self.assertEqual(raw, u.prt_bytes(bytes_, False).lstrip())
        self.assertEqual(human, u.prt_bytes(bytes_, True).lstrip())

    def test_just_a_hair_less_than_one_meg(self):
        bytes_ = (2 ** 20) - (2 ** 10) + 1
        raw = '1047553'
        human = '1.0M'
        self.assertEqual(raw, u.prt_bytes(bytes_, False).lstrip())
        self.assertEqual(human, u.prt_bytes(bytes_, True).lstrip())

    def test_one_meg(self):
        bytes_ = 2 ** 20
        raw = '1048576'
        human = '1.0M'
        self.assertEqual(raw, u.prt_bytes(bytes_, False).lstrip())
        self.assertEqual(human, u.prt_bytes(bytes_, True).lstrip())

    def test_ten_meg(self):
        bytes_ = 10 * 2 ** 20
        human = '10M'
        self.assertEqual(human, u.prt_bytes(bytes_, True).lstrip())

    def test_bit_less_than_ten_meg(self):
        bytes_ = (10 * 2 ** 20) - (100 * 2 ** 10)
        human = '9.9M'
        self.assertEqual(human, u.prt_bytes(bytes_, True).lstrip())

    def test_just_a_hair_less_than_ten_meg(self):
        bytes_ = (10 * 2 ** 20) - 1
        human = '10.0M'
        self.assertEqual(human, u.prt_bytes(bytes_, True).lstrip())

    def test_a_yotta(self):
        bytes_ = 42 * 2 ** 80
        self.assertEqual('42Y', u.prt_bytes(bytes_, True).lstrip())

    def test_overflow(self):
        bytes_ = 2 ** 90
        self.assertEqual('1024Y', u.prt_bytes(bytes_, True).lstrip())


class TestTempURL(testtools.TestCase):

    def setUp(self):
        super(TestTempURL, self).setUp()
        self.url = '/v1/AUTH_account/c/o'
        self.seconds = 3600
        self.key = 'correcthorsebatterystaple'
        self.method = 'GET'

    @mock.patch('hmac.HMAC.hexdigest')
    @mock.patch('time.time')
    def test_generate_temp_url(self, time_mock, hmac_mock):
        time_mock.return_value = 1400000000
        hmac_mock.return_value = 'temp_url_signature'
        expected_url = (
            '/v1/AUTH_account/c/o?'
            'temp_url_sig=temp_url_signature&'
            'temp_url_expires=1400003600')
        url = u.generate_temp_url(self.url, self.seconds, self.key,
                                  self.method)
        self.assertEqual(url, expected_url)

    def test_generate_temp_url_bad_seconds(self):
        self.assertRaises(TypeError,
                          u.generate_temp_url,
                          self.url,
                          'not_an_int',
                          self.key,
                          self.method)

        self.assertRaises(ValueError,
                          u.generate_temp_url,
                          self.url,
                          -1,
                          self.key,
                          self.method)


class TestReadableToIterable(testtools.TestCase):

    def test_iter(self):
        chunk_size = 4
        write_data = tuple(x.encode() for x in ('a', 'b', 'c', 'd'))
        actual_md5sum = md5()

        with tempfile.TemporaryFile() as f:
            for x in write_data:
                f.write(x * chunk_size)
                actual_md5sum.update(x * chunk_size)
            f.seek(0)
            data = u.ReadableToIterable(f, chunk_size, True)

            for i, data_chunk in enumerate(data):
                self.assertEquals(chunk_size, len(data_chunk))
                self.assertEquals(data_chunk, write_data[i] * chunk_size)

            self.assertEquals(actual_md5sum.hexdigest(), data.get_md5sum())

    def test_md5_creation(self):
        # Check creation with a real and noop md5 class
        data = u.ReadableToIterable(None, None, md5=True)
        self.assertEquals(md5().hexdigest(), data.get_md5sum())
        self.assertTrue(isinstance(data.md5sum, type(md5())))

        data = u.ReadableToIterable(None, None, md5=False)
        self.assertEquals('', data.get_md5sum())
        self.assertTrue(isinstance(data.md5sum, type(u.NoopMD5())))

    def test_unicode(self):
        # Check no errors are raised if unicode data is feed in.
        unicode_data = u'abc'
        actual_md5sum = md5(unicode_data.encode()).hexdigest()
        chunk_size = 2

        with tempfile.TemporaryFile(mode='w+') as f:
            f.write(unicode_data)
            f.seek(0)
            data = u.ReadableToIterable(f, chunk_size, True)

            x = next(data)
            self.assertEquals(2, len(x))
            self.assertEquals(unicode_data[:2], x)

            x = next(data)
            self.assertEquals(1, len(x))
            self.assertEquals(unicode_data[2:], x)

            self.assertEquals(actual_md5sum, data.get_md5sum())


class TestLengthWrapper(testtools.TestCase):

    def test_stringio(self):
        contents = six.StringIO(u'a' * 100)
        data = u.LengthWrapper(contents, 42, True)
        s = u'a' * 42
        read_data = u''.join(iter(data.read, ''))

        self.assertEqual(42, len(data))
        self.assertEqual(42, len(read_data))
        self.assertEqual(s, read_data)
        self.assertEqual(md5(s.encode()).hexdigest(), data.get_md5sum())

    def test_bytesio(self):
        contents = six.BytesIO(b'a' * 100)
        data = u.LengthWrapper(contents, 42, True)
        s = b'a' * 42
        read_data = b''.join(iter(data.read, ''))

        self.assertEqual(42, len(data))
        self.assertEqual(42, len(read_data))
        self.assertEqual(s, read_data)
        self.assertEqual(md5(s).hexdigest(), data.get_md5sum())

    def test_tempfile(self):
        with tempfile.NamedTemporaryFile(mode='wb') as f:
            f.write(b'a' * 100)
            f.flush()
            contents = open(f.name, 'rb')
            data = u.LengthWrapper(contents, 42, True)
            s = b'a' * 42
            read_data = b''.join(iter(data.read, ''))

            self.assertEqual(42, len(data))
            self.assertEqual(42, len(read_data))
            self.assertEqual(s, read_data)
            self.assertEqual(md5(s).hexdigest(), data.get_md5sum())

    def test_segmented_file(self):
        with tempfile.NamedTemporaryFile(mode='wb') as f:
            segment_length = 1024
            segments = ('a', 'b', 'c', 'd')
            for c in segments:
                f.write((c * segment_length).encode())
            f.flush()
            for i, c in enumerate(segments):
                contents = open(f.name, 'rb')
                contents.seek(i * segment_length)
                data = u.LengthWrapper(contents, segment_length, True)
                read_data = b''.join(iter(data.read, ''))
                s = (c * segment_length).encode()

                self.assertEqual(segment_length, len(data))
                self.assertEqual(segment_length, len(read_data))
                self.assertEqual(s, read_data)
                self.assertEqual(md5(s).hexdigest(), data.get_md5sum())
