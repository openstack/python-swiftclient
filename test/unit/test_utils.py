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

import gzip
import io
import json
import unittest
from unittest import mock
import tempfile
from time import gmtime, localtime, mktime, strftime, strptime
import hashlib

from swiftclient import utils as u


class TestConfigTrueValue(unittest.TestCase):

    def test_TRUE_VALUES(self):
        for v in u.TRUE_VALUES:
            self.assertEqual(v, v.lower())

    @mock.patch.object(u, 'TRUE_VALUES', 'hello world'.split())
    def test_config_true_value(self):
        for val in 'hello world HELLO WORLD'.split():
            self.assertIs(True, u.config_true_value(val))
        self.assertIs(True, u.config_true_value(True))
        self.assertIs(False, u.config_true_value('foo'))
        self.assertIs(False, u.config_true_value(False))


class TestPrtBytes(unittest.TestCase):

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


class TestParseTimestamp(unittest.TestCase):
    def test_int(self):
        self.assertEqual((1234, False), u.parse_timestamp(1234, False))
        self.assertEqual((3600, False), u.parse_timestamp('3600', False))

    def test_suffixed(self):
        self.assertEqual((54, False), u.parse_timestamp('54.321s', False))
        self.assertEqual((int(54.321 * 60), False),
                         u.parse_timestamp('54.321m', False))
        self.assertEqual((900, False),
                         u.parse_timestamp('15min', False))
        self.assertEqual((int(54.321 * 60 * 60), False),
                         u.parse_timestamp('54.321h', False))
        self.assertEqual((7200, False),
                         u.parse_timestamp('2hr', False))
        self.assertEqual((60 * 60 * 24, False), u.parse_timestamp('1d', False))

    def test_str(self):
        self.assertEqual((1615852800, True),
                         u.parse_timestamp('2021-03-16T00:00:00Z', False))

    def test_absolute(self):
        self.assertEqual((1234, True), u.parse_timestamp(1234, True))
        self.assertEqual((1615852800, True),
                         u.parse_timestamp('2021-03-16T00:00:00Z', True))

    def test_error(self):
        with self.assertRaises(ValueError):
            u.parse_timestamp('asdf', False)
        with self.assertRaises(ValueError):
            u.parse_timestamp(12.34, False)
        with self.assertRaises(ValueError):
            u.parse_timestamp('54.321', True)
        with self.assertRaises(ValueError):
            u.parse_timestamp(-1, False)


class TestTempURL(unittest.TestCase):
    url = '/v1/AUTH_account/c/o'
    seconds = 3600
    key = 'correcthorsebatterystaple'
    method = 'GET'
    expected_body = '\n'.join([
        method,
        '1400003600',
        url,
    ]).encode('utf-8')

    @property
    def expected_url(self):
        if isinstance(self.url, bytes):
            return self.url + (b'?temp_url_sig=temp_url_signature'
                               b'&temp_url_expires=1400003600')
        return self.url + (u'?temp_url_sig=temp_url_signature'
                           u'&temp_url_expires=1400003600')

    @property
    def expected_sha512_url(self):
        if isinstance(self.url, bytes):
            return self.url + (b'?temp_url_sig=sha512:dGVtcF91cmxfc2lnbmF0dXJl'
                               b'&temp_url_expires=1400003600')
        return self.url + (u'?temp_url_sig=sha512:dGVtcF91cmxfc2lnbmF0dXJl'
                           u'&temp_url_expires=1400003600')

    @mock.patch('hmac.HMAC')
    @mock.patch('time.time', return_value=1400000000)
    def test_generate_sha1_temp_url(self, time_mock, hmac_mock):
        hmac_mock().hexdigest.return_value = 'temp_url_signature'
        url = u.generate_temp_url(self.url, self.seconds,
                                  self.key, self.method, digest='sha1')
        key = self.key
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        self.assertEqual(url, self.expected_url)
        self.assertEqual(hmac_mock.mock_calls, [
            mock.call(),
            mock.call(key, self.expected_body, hashlib.sha1),
            mock.call().hexdigest(),
        ])
        self.assertIsInstance(url, type(self.url))

    @mock.patch('hmac.HMAC')
    @mock.patch('time.time', return_value=1400000000)
    def test_generate_sha512_temp_url(self, time_mock, hmac_mock):
        hmac_mock().digest.return_value = b'temp_url_signature'
        url = u.generate_temp_url(self.url, self.seconds,
                                  self.key, self.method, digest=hashlib.sha512)
        key = self.key
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        self.assertEqual(url, self.expected_sha512_url)
        self.assertEqual(hmac_mock.mock_calls, [
            mock.call(),
            mock.call(key, self.expected_body, hashlib.sha512),
            mock.call().digest(),
        ])
        self.assertIsInstance(url, type(self.url))

    @mock.patch('hmac.HMAC')
    @mock.patch('time.time', return_value=1400000000)
    def test_generate_sha256_temp_url_by_default(self, time_mock, hmac_mock):
        hmac_mock().hexdigest.return_value = 'temp_url_signature'
        url = u.generate_temp_url(self.url, self.seconds,
                                  self.key, self.method)
        key = self.key
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        self.assertEqual(url, self.expected_url)
        self.assertEqual(hmac_mock.mock_calls, [
            mock.call(),
            mock.call(key, self.expected_body, hashlib.sha256),
            mock.call().hexdigest(),
        ])
        self.assertIsInstance(url, type(self.url))

    @mock.patch('hmac.HMAC')
    @mock.patch('time.time', return_value=1400000000)
    def test_generate_temp_url_ip_range(self, time_mock, hmac_mock):
        hmac_mock().hexdigest.return_value = 'temp_url_signature'
        ip_ranges = [
            '1.2.3.4', '1.2.3.4/24', '2001:db8::',
            b'1.2.3.4', b'1.2.3.4/24', b'2001:db8::',
        ]
        path = '/v1/AUTH_account/c/o/'
        expected_url = path + ('?temp_url_sig=temp_url_signature'
                               '&temp_url_expires=1400003600'
                               '&temp_url_ip_range=')
        for ip_range in ip_ranges:
            hmac_mock.reset_mock()
            url = u.generate_temp_url(path, self.seconds,
                                      self.key, self.method,
                                      ip_range=ip_range)
            key = self.key
            if not isinstance(key, bytes):
                key = key.encode('utf-8')

            if isinstance(ip_range, bytes):
                ip_range_expected_url = (
                    expected_url + ip_range.decode('utf-8')
                )
                expected_body = '\n'.join([
                    'ip=' + ip_range.decode('utf-8'),
                    self.method,
                    '1400003600',
                    path,
                ]).encode('utf-8')
            else:
                ip_range_expected_url = expected_url + ip_range
                expected_body = '\n'.join([
                    'ip=' + ip_range,
                    self.method,
                    '1400003600',
                    path,
                ]).encode('utf-8')

            self.assertEqual(url, ip_range_expected_url)

            self.assertEqual(hmac_mock.mock_calls, [
                mock.call(key, expected_body, hashlib.sha256),
                mock.call().hexdigest(),
            ])
            self.assertIsInstance(url, type(path))

    @mock.patch('hmac.HMAC')
    def test_generate_temp_url_iso8601_argument(self, hmac_mock):
        hmac_mock().hexdigest.return_value = 'temp_url_signature'
        url = u.generate_temp_url(self.url, '2014-05-13T17:53:20Z',
                                  self.key, self.method)
        self.assertEqual(url, self.expected_url)

        # Don't care about absolute arg.
        url = u.generate_temp_url(self.url, '2014-05-13T17:53:20Z',
                                  self.key, self.method, absolute=True)
        self.assertEqual(url, self.expected_url)

        lt = localtime()
        expires = strftime(u.EXPIRES_ISO8601_FORMAT[:-1], lt)

        if not isinstance(self.expected_url, str):
            expected_url = self.expected_url.replace(
                b'1400003600', bytes(str(int(mktime(lt))), encoding='ascii'))
        else:
            expected_url = self.expected_url.replace(
                '1400003600', str(int(mktime(lt))))
        url = u.generate_temp_url(self.url, expires,
                                  self.key, self.method)
        self.assertEqual(url, expected_url)

        expires = strftime(u.SHORT_EXPIRES_ISO8601_FORMAT, lt)
        lt = strptime(expires, u.SHORT_EXPIRES_ISO8601_FORMAT)

        if not isinstance(self.expected_url, str):
            expected_url = self.expected_url.replace(
                b'1400003600', bytes(str(int(mktime(lt))), encoding='ascii'))
        else:
            expected_url = self.expected_url.replace(
                '1400003600', str(int(mktime(lt))))
        url = u.generate_temp_url(self.url, expires,
                                  self.key, self.method)
        self.assertEqual(url, expected_url)

    @mock.patch('hmac.HMAC')
    @mock.patch('time.time', return_value=1400000000)
    def test_generate_temp_url_iso8601_output(self, time_mock, hmac_mock):
        hmac_mock().hexdigest.return_value = 'temp_url_signature'
        url = u.generate_temp_url(self.url, self.seconds,
                                  self.key, self.method,
                                  iso8601=True)
        key = self.key
        if not isinstance(key, bytes):
            key = key.encode('utf-8')

        expires = strftime(u.EXPIRES_ISO8601_FORMAT, gmtime(1400003600))
        if not isinstance(self.url, str):
            self.assertTrue(url.endswith(bytes(expires, 'utf-8')))
        else:
            self.assertTrue(url.endswith(expires))
        self.assertEqual(hmac_mock.mock_calls, [
            mock.call(),
            mock.call(key, self.expected_body, hashlib.sha256),
            mock.call().hexdigest(),
        ])
        self.assertIsInstance(url, type(self.url))

    @mock.patch('hmac.HMAC')
    @mock.patch('time.time', return_value=1400000000)
    def test_generate_temp_url_prefix(self, time_mock, hmac_mock):
        hmac_mock().hexdigest.return_value = 'temp_url_signature'
        prefixes = ['', 'o', 'p0/p1/']
        for p in prefixes:
            hmac_mock.reset_mock()
            path = '/v1/AUTH_account/c/' + p
            expected_url = path + ('?temp_url_sig=temp_url_signature'
                                   '&temp_url_expires=1400003600'
                                   '&temp_url_prefix=' + p)
            expected_body = '\n'.join([
                self.method,
                '1400003600',
                'prefix:' + path,
            ]).encode('utf-8')
            url = u.generate_temp_url(path, self.seconds,
                                      self.key, self.method, prefix=True)
            key = self.key
            if not isinstance(key, bytes):
                key = key.encode('utf-8')
            self.assertEqual(url, expected_url)
            self.assertEqual(hmac_mock.mock_calls, [
                mock.call(key, expected_body, hashlib.sha256),
                mock.call().hexdigest(),
            ])

            self.assertIsInstance(url, type(path))

    def test_generate_temp_url_invalid_path(self):
        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url(b'/v1/a/c/\xff', self.seconds, self.key,
                                self.method)
        self.assertEqual(exc_manager.exception.args[0],
                         'path must be representable as UTF-8')

    @mock.patch('hmac.HMAC.hexdigest', return_value="temp_url_signature")
    def test_generate_absolute_expiry_temp_url(self, hmac_mock):
        if isinstance(self.expected_url, bytes):
            expected_url = self.expected_url.replace(
                b'1400003600', b'2146636800')
        else:
            expected_url = self.expected_url.replace(
                '1400003600', '2146636800')
        url = u.generate_temp_url(self.url, 2146636800, self.key, self.method,
                                  absolute=True)
        self.assertEqual(url, expected_url)

    def test_generate_temp_url_bad_time(self):
        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url(self.url, 'not_an_int', self.key, self.method)
        self.assertEqual(exc_manager.exception.args[0], u.TIME_ERRMSG)

        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url(self.url, -1, self.key, self.method)
        self.assertEqual(exc_manager.exception.args[0], u.TIME_ERRMSG)

        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url(self.url, 1.1, self.key, self.method)
        self.assertEqual(exc_manager.exception.args[0], u.TIME_ERRMSG)

        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url(self.url, '-1', self.key, self.method)
        self.assertEqual(exc_manager.exception.args[0], u.TIME_ERRMSG)

        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url(self.url, '1.1', self.key, self.method)
        self.assertEqual(exc_manager.exception.args[0], u.TIME_ERRMSG)
        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url(self.url, '2015-05', self.key, self.method)
        self.assertEqual(exc_manager.exception.args[0], u.TIME_ERRMSG)

        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url(
                self.url, '2015-05-01T01:00', self.key, self.method)
        self.assertEqual(exc_manager.exception.args[0], u.TIME_ERRMSG)

    def test_generate_temp_url_bad_path(self):
        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url('/v1/a/c', 60, self.key, self.method)
        self.assertEqual(exc_manager.exception.args[0],
                         'path must be full path to an object e.g. /v1/a/c/o')

        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url('v1/a/c/o', 60, self.key, self.method)
        self.assertEqual(exc_manager.exception.args[0],
                         'path must be full path to an object e.g. /v1/a/c/o')

        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url('blah/v1/a/c/o', 60, self.key, self.method)
        self.assertEqual(exc_manager.exception.args[0],
                         'path must be full path to an object e.g. /v1/a/c/o')

        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url('/v1//c/o', 60, self.key, self.method)
        self.assertEqual(exc_manager.exception.args[0],
                         'path must be full path to an object e.g. /v1/a/c/o')

        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url('/v1/a/c/', 60, self.key, self.method)
        self.assertEqual(exc_manager.exception.args[0],
                         'path must be full path to an object e.g. /v1/a/c/o')

        with self.assertRaises(ValueError) as exc_manager:
            u.generate_temp_url('/v1/a/c', 60, self.key, self.method,
                                prefix=True)
        self.assertEqual(exc_manager.exception.args[0],
                         'path must at least contain /v1/a/c/')


class TestTempURLUnicodePathAndKey(TestTempURL):
    url = '/v1/\u00e4/c/\u00f3'
    key = 'k\u00e9y'
    seconds = '1hr'
    expected_body = '\n'.join([
        'GET',
        '1400003600',
        url,
    ]).encode('utf-8')


class TestTempURLUnicodePathBytesKey(TestTempURL):
    url = '/v1/\u00e4/c/\u00f3'
    key = 'k\u00e9y'.encode('utf-8')
    seconds = '60m'
    expected_body = '\n'.join([
        'GET',
        '1400003600',
        url,
    ]).encode('utf-8')


class TestTempURLBytesPathUnicodeKey(TestTempURL):
    url = '/v1/\u00e4/c/\u00f3'.encode('utf-8')
    key = 'k\u00e9y'
    expected_body = b'\n'.join([
        b'GET',
        b'1400003600',
        url,
    ])


class TestTempURLBytesPathAndKey(TestTempURL):
    url = '/v1/\u00e4/c/\u00f3'.encode('utf-8')
    key = 'k\u00e9y'.encode('utf-8')
    expected_body = b'\n'.join([
        b'GET',
        b'1400003600',
        url,
    ])


class TestTempURLBytesPathAndNonUtf8Key(TestTempURL):
    url = '/v1/\u00e4/c/\u00f3'.encode('utf-8')
    key = b'k\xffy'
    expected_body = b'\n'.join([
        b'GET',
        b'1400003600',
        url,
    ])


class TestReadableToIterable(unittest.TestCase):

    def test_iter(self):
        chunk_size = 4
        write_data = tuple(x.encode() for x in ('a', 'b', 'c', 'd'))
        actual_md5sum = hashlib.md5()

        with tempfile.TemporaryFile() as f:
            for x in write_data:
                f.write(x * chunk_size)
                actual_md5sum.update(x * chunk_size)
            f.seek(0)
            data = u.ReadableToIterable(f, chunk_size, True)

            for i, data_chunk in enumerate(data):
                self.assertEqual(chunk_size, len(data_chunk))
                self.assertEqual(data_chunk, write_data[i] * chunk_size)

            self.assertEqual(actual_md5sum.hexdigest(), data.get_md5sum())

    def test_md5_creation(self):
        # Check creation with a real and noop md5 class
        data = u.ReadableToIterable(None, None, md5=True)
        self.assertEqual(hashlib.md5().hexdigest(), data.get_md5sum())
        self.assertIs(type(hashlib.md5()), type(data.md5sum))

        data = u.ReadableToIterable(None, None, md5=False)
        self.assertEqual('', data.get_md5sum())
        self.assertIs(u.NoopMD5, type(data.md5sum))

    def test_unicode(self):
        # Check no errors are raised if unicode data is feed in.
        unicode_data = 'abc'
        actual_md5sum = hashlib.md5(unicode_data.encode()).hexdigest()
        chunk_size = 2

        with tempfile.TemporaryFile(mode='w+') as f:
            f.write(unicode_data)
            f.seek(0)
            data = u.ReadableToIterable(f, chunk_size, True)

            x = next(data)
            self.assertEqual(2, len(x))
            self.assertEqual(unicode_data[:2], x)

            x = next(data)
            self.assertEqual(1, len(x))
            self.assertEqual(unicode_data[2:], x)

            self.assertEqual(actual_md5sum, data.get_md5sum())


class TestLengthWrapper(unittest.TestCase):

    def test_stringio(self):
        contents = io.StringIO('a' * 50 + 'b' * 50)
        contents.seek(22)
        data = u.LengthWrapper(contents, 42, True)
        s = 'a' * 28 + 'b' * 14
        read_data = ''.join(iter(data.read, ''))

        self.assertEqual(42, len(data))
        self.assertEqual(42, len(read_data))
        self.assertEqual(s, read_data)
        self.assertEqual(hashlib.md5(s.encode()).hexdigest(),
                         data.get_md5sum())

        data.reset()
        self.assertEqual(hashlib.md5().hexdigest(), data.get_md5sum())

        read_data = ''.join(iter(data.read, ''))
        self.assertEqual(42, len(read_data))
        self.assertEqual(s, read_data)
        self.assertEqual(hashlib.md5(s.encode()).hexdigest(),
                         data.get_md5sum())

    def test_bytesio(self):
        contents = io.BytesIO(b'a' * 50 + b'b' * 50)
        contents.seek(22)
        data = u.LengthWrapper(contents, 42, True)
        s = b'a' * 28 + b'b' * 14
        read_data = b''.join(iter(data.read, ''))

        self.assertEqual(42, len(data))
        self.assertEqual(42, len(read_data))
        self.assertEqual(s, read_data)
        self.assertEqual(hashlib.md5(s).hexdigest(), data.get_md5sum())

    def test_tempfile(self):
        with tempfile.NamedTemporaryFile(mode='wb') as f:
            f.write(b'a' * 100)
            f.flush()
            with open(f.name, 'rb') as contents:
                data = u.LengthWrapper(contents, 42, True)
                s = b'a' * 42
                read_data = b''.join(iter(data.read, ''))

                self.assertEqual(42, len(data))
                self.assertEqual(42, len(read_data))
                self.assertEqual(s, read_data)
                self.assertEqual(hashlib.md5(s).hexdigest(), data.get_md5sum())

    def test_segmented_file(self):
        with tempfile.NamedTemporaryFile(mode='wb') as f:
            segment_length = 1024
            segments = ('a', 'b', 'c', 'd')
            for c in segments:
                f.write((c * segment_length).encode())
            f.flush()
            for i, c in enumerate(segments):
                with open(f.name, 'rb') as contents:
                    contents.seek(i * segment_length)
                    data = u.LengthWrapper(contents, segment_length, True)
                    read_data = b''.join(iter(data.read, ''))
                    s = (c * segment_length).encode()

                    self.assertEqual(segment_length, len(data))
                    self.assertEqual(segment_length, len(read_data))
                    self.assertEqual(s, read_data)
                    self.assertEqual(hashlib.md5(s).hexdigest(),
                                     data.get_md5sum())

                    data.reset()
                    self.assertEqual(hashlib.md5().hexdigest(),
                                     data.get_md5sum())
                    read_data = b''.join(iter(data.read, ''))
                    self.assertEqual(segment_length, len(data))
                    self.assertEqual(segment_length, len(read_data))
                    self.assertEqual(s, read_data)
                    self.assertEqual(hashlib.md5(s).hexdigest(),
                                     data.get_md5sum())


class TestGroupers(unittest.TestCase):
    def test_n_at_a_time(self):
        result = list(u.n_at_a_time(range(100), 9))
        self.assertEqual([9] * 11 + [1], list(map(len, result)))

        result = list(u.n_at_a_time(range(100), 10))
        self.assertEqual([10] * 10, list(map(len, result)))

        result = list(u.n_at_a_time(range(100), 11))
        self.assertEqual([11] * 9 + [1], list(map(len, result)))

        result = list(u.n_at_a_time(range(100), 12))
        self.assertEqual([12] * 8 + [4], list(map(len, result)))

    def test_n_groups(self):
        result = list(u.n_groups(range(100), 9))
        self.assertEqual([12] * 8 + [4], list(map(len, result)))

        result = list(u.n_groups(range(100), 10))
        self.assertEqual([10] * 10, list(map(len, result)))

        result = list(u.n_groups(range(100), 11))
        self.assertEqual([10] * 10, list(map(len, result)))

        result = list(u.n_groups(range(100), 12))
        self.assertEqual([9] * 11 + [1], list(map(len, result)))


class TestApiResponeParser(unittest.TestCase):

    def test_utf8_default(self):
        result = u.parse_api_response(
            {}, '{"test": "\u2603"}'.encode('utf8'))
        self.assertEqual({'test': '\u2603'}, result)

        result = u.parse_api_response(
            {}, '{"test": "\\u2603"}'.encode('utf8'))
        self.assertEqual({'test': '\u2603'}, result)

    def test_bad_json(self):
        self.assertRaises(ValueError, u.parse_api_response,
                          {}, b'{"foo": "bar}')

    def test_bad_utf8(self):
        self.assertRaises(UnicodeDecodeError, u.parse_api_response,
                          {}, b'{"foo": "b\xffr"}')

    def test_latin_1(self):
        result = u.parse_api_response(
            {'content-type': 'application/json; charset=iso8859-1'},
            b'{"t\xe9st": "\xff"}')
        self.assertEqual({'t\xe9st': '\xff'}, result)

    def test_gzipped_utf8(self):
        buf = io.BytesIO()
        gz = gzip.GzipFile(fileobj=buf, mode='w')
        gz.write('{"test": "\u2603"}'.encode('utf8'))
        gz.close()
        result = u.parse_api_response(
            {'content-encoding': 'gzip'},
            buf.getvalue())
        self.assertEqual({'test': '\u2603'}, result)


class TestGetBody(unittest.TestCase):

    def test_not_gzipped(self):
        result = u.parse_api_response(
            {}, '{"test": "\\u2603"}'.encode('utf8'))
        self.assertEqual({'test': '\u2603'}, result)

    def test_gzipped_body(self):
        buf = io.BytesIO()
        gz = gzip.GzipFile(fileobj=buf, mode='w')
        gz.write('{"test": "\u2603"}'.encode('utf8'))
        gz.close()
        result = u.parse_api_response(
            {'content-encoding': 'gzip'},
            buf.getvalue())
        self.assertEqual({'test': '\u2603'}, result)


class JSONTracker:
    def __init__(self, data):
        self.data = data
        self.calls = []

    def __iter__(self):
        for item in self.data:
            self.calls.append(('read', item))
            yield item

    def write(self, s):
        self.calls.append(('write', s))


class TestJSONableIterable(unittest.TestCase):
    def test_json_dump_iterencodes(self):
        t = JSONTracker([1, 'fish', 2, 'fish'])
        json.dump(u.JSONableIterable(t), t)
        self.assertEqual(t.calls, [
            ('read', 1),
            ('write', '[1'),
            ('read', 'fish'),
            ('write', ', "fish"'),
            ('read', 2),
            ('write', ', 2'),
            ('read', 'fish'),
            ('write', ', "fish"'),
            ('write', ']'),
        ])

    def test_json_dump_empty_iter(self):
        t = JSONTracker([])
        json.dump(u.JSONableIterable(t), t)
        self.assertEqual(t.calls, [
            ('write', '[]'),
        ])
