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
"""Miscellaneous utility functions for use with Swift."""
from calendar import timegm
import collections
import gzip
import hashlib
import hmac
import json
import logging
import six
import time
import traceback

TRUE_VALUES = set(('true', '1', 'yes', 'on', 't', 'y'))
EMPTY_ETAG = 'd41d8cd98f00b204e9800998ecf8427e'
EXPIRES_ISO8601_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
SHORT_EXPIRES_ISO8601_FORMAT = '%Y-%m-%d'
TIME_ERRMSG = ('time must either be a whole number or in specific '
               'ISO 8601 format.')


def config_true_value(value):
    """
    Returns True if the value is either True or a string in TRUE_VALUES.
    Returns False otherwise.
    This function comes from swift.common.utils.config_true_value()
    """
    return value is True or \
        (isinstance(value, six.string_types) and value.lower() in TRUE_VALUES)


def prt_bytes(num_bytes, human_flag):
    """
    convert a number > 1024 to printable format, either in 4 char -h format as
    with ls -lh or return as 12 char right justified string
    """

    if not human_flag:
        return '%12s' % num_bytes

    num = float(num_bytes)
    suffixes = [None] + list('KMGTPEZY')
    for suffix in suffixes[:-1]:
        if num <= 1023:
            break
        num /= 1024.0
    else:
        suffix = suffixes[-1]

    if not suffix:  # num_bytes must be < 1024
        return '%4s' % num_bytes
    elif num >= 10:
        return '%3d%s' % (num, suffix)
    else:
        return '%.1f%s' % (num, suffix)


def generate_temp_url(path, seconds, key, method, absolute=False,
                      prefix=False, iso8601=False, ip_range=None):
    """Generates a temporary URL that gives unauthenticated access to the
    Swift object.

    :param path: The full path to the Swift object or prefix if
        a prefix-based temporary URL should be generated. Example:
        /v1/AUTH_account/c/o or /v1/AUTH_account/c/prefix.
    :param seconds: time in seconds or ISO 8601 timestamp.
        If absolute is False and this is the string representation of an
        integer, then this specifies the amount of time in seconds for which
        the temporary URL will be valid.
        If absolute is True then this specifies an absolute time at which the
        temporary URL will expire.
    :param key: The secret temporary URL key set on the Swift
        cluster. To set a key, run 'swift post -m
        "Temp-URL-Key: <substitute tempurl key here>"'
    :param method: A HTTP method, typically either GET or PUT, to allow
        for this temporary URL.
    :param absolute: if True then the seconds parameter is interpreted as a
        Unix timestamp, if seconds represents an integer.
    :param prefix: if True then a prefix-based temporary URL will be generated.
    :param iso8601: if True, a URL containing an ISO 8601 UTC timestamp
        instead of a UNIX timestamp will be created.
    :param ip_range: if a valid ip range, restricts the temporary URL to the
        range of ips.
    :raises ValueError: if timestamp or path is not in valid format.
    :return: the path portion of a temporary URL
    """
    try:
        try:
            timestamp = float(seconds)
        except ValueError:
            formats = (
                EXPIRES_ISO8601_FORMAT,
                EXPIRES_ISO8601_FORMAT[:-1],
                SHORT_EXPIRES_ISO8601_FORMAT)
            for f in formats:
                try:
                    t = time.strptime(seconds, f)
                except ValueError:
                    t = None
                else:
                    if f == EXPIRES_ISO8601_FORMAT:
                        timestamp = timegm(t)
                    else:
                        # Use local time if UTC designator is missing.
                        timestamp = int(time.mktime(t))

                    absolute = True
                    break

            if t is None:
                raise ValueError()
        else:
            if not timestamp.is_integer():
                raise ValueError()
            timestamp = int(timestamp)
            if timestamp < 0:
                raise ValueError()
    except ValueError:
        raise ValueError(TIME_ERRMSG)

    if isinstance(path, six.binary_type):
        try:
            path_for_body = path.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError('path must be representable as UTF-8')
    else:
        path_for_body = path

    parts = path_for_body.split('/', 4)
    if len(parts) != 5 or parts[0] or not all(parts[1:(4 if prefix else 5)]):
        if prefix:
            raise ValueError('path must at least contain /v1/a/c/')
        else:
            raise ValueError('path must be full path to an object'
                             ' e.g. /v1/a/c/o')

    standard_methods = ['GET', 'PUT', 'HEAD', 'POST', 'DELETE']
    if method.upper() not in standard_methods:
        logger = logging.getLogger("swiftclient")
        logger.warning('Non default HTTP method %s for tempurl specified, '
                       'possibly an error', method.upper())

    if not absolute:
        expiration = int(time.time() + timestamp)
    else:
        expiration = timestamp

    hmac_parts = [method.upper(), str(expiration),
                  ('prefix:' if prefix else '') + path_for_body]

    if ip_range:
        if isinstance(ip_range, six.binary_type):
            try:
                ip_range = ip_range.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError(
                    'ip_range must be representable as UTF-8'
                )
        hmac_parts.insert(0, "ip=%s" % ip_range)

    hmac_body = u'\n'.join(hmac_parts)

    # Encode to UTF-8 for py3 compatibility
    if not isinstance(key, six.binary_type):
        key = key.encode('utf-8')
    sig = hmac.new(key, hmac_body.encode('utf-8'), hashlib.sha1).hexdigest()

    if iso8601:
        expiration = time.strftime(
            EXPIRES_ISO8601_FORMAT, time.gmtime(expiration))

    temp_url = u'{path}?temp_url_sig={sig}&temp_url_expires={exp}'.format(
        path=path_for_body, sig=sig, exp=expiration)

    if ip_range:
        temp_url += u'&temp_url_ip_range={}'.format(ip_range)

    if prefix:
        temp_url += u'&temp_url_prefix={}'.format(parts[4])
    # Have return type match path from caller
    if isinstance(path, six.binary_type):
        return temp_url.encode('utf-8')
    else:
        return temp_url


def get_body(headers, body):
    if headers.get('content-encoding') == 'gzip':
        with gzip.GzipFile(fileobj=six.BytesIO(body), mode='r') as gz:
            nbody = gz.read()
        return nbody
    return body


def parse_api_response(headers, body):
    body = get_body(headers, body)
    charset = 'utf-8'
    # Swift *should* be speaking UTF-8, but check content-type just in case
    content_type = headers.get('content-type', '')
    if '; charset=' in content_type:
        charset = content_type.split('; charset=', 1)[1].split(';', 1)[0]

    return json.loads(body.decode(charset))


def split_request_headers(options, prefix=''):
    headers = {}
    if isinstance(options, collections.Mapping):
        options = options.items()
    for item in options:
        if isinstance(item, six.string_types):
            if ':' not in item:
                raise ValueError(
                    "Metadata parameter %s must contain a ':'.\n"
                    "Example: 'Color:Blue' or 'Size:Large'"
                    % item
                )
            item = item.split(':', 1)
        if len(item) != 2:
            raise ValueError(
                "Metadata parameter %r must have exactly two items.\n"
                "Example: ('Color', 'Blue') or ['Size', 'Large']"
                % (item, )
            )
        headers[(prefix + item[0]).title()] = item[1].strip()
    return headers


def report_traceback():
    """
    Reports a timestamp and full traceback for a given exception.

    :return: Full traceback and timestamp.
    """
    try:
        formatted_lines = traceback.format_exc()
        now = time.time()
        return formatted_lines, now
    except AttributeError:
        return None, None


class NoopMD5(object):
    def __init__(self, *a, **kw):
        pass

    def update(self, *a, **kw):
        pass

    def hexdigest(self, *a, **kw):
        return ''


class ReadableToIterable(object):
    """
    Wrap a filelike object and act as an iterator.

    It is recommended to use this class only on files opened in binary mode.
    Due to the Unicode changes in Python 3, files are now opened using an
    encoding not suitable for use with the md5 class and because of this
    hit the exception on every call to next. This could cause problems,
    especially with large files and small chunk sizes.
    """

    def __init__(self, content, chunk_size=65536, md5=False):
        """
        :param content: The filelike object that is yielded from.
        :param chunk_size: The max size of each yielded item.
        :param md5: Flag to enable calculating the MD5 of the content
                    as it is yielded.
        """
        self.md5sum = hashlib.md5() if md5 else NoopMD5()
        self.content = content
        self.chunk_size = chunk_size

    def get_md5sum(self):
        return self.md5sum.hexdigest()

    def __next__(self):
        """
        Both ``__next__`` and ``next`` are provided to allow compatibility
        with python 2 and python 3 and their use of ``iterable.next()``
        and ``next(iterable)`` respectively.
        """
        chunk = self.content.read(self.chunk_size)
        if not chunk:
            raise StopIteration

        try:
            self.md5sum.update(chunk)
        except TypeError:
            self.md5sum.update(chunk.encode())

        return chunk

    def next(self):
        return self.__next__()

    def __iter__(self):
        return self


class LengthWrapper(object):
    """
    Wrap a filelike object with a maximum length.

    Fix for https://github.com/kennethreitz/requests/issues/1648.
    It is recommended to use this class only on files opened in binary mode.
    """
    def __init__(self, readable, length, md5=False):
        """
        :param readable: The filelike object to read from.
        :param length: The maximum amount of content that can be read from
                       the filelike object before it is simulated to be
                       empty.
        :param md5: Flag to enable calculating the MD5 of the content
                    as it is read.
        """
        self._md5 = md5
        self._reset_md5()
        self._length = self._remaining = length
        self._readable = readable
        self._can_reset = all(hasattr(readable, attr)
                              for attr in ('seek', 'tell'))
        if self._can_reset:
            self._start = readable.tell()

    def __len__(self):
        return self._length

    def _reset_md5(self):
        self.md5sum = hashlib.md5() if self._md5 else NoopMD5()

    def get_md5sum(self):
        return self.md5sum.hexdigest()

    def read(self, size=-1):
        if self._remaining <= 0:
            return ''

        to_read = self._remaining if size < 0 else min(size, self._remaining)
        chunk = self._readable.read(to_read)
        self._remaining -= len(chunk)

        try:
            self.md5sum.update(chunk)
        except TypeError:
            self.md5sum.update(chunk.encode())

        return chunk

    @property
    def reset(self):
        if self._can_reset:
            return self._reset
        raise AttributeError("%r object has no attribute 'reset'" %
                             type(self).__name__)

    def _reset(self, *args, **kwargs):
        if not self._can_reset:
            raise TypeError('%r object cannot be reset; needs both seek and '
                            'tell methods' % type(self._readable).__name__)
        self._readable.seek(self._start)
        self._reset_md5()
        self._remaining = self._length


def iter_wrapper(iterable):
    for chunk in iterable:
        if len(chunk) == 0:
            # If we emit an empty chunk, requests will go ahead and send it,
            # causing the server to close the connection
            continue
        yield chunk


def n_at_a_time(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def n_groups(seq, n):
    items_per_group = ((len(seq) - 1) // n) + 1
    return n_at_a_time(seq, items_per_group)


def normalize_manifest_path(path):
    if six.PY2 and isinstance(path, six.text_type):
        path = path.encode('utf-8')
    if path.startswith('/'):
        return path[1:]
    return path


class JSONableIterable(list):
    def __init__(self, iterable):
        self._iterable = iter(iterable)
        try:
            self._peeked = next(self._iterable)
            self._has_items = True
        except StopIteration:
            self._peeked = None
            self._has_items = False

    def __bool__(self):
        return self._has_items

    __nonzero__ = __bool__

    def __iter__(self):
        if self._has_items:
            yield self._peeked
        for item in self._iterable:
            yield item
