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

import io
import contextlib
from genericpath import getmtime
import getpass
import hashlib
import json
import logging
import os
import tempfile
import unittest
from unittest import mock
import textwrap
from time import localtime, mktime, strftime, strptime

import swiftclient
from swiftclient.service import SwiftError
import swiftclient.shell
import swiftclient.utils

from os.path import basename, dirname
from .utils import (
    CaptureOutput, fake_get_auth_keystone,
    FakeKeystone, StubResponse, MockHttpTest)
from swiftclient.utils import (
    EMPTY_ETAG, EXPIRES_ISO8601_FORMAT,
    SHORT_EXPIRES_ISO8601_FORMAT, TIME_ERRMSG)

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError:
    InsecureRequestWarning = None

BUILTIN_OPEN = 'builtins.open'

mocked_os_environ = {
    'ST_AUTH': 'http://localhost:8080/auth/v1.0',
    'ST_USER': 'test:tester',
    'ST_KEY': 'testing'
}
clean_os_environ = {}
environ_prefixes = ('ST_', 'OS_')
for key in os.environ:
    if any(key.startswith(m) for m in environ_prefixes):
        clean_os_environ[key] = ''


def _make_args(cmd, opts, os_opts, separator='-', flags=None, cmd_args=None):
    """
    Construct command line arguments for given options.
    """
    args = [""]
    flags = flags or []
    for k, v in opts.items():
        args.append("--" + k.replace("_", "-"))
        if v is not None:
            args.append(v)
    for k, v in os_opts.items():
        args.append("--os" + separator + k.replace("_", separator))
        if v is not None:
            args.append(v)
    for flag in flags:
        args.append('--%s' % flag)
    if cmd:
        args.append(cmd)
    if cmd_args:
        args.extend(cmd_args)
    return args


def _make_env(opts, os_opts):
    """
    Construct a dict of environment variables for given options.
    """
    env = {}
    for k, v in opts.items():
        key = 'ST_' + k.upper().replace('-', '_')
        env[key] = v
    for k, v in os_opts.items():
        key = 'OS_' + k.upper().replace('-', '_')
        env[key] = v
    return env


def _make_cmd(cmd, opts, os_opts, use_env=False, flags=None, cmd_args=None):
    flags = flags or []
    if use_env:
        # set up fake environment variables and make a minimal command line
        env = _make_env(opts, os_opts)
        args = _make_args(cmd, {}, {}, separator='-', flags=flags,
                          cmd_args=cmd_args)
    else:
        # set up empty environment and make full command line
        env = {}
        args = _make_args(cmd, opts, os_opts, separator='-', flags=flags,
                          cmd_args=cmd_args)
    return args, env


@contextlib.contextmanager
def patch_disable_warnings():
    if InsecureRequestWarning is None:
        # If InsecureRequestWarning isn't available, disbale_warnings won't
        # be either; they both came in with
        # https://github.com/requests/requests/commit/811ee4e and left again
        # in https://github.com/requests/requests/commit/8e17600
        yield None
    else:
        with mock.patch('requests.packages.urllib3.disable_warnings') \
                as patched:
            yield patched


@mock.patch.dict(os.environ, mocked_os_environ)
class TestShell(unittest.TestCase):
    def setUp(self):
        super(TestShell, self).setUp()
        tmpfile = tempfile.NamedTemporaryFile(delete=False)
        self.tmpfile = tmpfile.name

    def tearDown(self):
        try:
            os.remove(self.tmpfile)
        except OSError:
            pass
        super(TestShell, self).tearDown()

    @mock.patch('swiftclient.service.Connection')
    def test_stat_account(self, connection):
        argv = ["", "stat"]
        return_headers = {
            'x-account-container-count': '1',
            'x-account-object-count': '2',
            'x-account-bytes-used': '3',
            'content-length': 0,
            'date': ''}
        connection.return_value.head_account.return_value = return_headers
        connection.return_value.url = 'http://127.0.0.1/v1/AUTH_account'
        with CaptureOutput() as output:
            swiftclient.shell.main(argv)

            self.assertEqual(output.out,
                             '   Account: AUTH_account\n'
                             'Containers: 1\n'
                             '   Objects: 2\n'
                             '     Bytes: 3\n')

    @mock.patch('swiftclient.service.Connection')
    def test_stat_account_with_headers(self, connection):
        argv = ["", "stat", "-H", "Skip-Middleware: Test"]
        return_headers = {
            'x-account-container-count': '1',
            'x-account-object-count': '2',
            'x-account-bytes-used': '3',
            'content-length': 0,
            'date': ''}
        connection.return_value.head_account.return_value = return_headers
        connection.return_value.url = 'http://127.0.0.1/v1/AUTH_account'
        with CaptureOutput() as output:
            swiftclient.shell.main(argv)

            self.assertEqual(output.out,
                             '   Account: AUTH_account\n'
                             'Containers: 1\n'
                             '   Objects: 2\n'
                             '     Bytes: 3\n')
        self.assertEqual(connection.return_value.head_account.mock_calls, [
            mock.call(headers={'Skip-Middleware': 'Test'})])

    @mock.patch('swiftclient.service.Connection')
    def test_stat_container(self, connection):
        return_headers = {
            'x-container-object-count': '1',
            'x-container-bytes-used': '2',
            'x-container-read': 'test2:tester2',
            'x-container-write': 'test3:tester3',
            'x-container-sync-to': 'other',
            'x-container-sync-key': 'secret',
        }
        argv = ["", "stat", "container"]
        connection.return_value.head_container.return_value = return_headers
        connection.return_value.url = 'http://127.0.0.1/v1/AUTH_account'
        with CaptureOutput() as output:
            swiftclient.shell.main(argv)

            self.assertEqual(output.out,
                             '  Account: AUTH_account\n'
                             'Container: container\n'
                             '  Objects: 1\n'
                             '    Bytes: 2\n'
                             ' Read ACL: test2:tester2\n'
                             'Write ACL: test3:tester3\n'
                             '  Sync To: other\n'
                             ' Sync Key: secret\n')

    @mock.patch('swiftclient.service.Connection')
    def test_stat_container_with_headers(self, connection):
        return_headers = {
            'x-container-object-count': '1',
            'x-container-bytes-used': '2',
            'x-container-read': 'test2:tester2',
            'x-container-write': 'test3:tester3',
            'x-container-sync-to': 'other',
            'x-container-sync-key': 'secret',
        }
        argv = ["", "stat", "container", "-H", "Skip-Middleware: Test"]
        connection.return_value.head_container.return_value = return_headers
        connection.return_value.url = 'http://127.0.0.1/v1/AUTH_account'
        with CaptureOutput() as output:
            swiftclient.shell.main(argv)

            self.assertEqual(output.out,
                             '  Account: AUTH_account\n'
                             'Container: container\n'
                             '  Objects: 1\n'
                             '    Bytes: 2\n'
                             ' Read ACL: test2:tester2\n'
                             'Write ACL: test3:tester3\n'
                             '  Sync To: other\n'
                             ' Sync Key: secret\n')
        self.assertEqual(connection.return_value.head_container.mock_calls, [
            mock.call('container', headers={'Skip-Middleware': 'Test'})])

    @mock.patch('swiftclient.service.Connection')
    def test_stat_version_id(self, connection):
        argv = ["", "stat", "--version-id", "1"]
        with self.assertRaises(SystemExit) as caught:
            swiftclient.shell.main(argv)
        self.assertEqual(str(caught.exception),
                         "--version-id option only allowed for "
                         "object stats")

        argv = ["", "stat", "--version-id", "1", "container"]
        with self.assertRaises(SystemExit) as caught:
            swiftclient.shell.main(argv)
        self.assertEqual(str(caught.exception),
                         "--version-id option only allowed for "
                         "object stats")

        argv = ["", "stat", "--version-id", "1", "container", "object"]
        connection.return_value.head_object.return_value = {}
        with CaptureOutput():
            swiftclient.shell.main(argv)
        self.assertEqual([mock.call('container', 'object', headers={},
                                    query_string='version-id=1')],
                         connection.return_value.head_object.mock_calls)

    @mock.patch('swiftclient.service.Connection')
    def test_stat_object(self, connection):
        return_headers = {
            'x-object-manifest': 'manifest',
            'etag': 'md5',
            'last-modified': 'yesterday',
            'content-type': 'text/plain',
            'content-length': 42,
        }
        argv = ["", "stat", "container", "object"]
        connection.return_value.head_object.return_value = return_headers
        connection.return_value.url = 'http://127.0.0.1/v1/AUTH_account'

        with CaptureOutput() as output:
            swiftclient.shell.main(argv)

            self.assertEqual(output.out,
                             '       Account: AUTH_account\n'
                             '     Container: container\n'
                             '        Object: object\n'
                             '  Content Type: text/plain\n'
                             'Content Length: 42\n'
                             ' Last Modified: yesterday\n'
                             '          ETag: md5\n'
                             '      Manifest: manifest\n')

    @mock.patch('swiftclient.service.Connection')
    def test_stat_object_with_headers(self, connection):
        return_headers = {
            'x-object-manifest': 'manifest',
            'etag': 'md5',
            'last-modified': 'yesterday',
            'content-type': 'text/plain',
            'content-length': 42,
        }
        argv = ["", "stat", "container", "object",
                "-H", "Skip-Middleware: Test"]
        connection.return_value.head_object.return_value = return_headers
        connection.return_value.url = 'http://127.0.0.1/v1/AUTH_account'

        with CaptureOutput() as output:
            swiftclient.shell.main(argv)

            self.assertEqual(output.out,
                             '       Account: AUTH_account\n'
                             '     Container: container\n'
                             '        Object: object\n'
                             '  Content Type: text/plain\n'
                             'Content Length: 42\n'
                             ' Last Modified: yesterday\n'
                             '          ETag: md5\n'
                             '      Manifest: manifest\n')
        self.assertEqual(connection.return_value.head_object.mock_calls, [
            mock.call('container', 'object',
                      headers={'Skip-Middleware': 'Test'},
                      query_string=None)])

    def test_list_account_with_delimiter(self):
        argv = ["", "list", "--delimiter", "foo"]
        with self.assertRaises(SystemExit) as caught:
            swiftclient.shell.main(argv)
        self.assertEqual(str(caught.exception),
                         "-d option only allowed for "
                         "container listings")

    @mock.patch('swiftclient.service.Connection')
    def test_list_container_with_versions(self, connection):
        connection.return_value.get_container.side_effect = [
            [None, [
                {'name': 'foo', 'version_id': '2',
                 'content_type': 'text/plain',
                 'last_modified': '123T456', 'bytes': 78},
                {'name': 'foo', 'version_id': '1',
                 'content_type': 'text/rtf',
                 'last_modified': '123T456', 'bytes': 90},
                {'name': 'bar', 'version_id': 'null',
                 'content_type': 'text/plain',
                 'last_modified': '123T456', 'bytes': 123},
            ]],
            [None, []],
        ]
        argv = ["", "list", "container", "--versions"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        calls = [mock.call('container', delimiter=None, headers={}, marker='',
                           prefix=None, query_string='versions=true',
                           version_marker=''),
                 mock.call('container', delimiter=None, headers={},
                           marker='bar', prefix=None,
                           query_string='versions=true',
                           version_marker='null')]
        connection.return_value.get_container.assert_has_calls(calls)
        self.assertEqual([line.split() for line in output.out.split('\n')], [
            ['78', '123', '456', '2', 'text/plain', 'foo'],
            ['90', '123', '456', '1', 'text/rtf', 'foo'],
            ['123', '123', '456', 'null', 'text/plain', 'bar'],
            [],
        ])

    @mock.patch('swiftclient.service.Connection')
    def test_list_container_with_versions_old_swift(self, connection):
        # Versions of swift that don't support object-versioning won't
        # include verison_id keys in listings. We want to present that
        # as though the container is unversioned.
        connection.return_value.get_container.side_effect = [
            [None, [
                {'name': 'foo', 'content_type': 'text/plain',
                 'last_modified': '123T456', 'bytes': 78},
                {'name': 'bar', 'content_type': 'text/plain',
                 'last_modified': '123T456', 'bytes': 123},
            ]],
            [None, []],
        ]
        argv = ["", "list", "container", "--versions"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        calls = [mock.call('container', delimiter=None, headers={}, marker='',
                           prefix=None, query_string='versions=true',
                           version_marker=''),
                 mock.call('container', delimiter=None, headers={},
                           marker='bar', prefix=None,
                           query_string='versions=true', version_marker='')]
        connection.return_value.get_container.assert_has_calls(calls)
        self.assertEqual([line.split() for line in output.out.split('\n')], [
            ['78', '123', '456', 'null', 'text/plain', 'foo'],
            ['123', '123', '456', 'null', 'text/plain', 'bar'],
            [],
        ])

    def test_list_account_with_versions(self):
        argv = ["", "list", "--versions"]
        with self.assertRaises(SystemExit) as caught:
            swiftclient.shell.main(argv)
        self.assertEqual(str(caught.exception),
                         "--versions option only allowed for "
                         "container listings")

    @mock.patch('swiftclient.service.Connection')
    def test_list_json(self, connection):
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container'}]],
            [None, [{'name': '\u263A', 'some-custom-key': 'and value'}]],
            [None, []],
        ]

        argv = ["", "list", "--json"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        calls = [mock.call(marker='', prefix=None, headers={}),
                 mock.call(marker='container', prefix=None, headers={})]
        connection.return_value.get_account.assert_has_calls(calls)

        listing = [{'name': 'container'},
                   {'name': '\u263A', 'some-custom-key': 'and value'}]
        expected = json.dumps(listing, sort_keys=True, indent=2) + '\n'
        self.assertEqual(output.out, expected)

    @mock.patch('swiftclient.service.Connection')
    def test_list_account(self, connection):
        # Test account listing
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container'}]],
            [None, []],
        ]

        argv = ["", "list"]

        with CaptureOutput() as output:
            swiftclient.shell.main(argv)
            calls = [mock.call(marker='', prefix=None, headers={}),
                     mock.call(marker='container', prefix=None, headers={})]
            connection.return_value.get_account.assert_has_calls(calls)

            self.assertEqual(output.out, 'container\n')

    @mock.patch('swiftclient.service.Connection')
    def test_list_account_with_headers(self, connection):
        # Test account listing
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container'}]],
            [None, []],
        ]

        argv = ["", "list", '-H', 'Skip-Custom-Middleware: True']

        with CaptureOutput() as output:
            swiftclient.shell.main(argv)
            calls = [mock.call(marker='', prefix=None,
                               headers={'Skip-Custom-Middleware': 'True'}),
                     mock.call(marker='container', prefix=None,
                               headers={'Skip-Custom-Middleware': 'True'})]
            connection.return_value.get_account.assert_has_calls(calls)

            self.assertEqual(output.out, 'container\n')

    @mock.patch('swiftclient.service.Connection')
    def test_list_account_long(self, connection):
        # Test account listing
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container', 'bytes': 0, 'count': 0}]],
            [None, []],
        ]
        connection.return_value.head_container.return_value = {
            'x-timestamp': '1617393213.49752',
            'x-storage-policy': 'some-policy',
        }

        argv = ["", "list", "--lh"]
        with CaptureOutput() as output:
            swiftclient.shell.main(argv)
            calls = [mock.call(marker='', prefix=None, headers={}),
                     mock.call(marker='container', prefix=None, headers={})]
            connection.return_value.get_account.assert_has_calls(calls)

        self.assertEqual(
            output.out,
            '           0    0 2021-04-02 19:53:33 some-policy     container\n'
            '           0    0\n')

        # Now test again, this time without returning metadata
        connection.return_value.head_container.return_value = {}

        # Test account listing
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container', 'bytes': 0, 'count': 0}]],
            [None, []],
        ]

        argv = ["", "list", "--lh"]
        with CaptureOutput() as output:
            swiftclient.shell.main(argv)
            calls = [mock.call(marker='', prefix=None, headers={}),
                     mock.call(marker='container', prefix=None, headers={})]
            connection.return_value.get_account.assert_has_calls(calls)

        self.assertEqual(
            output.out,
            '           0    0 ????-??-?? ??:??:?? ???             container\n'
            '           0    0\n')

    def test_list_account_totals_error(self):
        # No --lh provided: expect info message about incorrect --totals use
        argv = ["", "list", "--totals"]

        with CaptureOutput() as output:
            self.assertRaises(SystemExit, swiftclient.shell.main, argv)
            self.assertEqual(output.err,
                             "Listing totals only works with -l or --lh.\n")

    @mock.patch('swiftclient.service.Connection')
    def test_list_account_totals(self, connection):

        # Test account listing, only total count and size
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container1', 'bytes': 1, 'count': 2},
                    {'name': 'container2', 'bytes': 2, 'count': 4}]],
            [None, []],
        ]

        argv = ["", "list", "--lh", "--totals"]
        with CaptureOutput() as output:
            swiftclient.shell.main(argv)
            calls = [mock.call(marker='', prefix=None, headers={})]
            connection.return_value.get_account.assert_has_calls(calls)
            self.assertEqual(output.out, '           6    3\n')

    @mock.patch('swiftclient.service.Connection')
    def test_list_container(self, connection):
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object_a'}]],
            [None, []],
        ]
        argv = ["", "list", "container"]
        with CaptureOutput() as output:
            swiftclient.shell.main(argv)
            calls = [
                mock.call('container', marker='',
                          delimiter=None, prefix=None, headers={},
                          query_string=None, version_marker=''),
                mock.call('container', marker='object_a',
                          delimiter=None, prefix=None, headers={},
                          query_string=None, version_marker='')]
            connection.return_value.get_container.assert_has_calls(calls)

            self.assertEqual(output.out, 'object_a\n')

        # Test container listing with --long and multiple pages
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object_a', 'bytes': 3,
                     'content_type': 'type/content',
                     'last_modified': '123T456'}]],
            [None, [{'name': 'object_b', 'bytes': 5,
                     'content_type': 'type/content',
                     'last_modified': '123T456'}]],
            [None, []],
        ]
        argv = ["", "list", "container", "--long"]
        with CaptureOutput() as output:
            swiftclient.shell.main(argv)
            calls = [
                mock.call('container', marker='',
                          delimiter=None, prefix=None, headers={},
                          query_string=None, version_marker=''),
                mock.call('container', marker='object_a',
                          delimiter=None, prefix=None, headers={},
                          query_string=None, version_marker='')]
            connection.return_value.get_container.assert_has_calls(calls)

            self.assertEqual(output.out,
                             '           3        123      456'
                             '             type/content object_a\n'
                             '           5        123      456'
                             '             type/content object_b\n'
                             '           8\n')

    @mock.patch('swiftclient.service.Connection')
    def test_list_container_with_headers(self, connection):
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object_a'}]],
            [None, []],
        ]
        argv = ["", "list", "container", "-H", "Skip-Middleware: Test"]
        with CaptureOutput() as output:
            swiftclient.shell.main(argv)
            calls = [
                mock.call('container', marker='',
                          delimiter=None, prefix=None,
                          headers={'Skip-Middleware': 'Test'},
                          query_string=None, version_marker=''),
                mock.call('container', marker='object_a',
                          delimiter=None, prefix=None,
                          headers={'Skip-Middleware': 'Test'},
                          query_string=None, version_marker='')]
            connection.return_value.get_container.assert_has_calls(calls)

            self.assertEqual(output.out, 'object_a\n')

    @mock.patch('swiftclient.service.Connection')
    def test_download_version_id(self, connection):
        argv = ["", "download", "--yes-all", "--version-id", "5"]
        with self.assertRaises(SystemExit) as caught:
            swiftclient.shell.main(argv)
        self.assertEqual(str(caught.exception),
                         "--version-id option only allowed for "
                         "object downloads")

        argv = ["", "download", "--version-id", "2", "container"]
        with self.assertRaises(SystemExit) as caught:
            swiftclient.shell.main(argv)
        self.assertEqual(str(caught.exception),
                         "--version-id option only allowed for "
                         "object downloads")

        argv = ["", "download", "--version-id", "1", "container", "object"]
        connection.return_value.head_object.return_value = {}
        connection.return_value.get_object.return_value = {}, ''
        connection.return_value.attempts = 0
        with CaptureOutput():
            swiftclient.shell.main(argv)
        self.assertEqual([mock.call('container', 'object', headers={},
                                    query_string='version-id=1',
                                    resp_chunk_size=65536,
                                    response_dict={})],
                         connection.return_value.get_object.mock_calls)

    @mock.patch('swiftclient.service.makedirs')
    @mock.patch('swiftclient.service.Connection')
    def test_download(self, connection, makedirs):
        objcontent = io.BytesIO(b'objcontent')
        connection.return_value.get_object.side_effect = [
            ({'content-type': 'text/plain',
              'etag': '2cbbfe139a744d6abbe695e17f3c1991'},
             objcontent),
            ({'content-type': 'text/plain',
              'etag': EMPTY_ETAG},
             '')
        ]

        # Test downloading whole container
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object'}]],
            [None, [{'name': 'pseudo/'}]],
            [None, []],
        ]
        connection.return_value.auth_end_time = 0
        connection.return_value.attempts = 0

        with mock.patch(BUILTIN_OPEN) as mock_open:
            argv = ["", "download", "container"]
            swiftclient.shell.main(argv)
        calls = [mock.call('container', 'object',
                           headers={}, resp_chunk_size=65536,
                           response_dict={}),
                 mock.call('container', 'pseudo/',
                           headers={}, resp_chunk_size=65536,
                           response_dict={})]
        connection.return_value.get_object.assert_has_calls(
            calls, any_order=True)
        mock_open.assert_called_once_with('object', 'wb', 65536)
        self.assertEqual([mock.call('pseudo')], makedirs.mock_calls)
        makedirs.reset_mock()

        # Test downloading single object
        objcontent = io.BytesIO(b'objcontent')
        connection.return_value.get_object.side_effect = [
            ({'content-type': 'text/plain',
              'etag': '2cbbfe139a744d6abbe695e17f3c1991'},
             objcontent)
        ]
        with mock.patch(BUILTIN_OPEN) as mock_open:
            argv = ["", "download", "container", "object"]
            swiftclient.shell.main(argv)
        connection.return_value.get_object.assert_called_with(
            'container', 'object', headers={}, resp_chunk_size=65536,
            response_dict={})
        mock_open.assert_called_with('object', 'wb', 65536)
        self.assertEqual([], makedirs.mock_calls)

        # Test downloading without md5 checks
        objcontent = io.BytesIO(b'objcontent')
        connection.return_value.get_object.side_effect = [
            ({'content-type': 'text/plain',
              'etag': '2cbbfe139a744d6abbe695e17f3c1991'},
             objcontent)
        ]
        with mock.patch(BUILTIN_OPEN) as mock_open, mock.patch(
                'swiftclient.service._SwiftReader') as sr:
            argv = ["", "download", "container", "object", "--ignore-check"]
            swiftclient.shell.main(argv)
        connection.return_value.get_object.assert_called_with(
            'container', 'object', headers={}, resp_chunk_size=65536,
            response_dict={})
        mock_open.assert_called_with('object', 'wb', 65536)
        sr.assert_called_once_with('object', mock.ANY, mock.ANY, False)
        self.assertEqual([], makedirs.mock_calls)

        # Test downloading single object to stdout
        objcontent = io.BytesIO(b'objcontent')
        connection.return_value.get_object.side_effect = [
            ({'content-type': 'text/plain',
              'etag': '2cbbfe139a744d6abbe695e17f3c1991'},
             objcontent)
        ]
        with CaptureOutput() as output:
            argv = ["", "download", "--output", "-", "container", "object"]
            swiftclient.shell.main(argv)
            self.assertEqual('objcontent', output.out)

    @mock.patch('swiftclient.service.shuffle')
    @mock.patch('swiftclient.service.Connection')
    def test_download_shuffle(self, connection, mock_shuffle):
        # Test that the container and object lists are shuffled
        mock_shuffle.side_effect = lambda l: l
        connection.return_value.get_object.return_value = [
            {'content-type': 'text/plain',
             'etag': EMPTY_ETAG},
            '']

        connection.return_value.get_container.side_effect = [
            (None, [{'name': 'object'}]),
            (None, [{'name': 'pseudo/'}]),
            (None, []),
        ]
        connection.return_value.auth_end_time = 0
        connection.return_value.attempts = 0
        connection.return_value.get_account.side_effect = [
            (None, [{'name': 'container'}]),
            (None, [])
        ]

        with mock.patch(BUILTIN_OPEN) as mock_open:
            with mock.patch('swiftclient.service.makedirs') as mock_mkdir:
                argv = ["", "download", "--all"]
                swiftclient.shell.main(argv)
        self.assertEqual(3, mock_shuffle.call_count)
        mock_shuffle.assert_any_call(['container'])
        mock_shuffle.assert_any_call(['object'])
        mock_shuffle.assert_any_call(['pseudo/'])
        mock_open.assert_called_once_with('container/object', 'wb', 65536)
        self.assertEqual([
            mock.call('container'),
            mock.call('container/pseudo'),
        ], mock_mkdir.mock_calls)

        # Test that the container and object lists are not shuffled
        mock_shuffle.reset_mock()

        connection.return_value.get_container.side_effect = [
            (None, [{'name': 'object'}]),
            (None, [{'name': 'pseudo/'}]),
            (None, []),
        ]
        connection.return_value.get_account.side_effect = [
            (None, [{'name': 'container'}]),
            (None, [])
        ]

        with mock.patch(BUILTIN_OPEN) as mock_open:
            with mock.patch('swiftclient.service.makedirs') as mock_mkdir:
                argv = ["", "download", "--all", "--no-shuffle"]
                swiftclient.shell.main(argv)
        self.assertEqual(0, mock_shuffle.call_count)
        mock_open.assert_called_once_with('container/object', 'wb', 65536)
        self.assertEqual([
            mock.call('container'),
            mock.call('container/pseudo'),
        ], mock_mkdir.mock_calls)

    @mock.patch('swiftclient.service.Connection')
    def test_download_no_content_type(self, connection):
        connection.return_value.get_object.return_value = [
            {'etag': EMPTY_ETAG},
            '']

        # Test downloading whole container
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object'}]],
            [None, [{'name': 'pseudo/'}]],
            [None, []],
        ]
        connection.return_value.auth_end_time = 0
        connection.return_value.attempts = 0

        with mock.patch(BUILTIN_OPEN) as mock_open:
            with mock.patch('swiftclient.service.makedirs') as mock_mkdir:
                argv = ["", "download", "container"]
                swiftclient.shell.main(argv)
        calls = [mock.call('container', 'object',
                           headers={}, resp_chunk_size=65536,
                           response_dict={}),
                 mock.call('container', 'pseudo/',
                           headers={}, resp_chunk_size=65536,
                           response_dict={})]
        connection.return_value.get_object.assert_has_calls(
            calls, any_order=True)
        mock_open.assert_called_once_with('object', 'wb', 65536)
        self.assertEqual([
            mock.call('pseudo'),
        ], mock_mkdir.mock_calls)

    @mock.patch('swiftclient.shell.walk')
    @mock.patch('swiftclient.service.Connection')
    def test_upload(self, connection, walk):
        connection.return_value.head_object.return_value = {
            'content-length': '0'}
        connection.return_value.put_object.return_value = EMPTY_ETAG
        connection.return_value.attempts = 0
        argv = ["", "upload", "container", self.tmpfile,
                "-H", "X-Storage-Policy:one",
                "--meta", "Color:Blue"]
        swiftclient.shell.main(argv)
        connection.return_value.put_container.assert_called_once_with(
            'container',
            {'X-Storage-Policy': 'one'},
            response_dict={})

        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            mock.ANY,
            content_length=0,
            headers={'x-object-meta-mtime': mock.ANY,
                     'X-Storage-Policy': 'one',
                     'X-Object-Meta-Color': 'Blue'},
            response_dict={})

        # upload to pseudo-folder (via <container> param)
        argv = ["", "upload", "container/pseudo-folder/nested", self.tmpfile,
                "-H", "X-Storage-Policy:one"]
        swiftclient.shell.main(argv)
        connection.return_value.put_container.assert_called_with(
            'container',
            {'X-Storage-Policy': 'one'},
            response_dict={})

        connection.return_value.put_object.assert_called_with(
            'container',
            'pseudo-folder/nested' + self.tmpfile,
            mock.ANY,
            content_length=0,
            headers={'x-object-meta-mtime': mock.ANY,
                     'X-Storage-Policy': 'one'},
            response_dict={})

        # Upload whole directory
        argv = ["", "upload", "container", "/tmp"]
        _tmpfile = self.tmpfile
        _tmpfile_dir = dirname(_tmpfile)
        _tmpfile_base = basename(_tmpfile)
        walk.return_value = [(_tmpfile_dir, [], [_tmpfile_base])]
        swiftclient.shell.main(argv)
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            mock.ANY,
            content_length=0,
            headers={'x-object-meta-mtime': mock.ANY},
            response_dict={})

        # Upload in segments
        connection.return_value.head_container.return_value = {
            'x-storage-policy': 'one'}
        argv = ["", "upload", "container", self.tmpfile, "-S", "10"]
        with open(self.tmpfile, "wb") as fh:
            fh.write(b'12345678901234567890')
        swiftclient.shell.main(argv)
        expected_calls = [mock.call('container',
                                    {'X-Storage-Policy': mock.ANY},
                                    response_dict={}),
                          mock.call('container_segments',
                                    {'X-Storage-Policy': mock.ANY},
                                    response_dict={})]
        connection.return_value.put_container.has_calls(expected_calls)
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            '',
            content_length=0,
            headers={'x-object-manifest': mock.ANY,
                     'x-object-meta-mtime': mock.ANY},
            response_dict={})

        # upload in segments to pseudo-folder (via <container> param)
        connection.reset_mock()
        connection.return_value.head_container.return_value = {
            'x-storage-policy': 'one'}
        argv = ["", "upload", "container/pseudo-folder/nested",
                self.tmpfile, "-S", "10", "--use-slo"]
        with open(self.tmpfile, "wb") as fh:
            fh.write(b'12345678901234567890')
        swiftclient.shell.main(argv)
        expected_calls = [mock.call('container',
                                    {},
                                    response_dict={}),
                          mock.call('container_segments',
                                    {'X-Storage-Policy': 'one'},
                                    response_dict={})]
        connection.return_value.put_container.assert_has_calls(expected_calls)
        connection.return_value.put_object.assert_called_with(
            'container',
            'pseudo-folder/nested' + self.tmpfile,
            mock.ANY,
            headers={
                'x-object-meta-mtime': mock.ANY,
            },
            query_string='multipart-manifest=put',
            response_dict=mock.ANY)

    @mock.patch('swiftclient.shell.walk')
    @mock.patch('swiftclient.service.Connection')
    def test_upload_skip_container_put(self, connection, walk):
        connection.return_value.head_object.return_value = {
            'content-length': '0'}
        connection.return_value.put_object.return_value = EMPTY_ETAG
        connection.return_value.attempts = 0
        argv = ["", "upload", "container", "--skip-container-put",
                self.tmpfile, "-H", "X-Storage-Policy:one",
                "--meta", "Color:Blue"]
        swiftclient.shell.main(argv)
        connection.return_value.put_container.assert_not_called()

        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            mock.ANY,
            content_length=0,
            headers={'x-object-meta-mtime': mock.ANY,
                     'X-Storage-Policy': 'one',
                     'X-Object-Meta-Color': 'Blue'},
            response_dict={})

        # Upload in segments
        connection.return_value.head_container.return_value = {
            'x-storage-policy': 'one'}
        argv = ["", "upload", "container", "--skip-container-put",
                self.tmpfile, "-S", "10"]
        with open(self.tmpfile, "wb") as fh:
            fh.write(b'12345678901234567890')
        swiftclient.shell.main(argv)
        # Both base and segments container are assumed to exist already
        connection.return_value.put_container.assert_not_called()
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            '',
            content_length=0,
            headers={'x-object-manifest': mock.ANY,
                     'x-object-meta-mtime': mock.ANY},
            response_dict={})

    @mock.patch('swiftclient.service.SwiftService.upload')
    def test_upload_object_with_account_readonly(self, upload):
        argv = ["", "upload", "container", self.tmpfile]
        upload.return_value = [
            {"success": False,
             "headers": {},
             "container": 'container',
             "action": 'create_container',
             "error": swiftclient.ClientException(
                 'Container PUT failed',
                 http_status=403,
                 http_reason='Forbidden',
                 http_response_content=b'<html><h1>Forbidden</h1>')
             }]

        with CaptureOutput() as output:
            swiftclient.shell.main(argv)
            self.assertTrue(output.err != '')
            warning_msg = "Warning: failed to create container 'container': " \
                          "403 Forbidden"
            self.assertTrue(output.err.startswith(warning_msg))

    @mock.patch('swiftclient.service.Connection')
    def test_upload_delete_slo_segments(self, connection):
        # Upload delete existing segments
        connection.return_value.head_container.return_value = {
            'x-storage-policy': 'one'}
        connection.return_value.attempts = 0
        argv = ["", "upload", "container", self.tmpfile]
        connection.return_value.head_object.side_effect = [
            {'x-static-large-object': 'true',  # For the upload call
             'content-length': '2'},
            {'x-static-large-object': 'false',  # For the 1st delete call
             'content-length': '2'},
            {'x-static-large-object': 'false',  # For the 2nd delete call
             'content-length': '2'}
        ]
        connection.return_value.get_object.return_value = (
            {},
            b'[{"name": "container1/old_seg1"},'
            b' {"name": "container2/old_seg2"}]'
        )
        connection.return_value.put_object.return_value = EMPTY_ETAG
        # create the delete_object child mock here in attempt to fix
        # https://bugs.launchpad.net/python-swiftclient/+bug/1480223
        connection.return_value.delete_object.return_value = None
        swiftclient.shell.main(argv)
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            mock.ANY,
            content_length=0,
            headers={'x-object-meta-mtime': mock.ANY},
            response_dict={})
        expected_delete_calls = [
            mock.call(
                'container1', 'old_seg1',
                response_dict={}
            ),
            mock.call(
                'container2', 'old_seg2',
                response_dict={}
            )
        ]
        self.assertEqual(
            sorted(expected_delete_calls),
            sorted(connection.return_value.delete_object.mock_calls)
        )

    @mock.patch('swiftclient.service.Connection')
    def test_upload_over_symlink_to_slo(self, connection):
        # Upload delete existing segments
        connection.return_value.head_container.return_value = {
            'x-storage-policy': 'one'}
        connection.return_value.attempts = 0
        connection.return_value.head_object.side_effect = [
            {'x-static-large-object': 'true',
             'content-location': '/v1/a/c/manifest',
             'content-length': '2'},
        ]
        connection.return_value.get_object.return_value = (
            {'content-location': '/v1/a/c/manifest'},
            b'[{"name": "container1/old_seg1"},'
            b' {"name": "container2/old_seg2"}]'
        )
        connection.return_value.put_object.return_value = EMPTY_ETAG
        connection.return_value.delete_object.return_value = None
        argv = ["", "upload", "container", self.tmpfile]
        swiftclient.shell.main(argv)
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            mock.ANY,
            content_length=0,
            headers={'x-object-meta-mtime': mock.ANY},
            response_dict={})
        self.assertEqual([], connection.return_value.delete_object.mock_calls)

    @mock.patch('swiftclient.service.Connection')
    def test_upload_leave_slo_segments(self, connection):
        # Test upload overwriting a manifest respects --leave-segments
        connection.return_value.head_container.return_value = {
            'x-storage-policy': 'one'}
        connection.return_value.attempts = 0
        argv = ["", "upload", "container", self.tmpfile, "--leave-segments"]
        connection.return_value.head_object.side_effect = [
            {'x-static-large-object': 'true',  # For the upload call
             'content-length': '2'}]
        connection.return_value.put_object.return_value = (
            'd41d8cd98f00b204e9800998ecf8427e')
        swiftclient.shell.main(argv)
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            mock.ANY,
            content_length=0,
            headers={'x-object-meta-mtime': mock.ANY},
            response_dict={})
        self.assertFalse(connection.return_value.delete_object.mock_calls)

    @mock.patch('swiftclient.service.Connection')
    def test_reupload_leaves_slo_segments(self, connection):
        with open(self.tmpfile, "wb") as fh:
            fh.write(b'12345678901234567890')
        mtime = '{:.6f}'.format(os.path.getmtime(self.tmpfile))
        expected_segments = [
            'container_segments/{}/slo/{}/20/10/{:08d}'.format(
                self.tmpfile[1:], mtime, i)
            for i in range(2)
        ]

        # Test re-upload overwriting a manifest doesn't remove
        # segments it just wrote
        connection.return_value.head_container.return_value = {
            'x-storage-policy': 'one'}
        connection.return_value.attempts = 0
        argv = ["", "upload", "container", self.tmpfile,
                "--use-slo", "-S", "10"]
        connection.return_value.head_object.side_effect = [
            {'x-static-large-object': 'true',  # For the upload call
             'content-length': '20'}]
        connection.return_value.get_object.return_value = (
            {},
            # we've already *got* the expected manifest!
            json.dumps([
                {'name': seg} for seg in expected_segments
            ]).encode('ascii')
        )
        connection.return_value.put_object.return_value = (
            'd41d8cd98f00b204e9800998ecf8427e')
        swiftclient.shell.main(argv)
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile[1:],  # drop leading /
            mock.ANY,
            headers={'x-object-meta-mtime': mtime},
            query_string='multipart-manifest=put',
            response_dict={})
        self.assertFalse(connection.return_value.delete_object.mock_calls)

    @mock.patch('swiftclient.service.Connection')
    def test_upload_delete_dlo_segments(self, connection):
        # Upload delete existing segments
        connection.return_value.head_container.return_value = {
            'x-storage-policy': 'one'}
        connection.return_value.attempts = 0
        argv = ["", "upload", "container", self.tmpfile]
        connection.return_value.head_object.side_effect = [
            {'x-object-manifest': 'container1/prefix',
             'content-length': '0'},
            {},
            {}
        ]
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'prefix_a', 'bytes': 0,
                     'last_modified': '123T456'}]],
            # Have multiple pages worth of DLO segments
            [None, [{'name': 'prefix_b', 'bytes': 0,
                     'last_modified': '123T456'}]],
            [None, []]
        ]
        connection.return_value.put_object.return_value = EMPTY_ETAG
        # create the delete_object child mock here in attempt to fix
        # https://bugs.launchpad.net/python-swiftclient/+bug/1480223
        connection.return_value.delete_object.return_value = None
        swiftclient.shell.main(argv)
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            mock.ANY,
            content_length=0,
            headers={'x-object-meta-mtime': mock.ANY},
            response_dict={})
        expected_delete_calls = [
            mock.call(
                'container1', 'prefix_a',
                response_dict={}
            ),
            mock.call(
                'container1', 'prefix_b',
                response_dict={}
            )
        ]
        self.assertEqual(
            sorted(expected_delete_calls),
            sorted(connection.return_value.delete_object.mock_calls)
        )

    @mock.patch('swiftclient.service.Connection')
    def test_upload_leave_dlo_segments(self, connection):
        # Upload delete existing segments
        connection.return_value.head_container.return_value = {
            'x-storage-policy': 'one'}
        connection.return_value.attempts = 0
        argv = ["", "upload", "container", self.tmpfile, "--leave-segments"]
        connection.return_value.head_object.side_effect = [
            {'x-object-manifest': 'container1/prefix',
             'content-length': '0'}]
        connection.return_value.put_object.return_value = (
            'd41d8cd98f00b204e9800998ecf8427e')
        swiftclient.shell.main(argv)
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            mock.ANY,
            content_length=0,
            headers={'x-object-meta-mtime': mock.ANY},
            response_dict={})
        self.assertFalse(connection.return_value.delete_object.mock_calls)

    @mock.patch('swiftclient.service.Connection')
    def test_upload_segments_to_same_container(self, connection):
        # Upload in segments to same container
        connection.return_value.head_object.return_value = {
            'content-length': '0'}
        connection.return_value.attempts = 0
        connection.return_value.put_object.return_value = EMPTY_ETAG
        argv = ["", "upload", "container", self.tmpfile, "-S", "10",
                "-C", "container"]
        with open(self.tmpfile, "wb") as fh:
            fh.write(b'12345678901234567890')
        swiftclient.shell.main(argv)
        connection.return_value.put_container.assert_called_once_with(
            'container', {}, response_dict={})
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            '',
            content_length=0,
            headers={'x-object-manifest': mock.ANY,
                     'x-object-meta-mtime': mock.ANY},
            response_dict={})

    @mock.patch('swiftclient.shell.stdin')
    @mock.patch('swiftclient.shell.io.open')
    @mock.patch('swiftclient.service.SwiftService.upload')
    def test_upload_from_stdin(self, upload_mock, io_open_mock, stdin_mock):
        stdin_mock.fileno.return_value = 123

        def fake_open(fd, mode):
            mock_io = mock.Mock()
            mock_io.fileno.return_value = fd
            return mock_io

        io_open_mock.side_effect = fake_open

        argv = ["", "upload", "container", "-", "--object-name", "foo"]
        swiftclient.shell.main(argv)
        upload_mock.assert_called_once_with("container", mock.ANY)
        # This is a little convoluted: we want to examine the first call ([0]),
        # the argv list([1]), the second parameter ([1]), and the first
        # element.  This is because the upload method takes a container and a
        # list of SwiftUploadObjects.
        swift_upload_obj = upload_mock.mock_calls[0][1][1][0]
        self.assertEqual(123, swift_upload_obj.source.fileno())
        io_open_mock.assert_called_once_with(123, mode='rb')

    @mock.patch('swiftclient.service.SwiftService.upload')
    def test_upload_from_stdin_no_name(self, upload_mock):
        argv = ["", "upload", "container", "-"]
        with CaptureOutput() as out:
            self.assertRaises(SystemExit, swiftclient.shell.main, argv)
            self.assertEqual(0, len(upload_mock.mock_calls))
            self.assertTrue(out.err.find('object-name must be specified') >= 0)

    @mock.patch('swiftclient.service.SwiftService.upload')
    def test_upload_from_stdin_and_others(self, upload_mock):
        argv = ["", "upload", "container", "-", "foo", "--object-name", "bar"]
        with CaptureOutput() as out:
            self.assertRaises(SystemExit, swiftclient.shell.main, argv)
            self.assertEqual(0, len(upload_mock.mock_calls))
            self.assertTrue(out.err.find(
                'upload from stdin cannot be used') >= 0)

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 0)
    @mock.patch('swiftclient.service.Connection')
    def test_delete_bad_threads(self, mock_connection):
        mock_connection.return_value.get_container.return_value = (None, [])
        mock_connection.return_value.attempts = 0

        def check_bad(argv):
            args, env = _make_cmd(
                'delete', {}, {}, cmd_args=['cont'] + argv)
            with mock.patch.dict(os.environ, env):
                with CaptureOutput() as output:
                    self.assertRaises(SystemExit, swiftclient.shell.main, args)
            self.assertIn(
                'ERROR: option %s should be a positive integer.' % argv[0],
                output.err)

        def check_good(argv):
            args, env = _make_cmd(
                'delete', {}, {}, cmd_args=['cont'] + argv)
            with mock.patch.dict(os.environ, env):
                with CaptureOutput() as output:
                    swiftclient.shell.main(args)
            self.assertEqual('', output.err)
        check_bad(["--object-threads", "-1"])
        check_bad(["--object-threads", "0"])
        check_bad(["--container-threads", "-1"])
        check_bad(["--container-threads", "0"])
        check_good(["--object-threads", "1"])
        check_good(["--container-threads", "1"])

    @mock.patch('swiftclient.service.Connection')
    def test_delete_version_id(self, connection):
        argv = ["", "delete", "--yes-all", "--version-id", "3"]
        with self.assertRaises(SystemExit) as caught:
            swiftclient.shell.main(argv)
        self.assertEqual(str(caught.exception),
                         "--version-id option only allowed for "
                         "object deletes")

        argv = ["", "delete", "--version-id", "1", "container"]
        with self.assertRaises(SystemExit) as caught:
            swiftclient.shell.main(argv)
        self.assertEqual(str(caught.exception),
                         "--version-id option only allowed for "
                         "object deletes")

        argv = ["", "delete", "--version-id", "1", "container", "object"]
        connection.return_value.head_object.return_value = {}
        connection.return_value.delete_object.return_value = None
        connection.return_value.attempts = 0
        with CaptureOutput():
            swiftclient.shell.main(argv)
        self.assertEqual([mock.call('container', 'object', headers={},
                                    query_string='version-id=1',
                                    response_dict={})],
                         connection.return_value.delete_object.mock_calls)

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 1)
    @mock.patch('swiftclient.service.Connection')
    def test_delete_account(self, connection):
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container'}, {'name': 'container2'}]],
            [None, [{'name': 'empty_container'}]],
            [None, []],
        ]
        # N.B: --all implies --versions, clear it all out
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object'}, {'name': 'obj\xe9ct2'}]],
            [None, []],
            [None, [{'name': 'object', 'version_id': 1}]],
            [None, []],
            [None, []],
        ]
        connection.return_value.attempts = 0
        argv = ["", "delete", "--all"]
        connection.return_value.head_object.return_value = {}
        connection.return_value.delete_object.return_value = None
        swiftclient.shell.main(argv)
        connection.return_value.delete_object.assert_has_calls([
            mock.call('container', 'object', query_string='',
                      response_dict={}, headers={}),
            mock.call('container', 'obj\xe9ct2', query_string='',
                      response_dict={}, headers={}),
            mock.call('container2', 'object', query_string='version-id=1',
                      response_dict={}, headers={})], any_order=True)
        self.assertEqual(3, connection.return_value.delete_object.call_count,
                         'Expected 3 calls but found\n%r'
                         % connection.return_value.delete_object.mock_calls)
        self.assertEqual(
            connection.return_value.delete_container.mock_calls, [
                mock.call('container', response_dict={}, headers={}),
                mock.call('container2', response_dict={}, headers={}),
                mock.call('empty_container', response_dict={}, headers={})])

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 1)
    @mock.patch('swiftclient.service.Connection')
    def test_delete_account_versions(self, connection):
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container'}, {'name': 'container2'}]],
            [None, [{'name': 'empty_container'}]],
            [None, []],
        ]
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object'}, {'name': 'obj\xe9ct2'}]],
            [None, []],
            [None, [{'name': 'obj', 'version_id': 1}]],
            [None, []],
            [None, []],
        ]
        connection.return_value.attempts = 0
        argv = ["", "delete", "--all", "--versions"]
        connection.return_value.head_object.return_value = {}
        connection.return_value.delete_object.return_value = None
        swiftclient.shell.main(argv)
        connection.return_value.delete_object.assert_has_calls([
            mock.call('container', 'object', query_string='',
                      response_dict={}, headers={}),
            mock.call('container', 'obj\xe9ct2', query_string='',
                      response_dict={}, headers={}),
            mock.call('container2', 'obj', query_string='version-id=1',
                      response_dict={}, headers={})], any_order=True)
        self.assertEqual(3, connection.return_value.delete_object.call_count,
                         'Expected 3 calls but found\n%r'
                         % connection.return_value.delete_object.mock_calls)
        self.assertEqual(
            connection.return_value.delete_container.mock_calls, [
                mock.call('container', response_dict={}, headers={}),
                mock.call('container2', response_dict={}, headers={}),
                mock.call('empty_container', response_dict={}, headers={})])

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 10)
    @mock.patch('swiftclient.service.Connection')
    def test_delete_bulk_account(self, connection):
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container'}, {'name': 'container2'}]],
            [None, [{'name': 'empty_container'}]],
            [None, []],
        ]
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object'}, {'name': 'obj\xe9ct2'},
                    {'name': 'object3'}]],
            [None, []],
            [None, [{'name': 'object'}]],
            [None, []],
            [None, []],
        ]
        connection.return_value.attempts = 0
        argv = ["", "delete", "--all", "--object-threads", "2"]
        connection.return_value.post_account.return_value = {}, (
            b'{"Number Not Found": 0, "Response Status": "200 OK", '
            b'"Errors": [], "Number Deleted": 1, "Response Body": ""}')
        swiftclient.shell.main(argv)
        self.assertEqual(
            3, len(connection.return_value.post_account.mock_calls),
            'Expected 3 calls but found\n%r'
            % connection.return_value.post_account.mock_calls)
        # POSTs for same container are made in parallel so expect any order
        for expected in [
            mock.call(query_string='bulk-delete',
                      data=b'/container/object\n/container/obj%C3%A9ct2\n',
                      headers={'Content-Type': 'text/plain',
                               'Accept': 'application/json'},
                      response_dict={}),
            mock.call(query_string='bulk-delete',
                      data=b'/container/object3\n',
                      headers={'Content-Type': 'text/plain',
                               'Accept': 'application/json'},
                      response_dict={})]:
            self.assertIn(expected,
                          connection.return_value.post_account.mock_calls[:2])
        # POSTs for different containers are made sequentially so expect order
        self.assertEqual(
            mock.call(query_string='bulk-delete',
                      data=b'/container2/object\n',
                      headers={'Content-Type': 'text/plain',
                               'Accept': 'application/json'},
                      response_dict={}),
            connection.return_value.post_account.mock_calls[2])
        self.assertEqual(
            connection.return_value.delete_container.mock_calls, [
                mock.call('container', response_dict={}, headers={}),
                mock.call('container2', response_dict={}, headers={}),
                mock.call('empty_container', response_dict={}, headers={})])

    @mock.patch('swiftclient.service.Connection')
    def test_delete_bulk_account_with_capabilities(self, connection):
        connection.return_value.get_capabilities.return_value = {
            'bulk_delete': {
                'max_deletes_per_request': 10000,
                'max_failed_deletes': 1000,
            },
        }
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container'}]],
            [None, [{'name': 'container2'}]],
            [None, [{'name': 'empty_container'}]],
            [None, []],
        ]
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object'}, {'name': 'obj\xe9ct2'},
                    {'name': 'z_object'}, {'name': 'z_obj\xe9ct2'}]],
            [None, []],
            [None, [{'name': 'object'}, {'name': 'obj\xe9ct2'},
                    {'name': 'z_object'}, {'name': 'z_obj\xe9ct2'}]],
            [None, []],
            [None, []],
        ]
        connection.return_value.attempts = 0
        argv = ["", "delete", "--all", "--object-threads", "1"]
        connection.return_value.post_account.return_value = {}, (
            b'{"Number Not Found": 0, "Response Status": "200 OK", '
            b'"Errors": [], "Number Deleted": 1, "Response Body": ""}')
        swiftclient.shell.main(argv)
        self.assertEqual(
            connection.return_value.post_account.mock_calls, [
                mock.call(query_string='bulk-delete',
                          data=b''.join([
                              b'/container/object\n',
                              b'/container/obj%C3%A9ct2\n',
                              b'/container/z_object\n',
                              b'/container/z_obj%C3%A9ct2\n'
                          ]),
                          headers={'Content-Type': 'text/plain',
                                   'Accept': 'application/json'},
                          response_dict={}),
                mock.call(query_string='bulk-delete',
                          data=b''.join([
                              b'/container2/object\n',
                              b'/container2/obj%C3%A9ct2\n',
                              b'/container2/z_object\n',
                              b'/container2/z_obj%C3%A9ct2\n'
                          ]),
                          headers={'Content-Type': 'text/plain',
                                   'Accept': 'application/json'},
                          response_dict={})])
        self.assertEqual(
            connection.return_value.delete_container.mock_calls, [
                mock.call('container', response_dict={}, headers={}),
                mock.call('container2', response_dict={}, headers={}),
                mock.call('empty_container', response_dict={}, headers={})])
        self.assertEqual(connection.return_value.get_capabilities.mock_calls,
                         [mock.call(None)])  # only one /info request

    @mock.patch('swiftclient.service.Connection')
    def test_delete_bulk_account_with_capabilities_and_pages(self, connection):
        connection.return_value.get_capabilities.return_value = {
            'bulk_delete': {
                'max_deletes_per_request': 2,
                'max_failed_deletes': 1000,
            },
        }
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container'}]],
            [None, [{'name': 'container2'}]],
            [None, [{'name': 'empty_container'}]],
            [None, []],
        ]
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object'}, {'name': 'obj\xe9ct2'},
                    {'name': 'z_object'}, {'name': 'z_obj\xe9ct2'}]],
            [None, []],
            [None, [{'name': 'object'}, {'name': 'obj\xe9ct2'},
                    {'name': 'z_object'}, {'name': 'z_obj\xe9ct2'}]],
            [None, []],
            [None, []],
        ]
        connection.return_value.attempts = 0
        argv = ["", "delete", "--all", "--object-threads", "1"]
        connection.return_value.post_account.return_value = {}, (
            b'{"Number Not Found": 0, "Response Status": "200 OK", '
            b'"Errors": [], "Number Deleted": 1, "Response Body": ""}')
        swiftclient.shell.main(argv)
        # check that each bulk call was only called with 2 objects
        self.assertEqual(
            connection.return_value.post_account.mock_calls, [
                mock.call(query_string='bulk-delete',
                          data=b''.join([
                              b'/container/object\n',
                              b'/container/obj%C3%A9ct2\n',
                          ]),
                          headers={'Content-Type': 'text/plain',
                                   'Accept': 'application/json'},
                          response_dict={}),
                mock.call(query_string='bulk-delete',
                          data=b''.join([
                              b'/container/z_object\n',
                              b'/container/z_obj%C3%A9ct2\n'
                          ]),
                          headers={'Content-Type': 'text/plain',
                                   'Accept': 'application/json'},
                          response_dict={}),
                mock.call(query_string='bulk-delete',
                          data=b''.join([
                              b'/container2/object\n',
                              b'/container2/obj%C3%A9ct2\n',
                          ]),
                          headers={'Content-Type': 'text/plain',
                                   'Accept': 'application/json'},
                          response_dict={}),
                mock.call(query_string='bulk-delete',
                          data=b''.join([
                              b'/container2/z_object\n',
                              b'/container2/z_obj%C3%A9ct2\n'
                          ]),
                          headers={'Content-Type': 'text/plain',
                                   'Accept': 'application/json'},
                          response_dict={})])
        self.assertEqual(
            connection.return_value.delete_container.mock_calls, [
                mock.call('container', response_dict={}, headers={}),
                mock.call('container2', response_dict={}, headers={}),
                mock.call('empty_container', response_dict={}, headers={})])
        self.assertEqual(connection.return_value.get_capabilities.mock_calls,
                         [mock.call(None)])  # only one /info request

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 1)
    @mock.patch('swiftclient.service.Connection')
    def test_delete_container(self, connection):
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object'}]],
            [None, []],
        ]
        connection.return_value.attempts = 0
        argv = ["", "delete", "container"]
        connection.return_value.head_object.return_value = {}
        swiftclient.shell.main(argv)
        connection.return_value.delete_container.assert_called_with(
            'container', response_dict={}, headers={})
        connection.return_value.delete_object.assert_called_with(
            'container', 'object', query_string='', response_dict={},
            headers={})

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 1)
    @mock.patch('swiftclient.service.Connection')
    def test_delete_container_versions(self, connection):
        argv = ["", "delete", "--versions", "container", "obj"]
        with self.assertRaises(SystemExit) as caught:
            swiftclient.shell.main(argv)
        self.assertEqual(str(caught.exception),
                         "--versions option not allowed for object deletes")

        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object', 'version_id': 2},
                    {'name': 'object', 'version_id': 1}]],
            [None, []],
        ]
        connection.return_value.attempts = 0
        argv = ["", "delete", "--versions", "container", "--object-threads=1"]
        connection.return_value.head_object.return_value = {}
        swiftclient.shell.main(argv)
        connection.return_value.delete_container.assert_called_with(
            'container', response_dict={}, headers={})
        expected_calls = [
            mock.call('container', 'object', query_string='version-id=2',
                      response_dict={}, headers={}),
            mock.call('container', 'object', query_string='version-id=1',
                      response_dict={}, headers={})]

        self.assertEqual(connection.return_value.delete_object.mock_calls,
                         expected_calls)

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 1)
    @mock.patch('swiftclient.service.Connection')
    def test_delete_container_headers(self, connection):
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object'}]],
            [None, []],
        ]
        connection.return_value.attempts = 0
        argv = ["", "delete", "container", "-H", "Skip-Middleware: Test"]
        connection.return_value.head_object.return_value = {}
        swiftclient.shell.main(argv)
        connection.return_value.delete_container.assert_called_with(
            'container', response_dict={},
            headers={'Skip-Middleware': 'Test'})
        connection.return_value.delete_object.assert_called_with(
            'container', 'object', query_string='', response_dict={},
            headers={'Skip-Middleware': 'Test'})

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 10)
    @mock.patch('swiftclient.service.Connection')
    def test_delete_bulk_container(self, connection):
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object'}]],
            [None, []],
        ]
        connection.return_value.attempts = 0
        argv = ["", "delete", "container"]
        connection.return_value.post_account.return_value = {}, (
            b'{"Number Not Found": 0, "Response Status": "200 OK", '
            b'"Errors": [], "Number Deleted": 1, "Response Body": ""}')
        swiftclient.shell.main(argv)
        connection.return_value.post_account.assert_called_with(
            query_string='bulk-delete', data=b'/container/object\n',
            headers={'Content-Type': 'text/plain',
                     'Accept': 'application/json'},
            response_dict={})
        connection.return_value.delete_container.assert_called_with(
            'container', response_dict={}, headers={})

    def test_delete_verbose_output_utf8(self):
        container = 't\u00e9st_c'
        base_argv = ['', '--verbose', 'delete']

        # simulate container having an object with utf-8 code points in name,
        # just returning the object delete result
        res = {'success': True, 'response_dict': {}, 'attempts': 2,
               'container': container, 'action': 'delete_object',
               'object': 'obj_t\u00east_o'}

        with mock.patch('swiftclient.shell.SwiftService.delete') as mock_func:
            with CaptureOutput() as out:
                mock_func.return_value = [res]
                swiftclient.shell.main(base_argv + [container])

                mock_func.assert_called_once_with(container=container)
                self.assertTrue(out.out.find(
                    'obj_t\u00east_o [after 2 attempts]') >= 0, out)

        # simulate empty container
        res = {'success': True, 'response_dict': {}, 'attempts': 2,
               'container': container, 'action': 'delete_container'}

        with mock.patch('swiftclient.shell.SwiftService.delete') as mock_func:
            with CaptureOutput() as out:
                mock_func.return_value = [res]
                swiftclient.shell.main(base_argv + [container])

                mock_func.assert_called_once_with(container=container)
                self.assertTrue(out.out.find(
                    't\u00e9st_c [after 2 attempts]') >= 0, out)

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 1)
    @mock.patch('swiftclient.service.Connection')
    def test_delete_per_object(self, connection):
        argv = ["", "delete", "container", "object"]
        connection.return_value.head_object.return_value = {}
        connection.return_value.attempts = 0
        swiftclient.shell.main(argv)
        connection.return_value.delete_object.assert_called_with(
            'container', 'object', query_string='', response_dict={},
            headers={})

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 10)
    @mock.patch('swiftclient.service.Connection')
    def test_delete_bulk_object(self, connection):
        argv = ["", "delete", "container", "object"]
        connection.return_value.post_account.return_value = {}, (
            b'{"Number Not Found": 0, "Response Status": "200 OK", '
            b'"Errors": [], "Number Deleted": 1, "Response Body": ""}')
        connection.return_value.attempts = 0
        with CaptureOutput() as out:
            swiftclient.shell.main(argv)
        connection.return_value.post_account.assert_called_with(
            query_string='bulk-delete', data=b'/container/object\n',
            headers={'Content-Type': 'text/plain',
                     'Accept': 'application/json'},
            response_dict={})
        self.assertEqual('object\n', out.out)

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 10)
    @mock.patch('swiftclient.service.Connection')
    def test_delete_bulk_object_with_retry(self, connection):
        argv = ["", "delete", "container", "object"]
        connection.return_value.post_account.return_value = {}, (
            b'{"Number Not Found": 0, "Response Status": "200 OK", '
            b'"Errors": [], "Number Deleted": 1, "Response Body": ""}')
        connection.return_value.attempts = 3
        with CaptureOutput() as out:
            swiftclient.shell.main(argv)
        connection.return_value.post_account.assert_called_with(
            query_string='bulk-delete', data=b'/container/object\n',
            headers={'Content-Type': 'text/plain',
                     'Accept': 'application/json'},
            response_dict={})
        self.assertEqual('object [after 3 attempts]\n', out.out)

    def test_delete_verbose_output(self):
        del_obj_res = {'success': True, 'response_dict': {}, 'attempts': 2,
                       'container': 't\xe9st_c', 'action': 'delete_object',
                       'object': 't\xe9st_o'}

        del_seg_res = del_obj_res.copy()
        del_seg_res.update({'action': 'delete_segment'})

        del_con_res = del_obj_res.copy()
        del_con_res.update({'action': 'delete_container', 'object': None})

        test_exc = Exception('t\xe9st_exc')
        error_res = del_obj_res.copy()
        error_res.update({'success': False, 'error': test_exc, 'object': None})

        mock_delete = mock.Mock()
        base_argv = ['', '--verbose', 'delete']

        with mock.patch('swiftclient.shell.SwiftService.delete', mock_delete):
            with CaptureOutput() as out:
                mock_delete.return_value = [del_obj_res]
                swiftclient.shell.main(base_argv + ['t\xe9st_c', 't\xe9st_o'])

                mock_delete.assert_called_once_with(container='t\xe9st_c',
                                                    objects=['t\xe9st_o'])
                self.assertTrue(out.out.find(
                    't\xe9st_o [after 2 attempts]') >= 0)

            with CaptureOutput() as out:
                mock_delete.return_value = [del_seg_res]
                swiftclient.shell.main(base_argv + ['t\xe9st_c', 't\xe9st_o'])

                mock_delete.assert_called_with(container='t\xe9st_c',
                                               objects=['t\xe9st_o'])
                self.assertTrue(out.out.find(
                    't\xe9st_c/t\xe9st_o [after 2 attempts]') >= 0)

            with CaptureOutput() as out:
                mock_delete.return_value = [del_con_res]
                swiftclient.shell.main(base_argv + ['t\xe9st_c'])

                mock_delete.assert_called_with(container='t\xe9st_c')
                self.assertTrue(out.out.find(
                    't\xe9st_c [after 2 attempts]') >= 0)

            with CaptureOutput() as out:
                mock_delete.return_value = [error_res]
                self.assertRaises(SystemExit,
                                  swiftclient.shell.main,
                                  base_argv + ['t\xe9st_c'])

                mock_delete.assert_called_with(container='t\xe9st_c')
                self.assertTrue(out.err.find(
                    'Error Deleting: t\xe9st_c: t\xe9st_exc') >= 0)

    @mock.patch('swiftclient.service.Connection')
    def test_post_account(self, connection):
        argv = ["", "post"]
        swiftclient.shell.main(argv)
        connection.return_value.post_account.assert_called_with(
            headers={}, response_dict={})

    @mock.patch('swiftclient.service.Connection')
    def test_post_account_bad_auth(self, connection):
        argv = ["", "post"]
        connection.return_value.post_account.side_effect = \
            swiftclient.ClientException(
                'bad auth', http_response_headers={'X-Trans-Id': 'trans_id'})

        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                swiftclient.shell.main(argv)

            self.assertEqual(output.err,
                             'bad auth\nFailed Transaction ID: trans_id\n')

        # do it again with a unicode token
        connection.return_value.post_account.side_effect = \
            swiftclient.ClientException(
                'bad auth', http_response_headers={
                    'X-Trans-Id': 'non\u2011utf8'})

        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                swiftclient.shell.main(argv)

            self.assertEqual(output.err,
                             'bad auth\n'
                             'Failed Transaction ID: non\u2011utf8\n')

        # do it again with a wonky token
        connection.return_value.post_account.side_effect = \
            swiftclient.ClientException(
                'bad auth', http_response_headers={
                    'X-Trans-Id': b'non\xffutf8'})

        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                swiftclient.shell.main(argv)

            self.assertEqual(output.err,
                             'bad auth\nFailed Transaction ID: non%FFutf8\n')

    @mock.patch('swiftclient.service.Connection')
    def test_post_account_not_found(self, connection):
        argv = ["", "post"]
        connection.return_value.post_account.side_effect = \
            swiftclient.ClientException('test', http_status=404)

        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                swiftclient.shell.main(argv)

            self.assertEqual(output.err, 'Account not found\n')

    @mock.patch('swiftclient.service.Connection')
    def test_post_container(self, connection):
        argv = ["", "post", "container"]
        swiftclient.shell.main(argv)
        connection.return_value.post_container.assert_called_with(
            'container', headers={}, response_dict={})

    @mock.patch('swiftclient.service.Connection')
    def test_post_container_bad_auth(self, connection):
        argv = ["", "post", "container"]
        connection.return_value.post_container.side_effect = \
            swiftclient.ClientException('bad auth')

        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                swiftclient.shell.main(argv)

            self.assertEqual(output.err, 'bad auth\n')

    @mock.patch('swiftclient.service.Connection')
    def test_post_container_not_found_causes_put(self, connection):
        argv = ["", "post", "container"]
        connection.return_value.post_container.side_effect = \
            swiftclient.ClientException('test', http_status=404)
        swiftclient.shell.main(argv)
        self.assertEqual('container',
                         connection.return_value.put_container.call_args[0][0])

    def test_post_container_with_bad_name(self):
        argv = ["", "post", "conta/iner"]

        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                swiftclient.shell.main(argv)
            self.assertTrue(output.err != '')
            self.assertTrue(output.err.startswith('WARNING: / in'))

    @mock.patch('swiftclient.service.Connection')
    def test_post_container_with_options(self, connection):
        argv = ["", "post", "container",
                "--read-acl", "test2:tester2",
                "--write-acl", "test3:tester3 test4",
                "--sync-to", "othersite",
                "--sync-key", "secret",
                ]
        swiftclient.shell.main(argv)
        connection.return_value.post_container.assert_called_with(
            'container', headers={
                'X-Container-Write': 'test3:tester3 test4',
                'X-Container-Read': 'test2:tester2',
                'X-Container-Sync-Key': 'secret',
                'X-Container-Sync-To': 'othersite'}, response_dict={})

    @mock.patch('swiftclient.service.Connection')
    def test_post_object(self, connection):
        argv = ["", "post", "container", "object",
                "--meta", "Color:Blue",
                "--header", "content-type:text/plain"
                ]
        swiftclient.shell.main(argv)
        connection.return_value.post_object.assert_called_with(
            'container', 'object', headers={
                'Content-Type': 'text/plain',
                'X-Object-Meta-Color': 'Blue'}, response_dict={})

    @mock.patch('swiftclient.service.Connection')
    def test_post_object_bad_auth(self, connection):
        argv = ["", "post", "container", "object"]
        connection.return_value.post_object.side_effect = \
            swiftclient.ClientException("bad auth")

        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                swiftclient.shell.main(argv)

            self.assertEqual(output.err, 'bad auth\n')

    def test_post_object_too_many_args(self):
        argv = ["", "post", "container", "object", "bad_arg"]

        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                swiftclient.shell.main(argv)

            self.assertTrue(output.err != '')
            self.assertTrue(output.err.startswith('Usage'))

    @mock.patch('swiftclient.service.Connection')
    def test_copy_object_no_destination(self, connection):
        argv = ["", "copy", "container", "object",
                "--meta", "Color:Blue",
                "--header", "content-type:text/plain"
                ]
        with CaptureOutput() as output:
            swiftclient.shell.main(argv)
            connection.return_value.copy_object.assert_called_with(
                'container', 'object', destination=None, fresh_metadata=False,
                headers={
                    'Content-Type': 'text/plain',
                    'X-Object-Meta-Color': 'Blue'}, response_dict={})
        self.assertEqual(output.out, 'container/object copied to <self>\n')

    @mock.patch('swiftclient.service.Connection')
    def test_copy_object(self, connection):
        argv = ["", "copy", "container", "object",
                "--meta", "Color:Blue",
                "--header", "content-type:text/plain",
                "--destination", "/c/o"
                ]
        with CaptureOutput() as output:
            swiftclient.shell.main(argv)
            connection.return_value.copy_object.assert_called_with(
                'container', 'object', destination="/c/o",
                fresh_metadata=False,
                headers={
                    'Content-Type': 'text/plain',
                    'X-Object-Meta-Color': 'Blue'}, response_dict={})
        self.assertEqual(
            output.out,
            'created container c\ncontainer/object copied to /c/o\n'
        )

    @mock.patch('swiftclient.service.Connection')
    def test_copy_object_fresh_metadata(self, connection):
        argv = ["", "copy", "container", "object",
                "--meta", "Color:Blue", "--fresh-metadata",
                "--header", "content-type:text/plain",
                "--destination", "/c/o"
                ]
        swiftclient.shell.main(argv)
        connection.return_value.copy_object.assert_called_with(
            'container', 'object', destination="/c/o", fresh_metadata=True,
            headers={
                'Content-Type': 'text/plain',
                'X-Object-Meta-Color': 'Blue'}, response_dict={})

    @mock.patch('swiftclient.service.Connection')
    def test_copy_two_objects(self, connection):
        argv = ["", "copy", "container", "object", "object2",
                "--meta", "Color:Blue"]
        connection.return_value.copy_object.return_value = None
        swiftclient.shell.main(argv)
        calls = [
            mock.call(
                'container', 'object', destination=None,
                fresh_metadata=False, headers={'X-Object-Meta-Color': 'Blue'},
                response_dict={}),
            mock.call(
                'container', 'object2', destination=None,
                fresh_metadata=False, headers={'X-Object-Meta-Color': 'Blue'},
                response_dict={})
        ]
        connection.return_value.copy_object.assert_has_calls(
            calls, any_order=True)
        self.assertEqual(len(connection.return_value.copy_object.mock_calls),
                         len(calls))

    @mock.patch('swiftclient.service.Connection')
    def test_copy_two_objects_destination(self, connection):
        argv = ["", "copy", "container", "object", "object2",
                "--meta", "Color:Blue", "--destination", "/c"]
        connection.return_value.copy_object.return_value = None
        swiftclient.shell.main(argv)
        calls = [
            mock.call(
                'container', 'object', destination="/c/object",
                fresh_metadata=False, headers={'X-Object-Meta-Color': 'Blue'},
                response_dict={}),
            mock.call(
                'container', 'object2', destination="/c/object2",
                fresh_metadata=False, headers={'X-Object-Meta-Color': 'Blue'},
                response_dict={})
        ]
        connection.return_value.copy_object.assert_has_calls(
            calls, any_order=True)
        self.assertEqual(len(connection.return_value.copy_object.mock_calls),
                         len(calls))

    @mock.patch('swiftclient.service.Connection')
    def test_copy_two_objects_bad_destination(self, connection):
        argv = ["", "copy", "container", "object", "object2",
                "--meta", "Color:Blue", "--destination", "/c/o"]

        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                swiftclient.shell.main(argv)

            self.assertEqual(
                output.err,
                'Combination of multiple objects and destination '
                'including object is invalid\n')

    @mock.patch('swiftclient.service.Connection')
    def test_copy_object_bad_auth(self, connection):
        argv = ["", "copy", "container", "object"]
        connection.return_value.copy_object.side_effect = \
            swiftclient.ClientException("bad auth")

        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                swiftclient.shell.main(argv)

            self.assertEqual(output.err, 'bad auth\n')

    def test_copy_object_not_enough_args(self):
        argv = ["", "copy", "container"]

        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                swiftclient.shell.main(argv)

            self.assertTrue(output.err != '')
            self.assertTrue(output.err.startswith('Usage'))

    def test_copy_bad_container(self):
        argv = ["", "copy", "cont/ainer", "object"]

        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                swiftclient.shell.main(argv)

            self.assertTrue(output.err != '')
            self.assertTrue(output.err.startswith('WARN'))

    @mock.patch('swiftclient.shell.generate_temp_url', return_value='')
    def test_temp_url(self, temp_url):
        argv = ["", "tempurl", "GET", "60", "/v1/AUTH_account/c/o",
                "secret_key"]
        swiftclient.shell.main(argv)
        temp_url.assert_called_with(
            '/v1/AUTH_account/c/o', "60", 'secret_key', 'GET', absolute=False,
            iso8601=False, prefix=False, ip_range=None, digest='sha256')

        # sanity check that suffixes will just pass through to utils.py
        argv = ["", "tempurl", "GET", "2d", "/v1/AUTH_account/c/o",
                "secret_key"]
        swiftclient.shell.main(argv)
        temp_url.assert_called_with(
            '/v1/AUTH_account/c/o', "2d", 'secret_key', 'GET', absolute=False,
            iso8601=False, prefix=False, ip_range=None, digest='sha256')

    @mock.patch('swiftclient.shell.generate_temp_url', return_value='')
    def test_temp_url_prefix_based(self, temp_url):
        argv = ["", "tempurl", "GET", "60", "/v1/AUTH_account/c/",
                "secret_key", "--prefix-based"]
        swiftclient.shell.main(argv)
        temp_url.assert_called_with(
            '/v1/AUTH_account/c/', "60", 'secret_key', 'GET', absolute=False,
            iso8601=False, prefix=True, ip_range=None, digest='sha256')

    @mock.patch('swiftclient.shell.generate_temp_url', return_value='')
    def test_temp_url_iso8601_in(self, temp_url):
        dates = ('1970-01-01T00:01:00Z', '1970-01-01T00:01:00',
                 '1970-01-01')
        for d in dates:
            argv = ["", "tempurl", "GET", d, "/v1/AUTH_account/c/",
                    "secret_key"]
            swiftclient.shell.main(argv)
            temp_url.assert_called_with(
                '/v1/AUTH_account/c/', d, 'secret_key', 'GET', absolute=False,
                iso8601=False, prefix=False, ip_range=None, digest='sha256')

    @mock.patch('swiftclient.shell.generate_temp_url', return_value='')
    def test_temp_url_iso8601_out(self, temp_url):
        argv = ["", "tempurl", "GET", "60", "/v1/AUTH_account/c/",
                "secret_key", "--iso8601"]
        swiftclient.shell.main(argv)
        temp_url.assert_called_with(
            '/v1/AUTH_account/c/', "60", 'secret_key', 'GET', absolute=False,
            iso8601=True, prefix=False, ip_range=None, digest='sha256')

    @mock.patch('swiftclient.shell.generate_temp_url', return_value='')
    def test_absolute_expiry_temp_url(self, temp_url):
        argv = ["", "tempurl", "GET", "60", "/v1/AUTH_account/c/o",
                "secret_key", "--absolute"]
        swiftclient.shell.main(argv)
        temp_url.assert_called_with(
            '/v1/AUTH_account/c/o', "60", 'secret_key', 'GET', absolute=True,
            iso8601=False, prefix=False, ip_range=None, digest='sha256')

    @mock.patch('swiftclient.shell.generate_temp_url', return_value='')
    def test_temp_url_with_ip_range(self, temp_url):
        argv = ["", "tempurl", "GET", "60", "/v1/AUTH_account/c/o",
                "secret_key", "--ip-range", "1.2.3.4"]
        swiftclient.shell.main(argv)
        temp_url.assert_called_with(
            '/v1/AUTH_account/c/o', "60", 'secret_key', 'GET', absolute=False,
            iso8601=False, prefix=False, ip_range='1.2.3.4', digest='sha256')

    def test_temp_url_output(self):
        argv = ["", "tempurl", "GET", "60", "/v1/a/c/o",
                "secret_key", "--absolute", "--digest", "sha1"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        sig = "63bc77a473a1c2ce956548cacf916f292eb9eac3"
        expected = "/v1/a/c/o?temp_url_sig=%s&temp_url_expires=60\n" % sig
        self.assertEqual(expected, output.out)

        argv = ["", "tempurl", "GET", "60", "http://saio:8080/v1/a/c/o",
                "secret_key", "--absolute", "--digest", "sha1"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        expected = "http://saio:8080%s" % expected
        self.assertEqual(expected, output.out)

        argv = ["", "tempurl", "GET", "60", "/v1/a/c/",
                "secret_key", "--absolute", "--prefix", "--digest", "sha1"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        sig = '00008c4be1573ba74fc2ab9bce02e3a93d04b349'
        expected = ("/v1/a/c/?temp_url_sig=%s&temp_url_expires=60"
                    "&temp_url_prefix=\n" % sig)
        self.assertEqual(expected, output.out)

        argv = ["", "tempurl", "GET", "60", "/v1/a/c/",
                "secret_key", "--absolute", "--prefix", '--iso8601',
                "--digest", "sha1"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        sig = '00008c4be1573ba74fc2ab9bce02e3a93d04b349'
        expires = '1970-01-01T00:01:00Z'
        expected = ("/v1/a/c/?temp_url_sig=%s&temp_url_expires=%s"
                    "&temp_url_prefix=\n" % (sig, expires))
        self.assertEqual(expected, output.out)

        dates = ("1970-01-01T00:01:00Z",
                 strftime(EXPIRES_ISO8601_FORMAT[:-1], localtime(60)))
        for d in dates:
            argv = ["", "tempurl", "GET", d, "/v1/a/c/o",
                    "secret_key", "--digest", "sha1"]
            with CaptureOutput(suppress_systemexit=True) as output:
                swiftclient.shell.main(argv)
            sig = "63bc77a473a1c2ce956548cacf916f292eb9eac3"
            expected = "/v1/a/c/o?temp_url_sig=%s&temp_url_expires=60\n" % sig
            self.assertEqual(expected, output.out)

        ts = str(int(
            mktime(strptime('2005-05-01', SHORT_EXPIRES_ISO8601_FORMAT))))

        argv = ["", "tempurl", "GET", ts, "/v1/a/c/",
                "secret_key", "--absolute", "--digest", "sha1"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
            expected = output.out

        argv = ["", "tempurl", "GET", '2005-05-01', "/v1/a/c/",
                "secret_key", "--absolute", "--digest", "sha1"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
            self.assertEqual(expected, output.out)

        argv = ["", "tempurl", "GET", "60", "/v1/a/c/o",
                "secret_key", "--absolute", "--ip-range", "1.2.3.4",
                "--digest", "sha1"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        sig = "6a6ec8efa4be53904ecba8d055d841e24a937c98"
        expected = (
            "/v1/a/c/o?temp_url_sig=%s&temp_url_expires=60"
            "&temp_url_ip_range=1.2.3.4\n" % sig
        )
        self.assertEqual(expected, output.out)

    def test_temp_url_digests_output(self):
        argv = ["", "tempurl", "GET", "60", "/v1/a/c/o",
                "secret_key", "--absolute"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        s = "db04994a589b1a2538bff694f0a4f57c7a397617ac2cb49f924d222bbe2b3e01"
        expected = "/v1/a/c/o?temp_url_sig=%s&temp_url_expires=60\n" % s
        self.assertEqual(expected, output.out)

        argv = ["", "tempurl", "GET", "60", "/v1/a/c/o",
                "secret_key", "--absolute", "--digest", "sha256"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        # same signature/expectation
        self.assertEqual(expected, output.out)

        argv = ["", "tempurl", "GET", "60", "/v1/a/c/o",
                "secret_key", "--absolute", "--digest", "sha1"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        sig = "63bc77a473a1c2ce956548cacf916f292eb9eac3"
        expected = "/v1/a/c/o?temp_url_sig=%s&temp_url_expires=60\n" % sig
        self.assertEqual(expected, output.out)

        argv = ["", "tempurl", "GET", "60", "/v1/a/c/o",
                "secret_key", "--absolute", "--digest", "sha512"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        sig = ("sha512:nMXwEAHu3jzlCZi4wWO1juEq4DikFlX8a729PLJVvUp"
               "vg0GpgkJnX5uCG1x-v2KfTrmRtLOcT7KBK2RXLW1uKw")
        expected = "/v1/a/c/o?temp_url_sig=%s&temp_url_expires=60\n" % sig
        self.assertEqual(expected, output.out)

    def test_temp_url_error_output(self):
        expected = 'path must be full path to an object e.g. /v1/a/c/o\n'
        for bad_path in ('/v1/a/c', 'v1/a/c/o', '/v1/a/c/', '/v1/a//o',
                         'http://saio/v1/a/c', 'http://v1/a/c/o'):
            argv = ["", "tempurl", "GET", "60", bad_path,
                    "secret_key", "--absolute"]
            with CaptureOutput(suppress_systemexit=True) as output:
                swiftclient.shell.main(argv)
            self.assertEqual(expected, output.err,
                             'Expected %r but got %r for path %r' %
                             (expected, output.err, bad_path))

        expected = 'path must at least contain /v1/a/c/\n'
        argv = ["", "tempurl", "GET", "60", '/v1/a/c',
                    "secret_key", "--absolute", '--prefix-based']
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        self.assertEqual(expected, output.err,
                         'Expected %r but got %r for path %r' %
                         (expected, output.err, '/v1/a/c'))

        expected = TIME_ERRMSG + '\n'
        for bad_time in ('not_an_int', '-1', '2015-05', '2015-05-01T01:00'):
            argv = ["", "tempurl", "GET", bad_time, '/v1/a/c/o',
                        "secret_key", "--absolute"]
            with CaptureOutput(suppress_systemexit=True) as output:
                swiftclient.shell.main(argv)
            self.assertEqual(expected, output.err,
                             'Expected %r but got %r for time %r' %
                             (expected, output.err, bad_time))

    @mock.patch('swiftclient.service.Connection')
    def test_capabilities(self, connection):
        argv = ["", "capabilities"]
        connection.return_value.get_capabilities.return_value = {'swift': None}
        swiftclient.shell.main(argv)
        connection.return_value.get_capabilities.assert_called_with(None)

    @mock.patch('swiftclient.service.Connection')
    def test_capabilities_json(self, connection):
        capabilities = {
            'slo': {'min_segment_size': 1000000},
            'some': [{'arbitrary': 'nested'}, {'crazy': 'structure'}],
            'swift': {'version': '2.5.0'}}

        connection.return_value.get_capabilities.return_value = capabilities
        argv = ["", "capabilities", "--json"]
        with CaptureOutput(suppress_systemexit=True) as output:
            swiftclient.shell.main(argv)
        expected = json.dumps(capabilities, sort_keys=True, indent=2) + '\n'
        self.assertEqual(expected, output.out)
        connection.return_value.get_capabilities.assert_called_with(None)

    def test_human_readable_upload_segment_size(self):
        def _check_expected(x, expected):
            actual = x.call_args_list[-1][1]["options"]["segment_size"]
            self.assertEqual(int(actual), expected)

        mock_swift = mock.MagicMock(spec=swiftclient.shell.SwiftService)
        with mock.patch("swiftclient.shell.SwiftService", mock_swift):
            with CaptureOutput(suppress_systemexit=True) as output:
                # Test new behaviour with both upper and lower case
                # trailing characters
                argv = ["", "upload", "-S", "1B", "container", "object"]
                swiftclient.shell.main(argv)
                _check_expected(mock_swift, 1)

                argv = ["", "upload", "-S", "1K", "container", "object"]
                swiftclient.shell.main(argv)
                _check_expected(mock_swift, 1024)

                argv = ["", "upload", "-S", "1m", "container", "object"]
                swiftclient.shell.main(argv)
                _check_expected(mock_swift, 1048576)

                argv = ["", "upload", "-S", "1G", "container", "object"]
                swiftclient.shell.main(argv)
                _check_expected(mock_swift, 1073741824)

                # Test old behaviour is not affected
                argv = ["", "upload", "-S", "12345", "container", "object"]
                swiftclient.shell.main(argv)
                _check_expected(mock_swift, 12345)

            with CaptureOutput() as output:
                with self.assertRaises(SystemExit):
                    #  Test invalid states
                    argv = ["", "upload", "-S", "1234X", "container", "object"]
                    swiftclient.shell.main(argv)
                self.assertEqual(output.err, "Invalid segment size\n")
                output.clear()

                with self.assertRaises(SystemExit):
                    argv = ["", "upload", "-S", "K1234", "container", "object"]
                    swiftclient.shell.main(argv)
                self.assertEqual(output.err, "Invalid segment size\n")
                output.clear()

                with self.assertRaises(SystemExit):
                    argv = ["", "upload", "-S", "K", "container", "object"]
                    swiftclient.shell.main(argv)
                self.assertEqual(output.err, "Invalid segment size\n")

    def test_negative_upload_segment_size(self):
        with CaptureOutput() as output:
            with self.assertRaises(SystemExit):
                argv = ["", "upload", "-S", "-40", "container", "object"]
                swiftclient.shell.main(argv)
            self.assertEqual(output.err, "segment-size should be positive\n")
            output.clear()
            with self.assertRaises(SystemExit):
                argv = ["", "upload", "-S=-40K", "container", "object"]
                swiftclient.shell.main(argv)
            self.assertEqual(output.err, "segment-size should be positive\n")
            output.clear()
            with self.assertRaises(SystemExit):
                argv = ["", "upload", "-S=-40M", "container", "object"]
                swiftclient.shell.main(argv)
            self.assertEqual(output.err, "segment-size should be positive\n")
            output.clear()
            with self.assertRaises(SystemExit):
                argv = ["", "upload", "-S=-40G", "container", "object"]
                swiftclient.shell.main(argv)
            self.assertEqual(output.err, "segment-size should be positive\n")
            output.clear()


class TestSubcommandHelp(unittest.TestCase):

    def test_subcommand_help(self):
        for command in swiftclient.shell.commands:
            help_var = 'st_%s_help' % command
            options_var = 'st_%s_options' % command
            self.assertTrue(hasattr(swiftclient.shell, help_var))
            with CaptureOutput() as out:
                argv = ['', command, '--help']
                self.assertRaises(SystemExit, swiftclient.shell.main, argv)
            expected = 'Usage: swift %s %s\n%s' % (
                command, vars(swiftclient.shell).get(options_var, "\n"),
                vars(swiftclient.shell)[help_var])
            self.assertEqual(out.strip('\n'), expected)

    def test_no_help(self):
        with CaptureOutput() as out:
            argv = ['', 'bad_command', '--help']
            self.assertRaises(SystemExit, swiftclient.shell.main, argv)
        expected = 'no such command: bad_command'
        self.assertEqual(out.strip('\n'), expected)


@mock.patch.dict(os.environ, mocked_os_environ)
class TestDebugAndInfoOptions(unittest.TestCase):
    @mock.patch('logging.basicConfig')
    @mock.patch('swiftclient.service.Connection')
    def test_option_after_posarg(self, connection, mock_logging):
        argv = ["", "stat", "--info"]
        swiftclient.shell.main(argv)
        mock_logging.assert_called_with(level=logging.INFO)

        argv = ["", "stat", "--debug"]
        swiftclient.shell.main(argv)
        mock_logging.assert_called_with(level=logging.DEBUG)

    @mock.patch('logging.basicConfig')
    @mock.patch('swiftclient.service.Connection')
    def test_debug_trumps_info(self, connection, mock_logging):
        argv_scenarios = (["", "stat", "--info", "--debug"],
                          ["", "stat", "--debug", "--info"],
                          ["", "--info", "stat", "--debug"],
                          ["", "--debug", "stat", "--info"],
                          ["", "--info", "--debug", "stat"],
                          ["", "--debug", "--info", "stat"])
        for argv in argv_scenarios:
            mock_logging.reset_mock()
            swiftclient.shell.main(argv)
            try:
                mock_logging.assert_called_once_with(level=logging.DEBUG)
            except AssertionError:
                self.fail('Unexpected call(s) %r for args %r'
                          % (mock_logging.call_args_list, argv))


class TestBase(unittest.TestCase):
    """
    Provide some common methods to subclasses
    """
    def _remove_swift_env_vars(self):
        self._environ_vars = {}
        keys = list(os.environ.keys())
        for k in keys:
            if (k in ('ST_KEY', 'ST_USER', 'ST_AUTH') or
                    k.startswith('OS_')):
                self._environ_vars[k] = os.environ.pop(k)

    def _replace_swift_env_vars(self):
        os.environ.update(self._environ_vars)


class TestParsing(TestBase):

    def setUp(self):
        super(TestParsing, self).setUp()
        self._remove_swift_env_vars()

    def tearDown(self):
        self._replace_swift_env_vars()
        super(TestParsing, self).tearDown()

    def _make_fake_command(self, result):
        def fake_command(parser, args, thread_manager):
            result[0], result[1] = swiftclient.shell.parse_args(parser, args)
        return fake_command

    def _verify_opts(self, actual_opts, expected_opts, expected_os_opts=None,
                     expected_os_opts_dict=None):
        """
        Check parsed options are correct.

        :param expected_opts: v1 style options.
        :param expected_os_opts: openstack style options.
        :param expected_os_opts_dict: openstack options that should be found in
                                      the os_options dict.
        """
        expected_os_opts = expected_os_opts or {}
        expected_os_opts_dict = expected_os_opts_dict or {}
        # check the expected opts are set
        for key, v in expected_opts.items():
            actual = actual_opts.get(key)
            self.assertEqual(v, actual, 'Expected %s for key %s, found %s' %
                             (v, key, actual))

        for key, v in expected_os_opts.items():
            actual = actual_opts.get("os_" + key)
            self.assertEqual(v, actual, 'Expected %s for key %s, found %s' %
                             (v, key, actual))

        # check the os_options dict values are set
        self.assertIn('os_options', actual_opts)
        actual_os_opts_dict = actual_opts['os_options']
        expected_os_opts_keys = ['project_name', 'region_name',
                                 'tenant_name',
                                 'user_domain_name', 'endpoint_type',
                                 'object_storage_url', 'project_domain_id',
                                 'user_id', 'user_domain_id', 'tenant_id',
                                 'service_type', 'project_id', 'auth_token',
                                 'auth_type', 'application_credential_id',
                                 'application_credential_secret',
                                 'project_domain_name']
        for key in expected_os_opts_keys:
            self.assertIn(key, actual_os_opts_dict)
            cli_key = key
            if key == 'object_storage_url':
                # exceptions to the pattern...
                cli_key = 'storage_url'
            if cli_key in expected_os_opts_dict:
                expect = expected_os_opts_dict[cli_key]
            else:
                expect = None
            actual = actual_os_opts_dict[key]
            self.assertEqual(expect, actual, 'Expected %s for %s, got %s'
                             % (expect, key, actual))
        for key in actual_os_opts_dict:
            self.assertIn(key, expected_os_opts_keys)

        # check that equivalent keys have equal values
        equivalents = [('os_username', 'user'),
                       ('os_auth_url', 'auth'),
                       ('os_password', 'key')]
        for pair in equivalents:
            self.assertEqual(actual_opts.get(pair[0]),
                             actual_opts.get(pair[1]))

    def test_minimum_required_args_v3(self):
        opts = {"auth_version": "3"}
        os_opts = {"password": "secret",
                   "username": "user",
                   "auth_url": "http://example.com:5000/v3"}

        # username with domain is sufficient in args because keystone will
        # assume user is in default domain
        args = _make_args("stat", opts, os_opts, '-')
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch('swiftclient.shell.st_stat', fake_command):
            swiftclient.shell.main(args)
        self._verify_opts(result[0], opts, os_opts, {})

        # check its ok to have user_id instead of username
        os_opts = {"password": "secret",
                   "auth_url": "http://example.com:5000/v3"}
        os_opts_dict = {"user_id": "user_ID"}
        all_os_opts = os_opts.copy()
        all_os_opts.update(os_opts_dict)

        args = _make_args("stat", opts, all_os_opts, '-')
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch('swiftclient.shell.st_stat', fake_command):
            swiftclient.shell.main(args)
        self._verify_opts(result[0], opts, os_opts, os_opts_dict)

        # check no user credentials required if token and url supplied
        os_opts = {}
        os_opts_dict = {"storage_url": "http://example.com:8080/v1",
                        "auth_token": "0123abcd"}

        args = _make_args("stat", opts, os_opts_dict, '-')
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch('swiftclient.shell.st_stat', fake_command):
            swiftclient.shell.main(args)
        self._verify_opts(result[0], opts, os_opts, os_opts_dict)

    def test_sloppy_versions(self):
        os_opts = {"password": "secret",
                   "username": "user",
                   "auth_url": "http://example.com:5000/v3",
                   "identity-api-version": "3.0"}

        # check os_identity_api_version=3.0 is mapped to auth_version=3
        args = _make_args("stat", {}, os_opts, '-')
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch.dict(os.environ, {}):
            with mock.patch('swiftclient.shell.st_stat', fake_command):
                swiftclient.shell.main(args)
        expected_opts = {'auth_version': '3'}  # NB: not '3.0'
        expected_os_opts = {"password": "secret",
                            "username": "user",
                            "auth_url": "http://example.com:5000/v3"}
        self._verify_opts(result[0], expected_opts, expected_os_opts, {})

        # check os_identity_api_version=2 is mapped to auth_version=2.0
        # A somewhat contrived scenario - we need to pass in the v1 style opts
        # to prevent auth version defaulting to 2.0 due to lack of v1 style
        # options. That way we can actually verify that the sloppy 2 was
        # interpreted and mapped to 2.0
        os_opts = {"password": "secret",
                   "username": "user",
                   "auth_url": "http://example.com:5000/v2.0",
                   "identity-api-version": "2"}
        opts = {"key": "secret",
                "user": "user",
                "auth": "http://example.com:5000/v2.0"}
        args = _make_args("stat", opts, os_opts, '-')
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch.dict(os.environ, {}):
            with mock.patch('swiftclient.shell.st_stat', fake_command):
                swiftclient.shell.main(args)
        expected_opts = {'auth_version': '2.0'}  # NB: not '2'
        expected_os_opts = {"password": "secret",
                            "username": "user",
                            "auth_url": "http://example.com:5000/v2.0"}
        self._verify_opts(result[0], expected_opts, expected_os_opts, {})

    def test_os_identity_api_version(self):
        os_opts = {"password": "secret",
                   "username": "user",
                   "auth_url": "http://example.com:5000/v3",
                   "identity-api-version": "3"}

        # check os_identity_api_version is sufficient in place of auth_version
        args = _make_args("stat", {}, os_opts, '-')
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch.dict(os.environ, {}):
            with mock.patch('swiftclient.shell.st_stat', fake_command):
                swiftclient.shell.main(args)
        expected_opts = {'auth_version': '3'}
        expected_os_opts = {"password": "secret",
                            "username": "user",
                            "auth_url": "http://example.com:5000/v3"}
        self._verify_opts(result[0], expected_opts, expected_os_opts, {})

        # check again using environment variables
        args = _make_args("stat", {}, {})
        env = _make_env({}, os_opts)
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch.dict(os.environ, env):
            with mock.patch('swiftclient.shell.st_stat', fake_command):
                swiftclient.shell.main(args)
        self._verify_opts(result[0], expected_opts, expected_os_opts, {})

        # check that last of auth-version, os-identity-api-version is preferred
        args = _make_args("stat", {}, os_opts, '-') + ['--auth-version', '2.0']
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch.dict(os.environ, {}):
            with mock.patch('swiftclient.shell.st_stat', fake_command):
                swiftclient.shell.main(args)
        expected_opts = {'auth_version': '2.0'}
        self._verify_opts(result[0], expected_opts, expected_os_opts, {})

        # now put auth_version ahead of os-identity-api-version
        args = _make_args("stat", {"auth_version": "2.0"}, os_opts, '-')
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch.dict(os.environ, {}):
            with mock.patch('swiftclient.shell.st_stat', fake_command):
                swiftclient.shell.main(args)
        expected_opts = {'auth_version': '3'}
        self._verify_opts(result[0], expected_opts, expected_os_opts, {})

        # check that OS_AUTH_VERSION overrides OS_IDENTITY_API_VERSION
        args = _make_args("stat", {}, {})
        env = _make_env({}, os_opts)
        env.update({'OS_AUTH_VERSION': '2.0'})
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch.dict(os.environ, env):
            with mock.patch('swiftclient.shell.st_stat', fake_command):
                swiftclient.shell.main(args)
        expected_opts = {'auth_version': '2.0'}
        self._verify_opts(result[0], expected_opts, expected_os_opts, {})

        # check that ST_AUTH_VERSION overrides OS_IDENTITY_API_VERSION
        args = _make_args("stat", {}, {})
        env = _make_env({}, os_opts)
        env.update({'ST_AUTH_VERSION': '2.0'})
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch.dict(os.environ, env):
            with mock.patch('swiftclient.shell.st_stat', fake_command):
                swiftclient.shell.main(args)
        self._verify_opts(result[0], expected_opts, expected_os_opts, {})

        # check that ST_AUTH_VERSION overrides OS_AUTH_VERSION
        args = _make_args("stat", {}, {})
        env = _make_env({}, os_opts)
        env.update({'ST_AUTH_VERSION': '2.0', 'OS_AUTH_VERSION': '3'})
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch.dict(os.environ, env):
            with mock.patch('swiftclient.shell.st_stat', fake_command):
                swiftclient.shell.main(args)
        self._verify_opts(result[0], expected_opts, expected_os_opts, {})

    def test_args_v3(self):
        opts = {"auth_version": "3"}
        os_opts = {"password": "secret",
                   "username": "user",
                   "auth_url": "http://example.com:5000/v3"}
        os_opts_dict = {"user_id": "user_ID",
                        "project_id": "project_ID",
                        "tenant_id": "tenant_ID",
                        "project_domain_id": "project_domain_ID",
                        "user_domain_id": "user_domain_ID",
                        "tenant_name": "tenant",
                        "project_name": "project",
                        "project_domain_name": "project_domain",
                        "user_domain_name": "user_domain",
                        "auth_token": "token",
                        "storage_url": "http://example.com:8080/v1",
                        "region_name": "region",
                        "service_type": "service",
                        "endpoint_type": "endpoint"}
        all_os_opts = os_opts.copy()
        all_os_opts.update(os_opts_dict)

        # check using hyphen separator
        args = _make_args("stat", opts, all_os_opts, '-')
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch('swiftclient.shell.st_stat', fake_command):
            swiftclient.shell.main(args)
        self._verify_opts(result[0], opts, os_opts, os_opts_dict)

        # check using underscore separator
        args = _make_args("stat", opts, all_os_opts, '_')
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch('swiftclient.shell.st_stat', fake_command):
            swiftclient.shell.main(args)
        self._verify_opts(result[0], opts, os_opts, os_opts_dict)

        # check using environment variables
        args = _make_args("stat", {}, {})
        env = _make_env(opts, all_os_opts)
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch.dict(os.environ, env):
            with mock.patch('swiftclient.shell.st_stat', fake_command):
                swiftclient.shell.main(args)
        self._verify_opts(result[0], opts, os_opts, os_opts_dict)

        # check again using OS_AUTH_VERSION instead of ST_AUTH_VERSION
        env = _make_env({}, all_os_opts)
        env.update({'OS_AUTH_VERSION': '3'})
        result = [None, None]
        fake_command = self._make_fake_command(result)
        with mock.patch.dict(os.environ, env):
            with mock.patch('swiftclient.shell.st_stat', fake_command):
                swiftclient.shell.main(args)
        self._verify_opts(result[0], opts, os_opts, os_opts_dict)

    def test_command_args_v3(self):
        result = [None, None]
        fake_command = self._make_fake_command(result)
        opts = {"auth_version": "3"}
        os_opts = {"password": "secret",
                   "username": "user",
                   "auth_url": "http://example.com:5000/v3"}
        args = _make_args("stat", opts, os_opts)
        with mock.patch('swiftclient.shell.st_stat', fake_command):
            swiftclient.shell.main(args)
            self.assertEqual(['stat'], result[1])
        with mock.patch('swiftclient.shell.st_stat', fake_command):
            args = args + ["container_name"]
            swiftclient.shell.main(args)
            self.assertEqual(["stat", "container_name"], result[1])

    def test_insufficient_args_v3(self):
        opts = {"auth_version": "3"}
        os_opts = {"password": "secret",
                   "auth_url": "http://example.com:5000/v3"}
        args = _make_args("stat", opts, os_opts)
        with self.assertRaises(SystemExit) as cm:
            swiftclient.shell.main(args)
        self.assertIn(
            'Auth version 3 requires either OS_USERNAME or OS_USER_ID',
            str(cm.exception))

        os_opts = {"username": "user",
                   "auth_url": "http://example.com:5000/v3"}
        args = _make_args("stat", opts, os_opts)
        with self.assertRaises(SystemExit) as cm:
            swiftclient.shell.main(args)
        self.assertIn('Auth version 3 requires OS_PASSWORD', str(cm.exception))

        os_opts = {"username": "user",
                   "password": "secret"}
        args = _make_args("stat", opts, os_opts)
        with self.assertRaises(SystemExit) as cm:
            swiftclient.shell.main(args)
        self.assertIn('Auth version 3 requires OS_AUTH_URL', str(cm.exception))

    def test_command_args_v3applicationcredential(self):
        result = [None, None]
        fake_command = self._make_fake_command(result)
        opts = {"auth_version": "3"}
        os_opts = {
            "auth_type": "v3applicationcredential",
            "application_credential_id": "proejct_id",
            "application_credential_secret": "secret",
            "auth_url": "http://example.com:5000/v3"}

        args = _make_args("stat", opts, os_opts)
        with mock.patch('swiftclient.shell.st_stat', fake_command):
            swiftclient.shell.main(args)
            self.assertEqual(['stat'], result[1])
        with mock.patch('swiftclient.shell.st_stat', fake_command):
            args = args + ["container_name"]
            swiftclient.shell.main(args)
            self.assertEqual(["stat", "container_name"], result[1])

    def test_insufficient_args_v3applicationcredential(self):
        opts = {"auth_version": "3"}
        os_opts = {
            "auth_type": "v3applicationcredential",
            "application_credential_secret": "secret",
            "auth_url": "http://example.com:5000/v3"}

        args = _make_args("stat", opts, os_opts)
        with self.assertRaises(SystemExit) as cm:
            swiftclient.shell.main(args)
        self.assertIn('Auth version 3 (application credential) requires',
                      str(cm.exception))

        os_opts = {
            "auth_type": "v3oidcpassword",
            "application_credential_id": "proejct_id",
            "application_credential_secret": "secret",
            "auth_url": "http://example.com:5000/v3"}

        args = _make_args("stat", opts, os_opts)
        with self.assertRaises(SystemExit) as cm:
            swiftclient.shell.main(args)
        self.assertIn('Only "v3applicationcredential" is supported for',
                      str(cm.exception))

    def test_password_prompt(self):
        def do_test(opts, os_opts, auth_version):
            args = _make_args("stat", opts, os_opts)
            result = [None, None]
            fake_command = self._make_fake_command(result)
            with mock.patch('swiftclient.shell.st_stat', fake_command):
                with mock.patch('getpass.getpass',
                                return_value='input_pwd') as mock_getpass:
                    swiftclient.shell.main(args)
            mock_getpass.assert_called_once_with()
            self.assertEqual('input_pwd', result[0]['key'])
            self.assertEqual('input_pwd', result[0]['os_password'])

            # ctrl-D
            with self.assertRaises(SystemExit) as cm:
                with mock.patch('swiftclient.shell.st_stat', fake_command):
                    with mock.patch('getpass.getpass',
                                    side_effect=EOFError) as mock_getpass:
                        swiftclient.shell.main(args)
            mock_getpass.assert_called_once_with()
            self.assertIn(
                'Auth version %s requires' % auth_version, str(cm.exception))

            # force getpass to think it needs to use raw input
            with self.assertRaises(SystemExit) as cm:
                with mock.patch('getpass.getpass', getpass.fallback_getpass):
                    swiftclient.shell.main(args)
            self.assertIn(
                'Input stream incompatible', str(cm.exception))

        opts = {"prompt": None, "user": "bob", "key": "secret",
                "auth": "http://example.com:8080/auth/v1.0"}
        do_test(opts, {}, '1.0')
        os_opts = {"username": "user",
                   "password": "secret",
                   "auth_url": "http://example.com:5000/v3"}
        opts = {"auth_version": "2.0", "prompt": None}
        do_test(opts, os_opts, '2.0')
        opts = {"auth_version": "3", "prompt": None}
        do_test(opts, os_opts, '3')

    def test_no_tenant_name_or_id_v2(self):
        os_opts = {"password": "secret",
                   "username": "user",
                   "auth_url": "http://example.com:5000/v3",
                   "tenant_name": "",
                   "tenant_id": ""}

        with CaptureOutput() as output:
            args = _make_args("stat", {}, os_opts)
            self.assertRaises(SystemExit, swiftclient.shell.main, args)
        self.assertEqual(output.err.strip(), 'No tenant specified')

        with CaptureOutput() as output:
            args = _make_args("stat", {}, os_opts, cmd_args=["testcontainer"])
            self.assertRaises(SystemExit, swiftclient.shell.main, args)
        self.assertEqual(output.err.strip(), 'No tenant specified')

    def test_no_tenant_name_or_id_v3(self):
        os_opts = {"password": "secret",
                   "username": "user",
                   "auth_url": "http://example.com:5000/v3",
                   "tenant_name": "",
                   "tenant_id": ""}

        with CaptureOutput() as output:
            args = _make_args("stat", {"auth_version": "3"}, os_opts)
            self.assertRaises(SystemExit, swiftclient.shell.main, args)
        self.assertEqual(output.err.strip(),
                         'No project name or project id specified.')

        with CaptureOutput() as output:
            args = _make_args("stat", {"auth_version": "3"},
                              os_opts, cmd_args=["testcontainer"])
            self.assertRaises(SystemExit, swiftclient.shell.main, args)
        self.assertEqual(output.err.strip(),
                         'No project name or project id specified.')

    def test_insufficient_env_vars_v3(self):
        args = _make_args("stat", {}, {})
        opts = {"auth_version": "3"}
        os_opts = {"password": "secret",
                   "auth_url": "http://example.com:5000/v3"}
        env = _make_env(opts, os_opts)
        with mock.patch.dict(os.environ, env):
            self.assertRaises(SystemExit, swiftclient.shell.main, args)

        os_opts = {"username": "user",
                   "auth_url": "http://example.com:5000/v3"}
        env = _make_env(opts, os_opts)
        with mock.patch.dict(os.environ, env):
            self.assertRaises(SystemExit, swiftclient.shell.main, args)

        os_opts = {"username": "user",
                   "password": "secret"}
        env = _make_env(opts, os_opts)
        with mock.patch.dict(os.environ, env):
            self.assertRaises(SystemExit, swiftclient.shell.main, args)

    def test_help(self):
        # --help returns condensed help message
        opts = {"help": None}
        os_opts = {}
        args = _make_args(None, opts, os_opts)
        with CaptureOutput() as out:
            self.assertRaises(SystemExit, swiftclient.shell.main, args)
        self.assertTrue(out.find('[--key <api_key>]') > 0)
        self.assertEqual(-1, out.find('--os-username=<auth-user-name>'))

        # --help returns condensed help message, overrides --os-help
        opts = {"help": None}
        os_opts = {"help": None}
        args = _make_args("", opts, os_opts)
        with CaptureOutput() as out:
            self.assertRaises(SystemExit, swiftclient.shell.main, args)
        self.assertTrue(out.find('[--key <api_key>]') > 0)
        self.assertEqual(-1, out.find('--os-username=<auth-user-name>'))

        # --os-password, --os-username and --os-auth_url should be ignored
        # because --help overrides it
        opts = {"help": None}
        os_opts = {"help": None,
                   "password": "secret",
                   "username": "user",
                   "auth_url": "http://example.com:5000/v3"}
        args = _make_args("", opts, os_opts)
        with CaptureOutput() as out:
            self.assertRaises(SystemExit, swiftclient.shell.main, args)
        self.assertTrue(out.find('[--key <api_key>]') > 0)
        self.assertEqual(-1, out.find('--os-username=<auth-user-name>'))

        # --os-help return os options help
        opts = {}
        args = _make_args("", opts, os_opts)
        with CaptureOutput() as out:
            self.assertRaises(SystemExit, swiftclient.shell.main, args)
        self.assertTrue(out.find('[--key <api_key>]') > 0)
        self.assertTrue(out.find('--os-username=<auth-user-name>') > 0)


class TestKeystoneOptions(MockHttpTest):
    """
    Tests to check that options are passed from the command line or
    environment variables through to the keystone client interface.
    """
    all_os_opts = {'password': 'secret',
                   'username': 'user',
                   'auth-url': 'http://example.com:5000/v3',
                   'user-domain-name': 'userdomain',
                   'user-id': 'userid',
                   'user-domain-id': 'userdomainid',
                   'tenant-name': 'tenantname',
                   'tenant-id': 'tenantid',
                   'project-name': 'projectname',
                   'project-id': 'projectid',
                   'project-domain-id': 'projectdomainid',
                   'project-domain-name': 'projectdomain',
                   'cacert': 'foo',
                   'cert': 'minnie',
                   'key': 'mickey'}
    catalog_opts = {'service-type': 'my-object-store',
                    'endpoint-type': 'public',
                    'region-name': 'my-region'}
    flags = ['insecure', 'debug']

    # options that are given default values in code if missing from CLI
    defaults = {'auth-version': '2.0',
                'service-type': 'object-store',
                'endpoint-type': 'publicURL'}

    def _build_os_opts(self, keys):
        os_opts = {}
        for k in keys:
            os_opts[k] = self.all_os_opts.get(k, self.catalog_opts.get(k))
        return os_opts

    def _test_options_passed_to_keystone(self, cmd, opts, os_opts,
                                         flags=None, use_env=False,
                                         cmd_args=None, no_auth=False):
        flags = flags or []
        if use_env:
            # set up fake environment variables and make a minimal command line
            env = _make_env(opts, os_opts)
            args = _make_args(cmd, {}, {}, separator='-', flags=flags,
                              cmd_args=cmd_args)
        else:
            # set up empty environment and make full command line
            env = {}
            args = _make_args(cmd, opts, os_opts, separator='-', flags=flags,
                              cmd_args=cmd_args)
        ks_endpoint = 'http://example.com:8080/v1/AUTH_acc'
        ks_token = 'fake_auth_token'
        # check correct auth version gets used
        key = 'auth-version'
        fake_ks = FakeKeystone(endpoint=ks_endpoint, token=ks_token)
        if no_auth:
            fake_ks2 = fake_ks3 = None
        elif opts.get(key, self.defaults.get(key)) == '2.0':
            fake_ks2 = fake_ks
            fake_ks3 = None
        else:
            fake_ks2 = None
            fake_ks3 = fake_ks
        # fake_conn will check that storage_url and auth_token are as expected
        endpoint = os_opts.get('storage-url', ks_endpoint)
        token = os_opts.get('auth-token', ks_token)
        fake_conn = self.fake_http_connection(204, headers={},
                                              storage_url=endpoint,
                                              auth_token=token)

        with mock.patch('swiftclient.client.ksclient_v2', fake_ks2), \
                mock.patch('swiftclient.client.ksclient_v3', fake_ks3), \
                mock.patch('swiftclient.client.http_connection', fake_conn), \
                mock.patch.dict(os.environ, env, clear=True), \
                patch_disable_warnings() as mock_disable_warnings:
            try:
                swiftclient.shell.main(args)
            except SystemExit as e:
                self.fail('Unexpected SystemExit: %s' % e)
            except SwiftError as err:
                self.fail('Unexpected SwiftError: %s' % err)

        if InsecureRequestWarning is not None:
            if 'insecure' in flags:
                self.assertEqual([mock.call(InsecureRequestWarning)],
                                 mock_disable_warnings.mock_calls)
            else:
                self.assertEqual([], mock_disable_warnings.mock_calls)

        if no_auth:
            # We patched out both keystoneclient versions to be None;
            # they *can't* have been used and if we tried to, we would
            # have raised ClientExceptions
            return

        # check args passed to keystone Client __init__
        self.assertEqual(len(fake_ks.calls), 1)
        actual_args = fake_ks.calls[0]
        for key in self.all_os_opts.keys():
            expected = os_opts.get(key, self.defaults.get(key))
            key = key.replace('-', '_')
            self.assertIn(key, actual_args)
            self.assertEqual(expected, actual_args[key],
                             'Expected %s for key %s, found %s'
                             % (expected, key, actual_args[key]))
        for flag in flags:
            self.assertIn(flag, actual_args)
            self.assertTrue(actual_args[flag])

        check_attr = True
        # check args passed to ServiceCatalog.url_for() method
        self.assertEqual(len(fake_ks.client.service_catalog.calls), 1)
        actual_args = fake_ks.client.service_catalog.calls[0]
        for key in self.catalog_opts.keys():
            expected = os_opts.get(key, self.defaults.get(key))
            key = key.replace('-', '_')
            if key == 'region_name':
                key = 'filter_value'
                if expected is None:
                    check_attr = False
                    self.assertNotIn(key, actual_args)
                    self.assertNotIn('attr', actual_args)
                    continue
            self.assertIn(key, actual_args)
            self.assertEqual(expected, actual_args[key],
                             'Expected %s for key %s, found %s'
                             % (expected, key, actual_args[key]))
        if check_attr:
            key, v = 'attr', 'region'
            self.assertIn(key, actual_args)
            self.assertEqual(v, actual_args[key],
                             'Expected %s for key %s, found %s'
                             % (v, key, actual_args[key]))

    def _test_options(self, opts, os_opts, flags=None, no_auth=False):
        # repeat test for different commands using env and command line options
        for cmd in ('stat', 'post'):
            self._test_options_passed_to_keystone(cmd, opts, os_opts,
                                                  flags=flags, no_auth=no_auth)
            self._test_options_passed_to_keystone(cmd, opts, os_opts,
                                                  flags=flags, use_env=True,
                                                  no_auth=no_auth)

    def test_all_args_passed_to_keystone(self):
        rootLogger = logging.getLogger()
        orig_lvl = rootLogger.getEffectiveLevel()
        try:
            rootLogger.setLevel(logging.DEBUG)
            # check that all possible command line args are passed to keystone
            opts = {'auth-version': '3'}
            os_opts = dict(self.all_os_opts)
            os_opts.update(self.catalog_opts)
            self._test_options(opts, os_opts, flags=self.flags)

            opts = {'auth-version': '2.0'}
            self._test_options(opts, os_opts, flags=self.flags)

            opts = {}
            self.defaults['auth-version'] = '3'
            self._test_options(opts, os_opts, flags=self.flags)

            for o in ('user-domain-name', 'user-domain-id',
                      'project-domain-name', 'project-domain-id'):
                os_opts.pop(o)
            self.defaults['auth-version'] = '2.0'
            self._test_options(opts, os_opts, flags=self.flags)
        finally:
            rootLogger.setLevel(orig_lvl)

    def test_catalog_options_and_flags_not_required_v3(self):
        # check that all possible command line args are passed to keystone
        opts = {'auth-version': '3'}
        os_opts = dict(self.all_os_opts)
        self._test_options(opts, os_opts, flags=None)

    def test_ok_option_combinations_v3(self):
        opts = {'auth-version': '3'}
        keys = ('username', 'password', 'tenant-name', 'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

        keys = ('user-id', 'password', 'tenant-name', 'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

        keys = ('user-id', 'password', 'tenant-id', 'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

        keys = ('user-id', 'password', 'project-name', 'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

        keys = ('user-id', 'password', 'project-id', 'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

    def test_ok_option_combinations_v2(self):
        opts = {'auth-version': '2.0'}
        keys = ('username', 'password', 'tenant-name', 'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

        keys = ('username', 'password', 'tenant-id', 'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

        # allow auth_version to default to 2.0
        opts = {}
        keys = ('username', 'password', 'tenant-name', 'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

        keys = ('username', 'password', 'tenant-id', 'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

        # ...except when it should be 3
        self.defaults['auth-version'] = '3'
        keys = ('username', 'user-domain-name', 'password', 'project-name',
                'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

        keys = ('username', 'user-domain-id', 'password', 'project-name',
                'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

        keys = ('username', 'project-domain-name', 'password', 'project-name',
                'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

        keys = ('username', 'project-domain-id', 'password', 'project-name',
                'auth-url')
        os_opts = self._build_os_opts(keys)
        self._test_options(opts, os_opts)

    def test_url_and_token_provided_on_command_line(self):
        endpoint = 'http://alternate.com:8080/v1/AUTH_another'
        token = 'alternate_auth_token'
        os_opts = {'auth-token': token,
                   'storage-url': endpoint}
        opts = {'auth-version': '3'}
        self._test_options(opts, os_opts, no_auth=True)

        opts = {'auth-version': '2.0'}
        self._test_options(opts, os_opts, no_auth=True)

    def test_url_provided_on_command_line(self):
        endpoint = 'http://alternate.com:8080/v1/AUTH_another'
        os_opts = {'username': 'username',
                   'password': 'password',
                   'project-name': 'projectname',
                   'auth-url': 'http://example.com:5000/v3',
                   'storage-url': endpoint}
        opts = {'auth-version': '3'}
        self._test_options(opts, os_opts)

        opts = {'auth-version': '2.0'}
        self._test_options(opts, os_opts)


@mock.patch.dict(os.environ, clean_os_environ)
class TestAuth(MockHttpTest):

    def test_pre_authed_request(self):
        url = 'https://swift.storage.example.com/v1/AUTH_test'
        token = 'AUTH_tk5b6b12'

        pre_auth_env = {
            'OS_STORAGE_URL': url,
            'OS_AUTH_TOKEN': token,
        }
        fake_conn = self.fake_http_connection(200)
        with mock.patch('swiftclient.client.http_connection', new=fake_conn):
            with mock.patch.dict(os.environ, pre_auth_env):
                argv = ['', 'stat']
                swiftclient.shell.main(argv)
        self.assertRequests([
            ('HEAD', url, '', {'x-auth-token': token}),
        ])

        # and again with re-auth
        pre_auth_env.update(mocked_os_environ)
        pre_auth_env['OS_AUTH_TOKEN'] = 'expired'
        fake_conn = self.fake_http_connection(401, 200, 200, headers={
            'x-auth-token': token + '_new',
            'x-storage-url': url + '_not_used',
        })
        with mock.patch.multiple('swiftclient.client',
                                 http_connection=fake_conn,
                                 sleep=mock.DEFAULT):
            with mock.patch.dict(os.environ, pre_auth_env):
                argv = ['', 'stat']
                swiftclient.shell.main(argv)
        self.assertRequests([
            ('HEAD', url, '', {
                'x-auth-token': 'expired',
            }),
            ('GET', mocked_os_environ['ST_AUTH'], '', {
                'x-auth-user': mocked_os_environ['ST_USER'],
                'x-auth-key': mocked_os_environ['ST_KEY'],
            }),
            ('HEAD', url, '', {
                'x-auth-token': token + '_new',
            }),
        ])

    def test_os_pre_authed_request(self):
        url = 'https://swift.storage.example.com/v1/AUTH_test'
        token = 'AUTH_tk5b6b12'

        pre_auth_env = {
            'OS_STORAGE_URL': url,
            'OS_AUTH_TOKEN': token,
        }
        fake_conn = self.fake_http_connection(200)
        with mock.patch('swiftclient.client.http_connection', new=fake_conn):
            with mock.patch.dict(os.environ, pre_auth_env):
                argv = ['', 'stat']
                swiftclient.shell.main(argv)
        self.assertRequests([
            ('HEAD', url, '', {'x-auth-token': token}),
        ])

        # and again with re-auth
        os_environ = {
            'OS_AUTH_URL': 'https://keystone.example.com/v2.0/',
            'OS_TENANT_NAME': 'demo',
            'OS_USERNAME': 'demo',
            'OS_PASSWORD': 'admin',
        }
        os_environ.update(pre_auth_env)
        os_environ['OS_AUTH_TOKEN'] = 'expired'

        fake_conn = self.fake_http_connection(401, 200)
        fake_keystone = fake_get_auth_keystone(storage_url=url + '_not_used',
                                               token=token + '_new')
        with mock.patch.multiple('swiftclient.client',
                                 http_connection=fake_conn,
                                 get_auth_keystone=fake_keystone,
                                 sleep=mock.DEFAULT):
            with mock.patch.dict(os.environ, os_environ):
                argv = ['', 'stat']
                swiftclient.shell.main(argv)
        self.assertRequests([
            ('HEAD', url, '', {
                'x-auth-token': 'expired',
            }),
            ('HEAD', url, '', {
                'x-auth-token': token + '_new',
            }),
        ])

    def test_auth(self):
        headers = {
            'x-auth-token': 'AUTH_tk5b6b12',
            'x-storage-url': 'https://swift.storage.example.com/v1/AUTH_test',
        }
        mock_resp = self.fake_http_connection(200, headers=headers)
        with mock.patch('swiftclient.client.http_connection', new=mock_resp):
            stdout = io.StringIO()
            with mock.patch('sys.stdout', new=stdout):
                argv = [
                    '',
                    'auth',
                    '--auth', 'https://swift.storage.example.com/auth/v1.0',
                    '--user', 'test:tester', '--key', 'testing',
                ]
                swiftclient.shell.main(argv)

        expected = """
        export OS_STORAGE_URL=https://swift.storage.example.com/v1/AUTH_test
        export OS_AUTH_TOKEN=AUTH_tk5b6b12
        """
        self.assertEqual(textwrap.dedent(expected).lstrip(),
                         stdout.getvalue())

    def test_auth_verbose(self):
        with mock.patch('swiftclient.client.http_connection') as mock_conn:
            stdout = io.StringIO()
            with mock.patch('sys.stdout', new=stdout):
                argv = [
                    '',
                    'auth',
                    '--auth', 'https://swift.storage.example.com/auth/v1.0',
                    '--user', 'test:tester', '--key', 'te$tin&',
                    '--verbose',
                ]
                swiftclient.shell.main(argv)

        expected = """
        export ST_AUTH=https://swift.storage.example.com/auth/v1.0
        export ST_USER=test:tester
        export ST_KEY='te$tin&'
        """
        self.assertEqual(textwrap.dedent(expected).lstrip(),
                         stdout.getvalue())
        self.assertEqual([], mock_conn.mock_calls)

    def test_auth_v2(self):
        os_options = {'tenant_name': 'demo'}
        with mock.patch('swiftclient.client.get_auth_keystone',
                        new=fake_get_auth_keystone(os_options)):
            stdout = io.StringIO()
            with mock.patch('sys.stdout', new=stdout):
                argv = [
                    '',
                    'auth', '-V2',
                    '--auth', 'https://keystone.example.com/v2.0/',
                    '--os-tenant-name', 'demo',
                    '--os-username', 'demo', '--os-password', 'admin',
                ]
                swiftclient.shell.main(argv)

        expected = """
        export OS_STORAGE_URL=http://url/
        export OS_AUTH_TOKEN=token
        """
        self.assertEqual(textwrap.dedent(expected).lstrip(),
                         stdout.getvalue())

    def test_auth_verbose_v2(self):
        with mock.patch('swiftclient.client.get_auth_keystone') \
                as mock_keystone:
            stdout = io.StringIO()
            with mock.patch('sys.stdout', new=stdout):
                argv = [
                    '',
                    'auth', '-V2',
                    '--auth', 'https://keystone.example.com/v2.0/',
                    '--os-tenant-name', 'demo',
                    '--os-username', 'demo', '--os-password', '$eKr3t',
                    '--verbose',
                ]
                swiftclient.shell.main(argv)

        expected = """
        export OS_IDENTITY_API_VERSION=2.0
        export OS_AUTH_VERSION=2.0
        export OS_AUTH_URL=https://keystone.example.com/v2.0/
        export OS_PASSWORD='$eKr3t'
        export OS_TENANT_NAME=demo
        export OS_USERNAME=demo
        """
        self.assertEqual(textwrap.dedent(expected).lstrip(),
                         stdout.getvalue())
        self.assertEqual([], mock_keystone.mock_calls)


class TestCrossAccountObjectAccess(TestBase, MockHttpTest):
    """
    Tests to verify use of --os-storage-url will actually
    result in the object request being sent despite account
    read/write access and container write access being denied.
    """
    def setUp(self):
        super(TestCrossAccountObjectAccess, self).setUp()
        self._remove_swift_env_vars()
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.file.write(b'01234567890123456789')
        temp_file.file.flush()
        self.obj = temp_file.name
        self.url = 'http://alternate.com:8080/v1'

        # account tests will attempt to access
        self.account = 'AUTH_alice'

        # keystone returns endpoint for another account
        self.fake_ks = FakeKeystone(
            endpoint='http://example.com:8080/v1/AUTH_bob',
            token='bob_token')

        self.cont = 'c1'
        self.cont_path = '/v1/%s/%s' % (self.account, self.cont)
        self.obj_path = '%s%s' % (self.cont_path, self.obj)

        self.os_opts = {'username': 'bob',
                        'password': 'password',
                        'project-name': 'proj_bob',
                        'auth-url': 'http://example.com:5000/v3',
                        'storage-url': '%s/%s' % (self.url, self.account)}
        self.opts = {'auth-version': '3'}

    def tearDown(self):
        try:
            os.remove(self.obj)
        except OSError:
            pass
        self._replace_swift_env_vars()
        super(TestCrossAccountObjectAccess, self).tearDown()

    def _make_cmd(self, cmd, cmd_args=None):
        return _make_cmd(cmd, self.opts, self.os_opts, cmd_args=cmd_args)

    def _fake_cross_account_auth(self, read_ok, write_ok):
        def on_request(method, path, *args, **kwargs):
            """
            Modify response code to 200 if cross account permissions match.
            """
            status = 403
            if (path.startswith('/v1/%s/%s' % (self.account, self.cont)) and
                    read_ok and method in ('GET', 'HEAD')):
                status = 200
            elif (path.startswith('/v1/%s/%s%s'
                                  % (self.account, self.cont, self.obj)) and
                    write_ok and method in ('PUT', 'POST', 'DELETE')):
                status = 200
            return status
        return on_request

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 1)
    @mock.patch('swiftclient.service.Connection')
    def test_upload_bad_threads(self, mock_connection):
        mock_connection.return_value.put_object.return_value = EMPTY_ETAG
        mock_connection.return_value.attempts = 0

        def check_bad(argv):
            args, env = self._make_cmd(
                'upload', cmd_args=[self.cont, self.obj] + argv)
            with mock.patch.dict(os.environ, env):
                with CaptureOutput() as output:
                    self.assertRaises(SystemExit, swiftclient.shell.main, args)
            self.assertIn(
                'ERROR: option %s should be a positive integer.' % argv[0],
                output.err)

        def check_good(argv):
            args, env = self._make_cmd(
                'upload',
                cmd_args=[self.cont, self.obj, '--leave-segments'] + argv)
            with mock.patch.dict(os.environ, env):
                with CaptureOutput() as output:
                    swiftclient.shell.main(args)
            self.assertEqual('', output.err)
        check_bad(["--object-threads", "-1"])
        check_bad(["--object-threads", "0"])
        check_bad(["--segment-threads", "-1"])
        check_bad(["--segment-threads", "0"])
        check_good(["--object-threads", "1"])
        check_good(["--segment-threads", "1"])

    def test_upload_with_read_write_access(self):
        req_handler = self._fake_cross_account_auth(True, True)
        fake_conn = self.fake_http_connection(403, 403,
                                              on_request=req_handler)

        args, env = self._make_cmd('upload', cmd_args=[self.cont, self.obj,
                                                       '--leave-segments'])
        with mock.patch('swiftclient.client.ksclient_v3', self.fake_ks):
            with mock.patch('swiftclient.client.http_connection', fake_conn):
                with mock.patch.dict(os.environ, env):
                    with CaptureOutput() as out:
                        try:
                            swiftclient.shell.main(args)
                        except SystemExit as e:
                            self.fail('Unexpected SystemExit: %s' % e)

        self.assertRequests([('PUT', self.cont_path),
                             ('PUT', self.obj_path)])
        self.assertEqual(self.obj[1:], out.strip())
        expected_err = "Warning: failed to create container '%s': 403 Fake" \
                       % self.cont
        self.assertEqual(expected_err, out.err.strip())

    def test_upload_with_write_only_access(self):
        req_handler = self._fake_cross_account_auth(False, True)
        fake_conn = self.fake_http_connection(403, 403,
                                              on_request=req_handler)
        args, env = self._make_cmd('upload', cmd_args=[self.cont, self.obj,
                                                       '--leave-segments'])
        with mock.patch('swiftclient.client.ksclient_v3', self.fake_ks):
            with mock.patch('swiftclient.client.http_connection', fake_conn):
                with mock.patch.dict(os.environ, env):
                    with CaptureOutput() as out:
                        try:
                            swiftclient.shell.main(args)
                        except SystemExit as e:
                            self.fail('Unexpected SystemExit: %s' % e)
        self.assertRequests([('PUT', self.cont_path),
                             ('PUT', self.obj_path)])
        self.assertEqual(self.obj[1:], out.strip())
        expected_err = "Warning: failed to create container '%s': 403 Fake" \
                       % self.cont
        self.assertEqual(expected_err, out.err.strip())

    def test_segment_upload_with_write_only_access(self):
        req_handler = self._fake_cross_account_auth(False, True)
        fake_conn = self.fake_http_connection(403, 403, 403, 403,
                                              on_request=req_handler)

        args, env = self._make_cmd('upload',
                                   cmd_args=[self.cont, self.obj,
                                             '--leave-segments',
                                             '--segment-size=10',
                                             '--segment-container=%s'
                                             % self.cont])
        with mock.patch('swiftclient.client.ksclient_v3', self.fake_ks):
            with mock.patch('swiftclient.client.http_connection', fake_conn):
                with mock.patch.dict(os.environ, env):
                    with CaptureOutput() as out:
                        try:
                            swiftclient.shell.main(args)
                        except SystemExit as e:
                            self.fail('Unexpected SystemExit: %s' % e)

        segment_time = getmtime(self.obj)
        segment_path_0 = '%s/%f/20/10/00000000' % (self.obj_path, segment_time)
        segment_path_1 = '%s/%f/20/10/00000001' % (self.obj_path, segment_time)
        # Note that the order of segment PUTs cannot be asserted, so test for
        # existence in request log individually
        self.assert_request(('PUT', self.cont_path))
        self.assert_request(('PUT', segment_path_0))
        self.assert_request(('PUT', segment_path_1))
        self.assert_request(('PUT', self.obj_path))
        self.assertIn(self.obj[1:], out.out)
        expected_err = "Warning: failed to create container '%s': 403 Fake" \
                       % self.cont
        self.assertEqual(expected_err, out.err.strip())

    def test_segment_upload_with_write_only_access_segments_container(self):
        fake_conn = self.fake_http_connection(
            403,  # PUT c1
            # HEAD c1 to get storage policy
            StubResponse(200, headers={'X-Storage-Policy': 'foo'}),
            403,  # PUT c1_segments
            201,  # PUT c1_segments/...00
            201,  # PUT c1_segments/...01
            201,  # PUT c1/...
        )

        args, env = self._make_cmd('upload',
                                   cmd_args=[self.cont, self.obj,
                                             '--leave-segments',
                                             '--segment-size=10'])
        with mock.patch('swiftclient.client.ksclient_v3', self.fake_ks):
            with mock.patch('swiftclient.client.http_connection', fake_conn):
                with mock.patch.dict(os.environ, env):
                    with CaptureOutput() as out:
                        try:
                            swiftclient.shell.main(args)
                        except SystemExit as e:
                            self.fail('Unexpected SystemExit: %s' % e)

        segment_time = getmtime(self.obj)
        segment_path_0 = '%s_segments%s/%f/20/10/00000000' % (
            self.cont_path, self.obj, segment_time)
        segment_path_1 = '%s_segments%s/%f/20/10/00000001' % (
            self.cont_path, self.obj, segment_time)
        # Note that the order of segment PUTs cannot be asserted, so test for
        # existence in request log individually
        self.assert_request(('PUT', self.cont_path))
        self.assert_request(('PUT', self.cont_path + '_segments', '', {
            'X-Auth-Token': 'bob_token',
            'X-Storage-Policy': 'foo',
            'Content-Length': '0',
        }))
        self.assert_request(('PUT', segment_path_0))
        self.assert_request(('PUT', segment_path_1))
        self.assert_request(('PUT', self.obj_path))
        self.assertIn(self.obj[1:], out.out)
        expected_err = ("Warning: failed to create container '%s': 403 Fake\n"
                        "Warning: failed to create container '%s': 403 Fake"
                        ) % (self.cont, self.cont + '_segments')
        self.assertEqual(expected_err, out.err.strip())

    def test_upload_with_no_access(self):
        fake_conn = self.fake_http_connection(403, 403)

        args, env = self._make_cmd('upload', cmd_args=[self.cont, self.obj,
                                                       '--leave-segments'])
        with mock.patch('swiftclient.client.ksclient_v3', self.fake_ks):
            with mock.patch('swiftclient.client.http_connection', fake_conn):
                with mock.patch.dict(os.environ, env):
                    with CaptureOutput() as out:
                        try:
                            swiftclient.shell.main(args)
                            self.fail('Expected SystemExit')
                        except SystemExit:
                            pass

        self.assertRequests([('PUT', self.cont_path),
                             ('PUT', self.obj_path)])
        expected_err = 'Object PUT failed: http://1.2.3.4%s 403 Fake' \
                       % self.obj_path
        self.assertIn(expected_err, out.err)
        self.assertEqual('', out)

    @mock.patch.object(swiftclient.service.SwiftService,
                       '_bulk_delete_page_size', lambda *a: 1)
    @mock.patch('swiftclient.service.Connection')
    def test_download_bad_threads(self, mock_connection):
        mock_connection.return_value.get_object.return_value = [{}, '']
        mock_connection.return_value.attempts = 0

        def check_bad(argv):
            args, env = self._make_cmd(
                'download', cmd_args=[self.cont, self.obj] + argv)
            with mock.patch.dict(os.environ, env):
                with CaptureOutput() as output:
                    self.assertRaises(SystemExit, swiftclient.shell.main, args)
            self.assertIn(
                'ERROR: option %s should be a positive integer.' % argv[0],
                output.err)

        def check_good(argv):
            args, env = self._make_cmd(
                'download',
                cmd_args=[self.cont, self.obj, '--no-download'] + argv)
            with mock.patch.dict(os.environ, env):
                with CaptureOutput() as output:
                    swiftclient.shell.main(args)
            self.assertEqual('', output.err)
        check_bad(["--object-threads", "-1"])
        check_bad(["--object-threads", "0"])
        check_bad(["--container-threads", "-1"])
        check_bad(["--container-threads", "0"])
        check_good(["--object-threads", "1"])
        check_good(["--container-threads", "1"])

    def test_download_with_read_write_access(self):
        req_handler = self._fake_cross_account_auth(True, True)
        fake_conn = self.fake_http_connection(403, on_request=req_handler,
                                              etags=[EMPTY_ETAG])

        args, env = self._make_cmd('download', cmd_args=[self.cont,
                                                         self.obj.lstrip('/'),
                                                         '--no-download'])
        with mock.patch('swiftclient.client.ksclient_v3', self.fake_ks):
            with mock.patch('swiftclient.client.http_connection', fake_conn):
                with mock.patch.dict(os.environ, env):
                    with CaptureOutput() as out:
                        try:
                            swiftclient.shell.main(args)
                        except SystemExit as e:
                            self.fail('Unexpected SystemExit: %s' % e)

        self.assertRequests([('GET', self.obj_path)])
        self.assertTrue(out.out.startswith(self.obj.lstrip('/')))
        self.assertEqual('', out.err)

    def test_download_with_read_only_access(self):
        req_handler = self._fake_cross_account_auth(True, False)
        fake_conn = self.fake_http_connection(403, on_request=req_handler,
                                              etags=[EMPTY_ETAG])

        args, env = self._make_cmd('download', cmd_args=[self.cont,
                                                         self.obj.lstrip('/'),
                                                         '--no-download'])
        with mock.patch('swiftclient.client.ksclient_v3', self.fake_ks):
            with mock.patch('swiftclient.client.http_connection', fake_conn):
                with mock.patch.dict(os.environ, env):
                    with CaptureOutput() as out:
                        try:
                            swiftclient.shell.main(args)
                        except SystemExit as e:
                            self.fail('Unexpected SystemExit: %s' % e)

        self.assertRequests([('GET', self.obj_path)])
        self.assertTrue(out.out.startswith(self.obj.lstrip('/')))
        self.assertEqual('', out.err)

    def test_download_with_no_access(self):
        fake_conn = self.fake_http_connection(403)
        args, env = self._make_cmd('download', cmd_args=[self.cont,
                                                         self.obj.lstrip('/'),
                                                         '--no-download'])
        with mock.patch('swiftclient.client.ksclient_v3', self.fake_ks):
            with mock.patch('swiftclient.client.http_connection', fake_conn):
                with mock.patch.dict(os.environ, env):
                    with CaptureOutput() as out:
                        try:
                            swiftclient.shell.main(args)
                            self.fail('Expected SystemExit')
                        except SystemExit:
                            pass

        self.assertRequests([('GET', self.obj_path)])
        path = '%s%s' % (self.cont, self.obj)
        expected_err = "Error downloading object '%s'" % path
        self.assertTrue(out.err.startswith(expected_err))
        self.assertEqual('', out)

    def test_list_with_read_access(self):
        req_handler = self._fake_cross_account_auth(True, False)
        resp_body = b'{}'
        resp = StubResponse(403, resp_body, {
            'etag': hashlib.md5(resp_body).hexdigest()})
        fake_conn = self.fake_http_connection(resp, on_request=req_handler)

        args, env = self._make_cmd('download', cmd_args=[self.cont])
        with mock.patch('swiftclient.client.ksclient_v3', self.fake_ks):
            with mock.patch('swiftclient.client.http_connection', fake_conn):
                with mock.patch.dict(os.environ, env):
                    with CaptureOutput() as out:
                        try:
                            swiftclient.shell.main(args)
                        except SystemExit as e:
                            self.fail('Unexpected SystemExit: %s' % e)

        self.assertRequests([('GET', '%s?format=json' % self.cont_path)])
        self.assertEqual('', out)
        self.assertEqual('', out.err)

    def test_list_with_no_access(self):
        fake_conn = self.fake_http_connection(403)

        args, env = self._make_cmd('download', cmd_args=[self.cont])
        with mock.patch('swiftclient.client.ksclient_v3', self.fake_ks):
            with mock.patch('swiftclient.client.http_connection', fake_conn):
                with mock.patch.dict(os.environ, env):
                    with CaptureOutput() as out:
                        try:
                            swiftclient.shell.main(args)
                            self.fail('Expected SystemExit')
                        except SystemExit:
                            pass

        self.assertRequests([('GET', '%s?format=json' % self.cont_path)])
        self.assertEqual('', out)
        self.assertTrue(out.err.startswith('Container GET failed:'))


class TestCrossAccountObjectAccessUsingEnv(TestCrossAccountObjectAccess):
    """
    Repeat super-class tests using environment variables rather than command
    line to set options.
    """

    def _make_cmd(self, cmd, cmd_args=None):
        return _make_cmd(cmd, self.opts, self.os_opts, cmd_args=cmd_args,
                         use_env=True)
