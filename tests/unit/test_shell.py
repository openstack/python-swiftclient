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

import mock
import os
import tempfile
import unittest

import six

import swiftclient
import swiftclient.shell


if six.PY2:
    BUILTIN_OPEN = '__builtin__.open'
else:
    BUILTIN_OPEN = 'builtins.open'

mocked_os_environ = {
    'ST_AUTH': 'http://localhost:8080/auth/v1.0',
    'ST_USER': 'test:tester',
    'ST_KEY': 'testing'
}


@mock.patch.dict(os.environ, mocked_os_environ)
class TestShell(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestShell, self).__init__(*args, **kwargs)
        tmpfile = tempfile.NamedTemporaryFile(delete=False)
        self.tmpfile = tmpfile.name

    def tearDown(self):
        try:
            os.remove(self.tmpfile)
        except OSError:
            pass

    @mock.patch('swiftclient.shell.MultiThreadingManager._print')
    @mock.patch('swiftclient.shell.Connection')
    def test_stat_account(self, connection, mock_print):
        argv = ["", "stat"]
        return_headers = {
            'x-account-container-count': '1',
            'x-account-object-count': '2',
            'x-account-bytes-used': '3',
            'content-length': 0,
            'date': ''}
        connection.return_value.head_account.return_value = return_headers
        connection.return_value.url = 'http://127.0.0.1/v1/AUTH_account'
        swiftclient.shell.main(argv)
        calls = [mock.call('       Account: AUTH_account\n' +
                           '    Containers: 1\n' +
                           '       Objects: 2\n' +
                           '         Bytes: 3'),
                 mock.call('')]
        mock_print.assert_has_calls(calls)

    @mock.patch('swiftclient.shell.MultiThreadingManager._print')
    @mock.patch('swiftclient.shell.Connection')
    def test_stat_container(self, connection, mock_print):
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
        swiftclient.shell.main(argv)
        calls = [mock.call('       Account: AUTH_account\n' +
                           '     Container: container\n' +
                           '       Objects: 1\n' +
                           '         Bytes: 2\n' +
                           '      Read ACL: test2:tester2\n' +
                           '     Write ACL: test3:tester3\n' +
                           '       Sync To: other\n' +
                           '      Sync Key: secret'),
                 mock.call('')]
        mock_print.assert_has_calls(calls)

    @mock.patch('swiftclient.shell.MultiThreadingManager._print')
    @mock.patch('swiftclient.shell.Connection')
    def test_stat_object(self, connection, mock_print):
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
        swiftclient.shell.main(argv)
        calls = [mock.call('       Account: AUTH_account\n' +
                           '     Container: container\n' +
                           '        Object: object\n' +
                           '  Content Type: text/plain\n' +
                           'Content Length: 42\n' +
                           ' Last Modified: yesterday\n' +
                           '          ETag: md5\n' +
                           '      Manifest: manifest'),
                 mock.call('')]
        mock_print.assert_has_calls(calls)

    @mock.patch('swiftclient.shell.MultiThreadingManager._print')
    @mock.patch('swiftclient.shell.Connection')
    def test_list_account(self, connection, mock_print):
        # Test account listing
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container'}]],
            [None, []],
        ]

        argv = ["", "list"]
        swiftclient.shell.main(argv)
        calls = [mock.call(marker='', prefix=None),
                 mock.call(marker='container', prefix=None)]
        connection.return_value.get_account.assert_has_calls(calls)
        calls = [mock.call('container')]
        mock_print.assert_has_calls(calls)

    @mock.patch('swiftclient.shell.MultiThreadingManager._print')
    @mock.patch('swiftclient.shell.Connection')
    def test_list_container(self, connection, mock_print):
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object_a'}]],
            [None, []],
        ]
        argv = ["", "list", "container"]
        swiftclient.shell.main(argv)
        calls = [
            mock.call('container', marker='', delimiter=None, prefix=None),
            mock.call('container', marker='object_a',
                      delimiter=None, prefix=None)]
        connection.return_value.get_container.assert_has_calls(calls)
        calls = [mock.call('object_a')]
        mock_print.assert_has_calls(calls)

        # Test container listing with --long
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object_a', 'bytes': 0,
                     'last_modified': '123T456'}]],
            [None, []],
        ]
        argv = ["", "list", "container", "--long"]
        swiftclient.shell.main(argv)
        calls = [
            mock.call('container', marker='', delimiter=None, prefix=None),
            mock.call('container', marker='object_a',
                      delimiter=None, prefix=None)]
        connection.return_value.get_container.assert_has_calls(calls)
        calls = [mock.call('object_a'),
                 mock.call('           0        123      456 object_a'),
                 mock.call('           0')]
        mock_print.assert_has_calls(calls)

    @mock.patch('swiftclient.shell.Connection')
    def test_download(self, connection):
        connection.return_value.get_object.return_value = [
            {'content-type': 'text/plain',
             'etag': 'd41d8cd98f00b204e9800998ecf8427e'},
            '']

        # Test downloading whole container
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object'}]],
            [None, []],
        ]
        connection.return_value.auth_end_time = 0
        connection.return_value.attempts = 0

        with mock.patch(BUILTIN_OPEN) as mock_open:
            argv = ["", "download", "container"]
            swiftclient.shell.main(argv)
            connection.return_value.get_object.assert_called_with(
                'container', 'object', headers={}, resp_chunk_size=65536)
            mock_open.assert_called_with('object', 'wb')

        # Test downloading single object
        with mock.patch(BUILTIN_OPEN) as mock_open:
            argv = ["", "download", "container", "object"]
            swiftclient.shell.main(argv)
            connection.return_value.get_object.assert_called_with(
                'container', 'object', headers={}, resp_chunk_size=65536)
            mock_open.assert_called_with('object', 'wb')

    @mock.patch('swiftclient.shell.listdir')
    @mock.patch('swiftclient.shell.Connection')
    def test_upload(self, connection, listdir):
        connection.return_value.head_object.return_value = {
            'content-length': '0'}
        connection.return_value.attempts = 0
        argv = ["", "upload", "container", self.tmpfile]
        swiftclient.shell.main(argv)
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            mock.ANY,
            content_length=0,
            headers={'x-object-meta-mtime': mock.ANY})

       # Upload whole directory
        argv = ["", "upload", "container", "/tmp"]
        listdir.return_value = [self.tmpfile]
        swiftclient.shell.main(argv)
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            mock.ANY,
            content_length=0,
            headers={'x-object-meta-mtime': mock.ANY})

        # Upload in segments
        argv = ["", "upload", "container", self.tmpfile, "-S", "10"]
        with open(self.tmpfile, "wb") as fh:
            fh.write(b'12345678901234567890')
        swiftclient.shell.main(argv)
        connection.return_value.put_object.assert_called_with(
            'container',
            self.tmpfile.lstrip('/'),
            '',
            content_length=0,
            headers={'x-object-manifest': mock.ANY,
            'x-object-meta-mtime': mock.ANY})

    @mock.patch('swiftclient.shell.Connection')
    def test_delete_account(self, connection):
        connection.return_value.get_account.side_effect = [
            [None, [{'name': 'container'}]],
            [None, []],
        ]
        connection.return_value.get_container.side_effect = [
            [None, [{'name': 'object'}]],
            [None, []],
        ]
        connection.return_value.attempts = 0
        argv = ["", "delete", "--all"]
        connection.return_value.head_object.return_value = {}
        swiftclient.shell.main(argv)
        connection.return_value.delete_container.assert_called_with(
            'container')
        connection.return_value.delete_object.assert_called_with(
            'container', 'object', query_string=None)

    @mock.patch('swiftclient.shell.Connection')
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
            'container')
        connection.return_value.delete_object.assert_called_with(
            'container', 'object', query_string=None)

    @mock.patch('swiftclient.shell.Connection')
    def test_delete_object(self, connection):
        argv = ["", "delete", "container", "object"]
        connection.return_value.head_object.return_value = {}
        connection.return_value.attempts = 0
        swiftclient.shell.main(argv)
        connection.return_value.delete_object.assert_called_with(
            'container', 'object', query_string=None)

    @mock.patch('swiftclient.shell.Connection')
    def test_post_account(self, connection):
        argv = ["", "post"]
        connection.return_value.head_object.return_value = {}
        swiftclient.shell.main(argv)
        connection.return_value.post_account.assert_called_with(
            headers={})

        argv = ["", "post", "container"]
        connection.return_value.head_object.return_value = {}
        swiftclient.shell.main(argv)
        connection.return_value.post_container.assert_called_with(
            'container', headers={})

    @mock.patch('swiftclient.shell.Connection')
    def test_post_container(self, connection):
        argv = ["", "post", "container",
                "--read-acl", "test2:tester2",
                "--write-acl", "test3:tester3 test4",
                "--sync-to", "othersite",
                "--sync-key", "secret",
                ]
        connection.return_value.head_object.return_value = {}
        swiftclient.shell.main(argv)
        connection.return_value.post_container.assert_called_with(
            'container', headers={
                'X-Container-Write': 'test3:tester3 test4',
                'X-Container-Read': 'test2:tester2',
                'X-Container-Sync-Key': 'secret',
                'X-Container-Sync-To': 'othersite'})

    @mock.patch('swiftclient.shell.Connection')
    def test_post_object(self, connection):
        argv = ["", "post", "container", "object",
                "--meta", "Color:Blue",
                "--header", "content-type:text/plain"
                ]
        connection.return_value.head_object.return_value = {}
        swiftclient.shell.main(argv)
        connection.return_value.post_object.assert_called_with(
            'container', 'object', headers={
                'Content-Type': 'text/plain',
                'X-Object-Meta-Color': 'Blue'})

    @mock.patch('swiftclient.shell.Connection')
    def test_capabilities(self, connection):
        argv = ["", "capabilities"]
        connection.return_value.get_capabilities.return_value = {'swift': None}
        swiftclient.shell.main(argv)
        connection.return_value.get_capabilities.assert_called_with(None)
