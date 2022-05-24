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

from io import StringIO
import unittest
from unittest import mock

from swiftclient import command_helpers as h
from swiftclient.multithreading import OutputManager


class TestStatHelpers(unittest.TestCase):

    def setUp(self):
        super(TestStatHelpers, self).setUp()
        conn_attrs = {
            'url': 'http://storage/v1/a',
            'token': 'tk12345',
        }
        self.conn = mock.MagicMock(**conn_attrs)
        self.options = {'human': False, 'verbose': 1}
        self.stdout = StringIO()
        self.stderr = StringIO()
        self.output_manager = OutputManager(self.stdout, self.stderr)

    def assertOut(self, expected):
        real = self.stdout.getvalue()
        # commonly if we strip of blank lines we have a match
        try:
            self.assertEqual(expected.strip('\n'),
                             real.strip('\n'))
        except AssertionError:
            # could be anything, try to find typos line by line
            expected_lines = [line.lstrip() for line in
                              expected.splitlines() if line.strip()]
            real_lines = [line.lstrip() for line in
                          real.splitlines() if line.strip()]
            for expected, real in zip(expected_lines, real_lines):
                self.assertEqual(expected, real)
            # not a typo, might be an indent thing, hopefully you can spot it
            raise

    def test_stat_account_human(self):
        self.options['human'] = True
        # stub head_account
        stub_headers = {
            'x-account-container-count': 42,
            'x-account-object-count': 1000000,
            'x-account-bytes-used': 2 ** 30,
        }
        self.conn.head_account.return_value = stub_headers

        with self.output_manager as output_manager:
            items, headers = h.stat_account(self.conn, self.options)
            h.print_account_stats(items, headers, output_manager)
        expected = """
   Account: a
Containers: 42
   Objects: 976K
     Bytes: 1.0G
"""
        self.assertOut(expected)

    def test_stat_account_verbose(self):
        self.options['verbose'] += 1
        # stub head_account
        stub_headers = {
            'x-account-container-count': 42,
            'x-account-object-count': 1000000,
            'x-account-bytes-used': 2 ** 30,
        }
        self.conn.head_account.return_value = stub_headers

        with self.output_manager as output_manager:
            items, headers = h.stat_account(self.conn, self.options)
            h.print_account_stats(items, headers, output_manager)
        expected = """
StorageURL: http://storage/v1/a
Auth Token: tk12345
   Account: a
Containers: 42
   Objects: 1000000
     Bytes: 1073741824
"""
        self.assertOut(expected)

    def test_stat_account_policy_stat(self):
        # stub head_account
        stub_headers = {
            'x-account-container-count': 42,
            'x-account-object-count': 1000000,
            'x-account-bytes-used': 2 ** 30,
            'x-account-storage-policy-nada-object-count': 1000000,
            'x-account-storage-policy-nada-bytes-used': 2 ** 30,
        }
        self.conn.head_account.return_value = stub_headers

        with self.output_manager as output_manager:
            items, headers = h.stat_account(self.conn, self.options)
            h.print_account_stats(items, headers, output_manager)
        expected = """
                 Account: a
              Containers: 42
                 Objects: 1000000
                   Bytes: 1073741824
Objects in policy "nada": 1000000
  Bytes in policy "nada": 1073741824
"""
        self.assertOut(expected)

    def test_stat_account_policy_stat_with_container_counts(self):
        # stub head_account
        stub_headers = {
            'x-account-container-count': 42,
            'x-account-object-count': 1000000,
            'x-account-bytes-used': 2 ** 30,
            'x-account-storage-policy-nada-container-count': 10,
            'x-account-storage-policy-nada-object-count': 1000000,
            'x-account-storage-policy-nada-bytes-used': 2 ** 30,
        }
        self.conn.head_account.return_value = stub_headers

        with self.output_manager as output_manager:
            items, headers = h.stat_account(self.conn, self.options)
            h.print_account_stats(items, headers, output_manager)
        expected = """
                    Account: a
                 Containers: 42
                    Objects: 1000000
                      Bytes: 1073741824
Containers in policy "nada": 10
   Objects in policy "nada": 1000000
     Bytes in policy "nada": 1073741824
"""
        self.assertOut(expected)

    def test_stat_container_human(self):
        self.options['human'] = True
        # stub head container request
        stub_headers = {
            'x-container-object-count': 10 ** 6,
            'x-container-bytes-used': 2 ** 30,
        }
        self.conn.head_container.return_value = stub_headers
        args = ('c',)
        with self.output_manager as output_manager:
            items, headers = h.stat_container(self.conn, self.options, *args)
            h.print_container_stats(items, headers, output_manager)
        expected = """
  Account: a
Container: c
  Objects: 976K
    Bytes: 1.0G
 Read ACL:
Write ACL:
  Sync To:
 Sync Key:
"""
        self.assertOut(expected)

    def test_stat_container_verbose(self):
        self.options['verbose'] += 1
        # stub head container request
        stub_headers = {
            'x-container-object-count': 10 ** 6,
            'x-container-bytes-used': 2 ** 30,
        }
        self.conn.head_container.return_value = stub_headers
        args = ('c',)
        with self.output_manager as output_manager:
            items, headers = h.stat_container(self.conn, self.options, *args)
            h.print_container_stats(items, headers, output_manager)
        expected = """
       URL: http://storage/v1/a/c
Auth Token: tk12345
   Account: a
 Container: c
   Objects: 1000000
     Bytes: 1073741824
  Read ACL:
 Write ACL:
   Sync To:
  Sync Key:
"""
        self.assertOut(expected)

    def test_stat_object_human(self):
        self.options['human'] = True
        # stub head object request
        stub_headers = {
            'content-length': 2 ** 20,
            'x-object-meta-color': 'blue',
            'etag': '68b329da9893e34099c7d8ad5cb9c940',
            'content-encoding': 'gzip',
        }
        self.conn.head_object.return_value = stub_headers
        args = ('c', 'o')
        with self.output_manager as output_manager:
            items, headers = h.stat_object(self.conn, self.options, *args)
            h.print_object_stats(items, headers, output_manager)
        expected = """
         Account: a
       Container: c
          Object: o
  Content Length: 1.0M
            ETag: 68b329da9893e34099c7d8ad5cb9c940
      Meta Color: blue
Content-Encoding: gzip
"""
        self.assertOut(expected)

    def test_stat_object_verbose(self):
        self.options['verbose'] += 1
        # stub head object request
        stub_headers = {
            'content-length': 2 ** 20,
            'x-object-meta-color': 'blue',
            'etag': '68b329da9893e34099c7d8ad5cb9c940',
            'content-encoding': 'gzip',
        }
        self.conn.head_object.return_value = stub_headers
        args = ('c', 'o')
        with self.output_manager as output_manager:
            items, headers = h.stat_object(self.conn, self.options, *args)
            h.print_object_stats(items, headers, output_manager)
        expected = """
             URL: http://storage/v1/a/c/o
      Auth Token: tk12345
         Account: a
       Container: c
          Object: o
  Content Length: 1048576
            ETag: 68b329da9893e34099c7d8ad5cb9c940
      Meta Color: blue
Content-Encoding: gzip
"""
        self.assertOut(expected)
