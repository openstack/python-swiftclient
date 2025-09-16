# Copyright (c) 2025 NVIDIA
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
import subprocess
import unittest

from . import TEST_CONFIG


class TestOpenStackClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # NB: Only runs for v1 auth, to exercise our keystoneauth plugin
        cls.skip_tests = (TEST_CONFIG is None or
                          TEST_CONFIG['auth_version'] != '1')
        cls.env = {
            'OS_AUTH_TYPE': 'v1password',
            'OS_AUTH_URL': TEST_CONFIG['auth_url'] or '',
            'OS_USERNAME': TEST_CONFIG['account_username'] or '',
            'OS_PASSWORD': TEST_CONFIG['password'] or '',
            'OS_CACERT': TEST_CONFIG['cacert'] or '',
        }
        if 'PATH' in os.environ:
            cls.env['PATH'] = os.environ['PATH']

    def setUp(self):
        if self.skip_tests:
            raise unittest.SkipTest('SKIPPING V1-AUTH TESTS')

    def _run(self, *args):
        subprocess.run(args, env=self.env, check=True)

    def test_token_issue(self):
        self._run('openstack', 'token', 'issue')

    def test_catalog_list(self):
        self._run('openstack', 'catalog', 'list')

    def test_catalog_show(self):
        self._run('openstack', 'catalog', 'show', 'swift')
        self._run('openstack', 'catalog', 'show', 'object-store')
        self._run('openstack', 'catalog', 'show', 'auth')

    def test_account_show(self):
        self._run('openstack', 'object', 'store', 'account', 'show')
        # If account show works and the openstacksdk tests work, presumably
        # container/object commands work, too

    # service list? endpoint list?
