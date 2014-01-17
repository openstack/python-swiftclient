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
import os

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


class TestGetEnvironProxy(testtools.TestCase):

    ENV_VARS = ('http_proxy', 'https_proxy', 'no_proxy',
                'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY')

    def setUp(self):
        self.proxy_dict = {}
        super(TestGetEnvironProxy, self).setUp()
        for proxy_s in TestGetEnvironProxy.ENV_VARS:
            # Save old env value
            self.proxy_dict[proxy_s] = os.environ.get(proxy_s, None)

    def tearDown(self):
        super(TestGetEnvironProxy, self).tearDown()
        for proxy_s in TestGetEnvironProxy.ENV_VARS:
            if self.proxy_dict[proxy_s]:
                os.environ[proxy_s] = self.proxy_dict[proxy_s]
            elif os.environ.get(proxy_s):
                del os.environ[proxy_s]

    def setup_env(self, new_env={}):
        for proxy_s in TestGetEnvironProxy.ENV_VARS:
            # Set new env value
            if new_env.get(proxy_s):
                os.environ[proxy_s] = new_env.get(proxy_s)
            elif os.environ.get(proxy_s):
                del os.environ[proxy_s]

    def test_http_proxy(self):
        self.setup_env({'http_proxy': 'http://proxy.tests.com:8080'})
        proxy_dict = u.get_environ_proxies('www.tests.com:81')
        self.assertEqual(proxy_dict['http'], 'http://proxy.tests.com:8080')
        self.assertEqual(proxy_dict.get('https'), None)
        self.assertEqual(len(proxy_dict), 1)
        self.setup_env({'HTTP_PROXY': 'http://proxy.tests.com:8080'})
        proxy_dict = u.get_environ_proxies('www.tests.com:81')
        self.assertEqual(proxy_dict['http'], 'http://proxy.tests.com:8080')
        self.assertEqual(proxy_dict.get('https'), None)
        self.assertEqual(len(proxy_dict), 1)

    def test_https_proxy(self):
        self.setup_env({'https_proxy': 'http://proxy.tests.com:8080'})
        proxy_dict = u.get_environ_proxies('www.tests.com:81')
        self.assertEqual(proxy_dict['https'], 'http://proxy.tests.com:8080')
        self.assertEqual(proxy_dict.get('http'), None)
        self.assertEqual(len(proxy_dict), 1)
        self.setup_env({'HTTPS_PROXY': 'http://proxy.tests.com:8080'})
        proxy_dict = u.get_environ_proxies('www.tests.com:81')
        self.assertEqual(proxy_dict['https'], 'http://proxy.tests.com:8080')
        self.assertEqual(proxy_dict.get('http'), None)
        self.assertEqual(len(proxy_dict), 1)

    def test_http_https_proxy(self):
        self.setup_env({'http_proxy': 'http://proxy1.tests.com:8081',
                        'https_proxy': 'http://proxy2.tests.com:8082'})
        proxy_dict = u.get_environ_proxies('www.tests.com:81')
        self.assertEqual(proxy_dict['http'], 'http://proxy1.tests.com:8081')
        self.assertEqual(proxy_dict['https'], 'http://proxy2.tests.com:8082')
        self.assertEqual(len(proxy_dict), 2)
        self.setup_env({'http_proxy': 'http://proxy1.tests.com:8081',
                        'HTTPS_PROXY': 'http://proxy2.tests.com:8082'})
        proxy_dict = u.get_environ_proxies('www.tests.com:81')
        self.assertEqual(proxy_dict['http'], 'http://proxy1.tests.com:8081')
        self.assertEqual(proxy_dict['https'], 'http://proxy2.tests.com:8082')
        self.assertEqual(len(proxy_dict), 2)

    def test_proxy_exclusion(self):
        self.setup_env({'http_proxy': 'http://proxy1.tests.com:8081',
                        'https_proxy': 'http://proxy2.tests.com:8082',
                        'no_proxy': 'www.tests.com'})
        proxy_dict = u.get_environ_proxies('www.tests.com:81')
        self.assertEqual(len(proxy_dict), 0)
        self.setup_env({'http_proxy': 'http://proxy1.tests.com:8081',
                        'HTTPS_PROXY': 'http://proxy2.tests.com:8082',
                        'NO_PROXY': 'www.tests.com'})
        proxy_dict = u.get_environ_proxies('www.tests.com:81')
        self.assertEqual(len(proxy_dict), 0)
