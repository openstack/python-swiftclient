# Copyright 2016 OpenStack Foundation
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
# implied. See the License for the specific language governing
# permissions and limitations under the License.

import datetime
import json
import unittest
from unittest import mock
from keystoneauth1 import plugin
from keystoneauth1 import loading
from keystoneauth1 import exceptions
from swiftclient import authv1


class TestDataNoAccount:
    options = dict(
        auth_url='http://saio:8080/auth/v1.0',
        username='test:tester',
        password='testing')
    storage_url = 'http://saio:8080/v1/AUTH_test'
    expected_endpoint = storage_url
    token = 'token'


class TestDataWithAccount:
    options = dict(
        auth_url='http://saio:8080/auth/v1.0',
        username='test2:tester2',
        project_name='SOME_other_account',
        password='testing2')
    storage_url = 'http://saio:8080/v1/AUTH_test2'
    expected_endpoint = 'http://saio:8080/v1/SOME_other_account'
    token = 'other_token'


class TestPluginLoading(TestDataNoAccount, unittest.TestCase):
    def test_can_load(self):
        loader = loading.get_plugin_loader('v1password')
        self.assertIsInstance(loader, authv1.PasswordLoader)

        auth_plugin = loader.load_from_options(**self.options)
        self.assertIsInstance(auth_plugin, authv1.PasswordPlugin)

        self.assertEqual(self.options['auth_url'], auth_plugin.auth_url)
        self.assertEqual(self.options['username'], auth_plugin.user)
        self.assertEqual(self.options.get('project_name'), auth_plugin.account)
        self.assertEqual(self.options['password'], auth_plugin.key)

    def test_get_state(self):
        auth_plugin = authv1.PasswordPlugin(**self.options)
        self.assertIsNone(auth_plugin.get_auth_state())

        with mock.patch('swiftclient.authv1.time.time', return_value=1234.56):
            auth_plugin.auth_ref = authv1.AccessInfoV1(
                self.options['auth_url'],
                self.storage_url,
                self.options.get('project_name'),
                self.options['username'],
                self.token,
                60)

        expected = json.dumps({
            'auth_url': self.options['auth_url'],
            'username': self.options['username'],
            'account': self.options.get('project_name'),
            'issued': 1234.56,
            'storage_url': self.storage_url,
            'auth_token': self.token,
            'expires': 1234.56 + 60,
        }, sort_keys=True)
        self.assertEqual(expected, auth_plugin.auth_ref.get_state())
        self.assertEqual(expected, auth_plugin.get_auth_state())

    def test_set_state(self):
        auth_plugin = authv1.PasswordPlugin(**self.options)
        self.assertIsNone(auth_plugin.auth_ref)

        auth_plugin.auth_ref = object()
        auth_plugin.set_auth_state(None)
        self.assertIsNone(auth_plugin.get_auth_state())

        state = json.dumps({
            'auth_url': self.options['auth_url'],
            'username': self.options['username'],
            'account': self.options.get('project_name'),
            'issued': 1234.56,
            'storage_url': self.storage_url,
            'auth_token': self.token,
            'expires': None,
        }, sort_keys=True)
        auth_plugin.set_auth_state(state)
        self.assertIsInstance(auth_plugin.auth_ref, authv1.AccessInfoV1)

        self.assertEqual(self.options['username'],
                         auth_plugin.auth_ref.username)
        self.assertEqual(self.options['auth_url'],
                         auth_plugin.auth_ref.auth_url)
        self.assertEqual(self.storage_url, auth_plugin.auth_ref.storage_url)
        self.assertEqual(self.options.get('project_name'), auth_plugin.account)
        self.assertEqual(self.token, auth_plugin.auth_ref.auth_token)
        self.assertEqual(1234.56, auth_plugin.auth_ref._issued)
        self.assertIs(datetime.datetime, type(auth_plugin.auth_ref.issued))
        self.assertIsNone(auth_plugin.auth_ref._expires)
        self.assertIsNone(auth_plugin.auth_ref.expires)


class TestPluginLoadingWithAccount(TestDataWithAccount, TestPluginLoading):
    pass


class TestPlugin(TestDataNoAccount, unittest.TestCase):
    def setUp(self):
        self.mock_session = mock.MagicMock()
        self.mock_response = self.mock_session.get.return_value
        self.mock_response.status_code = 200
        self.mock_response.headers = {
            'X-Auth-Token': self.token,
            'X-Storage-Url': self.storage_url,
        }

    def test_get_access(self):
        auth_plugin = authv1.PasswordPlugin(**self.options)
        with mock.patch('swiftclient.authv1.time.time', return_value=1234.56):
            access = auth_plugin.get_access(self.mock_session)

        self.assertEqual(self.mock_session.get.mock_calls, [mock.call(
            self.options['auth_url'], authenticated=False, log=False, headers={
                'X-Auth-User': self.options['username'],
                'X-Auth-Key': self.options['password'],
            })])

        self.assertEqual(self.options['username'], access.username)
        # `openstack token issue` requires a user_id property
        self.assertEqual(self.options['username'], access.user_id)
        self.assertEqual(self.storage_url, access.storage_url)
        self.assertEqual(self.token, access.auth_token)
        self.assertEqual(1234.56, access._issued)
        self.assertIs(datetime.datetime, type(auth_plugin.auth_ref.issued))
        self.assertIsNone(access.expires)

        # `openstack catalog list/show` require a catalog property
        catalog = access.service_catalog.catalog
        self.assertEqual('swift', catalog[0].get('name'))
        self.assertEqual('object-store', catalog[0].get('type'))
        self.assertIn('endpoints', catalog[0])
        self.assertIn(self.storage_url, [
            e.get('publicURL') for e in catalog[0]['endpoints']])

    def test_get_access_with_expiry(self):
        auth_plugin = authv1.PasswordPlugin(**self.options)
        self.mock_response.headers['X-Auth-Token-Expires'] = '78.9'
        with mock.patch('swiftclient.authv1.time.time',
                        return_value=1234.56) as mock_time:
            access = auth_plugin.get_access(self.mock_session)
            self.assertEqual(1234.56 + 78.9, access._expires)
            self.assertIs(datetime.datetime,
                          type(auth_plugin.auth_ref.expires))

            self.assertIs(True, access.will_expire_soon(90))
            self.assertIs(False, access.will_expire_soon(60))
        self.assertEqual(3, len(mock_time.mock_calls))

    def test_get_access_bad_expiry(self):
        auth_plugin = authv1.PasswordPlugin(**self.options)
        self.mock_response.headers['X-Auth-Token-Expires'] = 'foo'
        access = auth_plugin.get_access(self.mock_session)
        self.assertIsNone(access.expires)

        self.assertIs(False, access.will_expire_soon(60))
        self.assertIs(False, access.will_expire_soon(1e20))

    def test_get_access_bad_status(self):
        auth_plugin = authv1.PasswordPlugin(**self.options)
        self.mock_response.status_code = 401
        self.assertRaises(exceptions.InvalidResponse,
                          auth_plugin.get_access, self.mock_session)

    def test_get_access_missing_token(self):
        auth_plugin = authv1.PasswordPlugin(**self.options)
        self.mock_response.headers.pop('X-Auth-Token')
        self.assertRaises(exceptions.InvalidResponse,
                          auth_plugin.get_access, self.mock_session)

    def test_get_access_accepts_storage_token(self):
        auth_plugin = authv1.PasswordPlugin(**self.options)
        self.mock_response.headers.pop('X-Auth-Token')
        self.mock_response.headers['X-Storage-Token'] = 'yet another token'
        access = auth_plugin.get_access(self.mock_session)
        self.assertEqual('yet another token', access.auth_token)

    def test_get_access_missing_url(self):
        auth_plugin = authv1.PasswordPlugin(**self.options)
        self.mock_response.headers.pop('X-Storage-Url')
        self.assertRaises(exceptions.InvalidResponse,
                          auth_plugin.get_access, self.mock_session)

    def test_get_endpoint(self):
        auth_plugin = authv1.PasswordPlugin(**self.options)

        object_store_endpoint = auth_plugin.get_endpoint(
            self.mock_session, service_type='object-store')
        self.assertEqual(object_store_endpoint, self.expected_endpoint)

        auth_endpoint = auth_plugin.get_endpoint(
            self.mock_session, interface=plugin.AUTH_INTERFACE)
        self.assertEqual(auth_endpoint, self.options['auth_url'])

        with self.assertRaises(exceptions.EndpointNotFound) as exc_mgr:
            auth_plugin.get_endpoint(self.mock_session)
        self.assertEqual('public endpoint for None service not found',
                         str(exc_mgr.exception))

        with self.assertRaises(exceptions.EndpointNotFound) as exc_mgr:
            auth_plugin.get_endpoint(
                self.mock_session, service_type='identity', region_name='DFW')
        self.assertEqual(
            'public endpoint for identity service in DFW region not found',
            str(exc_mgr.exception))

        with self.assertRaises(exceptions.EndpointNotFound) as exc_mgr:
            auth_plugin.get_endpoint(
                self.mock_session, service_type='image', service_name='glance')
        self.assertEqual(
            'public endpoint for image service named glance not found',
            str(exc_mgr.exception))

        with self.assertRaises(exceptions.EndpointNotFound) as exc_mgr:
            auth_plugin.get_endpoint(
                self.mock_session, service_type='compute', service_name='nova',
                region_name='IAD')
        self.assertEqual('public endpoint for compute service named nova in '
                         'IAD region not found', str(exc_mgr.exception))


class TestPluginWithAccount(TestDataWithAccount, TestPlugin):
    pass
