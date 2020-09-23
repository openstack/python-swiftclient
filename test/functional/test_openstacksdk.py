# Copyright (c) 2019 Tim Burke <tim@swiftstack.com>
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

import unittest
import uuid

import openstack

from . import TEST_CONFIG

PREFIX = 'test-swiftclient-'


class TestOpenStackSDK(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # NB: Only runs for v1 auth, to exercise our keystoneauth plugin
        cls.skip_tests = (TEST_CONFIG is None or
                          TEST_CONFIG['auth_version'] != '1')
        if not cls.skip_tests:
            cls.conn = openstack.connect(
                auth_type='v1password',
                auth_url=TEST_CONFIG['auth_url'],
                username=TEST_CONFIG['account_username'],
                password=TEST_CONFIG['password'],
                cacert=TEST_CONFIG['cacert'],
            )
            cls.object_store = cls.conn.object_store

    def setUp(self):
        if self.skip_tests:
            raise unittest.SkipTest('SKIPPING V1-AUTH TESTS')

    def tearDown(self):
        if self.skip_tests:
            return
        for c in self.object_store.containers():
            if c.name.startswith(PREFIX):
                for o in self.object_store.objects(c.name):
                    self.object_store.delete_object(
                        o.name, container=c.name)
                self.object_store.delete_container(c.name)

    def test_containers(self):
        meta = self.object_store.get_account_metadata()
        count_before = meta.account_container_count
        containers = sorted(PREFIX + str(uuid.uuid4())
                            for _ in range(10))
        for c in containers:
            self.object_store.create_container(c)
        self.assertEqual([
            c.name for c in self.object_store.containers()
            if c.name.startswith(PREFIX)
        ], containers)
        meta = self.object_store.get_account_metadata()
        self.assertEqual(count_before + len(containers),
                         meta.account_container_count)

    def test_objects(self):
        container = PREFIX + str(uuid.uuid4())
        self.object_store.create_container(container)
        objects = sorted(str(uuid.uuid4()) for _ in range(10))
        for o in objects:
            self.object_store.create_object(container, o, data=b'x')
        self.assertEqual([
            o.name for o in self.object_store.objects(container)
        ], objects)
        meta = self.object_store.get_container_metadata(container)
        self.assertEqual(len(objects), meta.object_count)

    def test_object_metadata(self):
        container = PREFIX + str(uuid.uuid4())
        self.object_store.create_container(container)
        obj = str(uuid.uuid4())
        obj_meta = {str(uuid.uuid4()): str(uuid.uuid4()) for _ in range(10)}
        # NB: as of 0.36.0, create_object() doesn't play well with passing
        # both data and metadata, so we do a PUT then POST
        self.object_store.create_object(container, obj, data=b'x')
        self.object_store.set_object_metadata(obj, container, **obj_meta)
        meta = self.object_store.get_object_metadata(obj, container)
        self.assertEqual(obj_meta, meta.metadata)
