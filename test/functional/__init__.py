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

import configparser
import os

TEST_CONFIG = None


def _load_config(force_reload=False):
    global TEST_CONFIG
    if not force_reload and TEST_CONFIG is not None:
        return TEST_CONFIG

    config_file = os.environ.get('SWIFT_TEST_CONFIG_FILE',
                                 '/etc/swift/test.conf')
    parser = configparser.ConfigParser({'auth_version': '1'})
    parser.read(config_file)
    conf = {}
    if parser.has_section('func_test'):
        if parser.has_option('func_test', 'auth_uri'):
            conf['auth_url'] = parser.get('func_test', 'auth_uri')
            try:
                conf['auth_version'] = parser.get('func_test', 'auth_version')
            except configparser.NoOptionError:
                last_piece = conf['auth_url'].rstrip('/').rsplit('/', 1)[1]
                if last_piece.endswith('.0'):
                    last_piece = last_piece[:-2]
                if last_piece in ('1', '2', '3'):
                    conf['auth_version'] = last_piece
                else:
                    raise
        else:
            auth_host = parser.get('func_test', 'auth_host')
            auth_port = parser.getint('func_test', 'auth_port')
            auth_ssl = parser.getboolean('func_test', 'auth_ssl')
            auth_prefix = parser.get('func_test', 'auth_prefix')
            conf['auth_version'] = parser.get('func_test', 'auth_version')
            if auth_ssl:
                auth_url = "https://"
            else:
                auth_url = "http://"
            auth_url += "%s:%s%s" % (auth_host, auth_port, auth_prefix)
            if conf['auth_version'] == "1":
                auth_url += 'v1.0'
            conf['auth_url'] = auth_url

        try:
            conf['cacert'] = parser.get('func_test', 'cacert')
        except configparser.NoOptionError:
            conf['cacert'] = None

        try:
            conf['account_username'] = parser.get('func_test',
                                                  'account_username')
        except configparser.NoOptionError:
            conf['account'] = parser.get('func_test', 'account')
            conf['username'] = parser.get('func_test', 'username')
            conf['account_username'] = "%s:%s" % (conf['account'],
                                                  conf['username'])
        else:
            # Still try to get separate account/usernames for keystone tests
            try:
                conf['account'] = parser.get('func_test', 'account')
                conf['username'] = parser.get('func_test', 'username')
            except configparser.NoOptionError:
                pass

        conf['password'] = parser.get('func_test', 'password')

        # For keystone v3
        try:
            conf['account4'] = parser.get('func_test', 'account4')
            conf['username4'] = parser.get('func_test', 'username4')
            conf['domain4'] = parser.get('func_test', 'domain4')
            conf['password4'] = parser.get('func_test', 'password4')
        except configparser.NoOptionError:
            pass

        TEST_CONFIG = conf


try:
    _load_config()
except configparser.NoOptionError:
    TEST_CONFIG = None  # sentinel used in test setup
