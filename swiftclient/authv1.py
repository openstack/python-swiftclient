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

"""
Authentication plugin for keystoneauth to support v1 endpoints.

Way back in the long-long ago, there was no Keystone. Swift used an auth
mechanism now known as "v1", which used only HTTP headers. Auth requests
and responses would look something like::

   > GET /auth/v1.0 HTTP/1.1
   > Host: <swift server>
   > X-Auth-User: <tenant>:<user>
   > X-Auth-Key: <password>
   >
   < HTTP/1.1 200 OK
   < X-Storage-Url: http://<swift server>/v1/<tenant account>
   < X-Auth-Token: <token>
   < X-Storage-Token: <token>
   <

This plugin provides a way for Keystone sessions (and clients that
use them, like python-openstackclient) to communicate with old auth
endpoints that still use this mechanism, such as tempauth, swauth,
or https://identity.api.rackspacecloud.com/v1.0
"""

import datetime
import json
import time

from urllib.parse import urljoin

# Note that while we import keystoneauth1 here, we *don't* need to add it to
# requirements.txt -- this entire module only makes sense (and should only be
# loaded) if keystoneauth is already installed.
from keystoneauth1 import discover
from keystoneauth1 import plugin
from keystoneauth1 import exceptions
from keystoneauth1 import loading
from keystoneauth1.identity import base


# stupid stdlib...
class _UTC(datetime.tzinfo):
    def utcoffset(self, dt):
        return datetime.timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return datetime.timedelta(0)


UTC = _UTC()
del _UTC


class ServiceCatalogV1:
    def __init__(self, auth_url, storage_url, account):
        self.auth_url = auth_url
        self._storage_url = storage_url
        self._account = account

    @property
    def storage_url(self):
        if self._account:
            return urljoin(self._storage_url.rstrip('/'), self._account)
        return self._storage_url

    @property
    def catalog(self):
        # openstackclient wants this for the `catalog list` and
        # `catalog show` commands
        endpoints = [{
            'region': 'default',
            'publicURL': self._storage_url,
        }]
        if self.storage_url != self._storage_url:
            endpoints.insert(0, {
                'region': 'override',
                'publicURL': self.storage_url,
            })

        return [
            {
                'name': 'swift',
                'type': 'object-store',
                'endpoints': endpoints,
            },
            {
                'name': 'auth',
                'type': 'identity',
                'endpoints': [{
                    'region': 'default',
                    'publicURL': self.auth_url,
                }],
            }
        ]

    def url_for(self, **kwargs):
        return self.endpoint_data_for(**kwargs).url

    def endpoint_data_for(self, **kwargs):
        kwargs.setdefault('interface', 'public')
        kwargs.setdefault('service_type', None)

        if kwargs['service_type'] == 'object-store':
            return discover.EndpointData(
                service_type='object-store',
                service_name='swift',
                interface=kwargs['interface'],
                region_name='default',
                catalog_url=self.storage_url,
            )

        # Although our "catalog" includes an identity entry, nothing that uses
        # url_for() (including `openstack endpoint list`) will know what to do
        # with it. Better to just raise the exception, cribbing error messages
        # from keystoneauth1/access/service_catalog.py

        if 'service_name' in kwargs and 'region_name' in kwargs:
            msg = ('%(interface)s endpoint for %(service_type)s service '
                   'named %(service_name)s in %(region_name)s region not '
                   'found' % kwargs)
        elif 'service_name' in kwargs:
            msg = ('%(interface)s endpoint for %(service_type)s service '
                   'named %(service_name)s not found' % kwargs)
        elif 'region_name' in kwargs:
            msg = ('%(interface)s endpoint for %(service_type)s service '
                   'in %(region_name)s region not found' % kwargs)
        else:
            msg = ('%(interface)s endpoint for %(service_type)s service '
                   'not found' % kwargs)

        raise exceptions.EndpointNotFound(msg)


class AccessInfoV1:
    """An object for encapsulating a raw v1 auth token."""

    def __init__(self, auth_url, storage_url, account, username, auth_token,
                 token_life):
        self.auth_url = auth_url
        self.storage_url = storage_url
        self.account = account
        self.service_catalog = ServiceCatalogV1(auth_url, storage_url, account)
        self.username = username
        self.auth_token = auth_token
        self._issued = time.time()
        try:
            self._expires = self._issued + float(token_life)
        except (TypeError, ValueError):
            self._expires = None
        # following is used by openstackclient
        self.project_id = None

    @property
    def expires(self):
        if self._expires is None:
            return None
        return datetime.datetime.fromtimestamp(self._expires, UTC)

    @property
    def issued(self):
        return datetime.datetime.fromtimestamp(self._issued, UTC)

    @property
    def user_id(self):
        # openstackclient wants this for the `token issue` command
        return self.username

    def will_expire_soon(self, stale_duration):
        """Determines if expiration is about to occur.

        :returns: true if expiration is within the given duration
        """
        if self._expires is None:
            return False  # assume no expiration
        return time.time() + stale_duration > self._expires

    def get_state(self):
        """Serialize the current state."""
        return json.dumps({
            'auth_url': self.auth_url,
            'storage_url': self.storage_url,
            'account': self.account,
            'username': self.username,
            'auth_token': self.auth_token,
            'issued': self._issued,
            'expires': self._expires}, sort_keys=True)

    @classmethod
    def from_state(cls, data):
        """Deserialize the given state.

        :returns: a new AccessInfoV1 object with the given state
        """
        data = json.loads(data)
        access = cls(
            data['auth_url'],
            data['storage_url'],
            data['account'],
            data['username'],
            data['auth_token'],
            token_life=None)
        access._issued = data['issued']
        access._expires = data['expires']
        return access


class PasswordPlugin(base.BaseIdentityPlugin):
    """A plugin for authenticating with a username and password.

    Subclassing from BaseIdentityPlugin gets us a few niceties, like handling
    token invalidation and locking during authentication.

    :param string auth_url: Identity v1 endpoint for authorization.
    :param string username: Username for authentication.
    :param string password: Password for authentication.
    :param string project_name: Swift account to use after authentication.
                                We use 'project_name' to be consistent with
                                other auth plugins.
    :param string reauthenticate: Whether to allow re-authentication.
    """
    access_class = AccessInfoV1

    def __init__(self, auth_url, username, password, project_name=None,
                 reauthenticate=True):
        super(PasswordPlugin, self).__init__(
            auth_url=auth_url,
            reauthenticate=reauthenticate)
        self.user = username
        self.key = password
        self.account = project_name

    def get_auth_ref(self, session, **kwargs):
        """Obtain a token from a v1 endpoint.

        This function should not be called independently and is expected to be
        invoked via the do_authenticate function.

        This function will be invoked if the AcessInfo object cached by the
        plugin is not valid. Thus plugins should always fetch a new AccessInfo
        when invoked. If you are looking to just retrieve the current auth
        data then you should use get_access.

        :param session: A session object that can be used for communication.

        :returns: Token access information.
        """
        headers = {'X-Auth-User': self.user,
                   'X-Auth-Key': self.key}

        resp = session.get(self.auth_url, headers=headers,
                           authenticated=False, log=False)

        if resp.status_code // 100 != 2:
            raise exceptions.InvalidResponse(response=resp)

        if 'X-Storage-Url' not in resp.headers:
            raise exceptions.InvalidResponse(response=resp)

        if 'X-Auth-Token' not in resp.headers and \
                'X-Storage-Token' not in resp.headers:
            raise exceptions.InvalidResponse(response=resp)
        token = resp.headers.get('X-Storage-Token',
                                 resp.headers.get('X-Auth-Token'))
        return AccessInfoV1(
            auth_url=self.auth_url,
            storage_url=resp.headers['X-Storage-Url'],
            account=self.account,
            username=self.user,
            auth_token=token,
            token_life=resp.headers.get('X-Auth-Token-Expires'))

    def get_cache_id_elements(self):
        """Get the elements for this auth plugin that make it unique."""
        return {'auth_url': self.auth_url,
                'user': self.user,
                'key': self.key,
                'account': self.account}

    def get_endpoint(self, session, interface='public', **kwargs):
        """Return an endpoint for the client."""
        if interface is plugin.AUTH_INTERFACE:
            return self.auth_url
        else:
            return self.get_access(session).service_catalog.url_for(
                interface=interface, **kwargs)

    def get_auth_state(self):
        """Retrieve the current authentication state for the plugin.

        :returns: raw python data (which can be JSON serialized) that can be
                  moved into another plugin (of the same type) to have the
                  same authenticated state.
        """
        if self.auth_ref:
            return self.auth_ref.get_state()

    def set_auth_state(self, data):
        """Install existing authentication state for a plugin.

        Take the output of get_auth_state and install that authentication state
        into the current authentication plugin.
        """
        if data:
            self.auth_ref = self.access_class.from_state(data)
        else:
            self.auth_ref = None

    def get_sp_auth_url(self, *args, **kwargs):
        raise NotImplementedError()

    def get_sp_url(self, *args, **kwargs):
        raise NotImplementedError()

    def get_discovery(self, *args, **kwargs):
        raise NotImplementedError()


class PasswordLoader(loading.BaseLoader):
    """Option handling for the ``v1password`` plugin."""
    plugin_class = PasswordPlugin

    def get_options(self):
        """Return the list of parameters associated with the auth plugin.

        This list may be used to generate CLI or config arguments.
        """
        return [
            loading.Opt('auth-url', required=True,
                        help='Authentication URL'),
            # overload project-name as a way to specify an alternate account,
            # since:
            #   - in a world of just users & passwords, this seems the closest
            #     analog to a project, and
            #   - openstackclient will (or used to?) still require that you
            #     provide one anyway
            loading.Opt('project-name', required=False,
                        help='Swift account to use'),
            loading.Opt('username', required=True,
                        deprecated=[loading.Opt('user-name')],
                        help='Username to login with'),
            loading.Opt('password', required=True, secret=True,
                        help='Password to use'),
        ]
