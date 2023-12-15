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

import logging
import os

from collections import defaultdict
from concurrent.futures import as_completed, CancelledError, TimeoutError
from copy import deepcopy
from errno import EEXIST, ENOENT
from hashlib import md5
from io import StringIO
from os import environ, makedirs, stat, utime
from os.path import (
    basename, dirname, getmtime, getsize, isdir, join, sep as os_path_sep
)
from posixpath import join as urljoin
from random import shuffle
from time import time
from threading import Thread
from queue import Queue
from queue import Empty as QueueEmpty
from requests.exceptions import RequestException
from socket import error as socket_error
from urllib3.exceptions import HTTPError as urllib_http_error
from urllib.parse import quote

import json


from swiftclient import Connection
from swiftclient.command_helpers import (
    stat_account, stat_container, stat_object
)
from swiftclient.utils import (
    config_true_value, ReadableToIterable, LengthWrapper, EMPTY_ETAG,
    parse_api_response, report_traceback, n_groups, split_request_headers,
    n_at_a_time, normalize_manifest_path
)
from swiftclient.exceptions import ClientException
from swiftclient.multithreading import MultiThreadingManager


DISK_BUFFER = 2 ** 16
logger = logging.getLogger("swiftclient.service")


class ResultsIterator:
    def __init__(self, futures):
        self.futures = interruptable_as_completed(futures)

    def __iter__(self):
        return self

    def __next__(self):
        next_completed_future = next(self.futures)
        return next_completed_future.result()


class SwiftError(Exception):
    def __init__(self, value, container=None, obj=None,
                 segment=None, exc=None, transaction_id=None):
        self.value = value
        self.container = container
        self.obj = obj
        self.segment = segment
        self.exception = exc
        if transaction_id is None:
            self.transaction_id = getattr(exc, 'transaction_id', None)
        else:
            self.transaction_id = transaction_id

    def __str__(self):
        value = repr(self.value)
        if self.container is not None:
            value += " container:%s" % self.container
        if self.obj is not None:
            value += " object:%s" % self.obj
        if self.segment is not None:
            value += " segment:%s" % self.segment
        return value

    def __repr__(self):
        return str(self)


def process_options(options):
    auth_types_to_versions = {
        'v1password': '1.0',
        'v2password': '2.0',
        'v3password': '3',
        'v3applicationcredential': '3',
    }

    version_from_type = auth_types_to_versions.get(options['os_auth_type'])
    if version_from_type:
        options['auth_version'] = version_from_type

    # tolerate sloppy auth_version
    if options.get('auth_version') == '3.0':
        options['auth_version'] = '3'
    elif options.get('auth_version') == '2':
        options['auth_version'] = '2.0'

    if options.get('auth_version') not in ('2.0', '3') and \
            options.get('os_auth_type') != 'v1password' and \
            not all(options.get(key) for key in ('auth', 'user', 'key')):
        # Use keystone auth if any of the new-style args are present
        if any(options.get(k) for k in (
                'os_user_domain_id',
                'os_user_domain_name',
                'os_project_domain_id',
                'os_project_domain_name')):
            # Use v3 if there's any reference to domains
            options['auth_version'] = '3'
        else:
            options['auth_version'] = '2.0'

    # Use new-style args if old ones not present
    if not options['auth'] and options['os_auth_url']:
        options['auth'] = options['os_auth_url']
    if not options['user'] and options['os_username']:
        options['user'] = options['os_username']
    if not options['key'] and options['os_password']:
        options['key'] = options['os_password']

    # Specific OpenStack options
    options['os_options'] = {
        opt: options['os_' + opt] for opt in (
            'user_id',
            'user_domain_id',
            'user_domain_name',
            'tenant_id',
            'tenant_name',
            'project_id',
            'project_name',
            'project_domain_id',
            'project_domain_name',
            'service_type',
            'endpoint_type',
            'auth_token',
            'region_name',
            'auth_type',
            'application_credential_id',
            'application_credential_secret',
        )
    }
    # this one doesn't follow the same convention
    options['os_options']['object_storage_url'] = options['os_storage_url']


def _build_default_global_options():
    return {
        "snet": False,
        "verbose": 1,
        "debug": False,
        "info": False,
        "auth": environ.get('ST_AUTH'),
        "auth_version": environ.get('ST_AUTH_VERSION', '1.0'),
        "user": environ.get('ST_USER'),
        "key": environ.get('ST_KEY'),
        "retries": 5,
        "retry_on_ratelimit": True,
        "force_auth_retry": False,
        "os_username": environ.get('OS_USERNAME'),
        "os_user_id": environ.get('OS_USER_ID'),
        "os_user_domain_name": environ.get('OS_USER_DOMAIN_NAME'),
        "os_user_domain_id": environ.get('OS_USER_DOMAIN_ID'),
        "os_password": environ.get('OS_PASSWORD'),
        "os_tenant_id": environ.get('OS_TENANT_ID'),
        "os_tenant_name": environ.get('OS_TENANT_NAME'),
        "os_project_name": environ.get('OS_PROJECT_NAME'),
        "os_project_id": environ.get('OS_PROJECT_ID'),
        "os_project_domain_name": environ.get('OS_PROJECT_DOMAIN_NAME'),
        "os_project_domain_id": environ.get('OS_PROJECT_DOMAIN_ID'),
        "os_auth_url": environ.get('OS_AUTH_URL'),
        "os_auth_token": environ.get('OS_AUTH_TOKEN'),
        "os_auth_type": environ.get('OS_AUTH_TYPE'),
        "os_application_credential_id":
        environ.get('OS_APPLICATION_CREDENTIAL_ID'),
        "os_application_credential_secret":
        environ.get('OS_APPLICATION_CREDENTIAL_SECRET'),
        "os_storage_url": environ.get('OS_STORAGE_URL'),
        "os_region_name": environ.get('OS_REGION_NAME'),
        "os_service_type": environ.get('OS_SERVICE_TYPE'),
        "os_endpoint_type": environ.get('OS_ENDPOINT_TYPE'),
        "os_cacert": environ.get('OS_CACERT'),
        "os_cert": environ.get('OS_CERT'),
        "os_key": environ.get('OS_KEY'),
        "insecure": config_true_value(environ.get('SWIFTCLIENT_INSECURE')),
        "ssl_compression": False,
        'segment_threads': 10,
        'object_dd_threads': 10,
        'object_uu_threads': 10,
        'container_threads': 10
    }


_default_global_options = _build_default_global_options()

_default_local_options = {
    'sync_to': None,
    'sync_key': None,
    'use_slo': None,
    'segment_size': None,
    'segment_container': None,
    'leave_segments': False,
    'changed': None,
    'skip_identical': False,
    'skip_container_put': False,
    'version_id': None,
    'yes_all': False,
    'read_acl': None,
    'write_acl': None,
    'out_file': None,
    'out_directory': None,
    'remove_prefix': False,
    'no_download': False,
    'long': False,
    'totals': False,
    'marker': '',
    'header': [],
    'meta': [],
    'prefix': None,
    'delimiter': None,
    'versions': False,
    'fail_fast': False,
    'human': False,
    'dir_marker': False,
    'checksum': True,
    'shuffle': False,
    'destination': None,
    'fresh_metadata': False,
    'ignore_mtime': False,
}

POLICY = 'X-Storage-Policy'
KNOWN_DIR_MARKERS = (
    'application/directory',  # Preferred
    'text/directory',  # Historically relevant
)


def get_from_queue(q, timeout=864000):
    while True:
        try:
            item = q.get(timeout=timeout)
            return item
        except QueueEmpty:
            # Do nothing here, we only have a timeout to allow interruption
            pass


def get_future_result(f, timeout=86400):
    while True:
        try:
            res = f.result(timeout=timeout)
            return res
        except TimeoutError:
            # Do nothing here, we only have a timeout to allow interruption
            pass


def interruptable_as_completed(fs, timeout=86400):
    while True:
        try:
            for f in as_completed(fs, timeout=timeout):
                fs.remove(f)
                yield f
            return
        except TimeoutError:
            # Do nothing here, we only have a timeout to allow interruption
            pass


def get_conn(options):
    """
    Return a connection building it from the options.
    """
    options = dict(_default_global_options, **options)
    return Connection(options['auth'],
                      options['user'],
                      options['key'],
                      timeout=options.get('timeout'),
                      retry_on_ratelimit=options['retry_on_ratelimit'],
                      retries=options['retries'],
                      auth_version=options['auth_version'],
                      os_options=options['os_options'],
                      snet=options['snet'],
                      cacert=options['os_cacert'],
                      insecure=options['insecure'],
                      cert=options['os_cert'],
                      cert_key=options['os_key'],
                      ssl_compression=options['ssl_compression'],
                      force_auth_retry=options['force_auth_retry'],
                      starting_backoff=options.get('starting_backoff', 1),
                      max_backoff=options.get('max_backoff', 64))


def mkdirs(path):
    try:
        makedirs(path)
    except OSError as err:
        if err.errno != EEXIST:
            raise


def split_headers(options, prefix=''):
    """
    Splits 'Key: Value' strings and returns them as a dictionary.

    :param options: Must be one of:
        * an iterable of 'Key: Value' strings
        * an iterable of ('Key', 'Value') pairs
        * a dict of {'Key': 'Value'} pairs
    :param prefix: String to prepend to all of the keys in the dictionary.
        reporting.
    """
    headers = {}
    try:
        headers = split_request_headers(options, prefix)
    except ValueError as e:
        raise SwiftError(e)

    return headers


class SwiftUploadObject:
    """
    Class for specifying an object upload, allowing the object source, name and
    options to be specified separately for each individual object.
    """
    def __init__(self, source, object_name=None, options=None):
        if isinstance(source, str):
            self.object_name = object_name or source
        elif source is None or hasattr(source, 'read'):
            if not object_name or not isinstance(object_name, str):
                raise SwiftError('Object names must be specified as '
                                 'strings for uploads from None or file '
                                 'like objects.')
            self.object_name = object_name
        else:
            raise SwiftError('Unexpected source type for '
                             'SwiftUploadObject: {0}'.format(type(source)))

        if not self.object_name:
            raise SwiftError('Object names must not be empty strings')

        self.object_name = self.object_name.lstrip('/')
        self.options = options
        self.source = source


class SwiftPostObject:
    """
    Class for specifying an object post, allowing the headers/metadata to be
    specified separately for each individual object.
    """
    def __init__(self, object_name, options=None):
        if not (isinstance(object_name, str) and object_name):
            raise SwiftError(
                "Object names must be specified as non-empty strings"
            )
        self.object_name = object_name
        self.options = options


class SwiftDeleteObject:
    """
    Class for specifying an object delete, allowing the headers/metadata to be
    specified separately for each individual object.
    """
    def __init__(self, object_name, options=None):
        if not (isinstance(object_name, str) and object_name):
            raise SwiftError(
                "Object names must be specified as non-empty strings"
            )
        self.object_name = object_name
        self.options = options


class SwiftCopyObject:
    """
    Class for specifying an object copy,
    allowing the destination/headers/metadata/fresh_metadata to be specified
    separately for each individual object.
    destination and fresh_metadata should be set in options
    """
    def __init__(self, object_name, options=None):
        if not (isinstance(object_name, str) and object_name):
            raise SwiftError(
                "Object names must be specified as non-empty strings"
            )

        self.object_name = object_name
        self.options = options

        if self.options is None:
            self.destination = None
            self.fresh_metadata = False
        else:
            self.destination = self.options.get('destination')
            self.fresh_metadata = self.options.get('fresh_metadata', False)

        if self.destination is not None:
            destination_components = self.destination.split('/')
            if destination_components[0] or len(destination_components) < 2:
                raise SwiftError("destination must be in format /cont[/obj]")
            if not destination_components[-1]:
                raise SwiftError("destination must not end in a slash")
            if len(destination_components) == 2:
                # only container set in destination
                self.destination = "{0}/{1}".format(
                    self.destination, object_name
                )


class _SwiftReader:
    """
    Class for downloading objects from swift and raising appropriate
    errors on failures caused by either invalid md5sum or size of the
    data read.
    """
    def __init__(self, path, body, headers, checksum=True):
        self._path = path
        self._body = body
        self._txn_id = headers.get('x-openstack-request-id')
        if self._txn_id is None:
            self._txn_id = headers.get('x-trans-id')
        self._actual_read = 0
        self._content_length = None
        self._actual_md5 = None
        self._expected_md5 = headers.get('etag', '')

        if len(self._expected_md5) > 1 and self._expected_md5[0] == '"' \
                and self._expected_md5[-1] == '"':
            self._expected_md5 = self._expected_md5[1:-1]

        # Some headers indicate the MD5 of the response
        # definitely *won't* match the ETag
        bad_md5_headers = set([
            'content-range',
            'x-object-manifest',
            'x-static-large-object',
        ])
        if bad_md5_headers.intersection(headers):
            # This isn't a useful checksum
            self._expected_md5 = ''

        if self._expected_md5 and checksum:
            self._actual_md5 = md5()

        if 'content-length' in headers:
            try:
                self._content_length = int(headers.get('content-length'))
            except ValueError:
                raise SwiftError(
                    'content-length header must be an integer',
                    transaction_id=self._txn_id)

    def __iter__(self):
        for chunk in self._body:
            if self._actual_md5:
                self._actual_md5.update(chunk)
            self._actual_read += len(chunk)
            yield chunk
        self._check_contents()

    def _check_contents(self):
        if (self._content_length is not None and
                self._actual_read != self._content_length):
            raise SwiftError(
                'Error downloading {0}: read_length != content_length, '
                '{1:d} != {2:d} (txn: {3})'.format(
                    self._path, self._actual_read, self._content_length,
                    self._txn_id or 'unknown'))

        if self._actual_md5 and self._expected_md5:
            etag = self._actual_md5.hexdigest()
            if etag != self._expected_md5:
                raise SwiftError(
                    'Error downloading {0}: md5sum != etag, '
                    '{1} != {2} (txn: {3})'.format(
                        self._path, etag, self._expected_md5,
                        self._txn_id or 'unknown'))

    def bytes_read(self):
        return self._actual_read


class SwiftService:
    """
    Service for performing swift operations
    """
    def __init__(self, options=None):
        if options is not None:
            self._options = dict(
                _default_global_options,
                **dict(_default_local_options, **options)
            )
        else:
            self._options = dict(
                _default_global_options,
                **_default_local_options
            )
        process_options(self._options)

        def create_connection():
            return get_conn(self._options)
        self.thread_manager = MultiThreadingManager(
            create_connection,
            segment_threads=self._options['segment_threads'],
            object_dd_threads=self._options['object_dd_threads'],
            object_uu_threads=self._options['object_uu_threads'],
            container_threads=self._options['container_threads']
        )
        self.capabilities_cache = {}  # Each instance should have its own cache

    def __enter__(self):
        self.thread_manager.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.thread_manager.__exit__(exc_type, exc_val, exc_tb)

    # Stat related methods
    #
    def stat(self, container=None, objects=None, options=None):
        """
        Get account stats, container stats or information about a list of
        objects in a container.

        :param container: The container to query.
        :param objects: A list of object paths about which to return
                        information (a list of strings).
        :param options: A dictionary containing options to override the global
                        options specified during the service object creation.
                        These options are applied to all stat operations
                        performed by this call::

                            {
                                'human': False,
                                'version_id': None,
                                'header': []
                            }

        :returns: Either a single dictionary containing stats about an account
                  or container, or an iterator for returning the results of the
                  stat operations on a list of objects.

        :raises SwiftError:
        """
        if options is not None:
            options = dict(self._options, **options)
        else:
            options = self._options

        if not container:
            if objects:
                raise SwiftError('Objects specified without container')
            else:
                res = {
                    'action': 'stat_account',
                    'success': True,
                    'container': container,
                    'object': None,
                }
                try:
                    stats_future = self.thread_manager.container_pool.submit(
                        stat_account, options
                    )
                    items, headers = get_future_result(stats_future)
                    res.update({
                        'items': items,
                        'headers': headers
                    })
                    return res
                except ClientException as err:
                    if err.http_status != 404:
                        traceback, err_time = report_traceback()
                        logger.exception(err)
                        res.update({
                            'success': False,
                            'error': err,
                            'traceback': traceback,
                            'error_timestamp': err_time
                        })
                        return res
                    raise SwiftError('Account not found', exc=err)
                except Exception as err:
                    traceback, err_time = report_traceback()
                    logger.exception(err)
                    res.update({
                        'success': False,
                        'error': err,
                        'traceback': traceback,
                        'error_timestamp': err_time
                    })
                    return res
        else:
            if not objects:
                res = {
                    'action': 'stat_container',
                    'container': container,
                    'object': None,
                    'success': True,
                }
                try:
                    stats_future = self.thread_manager.container_pool.submit(
                        stat_container, options, container
                    )
                    items, headers = get_future_result(stats_future)
                    res.update({
                        'items': items,
                        'headers': headers
                    })
                    return res
                except ClientException as err:
                    if err.http_status != 404:
                        traceback, err_time = report_traceback()
                        logger.exception(err)
                        res.update({
                            'success': False,
                            'error': err,
                            'traceback': traceback,
                            'error_timestamp': err_time
                        })
                        return res
                    raise SwiftError('Container %r not found' % container,
                                     container=container, exc=err)
                except Exception as err:
                    traceback, err_time = report_traceback()
                    logger.exception(err)
                    res.update({
                        'success': False,
                        'error': err,
                        'traceback': traceback,
                        'error_timestamp': err_time
                    })
                    return res
            else:
                stat_futures = []
                for stat_o in objects:
                    stat_future = self.thread_manager.object_dd_pool.submit(
                        self._stat_object, container, stat_o, options
                    )
                    stat_futures.append(stat_future)

                return ResultsIterator(stat_futures)

    @staticmethod
    def _stat_object(conn, container, obj, options):
        res = {
            'action': 'stat_object',
            'object': obj,
            'container': container,
            'success': True,
        }
        try:
            items, headers = stat_object(conn, options, container, obj)
            res.update({
                'items': items,
                'headers': headers
            })
            return res
        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            res.update({
                'success': False,
                'error': err,
                'traceback': traceback,
                'error_timestamp': err_time
            })
            return res

    # Post related methods
    #
    def post(self, container=None, objects=None, options=None):
        """
        Post operations on an account, container or list of objects

        :param container: The container to make the post operation against.
        :param objects: A list of object names (strings) or SwiftPostObject
                        instances containing an object name, and an
                        options dict (can be None) to override the options for
                        that individual post operation::

                            [
                                'object_name',
                                SwiftPostObject('object_name', options={...}),
                                ...
                            ]

                        The options dict is described below.
        :param options: A dictionary containing options to override the global
                        options specified during the service object creation.
                        These options are applied to all post operations
                        performed by this call, unless overridden on a per
                        object basis. Possible options are given below::

                            {
                                'meta': [],
                                'header': [],
                                'read_acl': None,   # For containers only
                                'write_acl': None,  # For containers only
                                'sync_to': None,    # For containers only
                                'sync_key': None    # For containers only
                            }

        :returns: Either a single result dictionary in the case of a post to a
                  container/account, or an iterator for returning the results
                  of posts to a list of objects.

        :raises SwiftError:
        """
        if options is not None:
            options = dict(self._options, **options)
        else:
            options = self._options

        res = {
            'success': True,
            'container': container,
            'object': None,
            'headers': {},
        }
        if not container:
            res["action"] = "post_account"
            if objects:
                raise SwiftError('Objects specified without container')
            else:
                response_dict = {}
                headers = split_headers(
                    options['meta'], 'X-Account-Meta-')
                headers.update(
                    split_headers(options['header'], ''))
                res['headers'] = headers
                try:
                    post = self.thread_manager.container_pool.submit(
                        self._post_account_job, headers, response_dict
                    )
                    get_future_result(post)
                except ClientException as err:
                    if err.http_status != 404:
                        traceback, err_time = report_traceback()
                        logger.exception(err)
                        res.update({
                            'success': False,
                            'error': err,
                            'traceback': traceback,
                            'error_timestamp': err_time,
                            'response_dict': response_dict
                        })
                        return res
                    raise SwiftError('Account not found', exc=err)
                except Exception as err:
                    traceback, err_time = report_traceback()
                    logger.exception(err)
                    res.update({
                        'success': False,
                        'error': err,
                        'response_dict': response_dict,
                        'traceback': traceback,
                        'error_timestamp': err_time
                    })
            return res
        if not objects:
            res["action"] = "post_container"
            response_dict = {}
            headers = split_headers(
                options['meta'], 'X-Container-Meta-')
            headers.update(
                split_headers(options['header'], ''))
            if options['read_acl'] is not None:
                headers['X-Container-Read'] = options['read_acl']
            if options['write_acl'] is not None:
                headers['X-Container-Write'] = options['write_acl']
            if options['sync_to'] is not None:
                headers['X-Container-Sync-To'] = options['sync_to']
            if options['sync_key'] is not None:
                headers['X-Container-Sync-Key'] = options['sync_key']
            res['headers'] = headers
            try:
                post = self.thread_manager.container_pool.submit(
                    self._post_container_job, container,
                    headers, response_dict
                )
                get_future_result(post)
            except ClientException as err:
                if err.http_status != 404:
                    traceback, err_time = report_traceback()
                    logger.exception(err)
                    res.update({
                        'action': 'post_container',
                        'success': False,
                        'error': err,
                        'traceback': traceback,
                        'error_timestamp': err_time,
                        'response_dict': response_dict
                    })
                    return res
                raise SwiftError(
                    "Container '%s' not found" % container,
                    container=container, exc=err
                )
            except Exception as err:
                traceback, err_time = report_traceback()
                logger.exception(err)
                res.update({
                    'action': 'post_container',
                    'success': False,
                    'error': err,
                    'response_dict': response_dict,
                    'traceback': traceback,
                    'error_timestamp': err_time
                })
            return res
        else:
            post_futures = []
            post_objects = self._make_post_objects(objects)
            for post_object in post_objects:
                obj = post_object.object_name
                obj_options = post_object.options
                response_dict = {}
                headers = split_headers(
                    options['meta'], 'X-Object-Meta-')
                # add header options to the headers object for the request.
                headers.update(
                    split_headers(options['header'], ''))
                if obj_options is not None:
                    if 'meta' in obj_options:
                        headers.update(
                            split_headers(
                                obj_options['meta'], 'X-Object-Meta-'
                            )
                        )
                    if 'header' in obj_options:
                        headers.update(
                            split_headers(obj_options['header'], '')
                        )

                post = self.thread_manager.object_uu_pool.submit(
                    self._post_object_job, container, obj,
                    headers, response_dict
                )
                post_futures.append(post)

            return ResultsIterator(post_futures)

    @staticmethod
    def _make_post_objects(objects):
        post_objects = []

        for o in objects:
            if isinstance(o, str):
                obj = SwiftPostObject(o)
                post_objects.append(obj)
            elif isinstance(o, SwiftPostObject):
                post_objects.append(o)
            else:
                raise SwiftError(
                    "The post operation takes only strings or "
                    "SwiftPostObjects as input",
                    obj=o)

        return post_objects

    @staticmethod
    def _post_account_job(conn, headers, result):
        return conn.post_account(headers=headers, response_dict=result)

    @staticmethod
    def _post_container_job(conn, container, headers, result):
        try:
            res = conn.post_container(
                container, headers=headers, response_dict=result)
        except ClientException as err:
            if err.http_status != 404:
                raise
            _response_dict = {}
            res = conn.put_container(
                container, headers=headers, response_dict=_response_dict)
            result['post_put'] = _response_dict
        return res

    @staticmethod
    def _post_object_job(conn, container, obj, headers, result):
        res = {
            'success': True,
            'action': 'post_object',
            'container': container,
            'object': obj,
            'headers': headers,
            'response_dict': result
        }
        try:
            conn.post_object(
                container, obj, headers=headers, response_dict=result)
        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            res.update({
                'success': False,
                'error': err,
                'traceback': traceback,
                'error_timestamp': err_time
            })

        return res

    # List related methods
    #
    def list(self, container=None, options=None):
        """
        List operations on an account, container.

        :param container: The container to make the list operation against.
        :param options: A dictionary containing options to override the global
                        options specified during the service object creation::

                            {
                                'long': False,
                                'prefix': None,
                                'delimiter': None,
                                'versions': False,
                                'header': []
                            }

        :returns: A generator for returning the results of the list operation
                  on an account or container. Each result yielded from the
                  generator is either a 'list_account_part' or
                  'list_container_part', containing part of the listing.
        """
        if options is not None:
            options = dict(self._options, **options)
        else:
            options = self._options

        rq = Queue(maxsize=10)  # Just stop list running away consuming memory

        if container is None:
            listing_future = self.thread_manager.container_pool.submit(
                self._list_account_job, options, rq
            )
        else:
            listing_future = self.thread_manager.container_pool.submit(
                self._list_container_job, container, options, rq
            )

        res = get_from_queue(rq)
        while res is not None:
            yield res
            res = get_from_queue(rq)

        # Make sure the future has completed
        get_future_result(listing_future)

    @staticmethod
    def _list_account_job(conn, options, result_queue):
        marker = ''
        error = None
        req_headers = split_headers(options.get('header', []))
        try:
            while True:
                _, items = conn.get_account(
                    marker=marker, prefix=options['prefix'],
                    headers=req_headers
                )

                if not items:
                    result_queue.put(None)
                    return

                if options['long']:
                    for i in items:
                        name = i['name']
                        i['meta'] = conn.head_container(name)

                res = {
                    'action': 'list_account_part',
                    'container': None,
                    'prefix': options['prefix'],
                    'success': True,
                    'listing': items,
                    'marker': marker,
                }
                result_queue.put(res)

                marker = items[-1].get('name', items[-1].get('subdir'))
        except ClientException as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            if err.http_status != 404:
                error = (err, traceback, err_time)
            else:
                error = (
                    SwiftError('Account not found', exc=err),
                    traceback, err_time
                )

        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            error = (err, traceback, err_time)

        res = {
            'action': 'list_account_part',
            'container': None,
            'prefix': options['prefix'],
            'success': False,
            'marker': marker,
            'error': error[0],
            'traceback': error[1],
            'error_timestamp': error[2]
        }
        result_queue.put(res)
        result_queue.put(None)

    @staticmethod
    def _list_container_job(conn, container, options, result_queue):
        marker = options.get('marker', '')
        version_marker = options.get('version_marker', '')
        error = None
        req_headers = split_headers(options.get('header', []))
        if options.get('versions', False):
            query_string = 'versions=true'
        else:
            query_string = None
        try:
            while True:
                _, items = conn.get_container(
                    container, marker=marker, version_marker=version_marker,
                    prefix=options['prefix'], delimiter=options['delimiter'],
                    headers=req_headers, query_string=query_string
                )

                if not items:
                    result_queue.put(None)
                    return

                res = {
                    'action': 'list_container_part',
                    'container': container,
                    'prefix': options['prefix'],
                    'success': True,
                    'marker': marker,
                    'listing': items,
                }
                result_queue.put(res)

                marker = items[-1].get('name', items[-1].get('subdir'))
                version_marker = items[-1].get('version_id', '')
        except ClientException as err:
            traceback, err_time = report_traceback()
            if err.http_status != 404:
                logger.exception(err)
                error = (err, traceback, err_time)
            else:
                error = (
                    SwiftError(
                        'Container %r not found' % container,
                        container=container, exc=err
                    ),
                    traceback,
                    err_time
                )
        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            error = (err, traceback, err_time)

        res = {
            'action': 'list_container_part',
            'container': container,
            'prefix': options['prefix'],
            'success': False,
            'marker': marker,
            'version_marker': version_marker,
            'error': error[0],
            'traceback': error[1],
            'error_timestamp': error[2]
        }
        result_queue.put(res)
        result_queue.put(None)

    # Download related methods
    #
    def download(self, container=None, objects=None, options=None):
        """
        Download operations on an account, optional container and optional list
        of objects.

        :param container: The container to download from.
        :param objects: A list of object names to download (a list of strings).
        :param options: A dictionary containing options to override the global
                        options specified during the service object creation::

                            {
                                'yes_all': False,
                                'marker': '',
                                'prefix': None,
                                'no_download': False,
                                'header': [],
                                'skip_identical': False,
                                'version_id': None,
                                'out_directory': None,
                                'checksum': True,
                                'out_file': None,
                                'remove_prefix': False,
                                'shuffle' : False
                            }

        :returns: A generator for returning the results of the download
                  operations. Each result yielded from the generator is a
                  'download_object' dictionary containing the results of an
                  individual file download.

        :raises ClientException:
        :raises SwiftError:
        """
        if options is not None:
            options = dict(self._options, **options)
        else:
            options = self._options

        if not container:
            # Download everything if options['yes_all'] is set
            if options['yes_all']:
                try:
                    options_copy = deepcopy(options)
                    options_copy["long"] = False

                    for part in self.list(options=options_copy):
                        if part["success"]:
                            containers = [i['name'] for i in part["listing"]]

                            if options['shuffle']:
                                shuffle(containers)

                            for con in containers:
                                for res in self._download_container(
                                        con, options_copy):
                                    yield res
                        else:
                            raise part["error"]

                # If we see a 404 here, the listing of the account failed
                except ClientException as err:
                    if err.http_status != 404:
                        raise
                    raise SwiftError('Account not found', exc=err)

        elif objects is None:
            if '/' in container:
                raise SwiftError('\'/\' in container name',
                                 container=container)
            for res in self._download_container(container, options):
                yield res

        else:
            if '/' in container:
                raise SwiftError('\'/\' in container name',
                                 container=container)
            if options['out_file'] and len(objects) > 1:
                options['out_file'] = None

            o_downs = [
                self.thread_manager.object_dd_pool.submit(
                    self._download_object_job, container, obj, options
                ) for obj in objects
            ]

            for o_down in interruptable_as_completed(o_downs):
                yield o_down.result()

    def _download_object_job(self, conn, container, obj, options):
        out_file = options['out_file']
        results_dict = {}

        req_headers = split_headers(options['header'], '')

        pseudodir = False
        path = join(container, obj) if options['yes_all'] else obj
        path = path.lstrip(os_path_sep)
        options['skip_identical'] = (options['skip_identical'] and
                                     out_file != '-')

        if options['prefix'] and options['remove_prefix']:
            path = path[len(options['prefix']):].lstrip('/')

        if options['out_directory']:
            path = os.path.join(options['out_directory'], path)

        if options['skip_identical']:
            filename = out_file if out_file else path
            try:
                fp = open(filename, 'rb', DISK_BUFFER)
            except IOError:
                pass
            else:
                with fp:
                    md5sum = md5()
                    while True:
                        data = fp.read(DISK_BUFFER)
                        if not data:
                            break
                        md5sum.update(data)
                    req_headers['If-None-Match'] = md5sum.hexdigest()

        try:
            start_time = time()
            get_args = {'resp_chunk_size': DISK_BUFFER,
                        'headers': req_headers,
                        'response_dict': results_dict}
            if options.get('version_id') is not None:
                get_args['query_string'] = (
                    'version-id=%s' % options['version_id'])
            if options['skip_identical']:
                # Assume the file is a large object; if we're wrong, the query
                # string is ignored and the If-None-Match header will trigger
                # the behavior we want
                get_args['query_string'] = 'multipart-manifest=get'

            try:
                headers, body = conn.get_object(container, obj, **get_args)
            except ClientException as e:
                if not options['skip_identical']:
                    raise
                if e.http_status != 304:  # Only handling Not Modified
                    raise

                headers = results_dict['headers']
                if 'x-object-manifest' in headers:
                    # DLO: most likely it has more than one page worth of
                    #      segments and we have an empty file locally
                    body = []
                elif config_true_value(headers.get('x-static-large-object')):
                    # SLO: apparently we have a copy of the manifest locally?
                    #      provide no chunking data to force a fresh download
                    body = [b'[]']
                else:
                    # Normal object: let it bubble up
                    raise

            if options['skip_identical']:
                if config_true_value(headers.get('x-static-large-object')) or \
                        'x-object-manifest' in headers:
                    # The request was chunked, so stitch it back together
                    chunk_data = self._get_chunk_data(conn, container, obj,
                                                      headers, b''.join(body))
                else:
                    chunk_data = None

                if chunk_data is not None:
                    if self._is_identical(chunk_data, filename):
                        raise ClientException('Large object is identical',
                                              http_status=304)

                    # Large objects are different; start the real download
                    del get_args['query_string']
                    get_args['response_dict'].clear()
                    headers, body = conn.get_object(container, obj, **get_args)

            headers_receipt = time()

            obj_body = _SwiftReader(path, body, headers,
                                    options.get('checksum', True))

            no_file = options['no_download']
            if out_file == "-" and not no_file:
                res = {
                    'action': 'download_object',
                    'container': container,
                    'object': obj,
                    'path': path,
                    'pseudodir': pseudodir,
                    'contents': obj_body
                }
                return res

            fp = None
            try:
                content_type = headers.get('content-type', '').split(';', 1)[0]
                if content_type in KNOWN_DIR_MARKERS:
                    make_dir = not no_file and out_file != "-"
                    if make_dir and not isdir(path):
                        mkdirs(path)

                else:
                    make_dir = not (no_file or out_file)
                    if make_dir:
                        dirpath = dirname(path)
                        if dirpath and not isdir(dirpath):
                            mkdirs(dirpath)

                    if not no_file:
                        if out_file:
                            fp = open(out_file, 'wb', DISK_BUFFER)
                        else:
                            if basename(path):
                                fp = open(path, 'wb', DISK_BUFFER)
                            else:
                                pseudodir = True

                try:
                    for chunk in obj_body:
                        if fp is not None:
                            fp.write(chunk)
                except (socket_error,
                        urllib_http_error,
                        RequestException) as err:
                    raise ClientException(
                        str(err), http_response_headers=headers)

                finish_time = time()

            finally:
                bytes_read = obj_body.bytes_read()
                if fp is not None:
                    fp.close()
                    if ('x-object-meta-mtime' in headers and not no_file and
                            not options['ignore_mtime']):
                        try:
                            mtime = float(headers['x-object-meta-mtime'])
                        except ValueError:
                            pass  # no real harm; couldn't trust it anyway
                        else:
                            if options['out_file']:
                                utime(options['out_file'], (mtime, mtime))
                            else:
                                utime(path, (mtime, mtime))

            res = {
                'action': 'download_object',
                'success': True,
                'container': container,
                'object': obj,
                'path': path,
                'pseudodir': pseudodir,
                'start_time': start_time,
                'finish_time': finish_time,
                'headers_receipt': headers_receipt,
                'auth_end_time': conn.auth_end_time,
                'read_length': bytes_read,
                'attempts': conn.attempts,
                'response_dict': results_dict
            }
            return res

        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            res = {
                'action': 'download_object',
                'container': container,
                'object': obj,
                'success': False,
                'error': err,
                'traceback': traceback,
                'error_timestamp': err_time,
                'response_dict': results_dict,
                'path': path,
                'pseudodir': pseudodir,
                'attempts': conn.attempts
            }
            return res

    def _submit_page_downloads(self, container, page_generator, options):
        try:
            list_page = next(page_generator)
        except StopIteration:
            return None

        if list_page["success"]:
            objects = [o["name"] for o in list_page["listing"]]

            if options["shuffle"]:
                shuffle(objects)

            o_downs = [
                self.thread_manager.object_dd_pool.submit(
                    self._download_object_job, container, obj, options
                ) for obj in objects
            ]

            return o_downs
        else:
            raise list_page["error"]

    def _download_container(self, container, options):
        _page_generator = self.list(container=container, options=options)
        try:
            next_page_downs = self._submit_page_downloads(
                container, _page_generator, options
            )
        except ClientException as err:
            if err.http_status != 404:
                raise
            raise SwiftError(
                'Container %r not found' % container,
                container=container, exc=err
            )

        error = None
        while next_page_downs:
            page_downs = next_page_downs
            next_page_downs = None

            # Start downloading the next page of list results when
            # we have completed 80% of the previous page
            next_page_triggered = False
            next_page_trigger_point = 0.8 * len(page_downs)

            page_results_yielded = 0
            for o_down in interruptable_as_completed(page_downs):
                yield o_down.result()

                # Do we need to start the next set of downloads yet?
                if not next_page_triggered:
                    page_results_yielded += 1
                    if page_results_yielded >= next_page_trigger_point:
                        try:
                            next_page_downs = self._submit_page_downloads(
                                container, _page_generator, options
                            )
                        except ClientException as err:
                            # Allow the current page to finish downloading
                            logger.exception(err)
                            error = err
                        except Exception:
                            # Something unexpected went wrong - cancel
                            # remaining downloads
                            for _d in page_downs:
                                _d.cancel()
                            raise
                        finally:
                            # Stop counting and testing
                            next_page_triggered = True

        if error:
            raise error

    # Upload related methods
    #
    def upload(self, container, objects, options=None):
        """
        Upload a list of objects to a given container.

        :param container: The container (or pseudo-folder path) to put the
                          uploads into.
        :param objects: A list of file/directory names (strings) or
                        SwiftUploadObject instances containing a source for the
                        created object, an object name, and an options dict
                        (can be None) to override the options for that
                        individual upload operation::

                            [
                                '/path/to/file',
                                SwiftUploadObject('/path', object_name='obj1'),
                                ...
                            ]

                        The options dict is as described below.

                        The SwiftUploadObject source may be one of:

                            * A file-like object (with a read method)
                            * A string containing the path to a local
                              file or directory
                            * None, to indicate that we want an empty object

        :param options: A dictionary containing options to override the global
                        options specified during the service object creation.
                        These options are applied to all upload operations
                        performed by this call, unless overridden on a per
                        object basis. Possible options are given below::

                            {
                                'meta': [],
                                'header': [],
                                'segment_size': None,
                                'use_slo': True,
                                'segment_container': None,
                                'leave_segments': False,
                                'changed': None,
                                'skip_identical': False,
                                'skip_container_put': False,
                                'fail_fast': False,
                                'dir_marker': False  # Only for None sources
                            }

        :returns: A generator for returning the results of the uploads.

        :raises SwiftError:
        :raises ClientException:
        """
        if options is not None:
            options = dict(self._options, **options)
        else:
            options = self._options

        try:
            segment_size = int(0 if options['segment_size'] is None else
                               options['segment_size'])
        except ValueError:
            raise SwiftError('Segment size should be an integer value')

        if segment_size and options['use_slo'] is None:
            try:
                cap_result = self.capabilities()
            except ClientException:
                # pre-info swift, maybe? assume no slo middleware
                options['use_slo'] = False
            else:
                if not cap_result['success']:
                    options['use_slo'] = False
                else:
                    options['use_slo'] = 'slo' in cap_result['capabilities']

        # Incase we have a psudeo-folder path for <container> arg, derive
        # the container name from the top path and prepend the rest to
        # the object name. (same as passing --object-name).
        container, _sep, pseudo_folder = container.partition('/')

        if not options['skip_container_put']:
            # Try to create the container, just in case it doesn't exist. If
            # this fails, it might just be because the user doesn't have
            # container PUT permissions, so we'll ignore any error. If there's
            # really a problem, it'll surface on the first object PUT.
            policy_header = {}
            _header = split_headers(options["header"])
            if POLICY in _header:
                policy_header[POLICY] = \
                    _header[POLICY]
            create_containers = [
                self.thread_manager.container_pool.submit(
                    self._create_container_job, container,
                    headers=policy_header)
            ]

            # wait for first container job to complete before possibly
            # attempting segment container job because segment container job
            # may attempt to HEAD the first container
            for r in interruptable_as_completed(create_containers):
                res = r.result()
                yield res

            if segment_size:
                seg_container = container + '_segments'
                if options['segment_container']:
                    seg_container = options['segment_container']
                if seg_container != container:
                    if not policy_header:
                        # Since no storage policy was specified on the command
                        # line, rather than just letting swift pick the default
                        # storage policy, we'll try to create the segments
                        # container with the same policy as the upload
                        # container
                        create_containers = [
                            self.thread_manager.container_pool.submit(
                                self._create_container_job, seg_container,
                                policy_source=container
                            )
                        ]
                    else:
                        create_containers = [
                            self.thread_manager.container_pool.submit(
                                self._create_container_job, seg_container,
                                headers=policy_header
                            )
                        ]

                    for r in interruptable_as_completed(create_containers):
                        res = r.result()
                        yield res

        # We maintain a results queue here and a separate thread to monitor
        # the futures because we want to get results back from potential
        # segment uploads too
        rq = Queue()
        file_jobs = {}

        upload_objects = self._make_upload_objects(objects, pseudo_folder)
        for upload_object in upload_objects:
            s = upload_object.source
            o = upload_object.object_name
            o_opts = upload_object.options
            details = {'action': 'upload', 'container': container}
            if o_opts is not None:
                object_options = deepcopy(options)
                object_options.update(o_opts)
            else:
                object_options = options
            if hasattr(s, 'read'):
                # We've got a file like object to upload to o
                file_future = self.thread_manager.object_uu_pool.submit(
                    self._upload_object_job, container, s, o, object_options,
                    results_queue=rq
                )
                details['file'] = s
                details['object'] = o
                file_jobs[file_future] = details
            elif s is not None:
                # We've got a path to upload to o
                details['path'] = s
                details['object'] = o
                if isdir(s):
                    dir_future = self.thread_manager.object_uu_pool.submit(
                        self._create_dir_marker_job, container, o,
                        object_options, path=s
                    )
                    file_jobs[dir_future] = details
                else:
                    try:
                        stat(s)
                        file_future = \
                            self.thread_manager.object_uu_pool.submit(
                                self._upload_object_job, container, s, o,
                                object_options, results_queue=rq
                            )
                        file_jobs[file_future] = details
                    except OSError as err:
                        # Avoid tying up threads with jobs that will fail
                        traceback, err_time = report_traceback()
                        logger.exception(err)
                        res = {
                            'action': 'upload_object',
                            'container': container,
                            'object': o,
                            'success': False,
                            'error': err,
                            'traceback': traceback,
                            'error_timestamp': err_time,
                            'path': s
                        }
                        rq.put(res)
            else:
                # Create an empty object (as a dir marker if is_dir)
                details['file'] = None
                details['object'] = o
                if object_options['dir_marker']:
                    dir_future = self.thread_manager.object_uu_pool.submit(
                        self._create_dir_marker_job, container, o,
                        object_options
                    )
                    file_jobs[dir_future] = details
                else:
                    file_future = self.thread_manager.object_uu_pool.submit(
                        self._upload_object_job, container, StringIO(),
                        o, object_options
                    )
                    file_jobs[file_future] = details

        # Start a thread to watch for upload results
        Thread(
            target=self._watch_futures, args=(file_jobs, rq)
        ).start()

        # yield results as they become available, including those from
        # segment uploads.
        res = get_from_queue(rq)
        cancelled = False
        while res is not None:
            yield res

            if not res['success']:
                if not cancelled and options['fail_fast']:
                    cancelled = True
                    for f in file_jobs:
                        f.cancel()

            res = get_from_queue(rq)

    @staticmethod
    def _make_upload_objects(objects, pseudo_folder=''):
        upload_objects = []

        for o in objects:
            if isinstance(o, str):
                obj = SwiftUploadObject(o, urljoin(pseudo_folder,
                                                   o.lstrip('/')))
                upload_objects.append(obj)
            elif isinstance(o, SwiftUploadObject):
                o.object_name = urljoin(pseudo_folder, o.object_name)
                upload_objects.append(o)
            else:
                raise SwiftError(
                    "The upload operation takes only strings or "
                    "SwiftUploadObjects as input",
                    obj=o)

        return upload_objects

    @staticmethod
    def _create_container_job(
            conn, container, headers=None, policy_source=None):
        """
        Create a container using the given connection

        :param conn: The swift connection used for requests.
        :param container: The container name to create.
        :param headers: An optional dict of headers for the
                        put_container request.
        :param policy_source: An optional name of a container whose policy we
                              should duplicate.
        :return: A dict containing the results of the operation.
        """
        res = {
            'action': 'create_container',
            'container': container,
            'headers': headers
        }
        create_response = {}
        try:
            if policy_source is not None:
                _meta = conn.head_container(policy_source)
                if 'x-storage-policy' in _meta:
                    policy_header = {
                        POLICY: _meta.get('x-storage-policy')
                    }
                    if headers is None:
                        headers = policy_header
                    else:
                        headers.update(policy_header)

            conn.put_container(
                container, headers, response_dict=create_response
            )
            res.update({
                'success': True,
                'response_dict': create_response
            })
        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            res.update({
                'success': False,
                'error': err,
                'traceback': traceback,
                'error_timestamp': err_time,
                'response_dict': create_response
            })
        return res

    @staticmethod
    def _create_dir_marker_job(conn, container, obj, options, path=None):
        res = {
            'action': 'create_dir_marker',
            'container': container,
            'object': obj,
            'path': path
        }
        results_dict = {}
        if obj.startswith('./') or obj.startswith('.\\'):
            obj = obj[2:]
        if obj.startswith('/'):
            obj = obj[1:]
        if path is not None:
            put_headers = {'x-object-meta-mtime': "%f" % getmtime(path)}
        else:
            put_headers = {'x-object-meta-mtime': "%f" % round(time())}
        res['headers'] = put_headers
        if options['changed']:
            try:
                headers = conn.head_object(container, obj)
                ct = headers.get('content-type', '').split(';', 1)[0]
                cl = int(headers.get('content-length'))
                et = headers.get('etag')
                mt = headers.get('x-object-meta-mtime')

                if (ct in KNOWN_DIR_MARKERS and
                        cl == 0 and
                        et == EMPTY_ETAG and
                        mt == put_headers['x-object-meta-mtime']):
                    res['success'] = True
                    return res
            except ClientException as err:
                if err.http_status != 404:
                    traceback, err_time = report_traceback()
                    logger.exception(err)
                    res.update({
                        'success': False,
                        'error': err,
                        'traceback': traceback,
                        'error_timestamp': err_time
                    })
                    return res
        try:
            conn.put_object(container, obj, '', content_length=0,
                            content_type=KNOWN_DIR_MARKERS[0],
                            headers=put_headers,
                            response_dict=results_dict)
            res.update({
                'success': True,
                'response_dict': results_dict})
            return res
        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            res.update({
                'success': False,
                'error': err,
                'traceback': traceback,
                'error_timestamp': err_time,
                'response_dict': results_dict})
            return res

    @staticmethod
    def _upload_segment_job(conn, path, container, segment_name, segment_start,
                            segment_size, segment_index, obj_name, options,
                            results_queue=None):
        results_dict = {}
        if options['segment_container']:
            segment_container = options['segment_container']
        else:
            segment_container = container + '_segments'

        res = {
            'action': 'upload_segment',
            'for_container': container,
            'for_object': obj_name,
            'segment_index': segment_index,
            'segment_size': segment_size,
            'segment_location': '/%s/%s' % (segment_container,
                                            segment_name),
            'log_line': '%s segment %s' % (obj_name, segment_index),
        }
        fp = None
        try:
            fp = open(path, 'rb', DISK_BUFFER)
            fp.seek(segment_start)

            contents = LengthWrapper(fp, segment_size, md5=options['checksum'])
            etag = conn.put_object(
                segment_container,
                segment_name,
                contents,
                content_length=segment_size,
                content_type='application/swiftclient-segment',
                response_dict=results_dict)

            if options['checksum'] and etag and etag != contents.get_md5sum():
                raise SwiftError('Segment {0}: upload verification failed: '
                                 'md5 mismatch, local {1} != remote {2} '
                                 '(remote segment has not been removed)'
                                 .format(segment_index,
                                         contents.get_md5sum(),
                                         etag))

            res.update({
                'success': True,
                'response_dict': results_dict,
                'segment_etag': etag,
                'attempts': conn.attempts
            })

            if results_queue is not None:
                results_queue.put(res)
            return res

        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            res.update({
                'success': False,
                'error': err,
                'traceback': traceback,
                'error_timestamp': err_time,
                'response_dict': results_dict,
                'attempts': conn.attempts
            })

            if results_queue is not None:
                results_queue.put(res)
            return res
        finally:
            if fp is not None:
                fp.close()

    @staticmethod
    def _put_object(conn, container, name, content, headers=None, md5=None):
        """
        Upload object into a given container and verify the resulting ETag, if
        the md5 optional parameter is passed.

        :param conn: The Swift connection to use for uploads.
        :param container: The container to put the object into.
        :param name: The name of the object.
        :param content: Object content.
        :param headers: Headers (optional) to associate with the object.
        :param md5: MD5 sum of the content. If passed in, will be used to
                    verify the returned ETag.

        :returns: A dictionary as the response from calling put_object.
                  The keys are:
                    - status
                    - reason
                    - headers
                  On error, the dictionary contains the following keys:
                    - success (with value False)
                    - error - the encountered exception (object)
                    - error_timestamp
                    - response_dict - results from the put_object call, as
                      documented above
                    - attempts - number of attempts made
        """
        if headers is None:
            headers = {}
        else:
            headers = dict(headers)
        if md5 is not None:
            headers['etag'] = md5
        results = {}
        try:
            etag = conn.put_object(
                container, name, content, content_length=len(content),
                headers=headers, response_dict=results)
            if md5 is not None and etag != md5:
                raise SwiftError('Upload verification failed for {0}: md5 '
                                 'mismatch {1} != {2}'.format(name, md5, etag))
            results['success'] = True
        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            return {
                'success': False,
                'error': err,
                'error_timestamp': err_time,
                'response_dict': results,
                'attempts': conn.attempts,
                'traceback': traceback
            }
        return results

    @staticmethod
    def _upload_stream_segment(conn, container, object_name,
                               segment_container, segment_name,
                               segment_size, segment_index,
                               headers, fd):
        """
        Upload a segment from a stream, buffering it in memory first. The
        resulting object is placed either as a segment in the segment
        container, or if it is smaller than a single segment, as the given
        object name.

        :param conn: Swift Connection to use.
        :param container: Container in which the object would be placed.
        :param object_name: Name of the final object (used in case the stream
                            is smaller than the segment_size)
        :param segment_container: Container to hold the object segments.
        :param segment_name: The name of the segment.
        :param segment_size: Minimum segment size.
        :param segment_index: The segment index.
        :param headers: Headers to attach to the segment/object.
        :param fd: File-like handle for the content. Must implement read().

        :returns: Dictionary, containing the following keys:
                    - complete -- whether the stream is exhausted
                    - segment_size - the actual size of the segment (may be
                                     smaller than the passed in segment_size)
                    - segment_location - path to the segment
                    - segment_index - index of the segment
                    - segment_etag - the ETag for the segment
        """
        buf = []
        dgst = md5()
        bytes_read = 0
        while bytes_read < segment_size:
            data = fd.read(segment_size - bytes_read)
            if not data:
                break
            bytes_read += len(data)
            dgst.update(data)
            buf.append(data)
        buf = b''.join(buf)
        segment_hash = dgst.hexdigest()

        if not buf and segment_index > 0:
            # Happens if the segment size aligns with the object size
            return {'complete': True,
                    'segment_size': 0,
                    'segment_index': None,
                    'segment_etag': None,
                    'segment_location': None,
                    'success': True}

        if segment_index == 0 and len(buf) < segment_size:
            ret = SwiftService._put_object(
                conn, container, object_name, buf, headers, segment_hash)
            ret['segment_location'] = '/%s/%s' % (container, object_name)
        else:
            ret = SwiftService._put_object(
                conn, segment_container, segment_name, buf, headers,
                segment_hash)
            ret['segment_location'] = '/%s/%s' % (
                segment_container, segment_name)

        ret.update(
            dict(complete=len(buf) < segment_size,
                 segment_size=len(buf),
                 segment_index=segment_index,
                 segment_etag=segment_hash,
                 for_object=object_name))
        return ret

    def _get_chunk_data(self, conn, container, obj, headers, manifest=None):
        chunks = []
        if 'x-object-manifest' in headers:
            scontainer, sprefix = headers['x-object-manifest'].split('/', 1)
            for part in self.list(scontainer, {'prefix': sprefix}):
                if part["success"]:
                    chunks.extend(part["listing"])
                else:
                    raise part["error"]
        elif config_true_value(headers.get('x-static-large-object')):
            if manifest is None:
                headers, manifest = conn.get_object(
                    container, obj, query_string='multipart-manifest=get')
            manifest = parse_api_response(headers, manifest)
            for chunk in manifest:
                if chunk.get('sub_slo'):
                    scont, sobj = chunk['name'].lstrip('/').split('/', 1)
                    chunks.extend(self._get_chunk_data(
                        conn, scont, sobj, {'x-static-large-object': True}))
                else:
                    chunks.append(chunk)
        else:
            chunks.append({'hash': headers.get('etag').strip('"'),
                           'bytes': int(headers.get('content-length'))})
        return chunks

    def _is_identical(self, chunk_data, path):
        if path is None:
            return False
        try:
            fp = open(path, 'rb', DISK_BUFFER)
        except IOError:
            return False

        with fp:
            for chunk in chunk_data:
                to_read = chunk['bytes']
                md5sum = md5()
                while to_read:
                    data = fp.read(min(DISK_BUFFER, to_read))
                    if not data:
                        return False
                    md5sum.update(data)
                    to_read -= len(data)
                if md5sum.hexdigest() != chunk['hash']:
                    return False
            # Each chunk is verified; check that we're at the end of the file
            return not fp.read(1)

    @staticmethod
    def _upload_slo_manifest(conn, segment_results, container, obj, headers):
        """
        Upload an SLO manifest, given the results of uploading each segment, to
        the specified container.

        :param segment_results: List of response_dict structures, as populated
                                by _upload_segment_job. Specifically, each
                                entry must container the following keys:
                                - segment_location
                                - segment_etag
                                - segment_size
                                - segment_index
        :param container: The container to put the manifest into.
        :param obj: The name of the manifest object to use.
        :param headers: Optional set of headers to attach to the manifest.
        """
        if headers is None:
            headers = {}
        segment_results.sort(key=lambda di: di['segment_index'])
        manifest_data = json.dumps([
            {
                'path': d['segment_location'],
                'etag': d['segment_etag'],
                'size_bytes': d['segment_size']
            } for d in segment_results
        ])

        response = {}
        conn.put_object(
            container, obj, manifest_data,
            headers=headers,
            query_string='multipart-manifest=put',
            response_dict=response)
        return response

    def _upload_object_job(self, conn, container, source, obj, options,
                           results_queue=None):
        if obj.startswith('./') or obj.startswith('.\\'):
            obj = obj[2:]
        if obj.startswith('/'):
            obj = obj[1:]
        res = {
            'action': 'upload_object',
            'container': container,
            'object': obj
        }
        if hasattr(source, 'read'):
            stream = source
            path = None
        else:
            path = source
        res['path'] = path
        try:
            if path is not None:
                put_headers = {'x-object-meta-mtime': "%f" % getmtime(path)}
            else:
                put_headers = {'x-object-meta-mtime': "%f" % round(time())}

            res['headers'] = put_headers

            # We need to HEAD all objects now in case we're overwriting a
            # manifest object and need to delete the old segments
            # ourselves.
            old_manifest = None
            old_slo_manifest_paths = []
            new_slo_manifest_paths = set()
            segment_size = int(0 if options['segment_size'] is None
                               else options['segment_size'])
            if (options['changed'] or options['skip_identical'] or
                    not options['leave_segments']):
                try:
                    headers = conn.head_object(container, obj)
                    is_slo = config_true_value(
                        headers.get('x-static-large-object'))

                    if options['skip_identical'] or (
                            is_slo and not options['leave_segments']):
                        chunk_data = self._get_chunk_data(
                            conn, container, obj, headers)

                    if options['skip_identical'] and self._is_identical(
                            chunk_data, path):
                        res.update({
                            'success': True,
                            'status': 'skipped-identical'
                        })
                        return res

                    cl = int(headers.get('content-length'))
                    mt = headers.get('x-object-meta-mtime')
                    if (path is not None and options['changed'] and
                            cl == getsize(path) and
                            mt == put_headers['x-object-meta-mtime']):
                        res.update({
                            'success': True,
                            'status': 'skipped-changed'
                        })
                        return res
                    if not options['leave_segments'] and not headers.get(
                            'content-location'):
                        old_manifest = headers.get('x-object-manifest')
                        if is_slo:
                            old_slo_manifest_paths.extend(
                                normalize_manifest_path(old_seg['name'])
                                for old_seg in chunk_data)
                except ClientException as err:
                    if err.http_status != 404:
                        traceback, err_time = report_traceback()
                        logger.exception(err)
                        res.update({
                            'success': False,
                            'error': err,
                            'traceback': traceback,
                            'error_timestamp': err_time
                        })
                        return res

            # Merge the command line header options to the put_headers
            put_headers.update(split_headers(
                options['meta'], 'X-Object-Meta-'))
            put_headers.update(split_headers(options['header'], ''))

            # Don't do segment job if object is not big enough, and never do
            # a segment job if we're reading from a stream - we may fail if we
            # go over the single object limit, but this gives us a nice way
            # to create objects from memory
            if (path is not None and segment_size and
                    (getsize(path) > segment_size)):
                res['large_object'] = True
                seg_container = container + '_segments'
                if options['segment_container']:
                    seg_container = options['segment_container']
                full_size = getsize(path)

                segment_futures = []
                segment_pool = self.thread_manager.segment_pool
                segment = 0
                segment_start = 0

                while segment_start < full_size:
                    if segment_start + segment_size > full_size:
                        segment_size = full_size - segment_start
                    if options['use_slo']:
                        segment_name = '%s/slo/%s/%s/%s/%08d' % (
                            obj, put_headers['x-object-meta-mtime'],
                            full_size, options['segment_size'], segment
                        )
                    else:
                        segment_name = '%s/%s/%s/%s/%08d' % (
                            obj, put_headers['x-object-meta-mtime'],
                            full_size, options['segment_size'], segment
                        )
                    seg = segment_pool.submit(
                        self._upload_segment_job, path, container,
                        segment_name, segment_start, segment_size, segment,
                        obj, options, results_queue=results_queue
                    )
                    segment_futures.append(seg)
                    segment += 1
                    segment_start += segment_size

                segment_results = []
                errors = False
                exceptions = []
                for f in interruptable_as_completed(segment_futures):
                    try:
                        r = f.result()
                        if not r['success']:
                            errors = True
                        segment_results.append(r)
                    except Exception as err:
                        traceback, err_time = report_traceback()
                        logger.exception(err)
                        errors = True
                        exceptions.append((err, traceback, err_time))
                if errors:
                    err = ClientException(
                        'Aborting manifest creation '
                        'because not all segments could be uploaded. %s/%s'
                        % (container, obj))
                    res.update({
                        'success': False,
                        'error': err,
                        'exceptions': exceptions,
                        'segment_results': segment_results
                    })
                    return res

                res['segment_results'] = segment_results

                if options['use_slo']:
                    response = self._upload_slo_manifest(
                        conn, segment_results, container, obj, put_headers)
                    res['manifest_response_dict'] = response
                    new_slo_manifest_paths.update(
                        normalize_manifest_path(new_seg['segment_location'])
                        for new_seg in segment_results)
                else:
                    new_object_manifest = '%s/%s/%s/%s/%s/' % (
                        quote(seg_container.encode('utf8')),
                        quote(obj.encode('utf8')),
                        put_headers['x-object-meta-mtime'], full_size,
                        options['segment_size'])
                    if old_manifest and old_manifest.rstrip('/') == \
                            new_object_manifest.rstrip('/'):
                        old_manifest = None
                    put_headers['x-object-manifest'] = new_object_manifest
                    mr = {}
                    conn.put_object(
                        container, obj, '', content_length=0,
                        headers=put_headers,
                        response_dict=mr
                    )
                    res['manifest_response_dict'] = mr
            elif options['use_slo'] and segment_size and not path:
                segment = 0
                results = []
                while True:
                    segment_name = '%s/slo/%s/%s/%08d' % (
                        obj, put_headers['x-object-meta-mtime'],
                        segment_size, segment
                    )
                    seg_container = container + '_segments'
                    if options['segment_container']:
                        seg_container = options['segment_container']
                    ret = self._upload_stream_segment(
                        conn, container, obj,
                        seg_container,
                        segment_name,
                        segment_size,
                        segment,
                        put_headers,
                        stream
                    )
                    if not ret['success']:
                        return ret
                    if (ret['complete'] and segment == 0) or\
                            ret['segment_size'] > 0:
                        results.append(ret)
                    if results_queue is not None:
                        # Don't insert the 0-sized segments or objects
                        # themselves
                        if ret['segment_location'] != '/%s/%s' % (
                                container, obj) and ret['segment_size'] > 0:
                            results_queue.put(ret)
                    if ret['complete']:
                        break
                    segment += 1
                if results[0]['segment_location'] != '/%s/%s' % (
                        container, obj):
                    response = self._upload_slo_manifest(
                        conn, results, container, obj, put_headers)
                    res['manifest_response_dict'] = response
                    new_slo_manifest_paths.update(
                        normalize_manifest_path(new_seg['segment_location'])
                        for new_seg in results)
                    res['large_object'] = True
                else:
                    res['response_dict'] = ret
                    res['large_object'] = False
            else:
                res['large_object'] = False
                obr = {}
                fp = None
                try:
                    if path is not None:
                        content_length = getsize(path)
                        fp = open(path, 'rb', DISK_BUFFER)
                        contents = LengthWrapper(fp,
                                                 content_length,
                                                 md5=options['checksum'])
                    else:
                        content_length = None
                        contents = ReadableToIterable(stream,
                                                      md5=options['checksum'])

                    etag = conn.put_object(
                        container, obj, contents,
                        content_length=content_length, headers=put_headers,
                        response_dict=obr
                    )
                    res['response_dict'] = obr

                    if (options['checksum'] and
                            etag and etag != contents.get_md5sum()):
                        raise SwiftError(
                            'Object upload verification failed: '
                            'md5 mismatch, local {0} != remote {1} '
                            '(remote object has not been removed)'
                            .format(contents.get_md5sum(), etag))
                finally:
                    if fp is not None:
                        fp.close()
            if old_manifest or old_slo_manifest_paths:
                drs = []
                delobjsmap = defaultdict(list)
                if old_manifest:
                    scontainer, sprefix = old_manifest.split('/', 1)
                    sprefix = sprefix.rstrip('/') + '/'
                    for part in self.list(scontainer, {'prefix': sprefix}):
                        if not part["success"]:
                            raise part["error"]
                        delobjsmap[scontainer].extend(
                            seg['name'] for seg in part['listing'])

                if old_slo_manifest_paths:
                    for seg_to_delete in old_slo_manifest_paths:
                        if seg_to_delete in new_slo_manifest_paths:
                            continue
                        scont, sobj = \
                            seg_to_delete.split('/', 1)
                        delobjsmap[scont].append(sobj)

                del_segs = []
                for dscont, dsobjs in delobjsmap.items():
                    for dsobj in dsobjs:
                        del_seg = self.thread_manager.segment_pool.submit(
                            self._delete_segment, dscont, dsobj,
                            results_queue=results_queue
                        )
                        del_segs.append(del_seg)

                for del_seg in interruptable_as_completed(del_segs):
                    drs.append(del_seg.result())
                res['segment_delete_results'] = drs

            # return dict for printing
            res.update({
                'success': True,
                'status': 'uploaded',
                'attempts': conn.attempts})
            return res

        except OSError as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            if err.errno == ENOENT:
                error = SwiftError('Local file %r not found' % path, exc=err)
            else:
                error = err
            res.update({
                'success': False,
                'error': error,
                'traceback': traceback,
                'error_timestamp': err_time
            })
        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            res.update({
                'success': False,
                'error': err,
                'traceback': traceback,
                'error_timestamp': err_time
            })
        return res

    # Delete related methods
    #
    def delete(self, container=None, objects=None, options=None):
        """
        Delete operations on an account, optional container and optional list
        of objects.

        :param container: The container to delete or delete from.
        :param objects: A list of object names (strings) or SwiftDeleteObject
                        instances containing an object name, and an
                        options dict (can be None) to override the options for
                        that individual delete operation::

                            [
                                'object_name',
                                SwiftDeleteObject('object_name',
                                                  options={...}),
                                ...
                            ]

                        The options dict is described below.
        :param options: A dictionary containing options to override the global
                        options specified during the service object creation::

                            {
                                'yes_all': False,
                                'leave_segments': False,
                                'version_id': None,
                                'prefix': None,
                                'versions': False,
                                'header': [],
                            }

        :returns: A generator for returning the results of the delete
                  operations. Each result yielded from the generator is either
                  a 'delete_container', 'delete_object', 'delete_segment', or
                  'bulk_delete' dictionary containing the results of an
                  individual delete operation.

        :raises ClientException:
        :raises SwiftError:
        """
        if options is not None:
            options = dict(self._options, **options)
        else:
            options = self._options

        if container is not None:
            if objects is not None:
                delete_objects = self._make_delete_objects(objects)
                if options['prefix']:
                    delete_objects = [
                        obj for obj in delete_objects
                        if obj.object_name.startswith(options['prefix'])]
                rq = Queue()
                obj_dels = {}

                bulk_page_size = self._bulk_delete_page_size(delete_objects)
                if bulk_page_size > 1:
                    page_at_a_time = n_at_a_time(delete_objects,
                                                 bulk_page_size)
                    for page_slice in page_at_a_time:
                        for obj_slice in n_groups(
                                page_slice,
                                self._options['object_dd_threads']):
                            object_names = [
                                obj.object_name for obj in obj_slice]
                            self._bulk_delete(container, object_names, options,
                                              obj_dels)
                else:
                    self._per_item_delete(container, delete_objects, options,
                                          obj_dels, rq)

                # Start a thread to watch for delete results
                Thread(
                    target=self._watch_futures, args=(obj_dels, rq)
                ).start()

                # yield results as they become available, raising the first
                # encountered exception
                res = get_from_queue(rq)
                while res is not None:
                    yield res

                    # Cancel the remaining jobs if necessary
                    if options['fail_fast'] and not res['success']:
                        for d in obj_dels.keys():
                            d.cancel()

                    res = get_from_queue(rq)
            else:
                for res in self._delete_container(container, options):
                    yield res
        else:
            if objects:
                raise SwiftError('Objects specified without container')
            if options['prefix']:
                raise SwiftError('Prefix specified without container')
            if options['yes_all']:
                cancelled = False
                containers = []
                for part in self.list():
                    if part["success"]:
                        containers.extend(c['name'] for c in part['listing'])
                    else:
                        raise part["error"]

                for con in containers:
                    if cancelled:
                        break
                    else:
                        for res in self._delete_container(
                                con, options=options):
                            yield res

                            # Cancel the remaining container deletes, but yield
                            # any pending results
                            if (not cancelled and options['fail_fast'] and
                                    not res['success']):
                                cancelled = True

    def _bulk_delete_page_size(self, objects):
        '''
        Given the iterable 'objects', will return how many items should be
        deleted at a time.

        :param objects: An iterable that supports 'len()'
        :returns: The bulk delete page size (i.e. the max number of
                  objects that can be bulk deleted at once, as reported by
                  the cluster). If bulk delete is disabled, return 1
        '''
        if len(objects) <= 2 * self._options['object_dd_threads']:
            # Not many objects; may as well delete one-by-one
            return 1

        if any(obj.options for obj in objects
               if isinstance(obj, SwiftDeleteObject)):
            # we can't do per option deletes for bulk
            return 1

        try:
            cap_result = self.capabilities()
            if not cap_result['success']:
                # This shouldn't actually happen, but just in case we start
                # being more nuanced about our capabilities result...
                return 1
        except ClientException:
            # Old swift, presumably; assume no bulk middleware
            return 1

        swift_info = cap_result['capabilities']
        if 'bulk_delete' in swift_info:
            return swift_info['bulk_delete'].get(
                'max_deletes_per_request', 10000)
        else:
            return 1

    def _per_item_delete(self, container, objects, options, rdict, rq):
        for delete_obj in objects:
            obj = delete_obj.object_name
            obj_options = dict(options, **delete_obj.options or {})
            obj_del = self.thread_manager.object_dd_pool.submit(
                self._delete_object, container, obj, obj_options,
                results_queue=rq
            )
            obj_details = {'container': container, 'object': obj}
            rdict[obj_del] = obj_details

    @staticmethod
    def _delete_segment(conn, container, obj, results_queue=None):
        results_dict = {}
        try:
            res = {'success': True}
            conn.delete_object(container, obj, response_dict=results_dict)
        except Exception as err:
            if not isinstance(err, ClientException) or err.http_status != 404:
                traceback, err_time = report_traceback()
                logger.exception(err)
                res = {
                    'success': False,
                    'error': err,
                    'traceback': traceback,
                    'error_timestamp': err_time
                }

        res.update({
            'action': 'delete_segment',
            'container': container,
            'object': obj,
            'attempts': conn.attempts,
            'response_dict': results_dict
        })

        if results_queue is not None:
            results_queue.put(res)
        return res

    @staticmethod
    def _make_delete_objects(objects):
        delete_objects = []

        for o in objects:
            if isinstance(o, str):
                obj = SwiftDeleteObject(o)
                delete_objects.append(obj)
            elif isinstance(o, SwiftDeleteObject):
                delete_objects.append(o)
            else:
                raise SwiftError(
                    "The delete operation takes only strings or "
                    "SwiftDeleteObjects as input",
                    obj=o)

        return delete_objects

    def _delete_object(self, conn, container, obj, options,
                       results_queue=None):
        _headers = {}
        _headers = split_headers(options.get('header', []))
        res = {
            'action': 'delete_object',
            'container': container,
            'object': obj
        }
        try:
            old_manifest = None
            query_params = {}

            if not options['leave_segments']:
                try:
                    headers = conn.head_object(container, obj,
                                               headers=_headers,
                                               query_string='symlink=get')
                    old_manifest = headers.get('x-object-manifest')
                    if config_true_value(headers.get('x-static-large-object')):
                        query_params['multipart-manifest'] = 'delete'
                except ClientException as err:
                    if err.http_status != 404:
                        raise

            if options.get('version_id') is not None:
                query_params['version-id'] = options['version_id']
            query_string = '&'.join('%s=%s' % (k, v) for (k, v)
                                    in sorted(query_params.items()))
            results_dict = {}
            conn.delete_object(container, obj,
                               headers=_headers,
                               query_string=query_string,
                               response_dict=results_dict)

            if old_manifest:

                dlo_segments_deleted = True
                segment_pool = self.thread_manager.segment_pool
                s_container, s_prefix = old_manifest.split('/', 1)
                s_prefix = s_prefix.rstrip('/') + '/'

                del_segs = []
                for part in self.list(
                        container=s_container, options={'prefix': s_prefix}):
                    if part["success"]:
                        seg_list = [o["name"] for o in part["listing"]]
                    else:
                        raise part["error"]

                    for seg in seg_list:
                        del_seg = segment_pool.submit(
                            self._delete_segment, s_container,
                            seg, results_queue=results_queue
                        )
                        del_segs.append(del_seg)

                for del_seg in interruptable_as_completed(del_segs):
                    del_res = del_seg.result()
                    if not del_res["success"]:
                        dlo_segments_deleted = False

                res['dlo_segments_deleted'] = dlo_segments_deleted

            res.update({
                'success': True,
                'response_dict': results_dict,
                'attempts': conn.attempts,
            })

        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            res.update({
                'success': False,
                'error': err,
                'traceback': traceback,
                'error_timestamp': err_time
            })
            return res

        return res

    @staticmethod
    def _delete_empty_container(conn, container, options):
        results_dict = {}
        _headers = {}
        _headers = split_headers(options.get('header', []))
        try:
            conn.delete_container(container, headers=_headers,
                                  response_dict=results_dict)
            res = {'success': True}
        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            res = {
                'success': False,
                'error': err,
                'traceback': traceback,
                'error_timestamp': err_time
            }

        res.update({
            'action': 'delete_container',
            'container': container,
            'object': None,
            'attempts': conn.attempts,
            'response_dict': results_dict
        })
        return res

    def _delete_container(self, container, options):
        try:
            for part in self.list(container=container, options=options):
                if not part["success"]:
                    raise part["error"]
                delete_objects = []
                for item in part['listing']:
                    delete_opts = {}
                    if options.get('versions', False) and 'version_id' in item:
                        delete_opts['version_id'] = item['version_id']
                    delete_obj = SwiftDeleteObject(item['name'], delete_opts)
                    delete_objects.append(delete_obj)
                for res in self.delete(
                        container=container,
                        objects=delete_objects,
                        options=options):
                    yield res
            if options['prefix']:
                # We're only deleting a subset of objects within the container
                return

            con_del = self.thread_manager.container_pool.submit(
                self._delete_empty_container, container, options
            )
            con_del_res = get_future_result(con_del)

        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            con_del_res = {
                'action': 'delete_container',
                'container': container,
                'object': None,
                'success': False,
                'error': err,
                'traceback': traceback,
                'error_timestamp': err_time
            }

        yield con_del_res

    # Bulk methods
    #
    def _bulk_delete(self, container, objects, options, rdict):
        if objects:
            bulk_del = self.thread_manager.object_dd_pool.submit(
                self._bulkdelete, container, objects, options
            )
            bulk_details = {'container': container, 'objects': objects}
            rdict[bulk_del] = bulk_details

    @staticmethod
    def _bulkdelete(conn, container, objects, options):
        results_dict = {}
        try:
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'text/plain',
            }
            res = {'container': container, 'objects': objects}
            objects = [quote(('/%s/%s' % (container, obj)).encode('utf-8'))
                       for obj in objects]
            headers, body = conn.post_account(
                headers=headers,
                query_string='bulk-delete',
                data=b''.join(obj.encode('utf-8') + b'\n' for obj in objects),
                response_dict=results_dict)
            if body:
                res.update({'success': True,
                            'result': parse_api_response(headers, body)})
            else:
                res.update({
                    'success': False,
                    'error': SwiftError(
                        'No content received on account POST. '
                        'Is the bulk operations middleware enabled?')})
        except Exception as e:
            traceback, err_time = report_traceback()
            logger.exception(e)
            res.update({'success': False, 'error': e, 'traceback': traceback})

        res.update({
            'action': 'bulk_delete',
            'attempts': conn.attempts,
            'response_dict': results_dict
        })

        return res

    # Copy related methods
    #
    def copy(self, container, objects, options=None):
        """
        Copy operations on a list of objects in a container. Destination
        containers will be created.

        :param container: The container from which to copy the objects.
        :param objects: A list of object names (strings) or SwiftCopyObject
                        instances containing an object name and an
                        options dict (can be None) to override the options for
                        that individual copy operation::

                            [
                                'object_name',
                                SwiftCopyObject(
                                    'object_name',
                                     options={
                                        'destination': '/container/object',
                                        'fresh_metadata': False,
                                        ...
                                        }),
                                ...
                            ]

                        The options dict is described below.
        :param options: A dictionary containing options to override the global
                        options specified during the service object creation.
                        These options are applied to all copy operations
                        performed by this call, unless overridden on a per
                        object basis.
                        The options "destination" and "fresh_metadata" do
                        not need to be set, in this case objects will be
                        copied onto themselves and metadata will not be
                        refreshed.
                        The option "destination" can also be specified in the
                        format '/container', in which case objects without an
                        explicit destination will be copied to the destination
                        /container/original_object_name. Combinations of
                        multiple objects and a destination in the format
                        '/container/object' is invalid. Possible options are
                        given below::

                            {
                                'meta': [],
                                'header': [],
                                'destination': '/container/object',
                                'fresh_metadata': False,
                            }

        :returns: A generator returning the results of copying the given list
                  of objects.

        :raises SwiftError:
        """
        if options is not None:
            options = dict(self._options, **options)
        else:
            options = self._options

        # Try to create the container, just in case it doesn't exist. If this
        # fails, it might just be because the user doesn't have container PUT
        # permissions, so we'll ignore any error. If there's really a problem,
        # it'll surface on the first object COPY.
        containers = set(
            next(p for p in obj.destination.split("/") if p)
            for obj in objects
            if isinstance(obj, SwiftCopyObject) and obj.destination
        )
        if options.get('destination'):
            destination_split = options['destination'].split('/')
            if destination_split[0]:
                raise SwiftError("destination must be in format /cont[/obj]")
            _str_objs = [
                o for o in objects if not isinstance(o, SwiftCopyObject)
            ]
            if len(destination_split) > 2 and len(_str_objs) > 1:
                # TODO (clayg): could be useful to copy multiple objects into
                # a destination like "/container/common/prefix/for/objects/"
                # where the trailing "/" indicates the destination option is a
                # prefix!
                raise SwiftError("Combination of multiple objects and "
                                 "destination including object is invalid")
            if destination_split[-1] == '':
                # N.B. this protects the above case
                raise SwiftError("destination can not end in a slash")
            containers.add(destination_split[1])

        policy_header = {}
        _header = split_headers(options["header"])
        if POLICY in _header:
            policy_header[POLICY] = _header[POLICY]
        create_containers = [
            self.thread_manager.container_pool.submit(
                self._create_container_job, cont, headers=policy_header)
            for cont in containers
        ]

        # wait for container creation jobs to complete before any COPY
        for r in interruptable_as_completed(create_containers):
            res = r.result()
            yield res

        copy_futures = []
        copy_objects = self._make_copy_objects(objects, options)
        for copy_object in copy_objects:
            obj = copy_object.object_name
            obj_options = copy_object.options
            destination = copy_object.destination
            fresh_metadata = copy_object.fresh_metadata
            headers = split_headers(
                options['meta'], 'X-Object-Meta-')
            # add header options to the headers object for the request.
            headers.update(
                split_headers(options['header'], ''))
            if obj_options is not None:
                if 'meta' in obj_options:
                    headers.update(
                        split_headers(
                            obj_options['meta'], 'X-Object-Meta-'
                        )
                    )
                if 'header' in obj_options:
                    headers.update(
                        split_headers(obj_options['header'], '')
                    )

            copy = self.thread_manager.object_uu_pool.submit(
                self._copy_object_job, container, obj, destination,
                headers, fresh_metadata
            )
            copy_futures.append(copy)

        for r in interruptable_as_completed(copy_futures):
            res = r.result()
            yield res

    @staticmethod
    def _make_copy_objects(objects, options):
        copy_objects = []

        for o in objects:
            if isinstance(o, str):
                obj = SwiftCopyObject(o, options)
                copy_objects.append(obj)
            elif isinstance(o, SwiftCopyObject):
                copy_objects.append(o)
            else:
                raise SwiftError(
                    "The copy operation takes only strings or "
                    "SwiftCopyObjects as input",
                    obj=o)

        return copy_objects

    @staticmethod
    def _copy_object_job(conn, container, obj, destination, headers,
                         fresh_metadata):
        response_dict = {}
        res = {
            'success': True,
            'action': 'copy_object',
            'container': container,
            'object': obj,
            'destination': destination,
            'headers': headers,
            'fresh_metadata': fresh_metadata,
            'response_dict': response_dict
        }
        try:
            conn.copy_object(
                container, obj, destination=destination, headers=headers,
                fresh_metadata=fresh_metadata, response_dict=response_dict)
        except Exception as err:
            traceback, err_time = report_traceback()
            logger.exception(err)
            res.update({
                'success': False,
                'error': err,
                'traceback': traceback,
                'error_timestamp': err_time
            })

        return res

    # Capabilities related methods
    #
    def capabilities(self, url=None, refresh_cache=False):
        """
        List the cluster capabilities.

        :param url: Proxy URL of the cluster to retrieve capabilities.

        :returns: A dictionary containing the capabilities of the cluster.

        :raises ClientException:
        """
        if not refresh_cache and url in self.capabilities_cache:
            return self.capabilities_cache[url]

        res = {
            'action': 'capabilities',
            'timestamp': time(),
        }

        cap = self.thread_manager.container_pool.submit(
            self._get_capabilities, url
        )
        capabilities = get_future_result(cap)
        res.update({
            'success': True,
            'capabilities': capabilities
        })
        if url is not None:
            res.update({
                'url': url
            })

        self.capabilities_cache[url] = res
        return res

    @staticmethod
    def _get_capabilities(conn, url):
        return conn.get_capabilities(url)

    # Helper methods
    #
    @staticmethod
    def _watch_futures(futures, result_queue):
        """
        Watches a dict of futures and pushes their results onto the given
        queue. We use this to wait for a set of futures which may create
        futures of their own to wait for, whilst also allowing us to
        immediately return the results of those sub-jobs.

        When all futures have completed, None is pushed to the queue

        If the future is cancelled, we use the dict to return details about
        the cancellation.
        """
        futures_only = list(futures.keys())
        for f in interruptable_as_completed(futures_only):
            try:
                r = f.result()
                if r is not None:
                    result_queue.put(r)
            except CancelledError:
                details = futures[f]
                res = details
                res['status'] = 'cancelled'
                result_queue.put(res)
            except Exception as err:
                traceback, err_time = report_traceback()
                logger.exception(err)
                details = futures[f]
                res = details
                res.update({
                    'success': False,
                    'error': err,
                    'traceback': traceback,
                    'error_timestamp': err_time
                })
                result_queue.put(res)

        result_queue.put(None)
