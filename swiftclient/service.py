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
from concurrent.futures import as_completed, CancelledError, TimeoutError
from copy import deepcopy
from errno import EEXIST, ENOENT
from hashlib import md5
from os import environ, makedirs, stat, utime
from os.path import (
    basename, dirname, getmtime, getsize, isdir, join, sep as os_path_sep
)
from random import shuffle
from time import time
from threading import Thread
from six import StringIO, text_type
from six.moves.queue import Queue
from six.moves.queue import Empty as QueueEmpty
from six.moves.urllib.parse import quote, unquote
from six import Iterator, string_types

try:
    import simplejson as json
except ImportError:
    import json


from swiftclient import Connection
from swiftclient.command_helpers import (
    stat_account, stat_container, stat_object
)
from swiftclient.utils import (
    config_true_value, ReadableToIterable, LengthWrapper, EMPTY_ETAG
)
from swiftclient.exceptions import ClientException
from swiftclient.multithreading import MultiThreadingManager


class ResultsIterator(Iterator):
    def __init__(self, futures):
        self.futures = interruptable_as_completed(futures)

    def __iter__(self):
        return self

    def __next__(self):
        next_completed_future = next(self.futures)
        return next_completed_future.result()


class SwiftError(Exception):
    def __init__(self, value, container=None, obj=None,
                 segment=None, exc=None):
        self.value = value
        self.container = container
        self.obj = obj
        self.segment = segment
        self.exception = exc

    def __str__(self):
        value = repr(self.value)
        if self.container is not None:
            value += " container:%s" % self.container
        if self.obj is not None:
            value += " object:%s" % self.obj
        if self.segment is not None:
            value += " segment:%s" % self.segment
        return value


def process_options(options):
    if (not (options.get('auth') and options.get('user')
             and options.get('key'))
            and options.get('auth_version') != '3'):
        # Use keystone 2.0 auth if any of the old-style args are missing
        options['auth_version'] = '2.0'

    # Use new-style args if old ones not present
    if not options['auth'] and options['os_auth_url']:
        options['auth'] = options['os_auth_url']
    if not options['user']and options['os_username']:
        options['user'] = options['os_username']
    if not options['key'] and options['os_password']:
        options['key'] = options['os_password']

    # Specific OpenStack options
    options['os_options'] = {
        'user_id': options['os_user_id'],
        'user_domain_id': options['os_user_domain_id'],
        'user_domain_name': options['os_user_domain_name'],
        'tenant_id': options['os_tenant_id'],
        'tenant_name': options['os_tenant_name'],
        'project_id': options['os_project_id'],
        'project_name': options['os_project_name'],
        'project_domain_id': options['os_project_domain_id'],
        'project_domain_name': options['os_project_domain_name'],
        'service_type': options['os_service_type'],
        'endpoint_type': options['os_endpoint_type'],
        'auth_token': options['os_auth_token'],
        'object_storage_url': options['os_storage_url'],
        'region_name': options['os_region_name'],
    }


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
        "os_storage_url": environ.get('OS_STORAGE_URL'),
        "os_region_name": environ.get('OS_REGION_NAME'),
        "os_service_type": environ.get('OS_SERVICE_TYPE'),
        "os_endpoint_type": environ.get('OS_ENDPOINT_TYPE'),
        "os_cacert": environ.get('OS_CACERT'),
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
    'use_slo': False,
    'segment_size': None,
    'segment_container': None,
    'leave_segments': False,
    'changed': None,
    'skip_identical': False,
    'yes_all': False,
    'read_acl': None,
    'write_acl': None,
    'out_file': None,
    'no_download': False,
    'long': False,
    'totals': False,
    'marker': '',
    'header': [],
    'meta': [],
    'prefix': None,
    'delimiter': None,
    'fail_fast': False,
    'human': False,
    'dir_marker': False,
    'checksum': True
}

POLICY = 'X-Storage-Policy'


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
    return Connection(options['auth'],
                      options['user'],
                      options['key'],
                      options['retries'],
                      auth_version=options['auth_version'],
                      os_options=options['os_options'],
                      snet=options['snet'],
                      cacert=options['os_cacert'],
                      insecure=options['insecure'],
                      ssl_compression=options['ssl_compression'])


def mkdirs(path):
    try:
        makedirs(path)
    except OSError as err:
        if err.errno != EEXIST:
            raise


def split_headers(options, prefix=''):
    """
    Splits 'Key: Value' strings and returns them as a dictionary.

    :param options: An array of 'Key: Value' strings
    :param prefix: String to prepend to all of the keys in the dictionary.
        reporting.
    """
    headers = {}
    for item in options:
        split_item = item.split(':', 1)
        if len(split_item) == 2:
            headers[(prefix + split_item[0]).title()] = split_item[1]
        else:
            raise SwiftError(
                "Metadata parameter %s must contain a ':'.\n%s"
                % (item, "Example: 'Color:Blue' or 'Size:Large'")
            )
    return headers


class SwiftUploadObject(object):
    """
    Class for specifying an object upload, allowing the object source, name and
    options to be specified separately for each individual object.
    """
    def __init__(self, source, object_name=None, options=None):
        if isinstance(source, string_types):
            self.object_name = object_name or source
        elif source is None or hasattr(source, 'read'):
            if not object_name or not isinstance(object_name, string_types):
                raise SwiftError('Object names must be specified as '
                                 'strings for uploads from None or file '
                                 'like objects.')
            self.object_name = object_name
        else:
            raise SwiftError('Unexpected source type for '
                             'SwiftUploadObject: {0}'.format(type(source)))

        if not self.object_name:
            raise SwiftError('Object names must not be empty strings')

        self.options = options
        self.source = source


class SwiftPostObject(object):
    """
    Class for specifying an object post, allowing the headers/metadata to be
    specified separately for each individual object.
    """
    def __init__(self, object_name, options=None):
        if not isinstance(object_name, string_types) or not object_name:
            raise SwiftError(
                "Object names must be specified as non-empty strings"
            )
        else:
            self.object_name = object_name
            self.options = options


class _SwiftReader(object):
    """
    Class for downloading objects from swift and raising appropriate
    errors on failures caused by either invalid md5sum or size of the
    data read.
    """
    def __init__(self, path, body, headers):
        self._path = path
        self._body = body
        self._actual_read = 0
        self._content_length = None
        self._actual_md5 = None
        self._expected_etag = headers.get('etag')

        if ('x-object-manifest' not in headers
                and 'x-static-large-object' not in headers):
            self._actual_md5 = md5()

        if 'content-length' in headers:
            try:
                self._content_length = int(headers.get('content-length'))
            except ValueError:
                raise SwiftError('content-length header must be an integer')

    def __iter__(self):
        for chunk in self._body:
            if self._actual_md5:
                self._actual_md5.update(chunk)
            self._actual_read += len(chunk)
            yield chunk
        self._check_contents()

    def _check_contents(self):
        if self._actual_md5 and self._expected_etag:
            etag = self._actual_md5.hexdigest()
            if etag != self._expected_etag:
                raise SwiftError('Error downloading {0}: md5sum != etag, '
                                 '{1} != {2}'.format(
                                     self._path, etag, self._expected_etag))

        if (self._content_length is not None
                and self._actual_read != self._content_length):
            raise SwiftError('Error downloading {0}: read_length != '
                             'content_length, {1:d} != {2:d}'.format(
                                 self._path, self._actual_read,
                                 self._content_length))

    def bytes_read(self):
        return self._actual_read


class SwiftService(object):
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
        create_connection = lambda: get_conn(self._options)
        self.thread_manager = MultiThreadingManager(
            create_connection,
            segment_threads=self._options['segment_threads'],
            object_dd_threads=self._options['object_dd_threads'],
            object_uu_threads=self._options['object_uu_threads'],
            container_threads=self._options['container_threads']
        )

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
                                'human': False
                            }

        :returns: Either a single dictionary containing stats about an account
                  or container, or an iterator for returning the results of the
                  stat operations on a list of objects.

        :raises: SwiftError
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
                        res.update({
                            'success': False,
                            'error': err
                        })
                        return res
                    raise SwiftError('Account not found', exc=err)
                except Exception as err:
                    res.update({
                        'success': False,
                        'error': err
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
                        res.update({
                            'success': False,
                            'error': err
                        })
                        return res
                    raise SwiftError('Container %r not found' % container,
                                     container=container, exc=err)
                except Exception as err:
                    res.update({
                        'success': False,
                        'error': err
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
            res.update({
                'success': False,
                'error': err
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
                                'headers': [],
                                'read_acl': None,   # For containers only
                                'write_acl': None,  # For containers only
                                'sync_to': None,    # For containers only
                                'sync_key': None    # For containers only
                            }

        :returns: Either a single result dictionary in the case of a post to a
                  container/account, or an iterator for returning the results
                  of posts to a list of objects.

        :raises: SwiftError
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
                        res.update({
                            'success': False,
                            'error': err,
                            'response_dict': response_dict
                        })
                        return res
                    raise SwiftError('Account not found')
                except Exception as err:
                    res.update({
                        'success': False,
                        'error': err,
                        'response_dict': response_dict
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
                    res.update({
                        'action': 'post_container',
                        'success': False,
                        'error': err,
                        'response_dict': response_dict
                    })
                    return res
                raise SwiftError(
                    "Container '%s' not found" % container,
                    container=container
                )
            except Exception as err:
                res.update({
                    'action': 'post_container',
                    'success': False,
                    'error': err,
                    'response_dict': response_dict
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
                                obj_options['meta'], 'X-Object-Meta'
                            )
                        )
                    if 'headers' in obj_options:
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
            if isinstance(o, string_types):
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
            res.update({
                'success': False,
                'error': err
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

        rq = Queue()

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
        success = True
        error = None
        try:
            while True:
                _, items = conn.get_account(
                    marker=marker, prefix=options['prefix']
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
            success = False
            if err.http_status != 404:
                error = err
            else:
                error = SwiftError('Account not found')

        except Exception as err:
            success = False
            error = err

        res = {
            'action': 'list_account_part',
            'container': None,
            'prefix': options['prefix'],
            'success': success,
            'marker': marker,
            'error': error,
        }
        result_queue.put(res)
        result_queue.put(None)

    @staticmethod
    def _list_container_job(conn, container, options, result_queue):
        marker = ''
        success = True
        error = None
        try:
            while True:
                _, items = conn.get_container(
                    container, marker=marker, prefix=options['prefix'],
                    delimiter=options['delimiter']
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
        except ClientException as err:
            success = False
            if err.http_status != 404:
                error = err
            else:
                error = SwiftError('Container %r not found' % container,
                                   container=container)
        except Exception as err:
            success = False
            error = err

        res = {
            'action': 'list_container_part',
            'container': container,
            'prefix': options['prefix'],
            'success': success,
            'marker': marker,
            'error': error,
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
                                'out_file': None
                            }

        :returns: A generator for returning the results of the download
                  operations. Each result yielded from the generator is a
                  'download_object' dictionary containing the results of an
                  individual file download.

        :raises: ClientException
        :raises: SwiftError
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
                    containers = []
                    for part in self.list(options=options_copy):
                        if part["success"]:
                            containers.extend([
                                i['name'] for i in part["listing"]
                            ])
                        else:
                            raise part["error"]

                    shuffle(containers)

                    o_downs = []
                    for con in containers:
                        objs = []
                        for part in self.list(
                                container=con, options=options_copy):
                            if part["success"]:
                                objs.extend([
                                    i['name'] for i in part["listing"]
                                ])
                            else:
                                raise part["error"]
                        shuffle(objs)

                        o_downs.extend(
                            self.thread_manager.object_dd_pool.submit(
                                self._download_object_job, con, obj,
                                options_copy
                            ) for obj in objs
                        )

                    for o_down in interruptable_as_completed(o_downs):
                        yield o_down.result()

                # If we see a 404 here, the listing of the account failed
                except ClientException as err:
                    if err.http_status != 404:
                        raise
                    raise SwiftError('Account not found')

        elif not objects:
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

    @staticmethod
    def _download_object_job(conn, container, obj, options):
        out_file = options['out_file']
        results_dict = {}

        req_headers = split_headers(options['header'], '')

        pseudodir = False
        path = join(container, obj) if options['yes_all'] else obj
        path = path.lstrip(os_path_sep)
        if options['skip_identical'] and out_file != '-':
            filename = out_file if out_file else path
            try:
                fp = open(filename, 'rb')
            except IOError:
                pass
            else:
                with fp:
                    md5sum = md5()
                    while True:
                        data = fp.read(65536)
                        if not data:
                            break
                        md5sum.update(data)
                    req_headers['If-None-Match'] = md5sum.hexdigest()

        try:
            start_time = time()
            headers, body = \
                conn.get_object(container, obj, resp_chunk_size=65536,
                                headers=req_headers,
                                response_dict=results_dict)
            headers_receipt = time()

            obj_body = _SwiftReader(path, body, headers)

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
                content_type = headers.get('content-type')
                if (content_type and
                   content_type.split(';', 1)[0] == 'text/directory'):
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
                            fp = open(out_file, 'wb')
                        else:
                            if basename(path):
                                fp = open(path, 'wb')
                            else:
                                pseudodir = True

                for chunk in obj_body:
                    if fp is not None:
                        fp.write(chunk)

                finish_time = time()

            finally:
                bytes_read = obj_body.bytes_read()
                if fp is not None:
                    fp.close()
                    if 'x-object-meta-mtime' in headers and not no_file:
                        mtime = float(headers['x-object-meta-mtime'])
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
            res = {
                'action': 'download_object',
                'container': container,
                'object': obj,
                'success': False,
                'error': err,
                'response_dict': results_dict,
                'path': path,
                'pseudodir': pseudodir,
                'attempts': conn.attempts
            }
            return res

    def _download_container(self, container, options):
        try:
            objects = []
            for part in self.list(container=container, options=options):
                if part["success"]:
                    objects.extend([o["name"] for o in part["listing"]])
                else:
                    raise part["error"]

            o_downs = [
                self.thread_manager.object_dd_pool.submit(
                    self._download_object_job, container, obj, options
                ) for obj in objects
            ]

            for o_down in interruptable_as_completed(o_downs):
                yield o_down.result()

        except ClientException as err:
            if err.http_status != 404:
                raise
            raise SwiftError('Container %r not found' % container,
                             container=container)

    # Upload related methods
    #
    def upload(self, container, objects, options=None):
        """
        Upload a list of objects to a given container.

        :param container: The container to put the uploads into.
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

                            file - A file like object (with a read method)
                            path - A string containing the path to a local file
                                   or directory
                            None - Indicates that we want an empty object

        :param options: A dictionary containing options to override the global
                        options specified during the service object creation.
                        These options are applied to all upload operations
                        performed by this call, unless overridden on a per
                        object basis. Possible options are given below::

                            {
                                'meta': [],
                                'headers': [],
                                'segment_size': None,
                                'use_slo': False,
                                'segment_container: None,
                                'leave_segments': False,
                                'changed': None,
                                'skip_identical': False,
                                'fail_fast': False,
                                'dir_marker': False  # Only for None sources
                            }

        :returns: A generator for returning the results of the uploads.

        :raises: SwiftError
        :raises: ClientException
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

        # Try to create the container, just in case it doesn't exist. If this
        # fails, it might just be because the user doesn't have container PUT
        # permissions, so we'll ignore any error. If there's really a problem,
        # it'll surface on the first object PUT.
        policy_header = {}
        _header = split_headers(options["header"])
        if POLICY in _header:
            policy_header[POLICY] = \
                _header[POLICY]
        create_containers = [
            self.thread_manager.container_pool.submit(
                self._create_container_job, container, headers=policy_header
            )
        ]

        # wait for first container job to complete before possibly attempting
        # segment container job because segment container job may attempt
        # to HEAD the first container
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
                    # container with the same policy as the upload container
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

        upload_objects = self._make_upload_objects(objects)
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
                    self._upload_object_job, container, s, o, object_options
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
                        res = {
                            'action': 'upload_object',
                            'container': container,
                            'object': o,
                            'success': False,
                            'error': err,
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
    def _make_upload_objects(objects):
        upload_objects = []

        for o in objects:
            if isinstance(o, string_types):
                obj = SwiftUploadObject(o)
                upload_objects.append(obj)
            elif isinstance(o, SwiftUploadObject):
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
            res.update({
                'success': False,
                'error': err,
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
                ct = headers.get('content-type')
                cl = int(headers.get('content-length'))
                et = headers.get('etag')
                mt = headers.get('x-object-meta-mtime')

                if (ct.split(';', 1)[0] == 'text/directory' and
                        cl == 0 and
                        et == EMPTY_ETAG and
                        mt == put_headers['x-object-meta-mtime']):
                    res['success'] = True
                    return res
            except ClientException as err:
                if err.http_status != 404:
                    res.update({
                        'success': False,
                        'error': err})
                    return res
        try:
            conn.put_object(container, obj, '', content_length=0,
                            content_type='text/directory',
                            headers=put_headers,
                            response_dict=results_dict)
            res.update({
                'success': True,
                'response_dict': results_dict})
            return res
        except Exception as err:
            res.update({
                'success': False,
                'error': err,
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
            'for_object': obj_name,
            'segment_index': segment_index,
            'segment_size': segment_size,
            'segment_location': '/%s/%s' % (segment_container,
                                            segment_name),
            'log_line': '%s segment %s' % (obj_name, segment_index),
        }
        try:
            fp = open(path, 'rb')
            fp.seek(segment_start)

            contents = LengthWrapper(fp, segment_size, md5=options['checksum'])
            etag = conn.put_object(segment_container,
                                   segment_name, contents,
                                   content_length=segment_size,
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
            res.update({
                'success': False,
                'error': err,
                'response_dict': results_dict,
                'attempts': conn.attempts
            })

            if results_queue is not None:
                results_queue.put(res)
            return res

    def _upload_object_job(self, conn, container, source, obj, options,
                           results_queue=None):
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
            if obj.startswith('./') or obj.startswith('.\\'):
                obj = obj[2:]
            if obj.startswith('/'):
                obj = obj[1:]
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
            if (options['changed'] or options['skip_identical']
                    or not options['leave_segments']):
                checksum = None
                if options['skip_identical']:
                    try:
                        fp = open(path, 'rb')
                    except IOError:
                        pass
                    else:
                        with fp:
                            md5sum = md5()
                            while True:
                                data = fp.read(65536)
                                if not data:
                                    break
                                md5sum.update(data)
                        checksum = md5sum.hexdigest()
                try:
                    headers = conn.head_object(container, obj)
                    if options['skip_identical'] and checksum is not None:
                        if checksum == headers.get('etag'):
                            res.update({
                                'success': True,
                                'status': 'skipped-identical'
                            })
                            return res

                    cl = int(headers.get('content-length'))
                    mt = headers.get('x-object-meta-mtime')
                    if (path is not None and options['changed']
                            and cl == getsize(path)
                            and mt == put_headers['x-object-meta-mtime']):
                        res.update({
                            'success': True,
                            'status': 'skipped-changed'
                        })
                        return res
                    if not options['leave_segments']:
                        old_manifest = headers.get('x-object-manifest')
                        if config_true_value(
                                headers.get('x-static-large-object')):
                            headers, manifest_data = conn.get_object(
                                container, obj,
                                query_string='multipart-manifest=get'
                            )
                            for old_seg in json.loads(manifest_data):
                                seg_path = old_seg['name'].lstrip('/')
                                if isinstance(seg_path, text_type):
                                    seg_path = seg_path.encode('utf-8')
                                old_slo_manifest_paths.append(seg_path)
                except ClientException as err:
                    if err.http_status != 404:
                        res.update({
                            'success': False,
                            'error': err
                        })
                        return res

            # Merge the command line header options to the put_headers
            put_headers.update(split_headers(options['header'], ''))

            # Don't do segment job if object is not big enough, and never do
            # a segment job if we're reading from a stream - we may fail if we
            # go over the single object limit, but this gives us a nice way
            # to create objects from memory
            if (path is not None and options['segment_size']
                    and (getsize(path) > int(options['segment_size']))):
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
                    segment_size = int(options['segment_size'])
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
                    except Exception as e:
                        errors = True
                        exceptions.append(e)
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
                    segment_results.sort(key=lambda di: di['segment_index'])
                    for seg in segment_results:
                        seg_loc = seg['segment_location'].lstrip('/')
                        if isinstance(seg_loc, text_type):
                            seg_loc = seg_loc.encode('utf-8')
                        new_slo_manifest_paths.add(seg_loc)

                    manifest_data = json.dumps([
                        {
                            'path': d['segment_location'],
                            'etag': d['segment_etag'],
                            'size_bytes': d['segment_size']
                        } for d in segment_results
                    ])

                    put_headers['x-static-large-object'] = 'true'
                    mr = {}
                    conn.put_object(
                        container, obj, manifest_data,
                        headers=put_headers,
                        query_string='multipart-manifest=put',
                        response_dict=mr
                    )
                    res['manifest_response_dict'] = mr
                else:
                    new_object_manifest = '%s/%s/%s/%s/%s/' % (
                        quote(seg_container), quote(obj),
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
            else:
                res['large_object'] = False
                obr = {}
                if path is not None:
                    content_length = getsize(path)
                    contents = LengthWrapper(open(path, 'rb'),
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
                    raise SwiftError('Object upload verification failed: '
                                     'md5 mismatch, local {0} != remote {1} '
                                     '(remote object has not been removed)'
                                     .format(contents.get_md5sum(), etag))

            if old_manifest or old_slo_manifest_paths:
                drs = []
                if old_manifest:
                    scontainer, sprefix = old_manifest.split('/', 1)
                    scontainer = unquote(scontainer)
                    sprefix = unquote(sprefix).rstrip('/') + '/'
                    delobjs = []
                    for delobj in conn.get_container(scontainer,
                                                     prefix=sprefix)[1]:
                        delobjs.append(delobj['name'])
                    for dr in self.delete(container=scontainer,
                                          objects=delobjs):
                        drs.append(dr)
                if old_slo_manifest_paths:
                    delobjsmap = {}
                    for seg_to_delete in old_slo_manifest_paths:
                        if seg_to_delete in new_slo_manifest_paths:
                            continue
                        scont, sobj = \
                            seg_to_delete.split(b'/', 1)
                        delobjs_cont = delobjsmap.get(scont, [])
                        delobjs_cont.append(sobj)
                        delobjsmap[scont] = delobjs_cont
                    for (dscont, dsobjs) in delobjsmap.items():
                        for dr in self.delete(container=dscont,
                                              objects=dsobjs):
                            drs.append(dr)
                res['segment_delete_results'] = drs

            # return dict for printing
            res.update({
                'success': True,
                'status': 'uploaded',
                'attempts': conn.attempts})
            return res

        except OSError as err:
            if err.errno == ENOENT:
                err = SwiftError('Local file %r not found' % path)
            res.update({
                'success': False,
                'error': err
            })
        except Exception as err:
            res.update({
                'success': False,
                'error': err
            })
        return res

    # Delete related methods
    #
    def delete(self, container=None, objects=None, options=None):
        """
        Delete operations on an account, optional container and optional list
        of objects.

        :param container: The container to delete or delete from.
        :param objects: The list of objects to delete.
        :param options: A dictionary containing options to override the global
                        options specified during the service object creation::

                            {
                                'yes_all': False,
                                'leave_segments': False,
                            }

        :returns: A generator for returning the results of the delete
                  operations. Each result yielded from the generator is either
                  a 'delete_container', 'delete_object' or 'delete_segment'
                  dictionary containing the results of an individual delete
                  operation.

        :raises: ClientException
        :raises: SwiftError
        """
        if options is not None:
            options = dict(self._options, **options)
        else:
            options = self._options

        rq = Queue()
        if container is not None:
            if objects is not None:
                obj_dels = {}
                for obj in objects:
                    obj_del = self.thread_manager.object_dd_pool.submit(
                        self._delete_object, container, obj, options,
                        results_queue=rq
                    )
                    obj_details = {'container': container, 'object': obj}
                    obj_dels[obj_del] = obj_details

                # Start a thread to watch for upload results
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
                            if (not cancelled and options['fail_fast']
                                    and not res['success']):
                                cancelled = True

    @staticmethod
    def _delete_segment(conn, container, obj, results_queue=None):
        results_dict = {}
        try:
            conn.delete_object(container, obj, response_dict=results_dict)
            res = {'success': True}
        except Exception as e:
            res = {'success': False, 'error': e}

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

    def _delete_object(self, conn, container, obj, options,
                       results_queue=None):
        try:
            res = {
                'action': 'delete_object',
                'container': container,
                'object': obj
            }
            old_manifest = None
            query_string = None

            if not options['leave_segments']:
                try:
                    headers = conn.head_object(container, obj)
                    old_manifest = headers.get('x-object-manifest')
                    if config_true_value(headers.get('x-static-large-object')):
                        query_string = 'multipart-manifest=delete'
                except ClientException as err:
                    if err.http_status != 404:
                        raise

            results_dict = {}
            conn.delete_object(container, obj, query_string=query_string,
                               response_dict=results_dict)

            if old_manifest:

                dlo_segments_deleted = True
                segment_pool = self.thread_manager.segment_pool
                s_container, s_prefix = old_manifest.split('/', 1)
                s_container = unquote(s_container)
                s_prefix = unquote(s_prefix).rstrip('/') + '/'

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
            res['success'] = False
            res['error'] = err
            return res

        return res

    @staticmethod
    def _delete_empty_container(conn, container):
        results_dict = {}
        try:
            conn.delete_container(container, response_dict=results_dict)
            res = {'success': True}
        except Exception as e:
            res = {'success': False, 'error': e}

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
            objs = []
            for part in self.list(container=container):
                if part["success"]:
                    objs.extend([o['name'] for o in part['listing']])
                else:
                    raise part["error"]

            for res in self.delete(
                    container=container, objects=objs, options=options):
                yield res

            con_del = self.thread_manager.container_pool.submit(
                self._delete_empty_container, container
            )
            con_del_res = get_future_result(con_del)

        except Exception as err:
            con_del_res = {
                'action': 'delete_container',
                'container': container,
                'object': None,
                'success': False,
                'error': err
            }

        yield con_del_res

    # Capabilities related methods
    #
    def capabilities(self, url=None):
        """
        List the cluster capabilities.

        :param url: Proxy URL of the cluster to retrieve capabilities.

        :returns: A dictionary containing the capabilities of the cluster.

        :raises: ClientException
        :raises: SwiftError
        """
        res = {
            'action': 'capabilities'
        }

        try:
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
        except ClientException as err:
            if err.http_status != 404:
                raise err
            raise SwiftError('Account not found')

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
                details = futures[f]
                res = details
                res['success'] = False
                res['error'] = err
                result_queue.put(res)

        result_queue.put(None)
