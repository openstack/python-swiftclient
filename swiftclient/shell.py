#!/usr/bin/python -u
# Copyright (c) 2010-2012 OpenStack, LLC.
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

import argparse
import getpass
import io
import json
import logging
import signal
import socket
import warnings

from os import environ, walk, _exit as os_exit
from os.path import isfile, isdir, join
from urllib.parse import unquote, urlparse
from sys import argv as sys_argv, exit, stderr, stdin
from time import gmtime, strftime

from swiftclient import RequestException
from swiftclient.utils import config_true_value, generate_temp_url, \
    prt_bytes, parse_timeout, JSONableIterable
from swiftclient.multithreading import OutputManager
from swiftclient.exceptions import ClientException
from swiftclient import __version__ as client_version
from swiftclient.client import logger_settings as client_logger_settings, \
    parse_header_string
from swiftclient.service import SwiftService, SwiftError, \
    SwiftUploadObject, get_conn, process_options
from swiftclient.command_helpers import print_account_stats, \
    print_container_stats, print_object_stats

try:
    from shlex import quote as sh_quote
except ImportError:
    from pipes import quote as sh_quote

BASENAME = 'swift'
commands = ('delete', 'download', 'list', 'post', 'copy', 'stat', 'upload',
            'capabilities', 'info', 'tempurl', 'auth', 'bash_completion')


def immediate_exit(signum, frame):
    stderr.write(" Aborted\n")
    os_exit(2)


st_delete_options = '''[--all] [--leave-segments]
                    [--object-threads <threads>]
                    [--container-threads <threads>]
                    [--header <header:value>]
                    [--prefix <prefix>]
                    [--versions]
                    [<container> [<object>] [--version-id <version_id>] [...]]
'''

st_delete_help = '''
Delete a container or objects within a container.

Positional arguments:
  [<container>]         Name of container to delete from.
  [<object>]            Name of object to delete. Specify multiple times
                        for multiple objects.

Optional arguments:
  -a, --all             Delete all containers and objects. Implies --versions.
  --versions            Delete all versions.
  --leave-segments      Do not delete segments of manifest objects.
  -H, --header <header:value>
                        Adds a custom request header to use for deleting
                        objects or an entire container .
  --object-threads <threads>
                        Number of threads to use for deleting objects.
                        Default is 10.
  --container-threads <threads>
                        Number of threads to use for deleting containers.
                        Default is 10.
  --prefix <prefix>     Only delete objects beginning with <prefix>.
  --version-id <version-id>
                        Delete specific version of a versioned object.
'''.strip("\n")


def st_delete(parser, args, output_manager, return_parser=False):
    parser.add_argument(
        '-a', '--all', action='store_true', dest='yes_all',
        default=False, help='Delete all containers and objects.')
    parser.add_argument('--versions', action='store_true',
                        help='delete all versions')
    parser.add_argument(
        '-p', '--prefix', dest='prefix',
        help='Only delete items beginning with <prefix>.')
    parser.add_argument(
        '--version-id', action='store', default=None,
        help='Delete a specific version of a versioned object')
    parser.add_argument(
        '-H', '--header', action='append', dest='header',
        default=[],
        help='Adds a custom request header to use for deleting objects '
        'or an entire container.')
    parser.add_argument(
        '--leave-segments', action='store_true',
        dest='leave_segments', default=False,
        help='Do not delete segments of manifest objects.')
    parser.add_argument(
        '--object-threads', type=int,
        default=10, help='Number of threads to use for deleting objects. '
        'Its value must be a positive integer. Default is 10.')
    parser.add_argument(
        '--container-threads', type=int,
        default=10, help='Number of threads to use for deleting containers. '
        'Its value must be a positive integer. Default is 10.')

    # We return the parser to build up the bash_completion
    if return_parser:
        return parser

    (options, args) = parse_args(parser, args)
    args = args[1:]
    if options['yes_all']:
        options['versions'] = True
    if (not args and not options['yes_all']) or (args and options['yes_all']):
        output_manager.error('Usage: %s delete %s\n%s',
                             BASENAME, st_delete_options,
                             st_delete_help)
        return
    if options['versions'] and len(args) >= 2:
        exit('--versions option not allowed for object deletes')
    if options['version_id'] and len(args) < 2:
        exit('--version-id option only allowed for object deletes')

    if options['object_threads'] <= 0:
        output_manager.error(
            'ERROR: option --object-threads should be a positive integer.'
            '\n\nUsage: %s delete %s\n%s',
            BASENAME, st_delete_options,
            st_delete_help)
        return

    if options['container_threads'] <= 0:
        output_manager.error(
            'ERROR: option --container-threads should be a positive integer.'
            '\n\nUsage: %s delete %s\n%s',
            BASENAME, st_delete_options,
            st_delete_help)
        return

    options['object_dd_threads'] = options['object_threads']
    with SwiftService(options=options) as swift:
        try:
            if not args:
                del_iter = swift.delete()
            else:
                container = args[0]
                if '/' in container:
                    output_manager.error(
                        'WARNING: / in container name; you '
                        "might have meant '%s' instead of '%s'." %
                        (container.replace('/', ' ', 1), container)
                    )
                    return
                objects = args[1:]
                if objects:
                    del_iter = swift.delete(container=container,
                                            objects=objects)
                else:
                    del_iter = swift.delete(container=container)

            for r in del_iter:
                c = r.get('container', '')
                o = r.get('object', '')
                a = (' [after {0} attempts]'.format(r.get('attempts'))
                     if r.get('attempts', 1) > 1 else '')

                if r['action'] == 'bulk_delete':
                    if r['success']:
                        objs = r.get('objects', [])
                        for o, err in r.get('result', {}).get('Errors', []):
                            # o will be of the form quote("/<cont>/<obj>")
                            o = unquote(o)
                            output_manager.error('Error Deleting: {0}: {1}'
                                                 .format(o[1:], err))
                            try:
                                objs.remove(o[len(c) + 2:])
                            except ValueError:
                                # shouldn't happen, but ignoring it won't hurt
                                pass

                        for o in objs:
                            if options['yes_all']:
                                p = '{0}/{1}'.format(c, o)
                            else:
                                p = o
                            output_manager.print_msg('{0}{1}'.format(p, a))
                    else:
                        for o in r.get('objects', []):
                            output_manager.error('Error Deleting: {0}/{1}: {2}'
                                                 .format(c, o, r['error']))
                else:
                    if r['success']:
                        if options['verbose']:
                            if r['action'] == 'delete_object':
                                if options['yes_all']:
                                    p = '{0}/{1}'.format(c, o)
                                else:
                                    p = o
                            elif r['action'] == 'delete_segment':
                                p = '{0}/{1}'.format(c, o)
                            elif r['action'] == 'delete_container':
                                p = c

                            output_manager.print_msg('{0}{1}'.format(p, a))
                    else:
                        p = '{0}/{1}'.format(c, o) if o else c
                        output_manager.error('Error Deleting: {0}: {1}'
                                             .format(p, r['error']))
        except SwiftError as err:
            output_manager.error_with_txn_id(err)


st_download_options = '''[--all] [--marker <marker>] [--prefix <prefix>]
                      [--output <out_file>] [--output-dir <out_directory>]
                      [--object-threads <threads>] [--ignore-checksum]
                      [--container-threads <threads>] [--no-download]
                      [--skip-identical] [--remove-prefix]
                      [--version-id <version_id>]
                      [--header <header:value>] [--no-shuffle]
                      [<container> [<object>] [...]]
'''

st_download_help = '''
Download objects from containers.

Positional arguments:
  [<container>]           Name of container to download from. To download a
                          whole account, omit this and specify --all.
  [<object>]              Name of object to download. Specify multiple times
                          for multiple objects. Omit this to download all
                          objects from the container.

Optional arguments:
  -a, --all             Indicates that you really want to download
                        everything in the account.
  -m, --marker <marker> Marker to use when starting a container or account
                        download.
  -p, --prefix <prefix> Only download items beginning with <prefix>
  -r, --remove-prefix   An optional flag for --prefix <prefix>, use this
                        option to download items without <prefix>
  -o, --output <out_file>
                        For a single file download, stream the output to
                        <out_file>. Specifying "-" as <out_file> will
                        redirect to stdout.
  -D, --output-dir <out_directory>
                        An optional directory to which to store objects.
                        By default, all objects are recreated in the current
                        directory.
  --object-threads <threads>
                        Number of threads to use for downloading objects.
                        Default is 10.
  --container-threads <threads>
                        Number of threads to use for downloading containers.
                        Default is 10.
  --no-download         Perform download(s), but don't actually write anything
                        to disk.
  -H, --header <header:value>
                        Adds a customized request header to the query, like
                        "Range" or "If-Match". This option may be repeated.
                        Example: --header "content-type:text/plain"
  --skip-identical      Skip downloading files that are identical on both
                        sides.
  --version-id <version-id>
                        Download specific version of a versioned object.
  --ignore-checksum     Turn off checksum validation for downloads.
  --no-shuffle          By default, when downloading a complete account or
                        container, download order is randomised in order to
                        reduce the load on individual drives when multiple
                        clients are executed simultaneously to download the
                        same set of objects (e.g. a nightly automated download
                        script to multiple servers). Enable this option to
                        submit download jobs to the thread pool in the order
                        they are listed in the object store.
  --ignore-mtime        Ignore the 'X-Object-Meta-Mtime' header when
                        downloading an object. Instead, create atime and mtime
                        with fresh timestamps.
'''.strip("\n")


def st_download(parser, args, output_manager, return_parser=False):
    parser.add_argument(
        '-a', '--all', action='store_true', dest='yes_all',
        default=False, help='Indicates that you really want to download '
        'everything in the account.')
    parser.add_argument(
        '-m', '--marker', dest='marker',
        default='', help='Marker to use when starting a container or '
        'account download.')
    parser.add_argument(
        '-p', '--prefix', dest='prefix',
        help='Only download items beginning with the <prefix>.')
    parser.add_argument(
        '-o', '--output', dest='out_file', help='For a single '
        'download, stream the output to <out_file>. '
        'Specifying "-" as <out_file> will redirect to stdout.')
    parser.add_argument(
        '-D', '--output-dir', dest='out_directory',
        help='An optional directory to which to store objects. '
        'By default, all objects are recreated in the current directory.')
    parser.add_argument(
        '-r', '--remove-prefix', action='store_true', dest='remove_prefix',
        default=False, help='An optional flag for --prefix <prefix>, '
        'use this option to download items without <prefix>.')
    parser.add_argument(
        '--object-threads', type=int,
        default=10, help='Number of threads to use for downloading objects. '
        'Its value must be a positive integer. Default is 10.')
    parser.add_argument(
        '--container-threads', type=int, default=10,
        help='Number of threads to use for downloading containers. '
        'Its value must be a positive integer. Default is 10.')
    parser.add_argument(
        '--no-download', action='store_true',
        default=False,
        help="Perform download(s), but don't actually write anything to disk.")
    parser.add_argument(
        '-H', '--header', action='append', dest='header',
        default=[],
        help='Adds a customized request header to the query, like "Range" or '
        '"If-Match". This option may be repeated. '
        'Example: --header "content-type:text/plain"')
    parser.add_argument(
        '--skip-identical', action='store_true', dest='skip_identical',
        default=False, help='Skip downloading files that are identical on '
        'both sides.')
    parser.add_argument(
        '--version-id', action='store', default=None,
        help='Download a specific version of a versioned object')
    parser.add_argument(
        '--ignore-checksum', action='store_false', dest='checksum',
        default=True, help='Turn off checksum validation for downloads.')
    parser.add_argument(
        '--no-shuffle', action='store_false', dest='shuffle',
        default=True, help='By default, download order is randomised in order '
        'to reduce the load on individual drives when multiple clients are '
        'executed simultaneously to download the same set of objects (e.g. a '
        'nightly automated download script to multiple servers). Enable this '
        'option to submit download jobs to the thread pool in the order they '
        'are listed in the object store.')
    parser.add_argument(
        '--ignore-mtime', action='store_true', dest='ignore_mtime',
        default=False, help='By default, the object-meta-mtime header is used '
        'to store the access and modified timestamp for the downloaded file. '
        'With this option, the header is ignored and the timestamps are '
        'created freshly.')

    # We return the parser to build up the bash_completion
    if return_parser:
        return parser

    (options, args) = parse_args(parser, args)
    args = args[1:]
    if options['out_file'] == '-':
        options['verbose'] = 0

    if options['out_file'] and len(args) != 2:
        exit('-o option only allowed for single file downloads')

    if not options['prefix']:
        options['remove_prefix'] = False

    if options['out_directory'] and len(args) == 2:
        exit('Please use -o option for single file downloads and renames')

    if (not args and not options['yes_all']) or (args and options['yes_all']):
        output_manager.error('Usage: %s download %s\n%s', BASENAME,
                             st_download_options, st_download_help)
        return
    if options['version_id'] and len(args) < 2:
        exit('--version-id option only allowed for object downloads')

    if options['object_threads'] <= 0:
        output_manager.error(
            'ERROR: option --object-threads should be a positive integer.\n\n'
            'Usage: %s download %s\n%s', BASENAME,
            st_download_options, st_download_help)
        return

    if options['container_threads'] <= 0:
        output_manager.error(
            'ERROR: option --container-threads should be a positive integer.'
            '\n\nUsage: %s download %s\n%s', BASENAME,
            st_download_options, st_download_help)
        return

    options['object_dd_threads'] = options['object_threads']
    with SwiftService(options=options) as swift:
        try:
            if not args:
                down_iter = swift.download()
            else:
                container = args[0]
                if '/' in container:
                    output_manager.error(
                        'WARNING: / in container name; you '
                        "might have meant '%s' instead of '%s'." %
                        (container.replace('/', ' ', 1), container)
                    )
                    return
                objects = args[1:]
                if not objects:
                    down_iter = swift.download(container)
                else:
                    down_iter = swift.download(container, objects)

            for down in down_iter:
                if options['out_file'] == '-' and 'contents' in down:
                    contents = down['contents']
                    for chunk in contents:
                        output_manager.print_raw(chunk)
                else:
                    if down['success']:
                        if options['verbose']:
                            start_time = down['start_time']
                            headers_receipt = \
                                down['headers_receipt'] - start_time
                            auth_time = down['auth_end_time'] - start_time
                            finish_time = down['finish_time']
                            read_length = down['read_length']
                            attempts = down['attempts']
                            total_time = finish_time - start_time
                            down_time = total_time - auth_time
                            _mega = 1000000
                            if down['pseudodir']:
                                time_str = (
                                    'auth %.3fs, headers %.3fs, total %.3fs, '
                                    'pseudo' % (
                                        auth_time, headers_receipt,
                                        total_time
                                    )
                                )
                            else:
                                speed = float(read_length) / down_time / _mega
                                time_str = (
                                    'auth %.3fs, headers %.3fs, total %.3fs, '
                                    '%.3f MB/s' % (
                                        auth_time, headers_receipt,
                                        total_time, speed
                                    )
                                )
                            path = down['path']
                            if attempts > 1:
                                output_manager.print_msg(
                                    '%s [%s after %d attempts]',
                                    path, time_str, attempts
                                )
                            else:
                                output_manager.print_msg(
                                    '%s [%s]', path, time_str
                                )
                    else:
                        error = down['error']
                        path = down['path']
                        container = down['container']
                        obj = down['object']
                        if isinstance(error, ClientException):
                            if error.http_status == 304 and \
                                    options['skip_identical']:
                                output_manager.print_msg(
                                    "Skipped identical file '%s'", path)
                                continue
                            if error.http_status == 404:
                                output_manager.error(
                                    "Object '%s/%s' not found", container, obj)
                                continue
                        output_manager.error(
                            "Error downloading object '%s/%s': %s\n"
                            "Failed Transaction ID: %s",
                            container, obj, error,
                            getattr(error, 'transaction_id', 'unknown'))

        except SwiftError as e:
            output_manager.error_with_txn_id(e)
        except Exception as e:
            output_manager.error(e)


st_list_options = '''[--long] [--lh] [--totals] [--prefix <prefix>]
                  [--delimiter <delimiter>] [--header <header:value>]
                  [--versions] [<container>]
'''

st_list_help = '''
Lists the containers for the account or the objects for a container.

Positional arguments:
  [<container>]           Name of container to list object in.

Optional arguments:
  -l, --long            Long listing format, similar to ls -l.
  --lh                  Report sizes in human readable format similar to
                        ls -lh.
  -t, --totals          Used with -l or --lh, only report totals.
  -p <prefix>, --prefix <prefix>
                        Only list items beginning with the prefix.
  -d <delim>, --delimiter <delim>
                        Roll up items with the given delimiter. For containers
                        only. See OpenStack Swift API documentation for what
                        this means.
  -j, --json            Display listing information in json
  --versions            Display listing information for all versions
  -H, --header <header:value>
                        Adds a custom request header to use for listing.
'''.strip('\n')


def st_list(parser, args, output_manager, return_parser=False):

    def _print_stats(options, stats, human, totals):
        container = stats.get("container", None)
        for item in stats["listing"]:
            item_name = item.get('name')
            if not options['long'] and not human and not options['versions']:
                output_manager.print_msg(item.get('name', item.get('subdir')))
            else:
                if not container:    # listing containers
                    item_bytes = item.get('bytes')
                    byte_str = prt_bytes(item_bytes, human)
                    count = item.get('count')
                    totals['count'] += count
                    try:
                        meta = item.get('meta')
                        utc = gmtime(float(meta.get('x-timestamp')))
                        datestamp = strftime('%Y-%m-%d %H:%M:%S', utc)
                    except TypeError:
                        datestamp = '????-??-?? ??:??:??'
                    storage_policy = meta.get('x-storage-policy', '???')
                    if not options['totals']:
                        output_manager.print_msg(
                            "%12s %s %s %-15s %s", count, byte_str,
                            datestamp, storage_policy, item_name)
                else:    # list container contents
                    subdir = item.get('subdir')
                    content_type = item.get('content_type')
                    if subdir is None:
                        item_bytes = item.get('bytes')
                        byte_str = prt_bytes(item_bytes, human)
                        date, xtime = item.get('last_modified').split('T')
                        xtime = xtime.split('.')[0]
                    else:
                        item_bytes = 0
                        byte_str = prt_bytes(item_bytes, human)
                        date = xtime = ''
                        item_name = subdir
                    if not options['totals']:
                        if options['versions']:
                            output_manager.print_msg(
                                "%s %10s %8s %16s %24s %s",
                                byte_str, date, xtime,
                                item.get('version_id', 'null'),
                                content_type, item_name)
                        else:
                            output_manager.print_msg(
                                "%s %10s %8s %24s %s",
                                byte_str, date, xtime, content_type, item_name)
                totals['bytes'] += item_bytes

    parser.add_argument(
        '-l', '--long', dest='long', action='store_true', default=False,
        help='Long listing format, similar to ls -l.')
    parser.add_argument(
        '--lh', dest='human', action='store_true',
        default=False, help='Report sizes in human readable format, '
        "similar to ls -lh.")
    parser.add_argument(
        '-t', '--totals', dest='totals',
        help='used with -l or --lh, only report totals.',
        action='store_true', default=False)
    parser.add_argument(
        '-p', '--prefix', dest='prefix',
        help='Only list items beginning with the prefix.')
    parser.add_argument(
        '-d', '--delimiter', dest='delimiter',
        help='Roll up items with the given delimiter. For containers '
             'only. See OpenStack Swift API documentation for '
             'what this means.')
    parser.add_argument('-j', '--json', action='store_true',
                        help='print listing information in json')
    parser.add_argument('--versions', action='store_true',
                        help='display all versions')
    parser.add_argument(
        '-H', '--header', action='append', dest='header',
        default=[],
        help='Adds a custom request header to use for listing.')

    # We return the parser to build up the bash_completion
    if return_parser:
        return parser

    options, args = parse_args(parser, args)
    args = args[1:]
    if options['delimiter'] and not args:
        exit('-d option only allowed for container listings')
    if options['versions'] and not args:
        exit('--versions option only allowed for container listings')

    human = options.pop('human')
    if human:
        options['long'] = True

    if options['totals'] and not options['long']:
        output_manager.error(
            "Listing totals only works with -l or --lh.")
        return

    with SwiftService(options=options) as swift:
        try:
            if not args:
                stats_parts_gen = swift.list()
                container = None
            else:
                container = args[0]
                args = args[1:]
                if "/" in container or args:
                    output_manager.error(
                        'Usage: %s list %s\n%s', BASENAME,
                        st_list_options, st_list_help)
                    return
                else:
                    stats_parts_gen = swift.list(container=container)

            if options.get('json', False):
                def listing(stats_parts_gen=stats_parts_gen):
                    for stats in stats_parts_gen:
                        if stats["success"]:
                            for item in stats['listing']:
                                yield item
                        else:
                            raise stats["error"]

                json.dump(
                    JSONableIterable(listing()), output_manager.print_stream,
                    sort_keys=True, indent=2)
                output_manager.print_msg('')
                return

            totals = {'count': 0, 'bytes': 0}
            for stats in stats_parts_gen:
                if stats["success"]:
                    _print_stats(options, stats, human, totals)
                else:
                    raise stats["error"]

            # report totals
            if options['long'] or human:
                if container is None:
                    output_manager.print_msg(
                        "%12s %s", prt_bytes(totals['count'], True),
                        prt_bytes(totals['bytes'], human))
                else:
                    output_manager.print_msg(
                        prt_bytes(totals['bytes'], human))

        except SwiftError as e:
            output_manager.error_with_txn_id(e)


st_stat_options = '''[--lh] [--header <header:value>]
                  [--version-id <version_id>]
                  [<container> [<object>]]
'''

st_stat_help = '''
Displays information for the account, container, or object.

Positional arguments:
  [<container>]           Name of container to stat from.
  [<object>]              Name of object to stat.

Optional arguments:
  --lh                  Report sizes in human readable format similar to
                        ls -lh.
  --version-id <version-id>
                        Report stat of specific version of a versioned object.
  -H, --header <header:value>
                        Adds a custom request header to use for stat.
'''.strip('\n')


def st_stat(parser, args, output_manager, return_parser=False):
    parser.add_argument(
        '--lh', dest='human', action='store_true', default=False,
        help='Report sizes in human readable format similar to ls -lh.')
    parser.add_argument(
        '--version-id', action='store', default=None,
        help='Report stat of a specific version of a versioned object')
    parser.add_argument(
        '-H', '--header', action='append', dest='header',
        default=[],
        help='Adds a custom request header to use for stat.')

    # We return the parser to build up the bash_completion
    if return_parser:
        return parser

    options, args = parse_args(parser, args)
    args = args[1:]
    if options['version_id'] and len(args) < 2:
        exit('--version-id option only allowed for object stats')

    with SwiftService(options=options) as swift:
        try:
            if not args:
                stat_result = swift.stat()
                if not stat_result['success']:
                    raise stat_result['error']
                items = stat_result['items']
                headers = stat_result['headers']
                print_account_stats(items, headers, output_manager)
            else:
                container = args[0]
                if '/' in container:
                    output_manager.error(
                        'WARNING: / in container name; you might have '
                        "meant '%s' instead of '%s'." %
                        (container.replace('/', ' ', 1), container))
                    return
                args = args[1:]
                if not args:
                    stat_result = swift.stat(container=container)
                    if not stat_result['success']:
                        raise stat_result['error']
                    items = stat_result['items']
                    headers = stat_result['headers']
                    print_container_stats(items, headers, output_manager)
                else:
                    if len(args) == 1:
                        objects = [args[0]]
                        stat_results = swift.stat(
                            container=container, objects=objects)
                        for stat_result in stat_results:  # only 1 result
                            if stat_result["success"]:
                                items = stat_result['items']
                                headers = stat_result['headers']
                                print_object_stats(
                                    items, headers, output_manager
                                )
                            else:
                                raise stat_result["error"]
                    else:
                        output_manager.error(
                            'Usage: %s stat %s\n%s', BASENAME,
                            st_stat_options, st_stat_help)

        except SwiftError as e:
            output_manager.error_with_txn_id(e)


st_post_options = '''[--read-acl <acl>] [--write-acl <acl>] [--sync-to <sync-to>]
                  [--sync-key <sync-key>] [--meta <name:value>]
                  [--header <header>]
                  [<container> [<object>]]
'''  # noqa

st_post_help = '''
Updates meta information for the account, container, or object.
If the container is not found, it will be created automatically.

Positional arguments:
  [<container>]           Name of container to post to.
  [<object>]              Name of object to post.

Optional arguments:
  -r, --read-acl <acl>  Read ACL for containers. Quick summary of ACL syntax:
                        .r:*, .r:-.example.com, .r:www.example.com,
                        account1 (v1.0 identity API only),
                        account1:*, account2:user2 (v2.0+ identity API).
  -w, --write-acl <acl> Write ACL for containers. Quick summary of ACL syntax:
                        account1 (v1.0 identity API only),
                        account1:*, account2:user2 (v2.0+ identity API).
  -t, --sync-to <sync-to>
                        Sync To for containers, for multi-cluster replication.
  -k, --sync-key <sync-key>
                        Sync Key for containers, for multi-cluster replication.
  -m, --meta <name:value>
                        Sets a meta data item. This option may be repeated.
                        Example: -m Color:Blue -m Size:Large
  -H, --header <header:value>
                        Adds a customized request header.
                        This option may be repeated. Example
                        -H "content-type:text/plain" -H "Content-Length: 4000"
'''.strip('\n')


def st_post(parser, args, output_manager, return_parser=False):
    parser.add_argument(
        '-r', '--read-acl', dest='read_acl', help='Read ACL for containers. '
        'Quick summary of ACL syntax: .r:*, .r:-.example.com, '
        '.r:www.example.com, account1, account2:user2')
    parser.add_argument(
        '-w', '--write-acl', dest='write_acl', help='Write ACL for '
        'containers. Quick summary of ACL syntax: account1, '
        'account2:user2')
    parser.add_argument(
        '-t', '--sync-to', dest='sync_to', help='Sets the '
        'Sync To for containers, for multi-cluster replication.')
    parser.add_argument(
        '-k', '--sync-key', dest='sync_key', help='Sets the '
        'Sync Key for containers, for multi-cluster replication.')
    parser.add_argument(
        '-m', '--meta', action='append', dest='meta', default=[],
        help='Sets a meta data item. This option may be repeated. '
        'Example: -m Color:Blue -m Size:Large')
    parser.add_argument(
        '-H', '--header', action='append', dest='header',
        default=[], help='Adds a customized request header. '
        'This option may be repeated. '
        'Example: -H "content-type:text/plain" '
        '-H "Content-Length: 4000"')

    # We return the parser to build up the bash_completion
    if return_parser:
        return parser

    (options, args) = parse_args(parser, args)
    args = args[1:]
    if (options['read_acl'] or options['write_acl'] or options['sync_to'] or
            options['sync_key']) and not args:
        exit('-r, -w, -t, and -k options only allowed for containers')

    with SwiftService(options=options) as swift:
        try:
            if not args:
                result = swift.post()
            else:
                container = args[0]
                if '/' in container:
                    output_manager.error(
                        'WARNING: / in container name; you might have '
                        "meant '%s' instead of '%s'." %
                        (args[0].replace('/', ' ', 1), args[0]))
                    return
                args = args[1:]
                if args:
                    if len(args) == 1:
                        objects = [args[0]]
                        results_iterator = swift.post(
                            container=container, objects=objects
                        )
                        result = next(results_iterator)
                    else:
                        output_manager.error(
                            'Usage: %s post %s\n%s', BASENAME,
                            st_post_options, st_post_help)
                        return
                else:
                    result = swift.post(container=container)
            if not result["success"]:
                raise result["error"]

        except SwiftError as e:
            output_manager.error_with_txn_id(e)


st_copy_options = '''[--destination </container/object>] [--fresh-metadata]
                  [--meta <name:value>] [--header <header>] <container>
                  <object> [<object>] [...]
'''

st_copy_help = '''
Copies object to new destination, optionally updates objects metadata.
If destination is not set, will update metadata of object

Positional arguments:
  <container>             Name of container to copy from.
  <object>                Name of object to copy. Specify multiple times
                          for multiple objects

Optional arguments:
  -d, --destination </container[/object]>
                        The container and name of the destination object. Name
                        of destination object can be omitted, then will be
                        same as name of source object. Supplying multiple
                        objects and destination with object name is invalid.
  -M, --fresh-metadata  Copy the object without any existing metadata,
                        If not set, metadata will be preserved or appended
  -m, --meta <name:value>
                        Sets a meta data item. This option may be repeated.
                        Example: -m Color:Blue -m Size:Large
  -H, --header <header:value>
                        Adds a customized request header.
                        This option may be repeated. Example
                        -H "content-type:text/plain" -H "Content-Length: 4000"
'''.strip('\n')


def st_copy(parser, args, output_manager, return_parser=False):
    parser.add_argument(
        '-d', '--destination', help='The container and name of the '
        'destination object')
    parser.add_argument(
        '-M', '--fresh-metadata', action='store_true',
        help='Copy the object without any existing metadata', default=False)
    parser.add_argument(
        '-m', '--meta', action='append', dest='meta', default=[],
        help='Sets a meta data item. This option may be repeated. '
        'Example: -m Color:Blue -m Size:Large')
    parser.add_argument(
        '-H', '--header', action='append', dest='header',
        default=[], help='Adds a customized request header. '
        'This option may be repeated. '
        'Example: -H "content-type:text/plain" '
        '-H "Content-Length: 4000"')

    # We return the parser to build up the bash_completion
    if return_parser:
        return parser

    (options, args) = parse_args(parser, args)
    args = args[1:]

    with SwiftService(options=options) as swift:
        try:
            if len(args) >= 2:
                container = args[0]
                if '/' in container:
                    output_manager.error(
                        'WARNING: / in container name; you might have '
                        "meant '%s' instead of '%s'." %
                        (args[0].replace('/', ' ', 1), args[0]))
                    return
                objects = [arg for arg in args[1:]]

                for r in swift.copy(
                        container=container, objects=objects,
                        options=options):
                    if r['success']:
                        if options['verbose']:
                            if r['action'] == 'copy_object':
                                output_manager.print_msg(
                                    '%s/%s copied to %s' % (
                                        r['container'],
                                        r['object'],
                                        r['destination'] or '<self>'))
                            if r['action'] == 'create_container':
                                output_manager.print_msg(
                                    'created container %s' % r['container']
                                )
                    else:
                        error = r['error']
                        if 'action' in r and r['action'] == 'create_container':
                            # it is not an error to be unable to create the
                            # container so print a warning and carry on
                            output_manager.warning(
                                'Warning: failed to create container '
                                "'%s': %s", container, error
                            )
                        else:
                            output_manager.error("%s" % error)
            else:
                output_manager.error(
                    'Usage: %s copy %s\n%s', BASENAME,
                    st_copy_options, st_copy_help)
                return

        except SwiftError as e:
            output_manager.error_with_txn_id(e)


st_upload_options = '''[--changed] [--skip-identical] [--segment-size <size>]
                    [--segment-container <container>] [--leave-segments]
                    [--object-threads <thread>] [--segment-threads <threads>]
                    [--meta <name:value>] [--header <header>] [--use-slo]
                    [--use-dlo] [--ignore-checksum] [--skip-container-put]
                    [--object-name <object-name>]
                    <container> <file_or_directory> [<file_or_directory>] [...]
'''

st_upload_help = '''
Uploads specified files and directories to the given container.

Positional arguments:
  <container>           Name of container to upload to.
  <file_or_directory>   Name of file or directory to upload. Specify multiple
                        times for multiple uploads. If "-" is specified, reads
                        content from standard input (--object-name is required
                        in this case).

Optional arguments:
  -c, --changed         Only upload files that have changed since the last
                        upload.
  --skip-identical      Skip uploading files that are identical on both sides.
  -S, --segment-size <size>
                        Upload files in segments no larger than <size> (in
                        Bytes) and then create a "manifest" file that will
                        download all the segments as if it were the original
                        file.
  --segment-container <container>
                        Upload the segments into the specified container. If
                        not specified, the segments will be uploaded to a
                        <container>_segments container to not pollute the
                        main <container> listings.
  --leave-segments      Indicates that you want the older segments of manifest
                        objects left alone (in the case of overwrites).
  --object-threads <threads>
                        Number of threads to use for uploading full objects.
                        Default is 10.
  --segment-threads <threads>
                        Number of threads to use for uploading object segments.
                        Default is 10.
  -m, --meta <name:value>
                        Sets a meta data item. This option may be repeated.
                        Example: -m Color:Blue -m Size:Large
  -H, --header <header:value>
                        Adds a customized request header. This option may be
                        repeated. Example: -H "content-type:text/plain"
                         -H "Content-Length: 4000".
  --use-slo             When used in conjunction with --segment-size it will
                        create a Static Large Object. Deprecated; this is now
                        the default behavior when the cluster supports it.
  --use-dlo             When used in conjunction with --segment-size it will
                        create a Dynamic Large Object. May be useful with old
                        swift clusters.
  --ignore-checksum     Turn off checksum validation for uploads.
  --skip-container-put  Assume all necessary containers already exist; don't
                        automatically try to create them.
  --object-name <object-name>
                        Upload file and name object to <object-name> or upload
                        dir and use <object-name> as object prefix instead of
                        folder name.
'''.strip('\n')


def st_upload(parser, args, output_manager, return_parser=False):
    DEFAULT_STDIN_SEGMENT = 10 * 1024 * 1024

    parser.add_argument(
        '-c', '--changed', action='store_true', dest='changed',
        default=False, help='Only upload files that have changed since '
        'the last upload.')
    parser.add_argument(
        '--skip-identical', action='store_true', dest='skip_identical',
        default=False, help='Skip uploading files that are identical on '
        'both sides.')
    parser.add_argument(
        '--skip-container-put', action='store_true', dest='skip_container_put',
        default=False, help='Assume all necessary containers already exist; '
        "don't automatically try to create them.")
    parser.add_argument(
        '-S', '--segment-size', dest='segment_size', help='Upload files '
        'in segments no larger than <size> (in Bytes) and then create a '
        '"manifest" file that will download all the segments as if it were '
        'the original file. Sizes may also be expressed as bytes with the '
        'B suffix, kilobytes with the K suffix, megabytes with the M suffix '
        'or gigabytes with the G suffix.')
    parser.add_argument(
        '-C', '--segment-container', dest='segment_container',
        help='Upload the segments into the specified container. '
        'If not specified, the segments will be uploaded to a '
        '<container>_segments container to not pollute the main '
        '<container> listings.')
    parser.add_argument(
        '--leave-segments', action='store_true',
        dest='leave_segments', default=False, help='Indicates that you want '
        'the older segments of manifest objects left alone (in the case of '
        'overwrites).')
    parser.add_argument(
        '--object-threads', type=int, default=10,
        help='Number of threads to use for uploading full objects. '
        'Its value must be a positive integer. Default is 10.')
    parser.add_argument(
        '--segment-threads', type=int, default=10,
        help='Number of threads to use for uploading object segments. '
        'Its value must be a positive integer. Default is 10.')
    parser.add_argument(
        '-m', '--meta', action='append', dest='meta', default=[],
        help='Sets a meta data item. This option may be repeated. '
        'Example: -m Color:Blue -m Size:Large')
    parser.add_argument(
        '-H', '--header', action='append', dest='header',
        default=[], help='Set request headers with the syntax header:value. '
        ' This option may be repeated. Example: -H "content-type:text/plain" '
        '-H "Content-Length: 4000"')
    parser.add_argument(
        '--use-slo', action='store_true', default=None,
        help='When used in conjunction with --segment-size, it will '
        'create a Static Large Object.')
    parser.add_argument(
        '--use-dlo', action='store_false', dest="use_slo", default=None,
        help='When used in conjunction with --segment-size, it will '
        'create a Dynamic Large Object.')
    parser.add_argument(
        '--object-name', dest='object_name',
        help='Upload file and name object to <object-name> or upload dir and '
        'use <object-name> as object prefix instead of folder name.')
    parser.add_argument(
        '--ignore-checksum', dest='checksum', default=True,
        action='store_false', help='Turn off checksum validation for uploads.')

    # We return the parser to build up the bash_completion
    if return_parser:
        return parser

    options, args = parse_args(parser, args)
    args = args[1:]
    if len(args) < 2:
        output_manager.error(
            'Usage: %s upload %s\n%s', BASENAME, st_upload_options,
            st_upload_help)
        return
    else:
        container = args[0]
        files = args[1:]
        from_stdin = '-' in files
        if from_stdin and len(files) > 1:
            output_manager.error(
                'upload from stdin cannot be used along with other files')
            return

    if options['object_name'] is not None:
        if len(files) > 1:
            output_manager.error('object-name only be used with 1 file or dir')
            return
        else:
            orig_path = files[0]
    elif from_stdin:
        output_manager.error(
            'object-name must be specified with uploads from stdin')
        return

    if options['segment_size']:
        try:
            # If segment size only has digits assume it is bytes
            int(options['segment_size'])
        except ValueError:
            try:
                size_mod = "BKMG".index(options['segment_size'][-1].upper())
                multiplier = int(options['segment_size'][:-1])
            except ValueError:
                output_manager.error("Invalid segment size")
                return

            options['segment_size'] = str((1024 ** size_mod) * multiplier)
        if int(options['segment_size']) <= 0:
            output_manager.error("segment-size should be positive")
            return

    if options['object_threads'] <= 0:
        output_manager.error(
            'ERROR: option --object-threads should be a positive integer.'
            '\n\nUsage: %s upload %s\n%s', BASENAME, st_upload_options,
            st_upload_help)
        return

    if options['segment_threads'] <= 0:
        output_manager.error(
            'ERROR: option --segment-threads should be a positive integer.'
            '\n\nUsage: %s upload %s\n%s', BASENAME, st_upload_options,
            st_upload_help)
        return

    if from_stdin:
        if options['use_slo'] is None:
            options['use_slo'] = True
        if not options['segment_size']:
            options['segment_size'] = DEFAULT_STDIN_SEGMENT

    options['object_uu_threads'] = options['object_threads']
    with SwiftService(options=options) as swift:
        try:
            objs = []
            dir_markers = []
            for f in files:
                if f == '-':
                    fd = io.open(stdin.fileno(), mode='rb')
                    objs.append(SwiftUploadObject(
                        fd, object_name=options['object_name']))
                    # We ensure that there is exactly one "file" to upload in
                    # this case -- stdin
                    break

                if isfile(f):
                    objs.append(f)
                elif isdir(f):
                    for (_dir, _ds, _fs) in walk(f):
                        if not (_ds + _fs):
                            dir_markers.append(_dir)
                        else:
                            objs.extend([join(_dir, _f) for _f in _fs])
                else:
                    output_manager.error("Local file '%s' not found" % f)

            # Now that we've collected all the required files and dir markers
            # build the tuples for the call to upload
            if options['object_name'] is not None and not from_stdin:
                objs = [
                    SwiftUploadObject(
                        o, object_name=o.replace(
                            orig_path, options['object_name'], 1
                        )
                    ) for o in objs
                ]
                dir_markers = [
                    SwiftUploadObject(
                        None, object_name=d.replace(
                            orig_path, options['object_name'], 1
                        ), options={'dir_marker': True}
                    ) for d in dir_markers
                ]

            for r in swift.upload(container, objs + dir_markers):
                if r['success']:
                    if options['verbose']:
                        if 'attempts' in r and r['attempts'] > 1:
                            if 'object' in r:
                                output_manager.print_msg(
                                    '%s [after %d attempts]' %
                                    (r['object'],
                                     r['attempts'])
                                )
                        else:
                            if 'object' in r:
                                output_manager.print_msg(r['object'])
                            elif 'for_object' in r:
                                output_manager.print_msg(
                                    '%s segment %s' % (r['for_object'],
                                                       r['segment_index'])
                                )
                else:
                    error = r['error']
                    if 'action' in r and r['action'] == "create_container":
                        # it is not an error to be unable to create the
                        # container so print a warning and carry on
                        if isinstance(error, ClientException):
                            if (r['headers'] and
                                    'X-Storage-Policy' in r['headers']):
                                msg = ' with Storage Policy %s' % \
                                      r['headers']['X-Storage-Policy'].strip()
                            else:
                                msg = ' '.join(str(x) for x in (
                                    error.http_status, error.http_reason)
                                )
                                if error.http_response_content:
                                    if msg:
                                        msg += ': '
                                    msg += (error.http_response_content
                                            .decode('utf8')[:60])
                                msg = ': %s' % msg
                        else:
                            msg = ': %s' % error
                        output_manager.warning(
                            'Warning: failed to create container '
                            "'%s'%s", r['container'], msg
                        )
                    else:
                        output_manager.error("%s" % error)
                        too_large = (isinstance(error, ClientException) and
                                     error.http_status == 413)
                        if too_large and options['verbose'] > 0:
                            output_manager.error(
                                "Consider using the --segment-size option "
                                "to chunk the object")

        except SwiftError as e:
            output_manager.error_with_txn_id(e)


st_capabilities_options = '''[--json] [<proxy_url>]
'''
st_info_options = st_capabilities_options
st_capabilities_help = '''
Retrieve capability of the proxy.

Optional positional arguments:
  <proxy_url>           Proxy URL of the cluster to retrieve capabilities.

Optional arguments:
  --json                Print the cluster capabilities in JSON format.
'''.strip('\n')
st_info_help = st_capabilities_help


def st_capabilities(parser, args, output_manager, return_parser=False):
    def _print_compo_cap(name, capabilities):
        for feature, options in sorted(capabilities.items(),
                                       key=lambda x: x[0]):
            output_manager.print_msg("%s: %s" % (name, feature))
            if options:
                output_manager.print_msg(" Options:")
                for key, value in sorted(options.items(),
                                         key=lambda x: x[0]):
                    output_manager.print_msg("  %s: %s" % (key, value))

    parser.add_argument('--json', action='store_true',
                        help='print capability information in json')

    # We return the parser to build up the bash_completion
    if return_parser:
        return parser

    (options, args) = parse_args(parser, args)
    if args and len(args) > 2:
        output_manager.error('Usage: %s capabilities %s\n%s',
                             BASENAME,
                             st_capabilities_options, st_capabilities_help)
        return

    with SwiftService(options=options) as swift:
        try:
            if len(args) == 2:
                url = args[1]
                capabilities_result = swift.capabilities(url)
                capabilities = capabilities_result['capabilities']
            else:
                capabilities_result = swift.capabilities()
                capabilities = capabilities_result['capabilities']

            if options['json']:
                output_manager.print_msg(
                    json.dumps(capabilities, sort_keys=True, indent=2))
            else:
                capabilities = dict(capabilities)
                _print_compo_cap('Core', {'swift': capabilities['swift']})
                del capabilities['swift']
                _print_compo_cap('Additional middleware', capabilities)
        except SwiftError as e:
            output_manager.error_with_txn_id(e)


st_info = st_capabilities

st_auth_help = '''
Display auth related authentication variables in shell friendly format.

  Commands to run to export storage url and auth token into
  OS_STORAGE_URL and OS_AUTH_TOKEN:

      swift auth

  Commands to append to a runcom file (e.g. ~/.bashrc, /etc/profile) for
  automatic authentication:

      swift auth -v -U test:tester -K testing \
          -A http://localhost:8080/auth/v1.0

'''.strip('\n')


def st_auth(parser, args, thread_manager, return_parser=False):

    # We return the parser to build up the bash_completion
    if return_parser:
        return parser

    (options, args) = parse_args(parser, args)
    if options['verbose'] > 1:
        if options['auth_version'] in ('1', '1.0'):
            print('export ST_AUTH=%s' % sh_quote(options['auth']))
            print('export ST_USER=%s' % sh_quote(options['user']))
            print('export ST_KEY=%s' % sh_quote(options['key']))
        else:
            print('export OS_IDENTITY_API_VERSION=%s' % sh_quote(
                options['auth_version']))
            print('export OS_AUTH_VERSION=%s' % sh_quote(
                options['auth_version']))
            print('export OS_AUTH_URL=%s' % sh_quote(options['auth']))
            for k, v in sorted(options.items()):
                if v and k.startswith('os_') and \
                        k not in ('os_auth_url', 'os_options'):
                    print('export %s=%s' % (k.upper(), sh_quote(v)))
    else:
        conn = get_conn(options)
        url, token = conn.get_auth()
        print('export OS_STORAGE_URL=%s' % sh_quote(url))
        print('export OS_AUTH_TOKEN=%s' % sh_quote(token))


st_tempurl_options = '''[--absolute] [--prefix-based] [--iso8601]
                     <method> <time> <path> <key>'''


st_tempurl_help = '''
Generates a temporary URL for a Swift object.

Positional arguments:
  <method>              An HTTP method to allow for this temporary URL.
                        Usually 'GET' or 'PUT'.
  <time>                The amount of time the temporary URL will be
                        valid. The time can be specified in three ways:
                        an integer representing the time in seconds;
                        a number with a 's', 'm', 'h', or 'd' suffix to specify
                        the time in seconds, minutes, hours, or days; or
                        an ISO 8601 timestamp in a specific format.
                        If --absolute is passed and time is an integer, the
                        seconds are intepreted as the Unix timestamp when the
                        temporary URL will expire.
                        The ISO 8601 timestamp can be specified in one of
                        following formats:

                        i) Complete date: YYYY-MM-DD (eg 1997-07-16)

                        ii) Complete date plus hours, minutes and seconds:

                            YYYY-MM-DDThh:mm:ss

                           (eg 1997-07-16T19:20:30)

                        iii) Complete date plus hours, minutes and seconds with
                             UTC designator:

                             YYYY-MM-DDThh:mm:ssZ

                             (eg 1997-07-16T19:20:30Z)

                        Please be aware that if you don't provide the UTC
                        designator (i.e., Z) the timestamp is generated using
                        your local timezone. If only a date is specified,
                        the time part used will equal to 00:00:00.
  <path>                The full path or storage URL to the Swift object.
                        Example: /v1/AUTH_account/c/o
                        or: http://saio:8080/v1/AUTH_account/c/o
  <key>                 The secret temporary URL key set on the Swift cluster.
                        To set a key, run \'swift post -m
                        "Temp-URL-Key:b3968d0207b54ece87cccc06515a89d4"\'

Optional arguments:
  --absolute            Interpret the <time> positional argument as a Unix
                        timestamp rather than a number of seconds in the
                        future. If an ISO 8601 timestamp is passed for <time>,
                        this argument is ignored.
  --prefix-based        If present, a prefix-based temporary URL will be
                        generated.
  --iso8601             If present, the generated temporary URL will contain an
                        ISO 8601 UTC timestamp instead of a Unix timestamp.
  --ip-range            If present, the temporary URL will be restricted to the
                        given ip or ip range.
  --digest              The digest algorithm to use. Defaults to sha256, but
                        older clusters may only support sha1.
'''.strip('\n')


def st_tempurl(parser, args, thread_manager, return_parser=False):
    parser.add_argument(
        '--absolute', action='store_true',
        dest='absolute_expiry', default=False,
        help=("If present, and time argument is an integer, "
              "time argument will be interpreted as a Unix "
              "timestamp representing when the temporary URL should expire, "
              "rather than an offset from the current time."),
    )
    parser.add_argument(
        '--prefix-based', action='store_true',
        default=False,
        help=("If present, a prefix-based temporary URL will be generated."),
    )
    parser.add_argument(
        '--iso8601', action='store_true',
        default=False,
        help=("If present, the temporary URL will contain an ISO 8601 UTC "
              "timestamp instead of a Unix timestamp."),
    )
    parser.add_argument(
        '--ip-range', action='store',
        default=None,
        help=("If present, the temporary URL will be restricted to the "
              "given ip or ip range."),
    )
    parser.add_argument(
        '--digest', choices=('sha1', 'sha256', 'sha512'),
        default='sha256',
        help=("The digest algorithm to use. Defaults to sha256, but "
              "older clusters may only support sha1."),
    )

    # We return the parser to build up the bash_completion
    if return_parser:
        return parser

    (options, args) = parse_args(parser, args)
    args = args[1:]
    if len(args) < 4:
        thread_manager.error('Usage: %s tempurl %s\n%s', BASENAME,
                             st_tempurl_options, st_tempurl_help)
        return
    method, timestamp, path, key = args[:4]

    parsed = urlparse(path)

    if method.upper() not in ['GET', 'PUT', 'HEAD', 'POST', 'DELETE']:
        thread_manager.print_msg('WARNING: Non default HTTP method %s for '
                                 'tempurl specified, possibly an error' %
                                 method.upper())
    try:
        path = generate_temp_url(parsed.path, timestamp, key, method,
                                 absolute=options['absolute_expiry'],
                                 iso8601=options['iso8601'],
                                 prefix=options['prefix_based'],
                                 ip_range=options['ip_range'],
                                 digest=options['digest'])
    except ValueError as err:
        thread_manager.error(err)
        return

    if parsed.scheme and parsed.netloc:
        url = "%s://%s%s" % (parsed.scheme, parsed.netloc, path)
    else:
        url = path
    thread_manager.print_msg(url)


st_bash_completion_help = '''Retrieve command specific flags used by bash_completion.

Optional positional arguments:
  <command>           Swift client command to filter the flags by.
'''.strip('\n')  # noqa


st_bash_completion_options = '''[command]
'''


def st_bash_completion(parser, args, thread_manager, return_parser=False):
    if return_parser:
        return parser

    global commands
    com = args[1] if len(args) > 1 else None

    if com:
        if com in commands:
            fn_commands = ["st_%s" % com]
        else:
            print("")
            return
    else:
        fn_commands = [fn for fn in globals().keys()
                       if fn.startswith('st_') and
                       not fn.endswith('_options') and
                       not fn.endswith('_help')]

    subparsers = parser.add_subparsers()
    subcommands = {}
    if not com:
        subcommands['base'] = parser
    for command in fn_commands:
        cmd = command[3:]
        if com:
            subparser = subparsers.add_parser(
                cmd, help=globals()['%s_help' % command])
            add_default_args(subparser)
            subparser = globals()[command](
                subparser, args, thread_manager, True)
            subcommands[cmd] = subparser
        else:
            subcommands[cmd] = None

    cmds = set()
    opts = set()
    for sc_str, sc in list(subcommands.items()):
        cmds.add(sc_str)
        if sc:
            for option in sc._optionals._option_string_actions:
                opts.add(option)

    for cmd_to_remove in (com, 'bash_completion', 'base'):
        if cmd_to_remove in cmds:
            cmds.remove(cmd_to_remove)
    print(' '.join(cmds | opts))


class HelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        if not action.option_strings:
            default = self._get_default_metavar_for_positional(action)
            metavar, = self._metavar_formatter(action, default)(1)
            return metavar

        else:
            parts = []

            # if the Optional doesn't take a value, format is:
            #    -s, --long
            if action.nargs == 0:
                parts.extend(action.option_strings)

            # if the Optional takes a value, format is:
            #    -s=ARGS, --long=ARGS
            else:
                default = self._get_default_metavar_for_optional(action)
                args_string = self._format_args(action, default)
                for option_string in action.option_strings:
                    parts.append('%s=%s' % (option_string, args_string))

            return ', '.join(parts)

    # Back-port py3 methods
    def _get_default_metavar_for_optional(self, action):
        return action.dest.upper()

    def _get_default_metavar_for_positional(self, action):
        return action.dest


def prompt_for_password():
    """
    Prompt the user for a password.

    :raise SystemExit: if a password cannot be entered without it being echoed
        to the terminal.
    :return: the entered password.
    """
    with warnings.catch_warnings():
        warnings.filterwarnings('error', category=getpass.GetPassWarning,
                                append=True)
        try:
            # temporarily set signal handling back to default to avoid user
            # Ctrl-c leaving terminal in weird state
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            return getpass.getpass()
        except EOFError:
            return None
        except getpass.GetPassWarning:
            exit('Input stream incompatible with --prompt option')
        finally:
            signal.signal(signal.SIGINT, immediate_exit)


def parse_args(parser, args, enforce_requires=True):
    options, args = parser.parse_known_args(args or ['-h'])
    options = vars(options)
    if enforce_requires and (options.get('debug') or options.get('info')):
        logging.getLogger("swiftclient")
        if options.get('debug'):
            logging.basicConfig(level=logging.DEBUG)
            logging.getLogger('iso8601').setLevel(logging.WARNING)
            client_logger_settings['redact_sensitive_headers'] = False
        elif options.get('info'):
            logging.basicConfig(level=logging.INFO)

    if args and options.get('help'):
        _help = globals().get('st_%s_help' % args[0])
        _options = globals().get('st_%s_options' % args[0], "\n")
        if _help:
            print("Usage: %s %s %s\n%s" % (BASENAME, args[0], _options, _help))
        else:
            print("no such command: %s" % args[0])
        exit()

    # Short circuit for tempurl, which doesn't need auth
    if args and args[0] == 'tempurl':
        return options, args

    # do this before process_options sets default auth version
    if enforce_requires and options['prompt']:
        options['key'] = options['os_password'] = prompt_for_password()

    # Massage auth version; build out os_options subdict
    process_options(options)

    if len(args) > 1 and args[0] == "capabilities":
        return options, args

    if (options['os_options']['object_storage_url'] and
            options['os_options']['auth_token']):
        return options, args

    if enforce_requires:
        if options['os_auth_type'] and options['os_auth_type'] not in (
                'password', 'v1password', 'v2password', 'v3password',
                'v3applicationcredential'):
            exit('Only "v3applicationcredential" is supported for '
                 '--os-auth-type')
        elif options['os_auth_type'] == 'v3applicationcredential':
            if not (options['os_application_credential_id'] and
                    options['os_application_credential_secret']):
                exit('Auth version 3 (application credential) requires '
                     'OS_APPLICATION_CREDENTIAL_ID and '
                     'OS_APPLICATION_CREDENTIAL_SECRET to be set or '
                     'overridden with --os-application-credential-id and '
                     '--os-application-credential-secret respectively.')
        elif options['auth_version'] == '3':
            if not options['auth']:
                exit('Auth version 3 requires OS_AUTH_URL to be set or '
                     'overridden with --os-auth-url')
            if not (options['user'] or options['os_user_id']):
                exit('Auth version 3 requires either OS_USERNAME or '
                     'OS_USER_ID to be set or overridden with '
                     '--os-username or --os-user-id respectively.')
            if not options['key']:
                exit('Auth version 3 requires OS_PASSWORD to be set or '
                     'overridden with --os-password')
        elif not (options['auth'] and options['user'] and options['key']):
            exit('''
Auth version 1.0 requires ST_AUTH, ST_USER, and ST_KEY environment variables
to be set or overridden with -A, -U, or -K.

Auth version 2.0 requires OS_AUTH_URL, OS_USERNAME, OS_PASSWORD, and
OS_TENANT_NAME OS_TENANT_ID to be set or overridden with --os-auth-url,
--os-username, --os-password, --os-tenant-name or os-tenant-id. Note:
adding "-V 2" is necessary for this.'''.strip('\n'))
    return options, args


def add_default_args(parser):
    default_auth_version = '1.0'
    for k in ('ST_AUTH_VERSION', 'OS_AUTH_VERSION', 'OS_IDENTITY_API_VERSION'):
        try:
            default_auth_version = environ[k]
            break
        except KeyError:
            pass

    parser.add_argument('--os-help', action='store_true', dest='os_help',
                        help='Show OpenStack authentication options.')
    parser.add_argument('--os_help', action='store_true',
                        help=argparse.SUPPRESS)
    parser.add_argument('-s', '--snet', action='store_true', dest='snet',
                        default=False, help='Use SERVICENET internal network.')
    parser.add_argument('-v', '--verbose', action='count', dest='verbose',
                        default=1, help='Print more info.')
    parser.add_argument('--debug', action='store_true', dest='debug',
                        default=False, help='Show the curl commands and '
                        'results of all http queries regardless of result '
                        'status.')
    parser.add_argument('--info', action='store_true', dest='info',
                        default=False, help='Show the curl commands and '
                        'results of all http queries which return an error.')
    parser.add_argument('-q', '--quiet', action='store_const', dest='verbose',
                        const=0, default=1, help='Suppress status output.')
    parser.add_argument('-A', '--auth', dest='auth',
                        default=environ.get('ST_AUTH'),
                        help='URL for obtaining an auth token.')
    parser.add_argument('-V', '--auth-version', '--os-identity-api-version',
                        dest='auth_version',
                        default=default_auth_version,
                        type=str,
                        help='Specify a version for authentication. '
                             'Defaults to env[ST_AUTH_VERSION], '
                             'env[OS_AUTH_VERSION], '
                             'env[OS_IDENTITY_API_VERSION] or 1.0.')
    parser.add_argument('-U', '--user', dest='user',
                        default=environ.get('ST_USER'),
                        help='User name for obtaining an auth token.')
    parser.add_argument('-K', '--key', dest='key',
                        default=environ.get('ST_KEY'),
                        help='Key for obtaining an auth token.')
    parser.add_argument('-T', '--timeout', type=parse_timeout, dest='timeout',
                        default=None,
                        help='Timeout in seconds to wait for response.')
    parser.add_argument('-R', '--retries', type=int, default=5, dest='retries',
                        help='The number of times to retry a failed '
                             'connection.')
    default_val = config_true_value(environ.get('SWIFTCLIENT_INSECURE'))
    parser.add_argument('--insecure',
                        action="store_true", dest="insecure",
                        default=default_val,
                        help='Allow swiftclient to access servers without '
                             'having to verify the SSL certificate. '
                             'Defaults to env[SWIFTCLIENT_INSECURE] '
                             '(set to \'true\' to enable).')
    parser.add_argument('--no-ssl-compression',
                        action='store_false', dest='ssl_compression',
                        default=True,
                        help='This option is deprecated and not used anymore. '
                             'SSL compression should be disabled by default '
                             'by the system SSL library.')
    parser.add_argument('--force-auth-retry',
                        action='store_true', dest='force_auth_retry',
                        default=False,
                        help='Force a re-auth attempt on '
                             'any error other than 401 unauthorized')
    parser.add_argument('--prompt',
                        action='store_true', dest='prompt',
                        default=False,
                        help='Prompt user to enter a password which overrides '
                             'any password supplied via --key, --os-password '
                             'or environment variables.')

    os_grp = parser.add_argument_group("OpenStack authentication options")
    os_grp.add_argument('--os-username',
                        metavar='<auth-user-name>',
                        default=environ.get('OS_USERNAME'),
                        help='OpenStack username. Defaults to '
                             'env[OS_USERNAME].')
    os_grp.add_argument('--os_username',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-user-id',
                        metavar='<auth-user-id>',
                        default=environ.get('OS_USER_ID'),
                        help='OpenStack user ID. '
                        'Defaults to env[OS_USER_ID].')
    os_grp.add_argument('--os_user_id',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-user-domain-id',
                        metavar='<auth-user-domain-id>',
                        default=environ.get('OS_USER_DOMAIN_ID'),
                        help='OpenStack user domain ID. '
                        'Defaults to env[OS_USER_DOMAIN_ID].')
    os_grp.add_argument('--os_user_domain_id',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-user-domain-name',
                        metavar='<auth-user-domain-name>',
                        default=environ.get('OS_USER_DOMAIN_NAME'),
                        help='OpenStack user domain name. '
                             'Defaults to env[OS_USER_DOMAIN_NAME].')
    os_grp.add_argument('--os_user_domain_name',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-password',
                        metavar='<auth-password>',
                        default=environ.get('OS_PASSWORD'),
                        help='OpenStack password. Defaults to '
                             'env[OS_PASSWORD].')
    os_grp.add_argument('--os_password',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-tenant-id',
                        metavar='<auth-tenant-id>',
                        default=environ.get('OS_TENANT_ID'),
                        help='OpenStack tenant ID. '
                        'Defaults to env[OS_TENANT_ID].')
    os_grp.add_argument('--os_tenant_id',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-tenant-name',
                        metavar='<auth-tenant-name>',
                        default=environ.get('OS_TENANT_NAME'),
                        help='OpenStack tenant name. '
                             'Defaults to env[OS_TENANT_NAME].')
    os_grp.add_argument('--os_tenant_name',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-project-id',
                        metavar='<auth-project-id>',
                        default=environ.get('OS_PROJECT_ID'),
                        help='OpenStack project ID. '
                        'Defaults to env[OS_PROJECT_ID].')
    os_grp.add_argument('--os_project_id',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-project-name',
                        metavar='<auth-project-name>',
                        default=environ.get('OS_PROJECT_NAME'),
                        help='OpenStack project name. '
                             'Defaults to env[OS_PROJECT_NAME].')
    os_grp.add_argument('--os_project_name',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-project-domain-id',
                        metavar='<auth-project-domain-id>',
                        default=environ.get('OS_PROJECT_DOMAIN_ID'),
                        help='OpenStack project domain ID. '
                        'Defaults to env[OS_PROJECT_DOMAIN_ID].')
    os_grp.add_argument('--os_project_domain_id',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-project-domain-name',
                        metavar='<auth-project-domain-name>',
                        default=environ.get('OS_PROJECT_DOMAIN_NAME'),
                        help='OpenStack project domain name. '
                             'Defaults to env[OS_PROJECT_DOMAIN_NAME].')
    os_grp.add_argument('--os_project_domain_name',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-auth-url',
                        metavar='<auth-url>',
                        default=environ.get('OS_AUTH_URL'),
                        help='OpenStack auth URL. Defaults to '
                             'env[OS_AUTH_URL].')
    os_grp.add_argument('--os_auth_url',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-auth-type',
                        metavar='<auth-type>',
                        default=environ.get('OS_AUTH_TYPE'),
                        help='OpenStack auth type for v3. Defaults to '
                             'env[OS_AUTH_TYPE].')
    os_grp.add_argument('--os_auth_type',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-application-credential-id',
                        metavar='<auth-application-credential-id>',
                        default=environ.get('OS_APPLICATION_CREDENTIAL_ID'),
                        help='OpenStack appplication credential id. '
                             'Defaults to env[OS_APPLICATION_CREDENTIAL_ID].')
    os_grp.add_argument('--os_application_credential_id',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-application-credential-secret',
                        metavar='<auth-application-credential-secret>',
                        default=environ.get(
                            'OS_APPLICATION_CREDENTIAL_SECRET'),
                        help='OpenStack appplication credential secret. '
                             'Defaults to '
                             'env[OS_APPLICATION_CREDENTIAL_SECRET].')
    os_grp.add_argument('--os_application_credential_secret',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-auth-token',
                        metavar='<auth-token>',
                        default=environ.get('OS_AUTH_TOKEN'),
                        help='OpenStack token. Defaults to '
                             'env[OS_AUTH_TOKEN]. Used with --os-storage-url '
                             'to bypass the usual username/password '
                             'authentication.')
    os_grp.add_argument('--os_auth_token',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-storage-url',
                        metavar='<storage-url>',
                        default=environ.get('OS_STORAGE_URL'),
                        help='OpenStack storage URL. '
                             'Defaults to env[OS_STORAGE_URL]. '
                             'Overrides the storage url returned during auth. '
                             'Will bypass authentication when used with '
                             '--os-auth-token.')
    os_grp.add_argument('--os_storage_url',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-region-name',
                        metavar='<region-name>',
                        default=environ.get('OS_REGION_NAME'),
                        help='OpenStack region name. '
                             'Defaults to env[OS_REGION_NAME].')
    os_grp.add_argument('--os_region_name',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-service-type',
                        metavar='<service-type>',
                        default=environ.get('OS_SERVICE_TYPE'),
                        help='OpenStack Service type. '
                             'Defaults to env[OS_SERVICE_TYPE].')
    os_grp.add_argument('--os_service_type',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-endpoint-type',
                        metavar='<endpoint-type>',
                        default=environ.get('OS_ENDPOINT_TYPE'),
                        help='OpenStack Endpoint type. '
                             'Defaults to env[OS_ENDPOINT_TYPE].')
    os_grp.add_argument('--os_endpoint_type',
                        help=argparse.SUPPRESS)
    os_grp.add_argument('--os-cacert',
                        metavar='<ca-certificate>',
                        default=environ.get('OS_CACERT'),
                        help='Specify a CA bundle file to use in verifying a '
                        'TLS (https) server certificate. '
                        'Defaults to env[OS_CACERT].')
    os_grp.add_argument('--os-cert',
                        metavar='<client-certificate-file>',
                        default=environ.get('OS_CERT'),
                        help='Specify a client certificate file (for client '
                        'auth). Defaults to env[OS_CERT].')
    os_grp.add_argument('--os-key',
                        metavar='<client-certificate-key-file>',
                        default=environ.get('OS_KEY'),
                        help='Specify a client certificate key file (for '
                        'client auth). Defaults to env[OS_KEY].')


def main(arguments=None):
    argv = sys_argv if arguments is None else arguments

    parser = argparse.ArgumentParser(
        add_help=False, formatter_class=HelpFormatter, usage='''
%(prog)s [--version] [--help] [--os-help] [--snet] [--verbose]
             [--debug] [--info] [--quiet] [--auth <auth_url>]
             [--auth-version <auth_version> |
                 --os-identity-api-version <auth_version> ]
             [--user <username>]
             [--key <api_key>] [--retries <num_retries>]
             [--os-username <auth-user-name>]
             [--os-password <auth-password>]
             [--os-user-id <auth-user-id>]
             [--os-user-domain-id <auth-user-domain-id>]
             [--os-user-domain-name <auth-user-domain-name>]
             [--os-tenant-id <auth-tenant-id>]
             [--os-tenant-name <auth-tenant-name>]
             [--os-project-id <auth-project-id>]
             [--os-project-name <auth-project-name>]
             [--os-project-domain-id <auth-project-domain-id>]
             [--os-project-domain-name <auth-project-domain-name>]
             [--os-auth-url <auth-url>]
             [--os-auth-token <auth-token>]
             [--os-auth-type <os-auth-type>]
             [--os-application-credential-id
                   <auth-application-credential-id>]
             [--os-application-credential-secret
                   <auth-application-credential-secret>]
             [--os-storage-url <storage-url>]
             [--os-region-name <region-name>]
             [--os-service-type <service-type>]
             [--os-endpoint-type <endpoint-type>]
             [--os-cacert <ca-certificate>]
             [--insecure]
             [--os-cert <client-certificate-file>]
             [--os-key <client-certificate-key-file>]
             [--no-ssl-compression]
             [--force-auth-retry]
             <subcommand> [--help] [<subcommand options>]

Command-line interface to the OpenStack Swift API.

Positional arguments:
  <subcommand>
    delete               Delete a container or objects within a container.
    download             Download objects from containers.
    list                 Lists the containers for the account or the objects
                         for a container.
    post                 Updates meta information for the account, container,
                         or object; creates containers if not present.
    copy                 Copies object, optionally adds meta
    stat                 Displays information for the account, container,
                         or object.
    upload               Uploads files or directories to the given container.
    capabilities         List cluster capabilities.
    tempurl              Create a temporary URL.
    auth                 Display auth related environment variables.
    bash_completion      Outputs option and flag cli data ready for
                         bash_completion.

Examples:
  %(prog)s download --help

  %(prog)s -A https://api.example.com/v1.0 \\
      -U user -K api_key stat -v

  %(prog)s --os-auth-url https://api.example.com/v2.0 \\
      --os-tenant-name tenant \\
      --os-username user --os-password password list

  %(prog)s --os-auth-url https://api.example.com/v3 --auth-version 3\\
      --os-project-name project1 --os-project-domain-name domain1 \\
      --os-username user --os-user-domain-name domain1 \\
      --os-password password list

  %(prog)s --os-auth-url https://api.example.com/v3 --auth-version 3\\
      --os-project-id 0123456789abcdef0123456789abcdef \\
      --os-user-id abcdef0123456789abcdef0123456789 \\
      --os-password password list

  %(prog)s --os-auth-url https://api.example.com/v3 --auth-version 3\\
      --os-application-credential-id d78683c92f0e4f9b9b02a2e208039412 \\
      --os-application-credential-secret APPLICATION_CREDENTIAL_SECRET \\
      --os-auth-type v3applicationcredential list

  %(prog)s --os-auth-token 6ee5eb33efad4e45ab46806eac010566 \\
      --os-storage-url https://10.1.5.2:8080/v1/AUTH_ced809b6a4baea7aeab61a \\
      list

  %(prog)s list --lh
'''.strip('\n'))

    version = client_version
    parser.add_argument('--version', action='version',
                        version='python-swiftclient %s' % version)
    parser.add_argument('-h', '--help', action='store_true')

    add_default_args(parser)

    options, args = parse_args(parser, argv[1:], enforce_requires=False)

    if options['help'] or options['os_help']:
        if options['help']:
            parser._action_groups.pop()
        parser.print_help()
        exit()

    if not args or args[0] not in commands:
        parser.print_usage()
        if args:
            exit('no such command: %s' % args[0])
        exit()

    signal.signal(signal.SIGINT, immediate_exit)

    with OutputManager() as output:
        parser.usage = globals()['st_%s_help' % args[0]]
        if options['insecure']:
            import requests
            try:
                from requests.packages.urllib3.exceptions import \
                    InsecureRequestWarning
            except ImportError:
                pass
            else:
                requests.packages.urllib3.disable_warnings(
                    InsecureRequestWarning)
        try:
            globals()['st_%s' % args[0]](parser, argv[1:], output)
        except ClientException as err:
            trans_id = err.transaction_id
            err.transaction_id = None  # clear it so we aren't overly noisy
            output.error(str(err))
            if trans_id:
                output.error("Failed Transaction ID: %s",
                             parse_header_string(trans_id))
        except (RequestException, socket.error) as err:
            output.error(str(err))

    if output.get_error_count() > 0:
        exit(1)


if __name__ == '__main__':
    main()
