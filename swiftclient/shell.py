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

from __future__ import print_function

import logging
import signal
import socket

from optparse import OptionParser, OptionGroup, SUPPRESS_HELP
from os import environ, walk, _exit as os_exit
from os.path import isfile, isdir, join
from sys import argv as sys_argv, exit, stderr
from time import gmtime, strftime

from swiftclient import RequestException
from swiftclient.utils import config_true_value, generate_temp_url, prt_bytes
from swiftclient.multithreading import OutputManager
from swiftclient.exceptions import ClientException
from swiftclient import __version__ as client_version
from swiftclient.service import SwiftService, SwiftError, SwiftUploadObject
from swiftclient.command_helpers import print_account_stats, \
    print_container_stats, print_object_stats


BASENAME = 'swift'
commands = ('delete', 'download', 'list', 'post',
            'stat', 'upload', 'capabilities', 'info', 'tempurl')


def immediate_exit(signum, frame):
    stderr.write(" Aborted\n")
    os_exit(2)

st_delete_options = '''[-all] [--leave-segments]
                    [--object-threads <threads>]
                    [--container-threads <threads>]
                    <container> [object]
'''

st_delete_help = '''
Delete a container or objects within a container.

Positional arguments:
  <container>           Name of container to delete from.
  [object]              Name of object to delete. Specify multiple times
                        for multiple objects.

Optional arguments:
  --all                 Delete all containers and objects.
  --leave-segments      Do not delete segments of manifest objects.
  --object-threads <threads>
                        Number of threads to use for deleting objects.
                        Default is 10.
  --container-threads <threads>
                        Number of threads to use for deleting containers.
                        Default is 10.
'''.strip("\n")


def st_delete(parser, args, output_manager):
    parser.add_option(
        '-a', '--all', action='store_true', dest='yes_all',
        default=False, help='Delete all containers and objects.')
    parser.add_option(
        '', '--leave-segments', action='store_true',
        dest='leave_segments', default=False,
        help='Do not delete segments of manifest objects.')
    parser.add_option(
        '', '--object-threads', type=int,
        default=10, help='Number of threads to use for deleting objects. '
        'Default is 10.')
    parser.add_option('', '--container-threads', type=int,
                      default=10, help='Number of threads to use for '
                      'deleting containers. '
                      'Default is 10.')
    (options, args) = parse_args(parser, args)
    args = args[1:]
    if (not args and not options.yes_all) or (args and options.yes_all):
        output_manager.error('Usage: %s delete %s\n%s',
                             BASENAME, st_delete_options,
                             st_delete_help)
        return

    _opts = vars(options)
    _opts['object_dd_threads'] = options.object_threads
    with SwiftService(options=_opts) as swift:
        try:
            if not args:
                del_iter = swift.delete()
            else:
                container = args[0]
                if '/' in container:
                    output_manager.error(
                        'WARNING: / in container name; you '
                        'might have meant %r instead of %r.' % (
                        container.replace('/', ' ', 1), container)
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
                a = r.get('attempts')

                if r['success']:
                    if options.verbose:
                        a = ' [after {0} attempts]'.format(a) if a > 1 else ''

                        if r['action'] == 'delete_object':
                            if options.yes_all:
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
            output_manager.error(err.value)


st_download_options = '''[--all] [--marker] [--prefix <prefix>]
                      [--output <out_file>] [--object-threads <threads>]
                      [--container-threads <threads>] [--no-download]
                      [--skip-identical] <container> <object>
'''

st_download_help = '''
Download objects from containers.

Positional arguments:
  <container>           Name of container to download from. To download a
                        whole account, omit this and specify --all.
  <object>              Name of object to download. Specify multiple times
                        for multiple objects. Omit this to download all
                        objects from the container.

Optional arguments:
  --all                 Indicates that you really want to download
                        everything in the account.
  --marker              Marker to use when starting a container or account
                        download.
  --prefix <prefix>     Only download items beginning with <prefix>
  --output <out_file>   For a single file download, stream the output to
                        <out_file>. Specifying "-" as <out_file> will
                        redirect to stdout.
  --object-threads <threads>
                        Number of threads to use for downloading objects.
                        Default is 10.
  --container-threads <threads>
                        Number of threads to use for downloading containers.
                        Default is 10.
  --no-download         Perform download(s), but don't actually write anything
                        to disk.
  --header <header_name:header_value>
                        Adds a customized request header to the query, like
                        "Range" or "If-Match". This argument is repeatable.
                        Example --header "content-type:text/plain"
  --skip-identical      Skip downloading files that are identical on both
                        sides.
'''.strip("\n")


def st_download(parser, args, output_manager):
    parser.add_option(
        '-a', '--all', action='store_true', dest='yes_all',
        default=False, help='Indicates that you really want to download '
        'everything in the account.')
    parser.add_option(
        '-m', '--marker', dest='marker',
        default='', help='Marker to use when starting a container or '
        'account download.')
    parser.add_option(
        '-p', '--prefix', dest='prefix',
        help='Only download items beginning with the <prefix>.')
    parser.add_option(
        '-o', '--output', dest='out_file', help='For a single '
        'download, stream the output to <out_file>. '
        'Specifying "-" as <out_file> will redirect to stdout.')
    parser.add_option(
        '', '--object-threads', type=int,
        default=10, help='Number of threads to use for downloading objects. '
        'Default is 10.')
    parser.add_option(
        '', '--container-threads', type=int, default=10,
        help='Number of threads to use for downloading containers. '
        'Default is 10.')
    parser.add_option(
        '', '--no-download', action='store_true',
        default=False,
        help="Perform download(s), but don't actually write anything to disk.")
    parser.add_option(
        '-H', '--header', action='append', dest='header',
        default=[],
        help='Adds a customized request header to the query, like "Range" or '
        '"If-Match". This argument is repeatable. '
        'Example: --header "content-type:text/plain"')
    parser.add_option(
        '--skip-identical', action='store_true', dest='skip_identical',
        default=False, help='Skip downloading files that are identical on '
        'both sides.')
    (options, args) = parse_args(parser, args)
    args = args[1:]
    if options.out_file == '-':
        options.verbose = 0

    if options.out_file and len(args) != 2:
        exit('-o option only allowed for single file downloads')

    if (not args and not options.yes_all) or (args and options.yes_all):
        output_manager.error('Usage: %s download %s\n%s', BASENAME,
                             st_download_options, st_download_help)
        return

    _opts = vars(options)
    _opts['object_dd_threads'] = options.object_threads
    with SwiftService(options=_opts) as swift:
        try:
            if not args:
                down_iter = swift.download()
            else:
                container = args[0]
                if '/' in container:
                    output_manager.error(
                        'WARNING: / in container name; you '
                        'might have meant %r instead of %r.' % (
                        container.replace('/', ' ', 1), container)
                    )
                    return
                objects = args[1:]
                if not objects:
                    down_iter = swift.download(container)
                else:
                    down_iter = swift.download(container, objects)

            for down in down_iter:
                if options.out_file == '-' and 'contents' in down:
                    contents = down['contents']
                    for chunk in contents:
                        output_manager.print_raw(chunk)
                else:
                    if down['success']:
                        if options.verbose:
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
                                    options.skip_identical:
                                output_manager.print_msg(
                                    "Skipped identical file '%s'", path)
                                continue
                            if error.http_status == 404:
                                output_manager.error(
                                    "Object '%s/%s' not found", container, obj)
                                continue
                        output_manager.error(
                            "Error downloading object '%s/%s': %s",
                            container, obj, error)

        except SwiftError as e:
            output_manager.error(e.value)


st_list_options = '''[--long] [--lh] [--totals] [--prefix <prefix>]
                  [--delimiter <delimiter>]
'''

st_list_help = '''
Lists the containers for the account or the objects for a container.

Positional arguments:
  [container]           Name of container to list object in.

Optional arguments:
  --long                Long listing format, similar to ls -l.
  --lh                  Report sizes in human readable format similar to
                        ls -lh.
  --totals              Used with -l or --lh, only report totals.
  --prefix              Only list items beginning with the prefix.
  --delimiter           Roll up items with the given delimiter. For containers
                        only. See OpenStack Swift API documentation for what
                        this means.
'''.strip('\n')


def st_list(parser, args, output_manager):

    def _print_stats(options, stats):
        total_count = total_bytes = 0
        container = stats.get("container", None)
        for item in stats["listing"]:
            item_name = item.get('name')
            if not options.long and not options.human:
                output_manager.print_msg(item.get('name', item.get('subdir')))
            else:
                if not container:    # listing containers
                    item_bytes = item.get('bytes')
                    byte_str = prt_bytes(item_bytes, options.human)
                    count = item.get('count')
                    total_count += count
                    try:
                        meta = item.get('meta')
                        utc = gmtime(float(meta.get('x-timestamp')))
                        datestamp = strftime('%Y-%m-%d %H:%M:%S', utc)
                    except TypeError:
                        datestamp = '????-??-?? ??:??:??'
                    if not options.totals:
                        output_manager.print_msg(
                            "%5s %s %s %s", count, byte_str,
                            datestamp, item_name)
                else:    # list container contents
                    subdir = item.get('subdir')
                    if subdir is None:
                        item_bytes = item.get('bytes')
                        byte_str = prt_bytes(item_bytes, options.human)
                        date, xtime = item.get('last_modified').split('T')
                        xtime = xtime.split('.')[0]
                    else:
                        item_bytes = 0
                        byte_str = prt_bytes(item_bytes, options.human)
                        date = xtime = ''
                        item_name = subdir
                    if not options.totals:
                        output_manager.print_msg(
                            "%s %10s %8s %s", byte_str, date, xtime, item_name)
                total_bytes += item_bytes

        # report totals
        if options.long or options.human:
            if not container:
                output_manager.print_msg(
                    "%5s %s", prt_bytes(total_count, True),
                    prt_bytes(total_bytes, options.human))
            else:
                output_manager.print_msg(
                    prt_bytes(total_bytes, options.human))

    parser.add_option(
        '-l', '--long', dest='long', action='store_true', default=False,
        help='Long listing format, similar to ls -l.')
    parser.add_option(
        '--lh', dest='human', action='store_true',
        default=False, help='Report sizes in human readable format, '
        "similar to ls -lh.")
    parser.add_option(
        '-t', '--totals', dest='totals',
        help='used with -l or --lh, only report totals.',
        action='store_true', default=False)
    parser.add_option(
        '-p', '--prefix', dest='prefix',
        help='Only list items beginning with the prefix.')
    parser.add_option(
        '-d', '--delimiter', dest='delimiter',
        help='Roll up items with the given delimiter. For containers '
             'only. See OpenStack Swift API documentation for '
             'what this means.')
    (options, args) = parse_args(parser, args)
    args = args[1:]
    if options.delimiter and not args:
        exit('-d option only allowed for container listings')

    _opts = vars(options).copy()
    if _opts['human']:
        _opts.pop('human')
        _opts['long'] = True

    if options.totals and not options.long and not options.human:
        output_manager.error(
            "Listing totals only works with -l or --lh.")
        return

    with SwiftService(options=_opts) as swift:
        try:
            if not args:
                stats_parts_gen = swift.list()
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

            for stats in stats_parts_gen:
                if stats["success"]:
                    _print_stats(options, stats)
                else:
                    raise stats["error"]

        except SwiftError as e:
            output_manager.error(e.value)


st_stat_options = '''[--lh]
                  [container] [object]
'''

st_stat_help = '''
Displays information for the account, container, or object.

Positional arguments:
  [container]           Name of container to stat from.
  [object]              Name of object to stat.

Optional arguments:
  --lh                  Report sizes in human readable format similar to
                        ls -lh.
'''.strip('\n')


def st_stat(parser, args, output_manager):
    parser.add_option(
        '--lh', dest='human', action='store_true', default=False,
        help='Report sizes in human readable format similar to ls -lh.')
    (options, args) = parse_args(parser, args)
    args = args[1:]

    _opts = vars(options)

    with SwiftService(options=_opts) as swift:
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
                        'meant %r instead of %r.' %
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
                                raise(stat_result["error"])
                    else:
                        output_manager.error(
                            'Usage: %s stat %s\n%s', BASENAME,
                            st_stat_options, st_stat_help)

        except SwiftError as e:
            output_manager.error(e.value)


st_post_options = '''[--read-acl <acl>] [--write-acl <acl>] [--sync-to]
                  [--sync-key <sync-key>] [--meta <name:value>]
                  [--header <header>]
                  [container] [object]
'''

st_post_help = '''
Updates meta information for the account, container, or object.
If the container is not found, it will be created automatically.

Positional arguments:
  [container]           Name of container to post to.
  [object]              Name of object to post.

Optional arguments:
  --read-acl <acl>      Read ACL for containers. Quick summary of ACL syntax:
                        .r:*, .r:-.example.com, .r:www.example.com, account1,
                        account2:user2
  --write-acl <acl>     Write ACL for containers. Quick summary of ACL syntax:
                        account1 account2:user2
  --sync-to <sync-to>   Sync To for containers, for multi-cluster replication.
  --sync-key <sync-key> Sync Key for containers, for multi-cluster replication.
  --meta <name:value>   Sets a meta data item. This option may be repeated.
                        Example: -m Color:Blue -m Size:Large
  --header <header>     Set request headers. This option may be repeated.
                        Example -H "content-type:text/plain"
'''.strip('\n')


def st_post(parser, args, output_manager):
    parser.add_option(
        '-r', '--read-acl', dest='read_acl', help='Read ACL for containers. '
        'Quick summary of ACL syntax: .r:*, .r:-.example.com, '
        '.r:www.example.com, account1, account2:user2')
    parser.add_option(
        '-w', '--write-acl', dest='write_acl', help='Write ACL for '
        'containers. Quick summary of ACL syntax: account1, '
        'account2:user2')
    parser.add_option(
        '-t', '--sync-to', dest='sync_to', help='Sets the '
        'Sync To for containers, for multi-cluster replication.')
    parser.add_option(
        '-k', '--sync-key', dest='sync_key', help='Sets the '
        'Sync Key for containers, for multi-cluster replication.')
    parser.add_option(
        '-m', '--meta', action='append', dest='meta', default=[],
        help='Sets a meta data item. This option may be repeated. '
        'Example: -m Color:Blue -m Size:Large')
    parser.add_option(
        '-H', '--header', action='append', dest='header',
        default=[], help='Set request headers. This option may be repeated. '
        'Example: -H "content-type:text/plain" '
        '-H "Content-Length: 4000"')
    (options, args) = parse_args(parser, args)
    args = args[1:]
    if (options.read_acl or options.write_acl or options.sync_to or
            options.sync_key) and not args:
        exit('-r, -w, -t, and -k options only allowed for containers')

    _opts = vars(options)

    with SwiftService(options=_opts) as swift:
        try:
            if not args:
                result = swift.post()
            else:
                container = args[0]
                if '/' in container:
                    output_manager.error(
                        'WARNING: / in container name; you might have '
                        'meant %r instead of %r.' %
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
                raise(result["error"])

        except SwiftError as e:
            output_manager.error(e.value)


st_upload_options = '''[--changed] [--skip-identical] [--segment-size <size>]
                    [--segment-container <container>] [--leave-segments]
                    [--object-threads <thread>] [--segment-threads <threads>]
                    [--header <header>] [--use-slo] [--ignore-checksum]
                    [--object-name <object-name>]
                    <container> <file_or_directory>
'''

st_upload_help = '''
Uploads specified files and directories to the given container.

Positional arguments:
  <container>           Name of container to upload to.
  <file_or_directory>   Name of file or directory to upload. Specify multiple
                        times for multiple uploads.

Optional arguments:
  --changed             Only upload files that have changed since the last
                        upload.
  --skip-identical      Skip uploading files that are identical on both sides.
  --segment-size <size> Upload files in segments no larger than <size> (in
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
  --header <header>     Set request headers with the syntax header:value.
                        This option may be repeated.
                        Example -H "content-type:text/plain".
  --use-slo             When used in conjunction with --segment-size it will
                        create a Static Large Object instead of the default
                        Dynamic Large Object.
  --object-name <object-name>
                        Upload file and name object to <object-name> or upload
                        dir and use <object-name> as object prefix instead of
                        folder name.
  --ignore-checksum     Turn off checksum validation for uploads.
'''.strip('\n')


def st_upload(parser, args, output_manager):
    parser.add_option(
        '-c', '--changed', action='store_true', dest='changed',
        default=False, help='Only upload files that have changed since '
        'the last upload.')
    parser.add_option(
        '--skip-identical', action='store_true', dest='skip_identical',
        default=False, help='Skip uploading files that are identical on '
        'both sides.')
    parser.add_option(
        '-S', '--segment-size', dest='segment_size', help='Upload files '
        'in segments no larger than <size> (in Bytes) and then create a '
        '"manifest" file that will download all the segments as if it were '
        'the original file. Sizes may also be expressed as bytes with the '
        'B suffix, kilobytes with the K suffix, megabytes with the M suffix '
        'or gigabytes with the G suffix.')
    parser.add_option(
        '-C', '--segment-container', dest='segment_container',
        help='Upload the segments into the specified container. '
        'If not specified, the segments will be uploaded to a '
        '<container>_segments container to not pollute the main '
        '<container> listings.')
    parser.add_option(
        '', '--leave-segments', action='store_true',
        dest='leave_segments', default=False, help='Indicates that you want '
        'the older segments of manifest objects left alone (in the case of '
        'overwrites).')
    parser.add_option(
        '', '--object-threads', type=int, default=10,
        help='Number of threads to use for uploading full objects. '
        'Default is 10.')
    parser.add_option(
        '', '--segment-threads', type=int, default=10,
        help='Number of threads to use for uploading object segments. '
        'Default is 10.')
    parser.add_option(
        '-H', '--header', action='append', dest='header',
        default=[], help='Set request headers with the syntax header:value. '
        ' This option may be repeated. Example -H "content-type:text/plain" '
        '-H "Content-Length: 4000"')
    parser.add_option(
        '', '--use-slo', action='store_true', default=False,
        help='When used in conjunction with --segment-size, it will '
        'create a Static Large Object instead of the default '
        'Dynamic Large Object.')
    parser.add_option(
        '', '--object-name', dest='object_name',
        help='Upload file and name object to <object-name> or upload dir and '
        'use <object-name> as object prefix instead of folder name.')
    parser.add_option(
        '', '--ignore-checksum', dest='checksum', default=True,
        action='store_false', help='Turn off checksum validation for uploads.')
    (options, args) = parse_args(parser, args)
    args = args[1:]
    if len(args) < 2:
        output_manager.error(
            'Usage: %s upload %s\n%s', BASENAME, st_upload_options,
            st_upload_help)
        return
    else:
        container = args[0]
        files = args[1:]

    if options.object_name is not None:
        if len(files) > 1:
            output_manager.error('object-name only be used with 1 file or dir')
            return
        else:
            orig_path = files[0]

    if options.segment_size:
        try:
            # If segment size only has digits assume it is bytes
            int(options.segment_size)
        except ValueError:
            try:
                size_mod = "BKMG".index(options.segment_size[-1].upper())
                multiplier = int(options.segment_size[:-1])
            except ValueError:
                output_manager.error("Invalid segment size")
                return

            options.segment_size = str((1024 ** size_mod) * multiplier)

    _opts = vars(options)
    _opts['object_uu_threads'] = options.object_threads
    with SwiftService(options=_opts) as swift:
        try:
            objs = []
            dir_markers = []
            for f in files:
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
            if options.object_name is not None:
                objs = [
                    SwiftUploadObject(
                        o, object_name=o.replace(
                            orig_path, options.object_name, 1
                        )
                    ) for o in objs
                ]
                dir_markers = [
                    SwiftUploadObject(
                        None, object_name=d.replace(
                            orig_path, options.object_name, 1
                        ), options={'dir_marker': True}
                    ) for d in dir_markers
                ]

            for r in swift.upload(container, objs + dir_markers):
                if r['success']:
                    if options.verbose:
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
                                    msg += error.http_response_content[:60]
                                msg = ': %s' % msg
                        else:
                            msg = ': %s' % error
                        output_manager.warning(
                            'Warning: failed to create container '
                            '%r%s', container, msg
                        )
                    else:
                        output_manager.error("%s" % error)
                        too_large = (isinstance(error, ClientException) and
                                     error.http_status == 413)
                        if too_large and options.verbose > 0:
                            output_manager.error(
                                "Consider using the --segment-size option "
                                "to chunk the object")

        except SwiftError as e:
            output_manager.error(e.value)


st_capabilities_options = "[<proxy_url>]"
st_info_options = st_capabilities_options
st_capabilities_help = '''
Retrieve capability of the proxy.

Optional positional arguments:
  <proxy_url>           Proxy URL of the cluster to retrieve capabilities.
'''.strip('\n')
st_info_help = st_capabilities_help


def st_capabilities(parser, args, output_manager):
    def _print_compo_cap(name, capabilities):
        for feature, options in sorted(capabilities.items(),
                                       key=lambda x: x[0]):
            output_manager.print_msg("%s: %s" % (name, feature))
            if options:
                output_manager.print_msg(" Options:")
                for key, value in sorted(options.items(),
                                         key=lambda x: x[0]):
                    output_manager.print_msg("  %s: %s" % (key, value))

    (options, args) = parse_args(parser, args)
    if args and len(args) > 2:
        output_manager.error('Usage: %s capabilities %s\n%s',
                             BASENAME,
                             st_capabilities_options, st_capabilities_help)
        return

    _opts = vars(options)
    with SwiftService(options=_opts) as swift:
        try:
            if len(args) == 2:
                url = args[1]
                capabilities_result = swift.capabilities(url)
                capabilities = capabilities_result['capabilities']
            else:
                capabilities_result = swift.capabilities()
                capabilities = capabilities_result['capabilities']

            _print_compo_cap('Core', {'swift': capabilities['swift']})
            del capabilities['swift']
            _print_compo_cap('Additional middleware', capabilities)
        except SwiftError as e:
            output_manager.error(e.value)


st_info = st_capabilities


st_tempurl_options = '<method> <seconds> <path> <key>'


st_tempurl_help = '''
Generates a temporary URL for a Swift object.

Positions arguments:
  [method]              An HTTP method to allow for this temporary URL.
                        Usually 'GET' or 'PUT'.
  [seconds]             The amount of time in seconds the temporary URL will
                        be valid for.
  [path]                The full path to the Swift object. Example:
                        /v1/AUTH_account/c/o.
  [key]                 The secret temporary URL key set on the Swift cluster.
                        To set a key, run \'swift post -m
                        "Temp-URL-Key:b3968d0207b54ece87cccc06515a89d4"\'
'''.strip('\n')


def st_tempurl(parser, args, thread_manager):
    (options, args) = parse_args(parser, args)
    args = args[1:]
    if len(args) < 4:
        thread_manager.error('Usage: %s tempurl %s\n%s', BASENAME,
                             st_tempurl_options, st_tempurl_help)
        return
    method, seconds, path, key = args[:4]
    try:
        seconds = int(seconds)
    except ValueError:
        thread_manager.error('Seconds must be an integer')
        return
    if method.upper() not in ['GET', 'PUT', 'HEAD', 'POST', 'DELETE']:
        thread_manager.print_msg('WARNING: Non default HTTP method %s for '
                                 'tempurl specified, possibly an error' %
                                 method.upper())
    url = generate_temp_url(path, seconds, key, method)
    thread_manager.print_msg(url)


def parse_args(parser, args, enforce_requires=True):
    if not args:
        args = ['-h']
    (options, args) = parser.parse_args(args)

    if len(args) > 1 and args[1] == '--help':
        _help = globals().get('st_%s_help' % args[0],
                              "no help for %s" % args[0])
        print(_help)
        exit()

    # Short circuit for tempurl, which doesn't need auth
    if len(args) > 0 and args[0] == 'tempurl':
        return options, args

    if options.auth_version == '3.0':
        # tolerate sloppy auth_version
        options.auth_version = '3'

    if (not (options.auth and options.user and options.key)
            and options.auth_version != '3'):
        # Use keystone auth if any of the old-style args are missing
        options.auth_version = '2.0'

    # Use new-style args if old ones not present
    if not options.auth and options.os_auth_url:
        options.auth = options.os_auth_url
    if not options.user and options.os_username:
        options.user = options.os_username
    if not options.key and options.os_password:
        options.key = options.os_password

    # Specific OpenStack options
    options.os_options = {
        'user_id': options.os_user_id,
        'user_domain_id': options.os_user_domain_id,
        'user_domain_name': options.os_user_domain_name,
        'tenant_id': options.os_tenant_id,
        'tenant_name': options.os_tenant_name,
        'project_id': options.os_project_id,
        'project_name': options.os_project_name,
        'project_domain_id': options.os_project_domain_id,
        'project_domain_name': options.os_project_domain_name,
        'service_type': options.os_service_type,
        'endpoint_type': options.os_endpoint_type,
        'auth_token': options.os_auth_token,
        'object_storage_url': options.os_storage_url,
        'region_name': options.os_region_name,
    }

    if len(args) > 1 and args[0] == "capabilities":
        return options, args

    if (options.os_options.get('object_storage_url') and
            options.os_options.get('auth_token') and
            (options.auth_version == '2.0' or options.auth_version == '3')):
        return options, args

    if enforce_requires:
        if options.auth_version == '3':
            if not options.auth:
                exit('Auth version 3 requires OS_AUTH_URL to be set or ' +
                     'overridden with --os-auth-url')
            if not (options.user or options.os_user_id):
                exit('Auth version 3 requires either OS_USERNAME or ' +
                     'OS_USER_ID to be set or overridden with ' +
                     '--os-username or --os-user-id respectively.')
            if not options.key:
                exit('Auth version 3 requires OS_PASSWORD to be set or ' +
                     'overridden with --os-password')
        elif not (options.auth and options.user and options.key):
            exit('''
Auth version 1.0 requires ST_AUTH, ST_USER, and ST_KEY environment variables
to be set or overridden with -A, -U, or -K.

Auth version 2.0 requires OS_AUTH_URL, OS_USERNAME, OS_PASSWORD, and
OS_TENANT_NAME OS_TENANT_ID to be set or overridden with --os-auth-url,
--os-username, --os-password, --os-tenant-name or os-tenant-id. Note:
adding "-V 2" is necessary for this.'''.strip('\n'))
    return options, args


def main(arguments=None):
    if arguments:
        argv = arguments
    else:
        argv = sys_argv

    version = client_version
    parser = OptionParser(version='%%prog %s' % version,
                          usage='''
usage: %%prog [--version] [--help] [--os-help] [--snet] [--verbose]
             [--debug] [--info] [--quiet] [--auth <auth_url>]
             [--auth-version <auth_version>] [--user <username>]
             [--key <api_key>] [--retries <num_retries>]
             [--os-username <auth-user-name>] [--os-password <auth-password>]
             [--os-user-id <auth-user-id>]
             [--os-user-domain-id <auth-user-domain-id>]
             [--os-user-domain-name <auth-user-domain-name>]
             [--os-tenant-id <auth-tenant-id>]
             [--os-tenant-name <auth-tenant-name>]
             [--os-project-id <auth-project-id>]
             [--os-project-name <auth-project-name>]
             [--os-project-domain-id <auth-project-domain-id>]
             [--os-project-domain-name <auth-project-domain-name>]
             [--os-auth-url <auth-url>] [--os-auth-token <auth-token>]
             [--os-storage-url <storage-url>] [--os-region-name <region-name>]
             [--os-service-type <service-type>]
             [--os-endpoint-type <endpoint-type>]
             [--os-cacert <ca-certificate>] [--insecure]
             [--no-ssl-compression]
             <subcommand> [--help]

Command-line interface to the OpenStack Swift API.

Positional arguments:
  <subcommand>
    delete               Delete a container or objects within a container.
    download             Download objects from containers.
    list                 Lists the containers for the account or the objects
                         for a container.
    post                 Updates meta information for the account, container,
                         or object; creates containers if not present.
    stat                 Displays information for the account, container,
                         or object.
    upload               Uploads files or directories to the given container.
    capabilities         List cluster capabilities.
    tempurl              Create a temporary URL

Examples:
  %%prog download --help

  %%prog -A https://auth.api.rackspacecloud.com/v1.0 -U user -K api_key stat -v

  %%prog --os-auth-url https://api.example.com/v2.0 --os-tenant-name tenant \\
      --os-username user --os-password password list

  %%prog --os-auth-url https://api.example.com/v3 --auth-version 3\\
      --os-project-name project1 --os-project-domain-name domain1 \\
      --os-username user --os-user-domain-name domain1 \\
      --os-password password list

  %%prog --os-auth-url https://api.example.com/v3 --auth-version 3\\
      --os-project-id 0123456789abcdef0123456789abcdef \\
      --os-user-id abcdef0123456789abcdef0123456789 \\
      --os-password password list

  %%prog --os-auth-token 6ee5eb33efad4e45ab46806eac010566 \\
      --os-storage-url https://10.1.5.2:8080/v1/AUTH_ced809b6a4baea7aeab61a \\
      list

  %%prog list --lh
'''.strip('\n') % globals())
    parser.add_option('--os-help', action='store_true', dest='os_help',
                      help='Show OpenStack authentication options.')
    parser.add_option('--os_help', action='store_true', help=SUPPRESS_HELP)
    parser.add_option('-s', '--snet', action='store_true', dest='snet',
                      default=False, help='Use SERVICENET internal network.')
    parser.add_option('-v', '--verbose', action='count', dest='verbose',
                      default=1, help='Print more info.')
    parser.add_option('--debug', action='store_true', dest='debug',
                      default=False, help='Show the curl commands and results '
                      'of all http queries regardless of result status.')
    parser.add_option('--info', action='store_true', dest='info',
                      default=False, help='Show the curl commands and results '
                      'of all http queries which return an error.')
    parser.add_option('-q', '--quiet', action='store_const', dest='verbose',
                      const=0, default=1, help='Suppress status output.')
    parser.add_option('-A', '--auth', dest='auth',
                      default=environ.get('ST_AUTH'),
                      help='URL for obtaining an auth token.')
    parser.add_option('-V', '--auth-version',
                      dest='auth_version',
                      default=environ.get('ST_AUTH_VERSION',
                                          (environ.get('OS_AUTH_VERSION',
                                                       '1.0'))),
                      type=str,
                      help='Specify a version for authentication. '
                           'Defaults to 1.0.')
    parser.add_option('-U', '--user', dest='user',
                      default=environ.get('ST_USER'),
                      help='User name for obtaining an auth token.')
    parser.add_option('-K', '--key', dest='key',
                      default=environ.get('ST_KEY'),
                      help='Key for obtaining an auth token.')
    parser.add_option('-R', '--retries', type=int, default=5, dest='retries',
                      help='The number of times to retry a failed connection.')
    default_val = config_true_value(environ.get('SWIFTCLIENT_INSECURE'))
    parser.add_option('--insecure',
                      action="store_true", dest="insecure",
                      default=default_val,
                      help='Allow swiftclient to access servers without '
                           'having to verify the SSL certificate. '
                           'Defaults to env[SWIFTCLIENT_INSECURE] '
                           '(set to \'true\' to enable).')
    parser.add_option('--no-ssl-compression',
                      action='store_false', dest='ssl_compression',
                      default=True,
                      help='This option is deprecated and not used anymore. '
                           'SSL compression should be disabled by default '
                           'by the system SSL library.')

    os_grp = OptionGroup(parser, "OpenStack authentication options")
    os_grp.add_option('--os-username',
                      metavar='<auth-user-name>',
                      default=environ.get('OS_USERNAME'),
                      help='OpenStack username. Defaults to env[OS_USERNAME].')
    os_grp.add_option('--os_username',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-user-id',
                      metavar='<auth-user-id>',
                      default=environ.get('OS_USER_ID'),
                      help='OpenStack user ID. '
                      'Defaults to env[OS_USER_ID].')
    os_grp.add_option('--os_user_id',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-user-domain-id',
                      metavar='<auth-user-domain-id>',
                      default=environ.get('OS_USER_DOMAIN_ID'),
                      help='OpenStack user domain ID. '
                      'Defaults to env[OS_USER_DOMAIN_ID].')
    os_grp.add_option('--os_user_domain_id',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-user-domain-name',
                      metavar='<auth-user-domain-name>',
                      default=environ.get('OS_USER_DOMAIN_NAME'),
                      help='OpenStack user domain name. '
                           'Defaults to env[OS_USER_DOMAIN_NAME].')
    os_grp.add_option('--os_user_domain_name',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-password',
                      metavar='<auth-password>',
                      default=environ.get('OS_PASSWORD'),
                      help='OpenStack password. Defaults to env[OS_PASSWORD].')
    os_grp.add_option('--os_password',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-tenant-id',
                      metavar='<auth-tenant-id>',
                      default=environ.get('OS_TENANT_ID'),
                      help='OpenStack tenant ID. '
                      'Defaults to env[OS_TENANT_ID].')
    os_grp.add_option('--os_tenant_id',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-tenant-name',
                      metavar='<auth-tenant-name>',
                      default=environ.get('OS_TENANT_NAME'),
                      help='OpenStack tenant name. '
                           'Defaults to env[OS_TENANT_NAME].')
    os_grp.add_option('--os_tenant_name',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-project-id',
                      metavar='<auth-project-id>',
                      default=environ.get('OS_PROJECT_ID'),
                      help='OpenStack project ID. '
                      'Defaults to env[OS_PROJECT_ID].')
    os_grp.add_option('--os_project_id',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-project-name',
                      metavar='<auth-project-name>',
                      default=environ.get('OS_PROJECT_NAME'),
                      help='OpenStack project name. '
                           'Defaults to env[OS_PROJECT_NAME].')
    os_grp.add_option('--os_project_name',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-project-domain-id',
                      metavar='<auth-project-domain-id>',
                      default=environ.get('OS_PROJECT_DOMAIN_ID'),
                      help='OpenStack project domain ID. '
                      'Defaults to env[OS_PROJECT_DOMAIN_ID].')
    os_grp.add_option('--os_project_domain_id',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-project-domain-name',
                      metavar='<auth-project-domain-name>',
                      default=environ.get('OS_PROJECT_DOMAIN_NAME'),
                      help='OpenStack project domain name. '
                           'Defaults to env[OS_PROJECT_DOMAIN_NAME].')
    os_grp.add_option('--os_project_domain_name',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-auth-url',
                      metavar='<auth-url>',
                      default=environ.get('OS_AUTH_URL'),
                      help='OpenStack auth URL. Defaults to env[OS_AUTH_URL].')
    os_grp.add_option('--os_auth_url',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-auth-token',
                      metavar='<auth-token>',
                      default=environ.get('OS_AUTH_TOKEN'),
                      help='OpenStack token. Defaults to env[OS_AUTH_TOKEN]. '
                           'Used with --os-storage-url to bypass the '
                           'usual username/password authentication.')
    os_grp.add_option('--os_auth_token',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-storage-url',
                      metavar='<storage-url>',
                      default=environ.get('OS_STORAGE_URL'),
                      help='OpenStack storage URL. '
                           'Defaults to env[OS_STORAGE_URL]. '
                           'Overrides the storage url returned during auth. '
                           'Will bypass authentication when used with '
                           '--os-auth-token.')
    os_grp.add_option('--os_storage_url',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-region-name',
                      metavar='<region-name>',
                      default=environ.get('OS_REGION_NAME'),
                      help='OpenStack region name. '
                           'Defaults to env[OS_REGION_NAME].')
    os_grp.add_option('--os_region_name',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-service-type',
                      metavar='<service-type>',
                      default=environ.get('OS_SERVICE_TYPE'),
                      help='OpenStack Service type. '
                           'Defaults to env[OS_SERVICE_TYPE].')
    os_grp.add_option('--os_service_type',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-endpoint-type',
                      metavar='<endpoint-type>',
                      default=environ.get('OS_ENDPOINT_TYPE'),
                      help='OpenStack Endpoint type. '
                           'Defaults to env[OS_ENDPOINT_TYPE].')
    os_grp.add_option('--os_endpoint_type',
                      help=SUPPRESS_HELP)
    os_grp.add_option('--os-cacert',
                      metavar='<ca-certificate>',
                      default=environ.get('OS_CACERT'),
                      help='Specify a CA bundle file to use in verifying a '
                      'TLS (https) server certificate. '
                      'Defaults to env[OS_CACERT].')
    parser.disable_interspersed_args()
    # call parse_args before adding os options group so that -h, --help will
    # print a condensed help message without the os options
    (options, args) = parse_args(parser, argv[1:], enforce_requires=False)
    parser.add_option_group(os_grp)
    if options.os_help:
        # if openstack option help has been explicitly requested then force
        # help message, now that os_options group has been added to parser
        argv = ['-h']
    (options, args) = parse_args(parser, argv[1:], enforce_requires=False)
    parser.enable_interspersed_args()

    if not args or args[0] not in commands:
        parser.print_usage()
        if args:
            exit('no such command: %s' % args[0])
        exit()

    signal.signal(signal.SIGINT, immediate_exit)

    if options.debug or options.info:
        logging.getLogger("swiftclient")
        if options.debug:
            logging.basicConfig(level=logging.DEBUG)
        elif options.info:
            logging.basicConfig(level=logging.INFO)

    with OutputManager() as output:

        parser.usage = globals()['st_%s_help' % args[0]]
        try:
            globals()['st_%s' % args[0]](parser, argv[1:], output)
        except (ClientException, RequestException, socket.error) as err:
            output.error(str(err))

    if output.get_error_count() > 0:
        exit(1)


if __name__ == '__main__':
    main()
