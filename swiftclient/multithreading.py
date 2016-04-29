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

import six
import sys

from concurrent.futures import ThreadPoolExecutor
from six.moves.queue import PriorityQueue


class OutputManager(object):
    """
    One object to manage and provide helper functions for output.

    This object is a context manager and returns itself into the context.  When
    entering the context, two printing threads are created (see below) and they
    are waited on and cleaned up when exiting the context.

    Also, thread-safe printing to two streams is provided.  The
    :meth:`print_msg` method will print to the supplied ``print_stream``
    (defaults to ``sys.stdout``) and the :meth:`error` method will print to the
    supplied ``error_stream`` (defaults to ``sys.stderr``).  Both of these
    printing methods will format the given string with any supplied ``*args``
    (a la printf). On Python 2, Unicode messages are encoded to utf8.

    The attribute :attr:`self.error_count` is incremented once per error
    message printed, so an application can tell if any worker threads
    encountered exceptions or otherwise called :meth:`error` on this instance.
    The swift command-line tool uses this to exit non-zero if any error strings
    were printed.
    """
    DEFAULT_OFFSET = 14

    def __init__(self, print_stream=None, error_stream=None):
        """
        :param print_stream: The stream to which :meth:`print_msg` sends
                             formatted messages.
        :param error_stream: The stream to which :meth:`error` sends formatted
                             messages.

        On Python 2, Unicode messages are encoded to utf8.
        """
        self.print_stream = print_stream or sys.stdout
        self.print_pool = ThreadPoolExecutor(max_workers=1)

        self.error_stream = error_stream or sys.stderr
        self.error_print_pool = ThreadPoolExecutor(max_workers=1)
        self.error_count = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.error_print_pool.__exit__(exc_type, exc_value, traceback)
        self.print_pool.__exit__(exc_type, exc_value, traceback)

    def print_raw(self, data):
        self.print_pool.submit(self._write, data, self.print_stream)

    def _write(self, data, stream):
        if six.PY3:
            stream.buffer.write(data)
            stream.flush()
        if six.PY2:
            stream.write(data)
            stream.flush()

    def print_msg(self, msg, *fmt_args):
        if fmt_args:
            msg = msg % fmt_args
        self.print_pool.submit(self._print, msg)

    def print_items(self, items, offset=DEFAULT_OFFSET, skip_missing=False):
        template = '%%%ds: %%s' % offset
        for k, v in items:
            if skip_missing and not v:
                continue
            self.print_msg((template % (k, v)).rstrip())

    def error(self, msg, *fmt_args):
        if fmt_args:
            msg = msg % fmt_args
        self.error_print_pool.submit(self._print_error, msg)

    def get_error_count(self):
        return self.error_count

    def _print(self, item, stream=None):
        if stream is None:
            stream = self.print_stream
        if six.PY2 and isinstance(item, six.text_type):
            item = item.encode('utf8')
        print(item, file=stream)

    def _print_error(self, item, count=1):
        self.error_count += count
        return self._print(item, stream=self.error_stream)

    def warning(self, msg, *fmt_args):
        # print to error stream but do not increment error count
        if fmt_args:
            msg = msg % fmt_args
        self.error_print_pool.submit(self._print_error, msg, count=0)


class MultiThreadingManager(object):
    """
    One object to manage context for multi-threading.  This should make
    bin/swift less error-prone and allow us to test this code.
    """

    def __init__(self, create_connection, segment_threads=10,
                 object_dd_threads=10, object_uu_threads=10,
                 container_threads=10):
        """
        :param segment_threads: The number of threads allocated to segment
                                uploads
        :param object_dd_threads: The number of threads allocated to object
                                  download/delete jobs
        :param object_uu_threads: The number of threads allocated to object
                                  upload/update based jobs
        :param container_threads: The number of threads allocated to
                                  container/account level jobs
        """
        self.segment_pool = ConnectionThreadPoolExecutor(
            create_connection, max_workers=segment_threads)
        self.object_dd_pool = ConnectionThreadPoolExecutor(
            create_connection, max_workers=object_dd_threads)
        self.object_uu_pool = ConnectionThreadPoolExecutor(
            create_connection, max_workers=object_uu_threads)
        self.container_pool = ConnectionThreadPoolExecutor(
            create_connection, max_workers=container_threads)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.segment_pool.__exit__(exc_type, exc_value, traceback)
        self.object_dd_pool.__exit__(exc_type, exc_value, traceback)
        self.object_uu_pool.__exit__(exc_type, exc_value, traceback)
        self.container_pool.__exit__(exc_type, exc_value, traceback)


class ConnectionThreadPoolExecutor(ThreadPoolExecutor):
    """
    A wrapper class to maintain a pool of connections alongside the thread
    pool. We start by creating a priority queue of connections, and each job
    submitted takes one of those connections (initialising if necessary) and
    passes it as the first arg to the executed function.

    At the end of execution that connection is returned to the queue.

    By using a PriorityQueue we avoid creating more connections than required.
    We will only create as many connections as are required concurrently.
    """
    def __init__(self, create_connection, max_workers):
        self._connections = PriorityQueue()
        self._create_connection = create_connection
        for p in range(0, max_workers):
            self._connections.put((p, None))
        super(ConnectionThreadPoolExecutor, self).__init__(max_workers)

    def submit(self, fn, *args, **kwargs):
        def conn_fn():
            priority = None
            conn = None
            try:
                # If we get a connection we must put it back later
                (priority, conn) = self._connections.get()
                if conn is None:
                    conn = self._create_connection()
                conn_args = (conn,) + args
                return fn(*conn_args, **kwargs)
            finally:
                if priority is not None:
                    self._connections.put((priority, conn))

        return super(ConnectionThreadPoolExecutor, self).submit(conn_fn)
