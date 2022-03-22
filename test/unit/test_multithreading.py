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

from queue import Queue, Empty
import sys
import unittest
import threading

from concurrent.futures import as_completed
from time import sleep

from swiftclient import multithreading as mt
from .utils import CaptureStream


class ThreadTestCase(unittest.TestCase):
    def setUp(self):
        super(ThreadTestCase, self).setUp()
        self.got_items = Queue()
        self.got_args_kwargs = Queue()
        self.starting_thread_count = threading.active_count()

    def _func(self, conn, item, *args, **kwargs):
        self.got_items.put((conn, item))
        self.got_args_kwargs.put((args, kwargs))

        if item == 'sleep':
            sleep(.1)
        if item == 'go boom':
            raise Exception('I went boom!')

        return 'success'

    def _create_conn(self):
        return "This is a connection"

    def _create_conn_fail(self):
        raise Exception("This is a failed connection")

    def assertQueueContains(self, queue, expected_contents):
        got_contents = []
        try:
            while True:
                got_contents.append(queue.get(timeout=0.1))
        except Empty:
            pass
        if isinstance(expected_contents, set):
            got_contents = set(got_contents)
        self.assertEqual(expected_contents, got_contents)


class TestConnectionThreadPoolExecutor(ThreadTestCase):
    def setUp(self):
        super(TestConnectionThreadPoolExecutor, self).setUp()
        self.input_queue = Queue()
        self.stored_results = []

    def tearDown(self):
        super(TestConnectionThreadPoolExecutor, self).tearDown()

    def test_submit_good_connection(self):
        ctpe = mt.ConnectionThreadPoolExecutor(self._create_conn, 1)
        with ctpe as pool:
            # Try submitting a job that should succeed
            f = pool.submit(self._func, "succeed")
            f.result()
            self.assertQueueContains(
                self.got_items,
                [("This is a connection", "succeed")]
            )

            # Now a job that fails
            try:
                f = pool.submit(self._func, "go boom")
                f.result()
            except Exception as e:
                self.assertEqual('I went boom!', str(e))
            else:
                self.fail('I never went boom!')

            # Has the connection been returned to the pool?
            f = pool.submit(self._func, "succeed")
            f.result()
            self.assertQueueContains(
                self.got_items,
                [
                    ("This is a connection", "go boom"),
                    ("This is a connection", "succeed")
                ]
            )

    def test_submit_bad_connection(self):
        ctpe = mt.ConnectionThreadPoolExecutor(self._create_conn_fail, 1)
        with ctpe as pool:
            # Now a connection that fails
            try:
                f = pool.submit(self._func, "succeed")
                f.result()
            except Exception as e:
                self.assertEqual('This is a failed connection', str(e))
            else:
                self.fail('The connection did not fail')

            # Make sure we don't lock up on failed connections
            try:
                f = pool.submit(self._func, "go boom")
                f.result()
            except Exception as e:
                self.assertEqual('This is a failed connection', str(e))
            else:
                self.fail('The connection did not fail')

    def test_lazy_connections(self):
        ctpe = mt.ConnectionThreadPoolExecutor(self._create_conn, 10)
        with ctpe as pool:
            # Submit multiple jobs sequentially - should only use 1 conn
            f = pool.submit(self._func, "succeed")
            f.result()
            f = pool.submit(self._func, "succeed")
            f.result()
            f = pool.submit(self._func, "succeed")
            f.result()

            expected_connections = [(0, "This is a connection")]
            expected_connections.extend([(x, None) for x in range(1, 10)])

            self.assertQueueContains(
                pool._connections, expected_connections
            )

        ctpe = mt.ConnectionThreadPoolExecutor(self._create_conn, 10)
        with ctpe as pool:
            fs = []
            f1 = pool.submit(self._func, "sleep")
            f2 = pool.submit(self._func, "sleep")
            f3 = pool.submit(self._func, "sleep")
            fs.extend([f1, f2, f3])

            expected_connections = [
                (0, "This is a connection"),
                (1, "This is a connection"),
                (2, "This is a connection")
            ]
            expected_connections.extend([(x, None) for x in range(3, 10)])

            for f in as_completed(fs):
                f.result()

            self.assertQueueContains(
                pool._connections, expected_connections
            )


class TestOutputManager(unittest.TestCase):

    def test_instantiation(self):
        output_manager = mt.OutputManager()

        self.assertEqual(sys.stdout, output_manager.print_stream)
        self.assertEqual(sys.stderr, output_manager.error_stream)

    def test_printers(self):
        out_stream = CaptureStream(sys.stdout)
        err_stream = CaptureStream(sys.stderr)
        starting_thread_count = threading.active_count()

        with mt.OutputManager(
                print_stream=out_stream,
                error_stream=err_stream) as thread_manager:

            # Sanity-checking these gives power to the previous test which
            # looked at the default values of thread_manager.print/error_stream
            self.assertEqual(out_stream, thread_manager.print_stream)
            self.assertEqual(err_stream, thread_manager.error_stream)

            # No printing has happened yet, so no new threads
            self.assertEqual(starting_thread_count,
                             threading.active_count())

            thread_manager.print_msg('one-argument')
            thread_manager.print_msg('one %s, %d fish', 'fish', 88)
            thread_manager.error('I have %d problems, but a %s is not one',
                                 99, '\u062A\u062A')
            thread_manager.print_msg('some\n%s\nover the %r', 'where',
                                     '\u062A\u062A')
            thread_manager.error('one-error-argument')
            thread_manager.error('Sometimes\n%.1f%% just\ndoes not\nwork!',
                                 3.14159)
            thread_manager.print_raw(
                'some raw bytes: \u062A\u062A'.encode('utf-8'))

            thread_manager.print_items([
                ('key', 'value'),
                ('object', 'O\u0308bject'),
            ])

            thread_manager.print_raw(b'\xffugly\xffraw')

            # Now we have a thread for error printing and a thread for
            # normal print messages
            self.assertEqual(starting_thread_count + 2,
                             threading.active_count())

        # The threads should have been cleaned up
        self.assertEqual(starting_thread_count, threading.active_count())

        self.assertEqual(''.join([
            'one-argument\n',
            'one fish, 88 fish\n',
            'some\n', 'where\n',
            "over the '\u062a\u062a'\n",
            'some raw bytes: \u062a\u062a',
            '           key: value\n',
            '        object: O\u0308bject\n'
        ]).encode('utf8') + b'\xffugly\xffraw', out_stream.getvalue())

        self.assertEqual(''.join([
            'I have 99 problems, but a \u062A\u062A is not one\n',
            'one-error-argument\n',
            'Sometimes\n', '3.1% just\n', 'does not\n', 'work!\n'
        ]), err_stream.getvalue().decode('utf8'))

        self.assertEqual(3, thread_manager.error_count)
