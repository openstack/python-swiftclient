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

import sys
import time
import mock
import testtools
import threading
from cStringIO import StringIO
from Queue import Queue, Empty

from swiftclient import multithreading as mt
from swiftclient.exceptions import ClientException


class ThreadTestCase(testtools.TestCase):
    def setUp(self):
        super(ThreadTestCase, self).setUp()
        self.got_args_kwargs = Queue()
        self.starting_thread_count = threading.active_count()

    def _func(self, q_item, *args, **kwargs):
        self.got_items.put(q_item)
        self.got_args_kwargs.put((args, kwargs))

        if q_item == 'go boom':
            raise Exception('I went boom!')
        if q_item == 'c boom':
            raise ClientException(
                'Client Boom', http_scheme='http', http_host='192.168.22.1',
                http_port=80, http_path='/booze', http_status=404,
                http_reason='to much', http_response_content='no sir!')

        return 'best result EVAR!'

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


class TestQueueFunctionThread(ThreadTestCase):
    def setUp(self):
        super(TestQueueFunctionThread, self).setUp()

        self.input_queue = Queue()
        self.got_items = Queue()
        self.stored_results = []

        self.qft = mt.QueueFunctionThread(self.input_queue, self._func,
                                          'one_arg', 'two_arg',
                                          red_fish='blue_arg',
                                          store_results=self.stored_results)
        self.qft.start()

    def tearDown(self):
        if self.qft.is_alive():
            self.finish_up_thread()

        super(TestQueueFunctionThread, self).tearDown()

    def finish_up_thread(self):
        self.input_queue.put(mt.StopWorkerThreadSignal())
        while self.qft.is_alive():
            time.sleep(0.05)

    def test_plumbing_and_store_results(self):
        self.input_queue.put('abc')
        self.input_queue.put(123)
        self.finish_up_thread()

        self.assertQueueContains(self.got_items, ['abc', 123])
        self.assertQueueContains(self.got_args_kwargs, [
            (('one_arg', 'two_arg'), {'red_fish': 'blue_arg'}),
            (('one_arg', 'two_arg'), {'red_fish': 'blue_arg'})])
        self.assertEqual(self.stored_results,
                         ['best result EVAR!', 'best result EVAR!'])

    def test_exception_handling(self):
        self.input_queue.put('go boom')
        self.input_queue.put('ok')
        self.input_queue.put('go boom')
        self.finish_up_thread()

        self.assertQueueContains(self.got_items,
                                 ['go boom', 'ok', 'go boom'])
        self.assertEqual(len(self.qft.exc_infos), 2)
        self.assertEqual(Exception, self.qft.exc_infos[0][0])
        self.assertEqual(Exception, self.qft.exc_infos[1][0])
        self.assertEqual(('I went boom!',), self.qft.exc_infos[0][1].args)
        self.assertEqual(('I went boom!',), self.qft.exc_infos[1][1].args)


class TestQueueFunctionManager(ThreadTestCase):
    def setUp(self):
        super(TestQueueFunctionManager, self).setUp()
        self.thread_manager = mock.create_autospec(
            mt.MultiThreadingManager, spec_set=True, instance=True)
        self.thread_count = 4
        self.error_counter = [0]
        self.got_items = Queue()
        self.stored_results = []
        self.qfq = mt.QueueFunctionManager(
            self._func, self.thread_count, self.thread_manager,
            thread_args=('1arg', '2arg'),
            thread_kwargs={'a': 'b', 'store_results': self.stored_results},
            error_counter=self.error_counter,
            connection_maker=self.connection_maker)

    def connection_maker(self):
        return 'yup, I made a connection'

    def test_context_manager_without_error_counter(self):
        self.qfq = mt.QueueFunctionManager(
            self._func, self.thread_count, self.thread_manager,
            thread_args=('1arg', '2arg'),
            thread_kwargs={'a': 'b', 'store_results': self.stored_results},
            connection_maker=self.connection_maker)

        with self.qfq as input_queue:
            self.assertEqual(self.starting_thread_count + self.thread_count,
                             threading.active_count())
            input_queue.put('go boom')

        self.assertEqual(self.starting_thread_count, threading.active_count())
        error_strs = map(str, self.thread_manager.error.call_args_list)
        self.assertEqual(1, len(error_strs))
        self.assertTrue('Exception: I went boom!' in error_strs[0])

    def test_context_manager_without_conn_maker_or_error_counter(self):
        self.qfq = mt.QueueFunctionManager(
            self._func, self.thread_count, self.thread_manager,
            thread_args=('1arg', '2arg'), thread_kwargs={'a': 'b'})

        with self.qfq as input_queue:
            self.assertEqual(self.starting_thread_count + self.thread_count,
                             threading.active_count())
            for i in range(20):
                input_queue.put('slap%d' % i)

        self.assertEqual(self.starting_thread_count, threading.active_count())
        self.assertEqual([], self.thread_manager.error.call_args_list)
        self.assertEqual(0, self.error_counter[0])
        self.assertQueueContains(self.got_items,
                                 set(['slap%d' % i for i in range(20)]))
        self.assertQueueContains(
            self.got_args_kwargs,
            [(('1arg', '2arg'), {'a': 'b'})] * 20)
        self.assertEqual(self.stored_results, [])

    def test_context_manager_with_exceptions(self):
        with self.qfq as input_queue:
            self.assertEqual(self.starting_thread_count + self.thread_count,
                             threading.active_count())
            for i in range(20):
                input_queue.put('item%d' % i if i % 2 == 0 else 'go boom')

        self.assertEqual(self.starting_thread_count, threading.active_count())
        error_strs = map(str, self.thread_manager.error.call_args_list)
        self.assertEqual(10, len(error_strs))
        self.assertTrue(all(['Exception: I went boom!' in s for s in
                             error_strs]))
        self.assertEqual(10, self.error_counter[0])
        expected_items = set(['go boom'] +
                             ['item%d' % i for i in range(20)
                              if i % 2 == 0])
        self.assertQueueContains(self.got_items, expected_items)
        self.assertQueueContains(
            self.got_args_kwargs,
            [(('yup, I made a connection', '1arg', '2arg'), {'a': 'b'})] * 20)
        self.assertEqual(self.stored_results, ['best result EVAR!'] * 10)

    def test_context_manager_with_client_exceptions(self):
        with self.qfq as input_queue:
            self.assertEqual(self.starting_thread_count + self.thread_count,
                             threading.active_count())
            for i in range(20):
                input_queue.put('item%d' % i if i % 2 == 0 else 'c boom')

        self.assertEqual(self.starting_thread_count, threading.active_count())
        error_strs = map(str, self.thread_manager.error.call_args_list)
        self.assertEqual(10, len(error_strs))
        stringification = 'Client Boom: ' \
            'http://192.168.22.1:80/booze 404 to much   no sir!'
        self.assertTrue(all([stringification in s for s in error_strs]))
        self.assertEqual(10, self.error_counter[0])
        expected_items = set(['c boom'] +
                             ['item%d' % i for i in range(20)
                              if i % 2 == 0])
        self.assertQueueContains(self.got_items, expected_items)
        self.assertQueueContains(
            self.got_args_kwargs,
            [(('yup, I made a connection', '1arg', '2arg'), {'a': 'b'})] * 20)
        self.assertEqual(self.stored_results, ['best result EVAR!'] * 10)

    def test_context_manager_with_connection_maker(self):
        with self.qfq as input_queue:
            self.assertEqual(self.starting_thread_count + self.thread_count,
                             threading.active_count())
            for i in range(20):
                input_queue.put('item%d' % i)

        self.assertEqual(self.starting_thread_count, threading.active_count())
        self.assertEqual([], self.thread_manager.error.call_args_list)
        self.assertEqual(0, self.error_counter[0])
        self.assertQueueContains(self.got_items,
                                 set(['item%d' % i for i in range(20)]))
        self.assertQueueContains(
            self.got_args_kwargs,
            [(('yup, I made a connection', '1arg', '2arg'), {'a': 'b'})] * 20)
        self.assertEqual(self.stored_results, ['best result EVAR!'] * 20)


class TestMultiThreadingManager(ThreadTestCase):

    @mock.patch('swiftclient.multithreading.QueueFunctionManager')
    def test_instantiation(self, mock_qfq):
        thread_manager = mt.MultiThreadingManager()

        self.assertEqual([
            mock.call(thread_manager._print, 1, thread_manager),
            mock.call(thread_manager._print_error, 1, thread_manager),
        ], mock_qfq.call_args_list)

        # These contexts don't get entered into until the
        # MultiThreadingManager's context is entered.
        self.assertEqual([], thread_manager.printer.__enter__.call_args_list)
        self.assertEqual([],
                         thread_manager.error_printer.__enter__.call_args_list)

        # Test default values for the streams.
        self.assertEqual(sys.stdout, thread_manager.print_stream)
        self.assertEqual(sys.stderr, thread_manager.error_stream)

    @mock.patch('swiftclient.multithreading.QueueFunctionManager')
    def test_queue_manager_no_args(self, mock_qfq):
        thread_manager = mt.MultiThreadingManager()

        mock_qfq.reset_mock()
        mock_qfq.return_value = 'slap happy!'

        self.assertEqual(
            'slap happy!',
            thread_manager.queue_manager(self._func, 88))

        self.assertEqual([
            mock.call(self._func, 88, thread_manager, thread_args=(),
                      thread_kwargs={}, connection_maker=None,
                      error_counter=None)
        ], mock_qfq.call_args_list)

    @mock.patch('swiftclient.multithreading.QueueFunctionManager')
    def test_queue_manager_with_args(self, mock_qfq):
        thread_manager = mt.MultiThreadingManager()

        mock_qfq.reset_mock()
        mock_qfq.return_value = 'do run run'

        self.assertEqual(
            'do run run',
            thread_manager.queue_manager(self._func, 88, 'fun', times='are',
                                         connection_maker='abc', to='be had',
                                         error_counter='def'))

        self.assertEqual([
            mock.call(self._func, 88, thread_manager, thread_args=('fun',),
                      thread_kwargs={'times': 'are', 'to': 'be had'},
                      connection_maker='abc', error_counter='def')
        ], mock_qfq.call_args_list)

    def test_printers(self):
        out_stream = StringIO()
        err_stream = StringIO()

        with mt.MultiThreadingManager(
                print_stream=out_stream,
                error_stream=err_stream) as thread_manager:

            # Sanity-checking these gives power to the previous test which
            # looked at the default values of thread_manager.print/error_stream
            self.assertEqual(out_stream, thread_manager.print_stream)
            self.assertEqual(err_stream, thread_manager.error_stream)

            self.assertEqual(self.starting_thread_count + 2,
                             threading.active_count())

            thread_manager.print_msg('one-argument')
            thread_manager.print_msg('one %s, %d fish', 'fish', 88)
            thread_manager.error('I have %d problems, but a %s is not one',
                                 99, u'\u062A\u062A')
            thread_manager.print_msg('some\n%s\nover the %r', 'where',
                                     u'\u062A\u062A')
            thread_manager.error('one-error-argument')
            thread_manager.error('Sometimes\n%.1f%% just\ndoes not\nwork!',
                                 3.14159)

        self.assertEqual(self.starting_thread_count, threading.active_count())

        out_stream.seek(0)
        self.assertEqual([
            'one-argument\n',
            'one fish, 88 fish\n',
            'some\n', 'where\n', "over the u'\\u062a\\u062a'\n",
        ], list(out_stream.readlines()))

        err_stream.seek(0)
        self.assertEqual([
            u'I have 99 problems, but a \u062A\u062A is not one\n'.encode(
                'utf8'),
            'one-error-argument\n',
            'Sometimes\n', '3.1% just\n', 'does not\n', 'work!\n',
        ], list(err_stream.readlines()))

        self.assertEqual(3, thread_manager.error_count)


if __name__ == '__main__':
    testtools.main()
