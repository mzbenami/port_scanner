import unittest
import mock
import random
import time

from port_scanner.scanner import *
from port_scanner.values import *
from port_scanner.chunker import LOWEST_PORT_NUMBER, HIGHEST_PORT_NUMBER

from mock_probe import MockProbe

VALID_PORT_LIST = range(LOWEST_PORT_NUMBER, HIGHEST_PORT_NUMBER + 1)


class ScannerBadHostTestCase(unittest.TestCase):

    @mock.patch('socket.gethostbyname', side_effect=socket.gaierror)
    def test_init_bad_host(self, mock_socket):
        host = 'badhost.com'
        port_list = [1, 2]

        with self.assertRaises(InvalidHostError):
            PortScanner(host, port_list)


def mock_select(r, w, e, timeout):
    time.sleep(random.uniform(0.0, timeout))

    return_empty = random.randint(0, 1)
    if return_empty:
        return [], [], []
    else:
        sample_size = random.randint(0, len(w))
        return [], list(random.sample(w, sample_size)), []


class ScannerTestCase(unittest.TestCase):

    def setUp(self):
        port_sample = random.sample(VALID_PORT_LIST, 100)
        self.scanner = PortScanner('goodhost.com', port_sample)

    @mock.patch('port_scanner.scanner.PortProbe', MockProbe)
    def test_launch_probes(self):
        port_chunk = random.sample(VALID_PORT_LIST, 20)
        fd_map = self.scanner.launch_probes(port_chunk)

        for fd in fd_map:
            probe = fd_map[fd]
            self.assertEqual(fd, probe.file_no)

            if probe.port not in port_chunk:
                self.assertIn(probe.port, self.scanner.results_map)
                self.assertEqual(probe.port, RESULT_FILTERED)

    @mock.patch('port_scanner.scanner.PortProbe', MockProbe)
    @mock.patch('select.select', mock_select)
    def test_poll(self):
        port_chunk = random.sample(VALID_PORT_LIST, 20)
        timeout = .1

        poll_start_time = time.time()
        self.scanner.poll(port_chunk, timeout=timeout)
        poll_elapsed_time = time.time() - poll_start_time

        self.assertLessEqual(poll_elapsed_time, timeout + .01)
        self.assertGreaterEqual(poll_elapsed_time, timeout - .01)

        for port in port_chunk:
            self.assertIn(port, self.scanner.results_map)
            self.assertIn(self.scanner.results_map[port], [RESULT_FILTERED, RESULT_OPEN, RESULT_CLOSED])

    @mock.patch('port_scanner.scanner.PortProbe', MockProbe)
    @mock.patch('select.select', mock_select)
    def test_run(self):
        self.scanner.run()

        for port in self.scanner.port_list:
            self.assertIn(port, self.scanner.results_map)
            self.assertIn(self.scanner.results_map[port], [RESULT_FILTERED, RESULT_OPEN, RESULT_CLOSED])

    def test_clear(self):
        self.scanner.results_map[5] = RESULT_OPEN
        self.scanner.clear()

        self.assertEqual(self.scanner.results_map, {})

    def test_reverse_chunk(self):
        chunk = [3, 2, 1]
        reversed_chunk = reverse_port_chunk(chunk)

        self.assertEqual(reversed_chunk, [1, 2, 3])


if __name__ == "__main__":
    unittest.main()